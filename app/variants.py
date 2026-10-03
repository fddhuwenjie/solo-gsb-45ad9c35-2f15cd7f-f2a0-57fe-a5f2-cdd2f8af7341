"""Minimum certificate-variant selection for heterogeneous clients.

Given the same unordered PEM bag used by ``/scenarios/normalize``, per-client
trust roots and cryptographic policies, per-endpoint candidate leaf-first
fingerprint chains and the client -> endpoint relationships that must stay
connected, this module picks, for each endpoint, the smallest set of chains
(variants) that must be deployed so every required relationship is covered.

A candidate chain covers a (client, endpoint) relationship iff *all* of the
following hold:

* every hop of the chain verifies cryptographically — each certificate's
  signature is checked against the public key of the next certificate in the
  chain (reusing the normalizer's signature verification; DN matching is never
  involved) — giving ``chain_signature_invalid`` otherwise;
* the chain ends at one of the client's declared trust roots — giving
  ``root_untrusted`` otherwise;
* the leaf public key type is in the client's acceptable list — giving
  ``leaf_key_type_incompatible`` otherwise;
* every certificate except the terminal trust root is signed with a signature
  algorithm OID the client accepts — giving
  ``signature_algorithm_incompatible`` otherwise (the trust root's own
  signature algorithm is never gated, exactly as a TLS verifier does not
  re-policy the anchor).

The four checks are evaluated independently: a chain that fails several of
them is reported with every failing reason.

The per-endpoint choice is a *minimum set cover* and is solved exactly by
enumerating chain subsets: there are at most
``MAX_VARIANT_CANDIDATES`` (12) candidates per endpoint, so at most 4096
subsets — a per-client greedy is deliberately *not* used, as it can miss the
global optimum. Ties between equally small sets are broken lexicographically:
sort the set's complete fingerprint chains and compare the sorted lists.
Each relationship is then mapped to the first compatible variant in that
sorted order.

Request-level failures (bad PEM, unknown/malformed fingerprints, malformed
OIDs, empty/cyclic chains, non-self-signed trust roots) are 422s via
``VariantSelectionError``; an otherwise valid request whose relationships
cannot all be covered produces a 409 conflict listing, stably per client and
endpoint, every reason every candidate chain fails for.
"""
from __future__ import annotations

import re
from itertools import combinations
from typing import TYPE_CHECKING, Optional

from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa

if TYPE_CHECKING:
    from cryptography import x509

from .models import (
    MAX_VARIANT_CANDIDATES,
    VARIANT_REASON_ORDER,
    NormalizeFingerprintIssue,
    NormalizePemIssue,
    VariantAssignment,
    VariantChainIssue,
    VariantClient,
    VariantEndpoint,
    VariantIncompatibility,
    VariantOidIssue,
    VariantSelection,
    VariantSelectionConflict,
    VariantSelectionErrorDetail,
    VariantSelectionRequest,
    VariantSelectionResult,
)
from .normalize import (
    FINGERPRINT_RE,
    _load_pem_bundle,
    _verify_signature,
)

# Dotted OID: non-empty dot-separated arcs of digits, no leading zeros on
# multi-digit arcs (ITU-T X.660 numbering), bounded to a sane total length.
_OID_RE = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))*$")
_OID_MAX_LEN = 256


class VariantSelectionError(ValueError):
    """Request-level variant-selection failure (mapped to HTTP 422)."""

    def __init__(
        self,
        error: str,
        message: str,
        *,
        pem_issues: Optional[list[NormalizePemIssue]] = None,
        fingerprint_issues: Optional[list[NormalizeFingerprintIssue]] = None,
        oid_issues: Optional[list[VariantOidIssue]] = None,
        chain_issues: Optional[list[VariantChainIssue]] = None,
    ) -> None:
        super().__init__(message)
        self.error = error
        self.message = message
        self.pem_issues = pem_issues or []
        self.fingerprint_issues = fingerprint_issues or []
        self.oid_issues = oid_issues or []
        self.chain_issues = chain_issues or []

    def detail(self) -> VariantSelectionErrorDetail:
        return VariantSelectionErrorDetail(
            error=self.error,
            message=self.message,
            pem_issues=self.pem_issues,
            fingerprint_issues=self.fingerprint_issues,
            oid_issues=self.oid_issues,
            chain_issues=self.chain_issues,
        )


# ---------------------------------------------------------------------------
# Leaf public key type classification
# ---------------------------------------------------------------------------


def leaf_key_type(public_key) -> Optional[str]:
    """Machine-readable leaf public-key type, or None when unclassifiable."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return "rsa"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ec"
    if isinstance(public_key, dsa.DSAPublicKey):
        return "dsa"
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "ed25519"
    if hasattr(ed448, "Ed448PublicKey") and isinstance(
        public_key, ed448.Ed448PublicKey
    ):
        return "ed448"
    return None


def _signature_oid(cert: x509.Certificate) -> Optional[str]:
    try:
        return cert.signature_algorithm_oid.dotted_string
    except Exception:  # pragma: no cover - defensive, cryptography always knows
        return None


# ---------------------------------------------------------------------------
# Exact minimum set-cover selection
# ---------------------------------------------------------------------------


def minimum_variant_set(
    candidates: list[tuple[str, ...]],
    required: list,
    covers,
):
    """Return the minimum subset of ``candidates`` covering every ``required``.

    ``candidates`` are hashable candidate keys; ``covers(candidate, item)`` is
    the coverage predicate. The optimum is found by exhaustive subset
    enumeration in increasing cardinality (a per-client greedy cannot be used:
    set cover optimum is not reachable greedily in general). Among equally
    small sets the lexicographically smallest list of sorted candidates wins,
    so the result is independent of candidate input order.

    Returns the selected candidate list (already sorted), or None when no
    subset covers every required item.
    """
    n = len(candidates)
    best: Optional[list] = None
    for size in range(1, n + 1):
        for combo in combinations(sorted(candidates), size):
            if all(any(covers(variant, item) for variant in combo)
                   for item in required):
                chosen = list(combo)
                if best is None or chosen < best:
                    best = chosen
        if best is not None:
            return best
    return None


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def select_variants(req: VariantSelectionRequest):
    """Validate the request and compute the per-endpoint minimum selection.

    Returns ``VariantSelectionResult`` on success or raises
    ``VariantSelectionError`` (422). When any relationship cannot be covered,
    returns a ``VariantSelectionConflict`` (409) listing every reason for
    every candidate chain of the uncovered relationships.
    """
    # -- structural uniqueness ------------------------------------------------
    client_ids = [c.client_id for c in req.clients]
    endpoint_ids = [e.endpoint_id for e in req.endpoints]
    if len(set(client_ids)) != len(client_ids):
        raise VariantSelectionError(
            "invalid_request", "clients: client_id values must be unique"
        )
    if len(set(endpoint_ids)) != len(endpoint_ids):
        raise VariantSelectionError(
            "invalid_request", "endpoints: endpoint_id values must be unique"
        )
    rel_keys = [(r.client_id, r.endpoint_id) for r in req.relationships]
    if len(set(rel_keys)) != len(rel_keys):
        raise VariantSelectionError(
            "invalid_request",
            "relationships: each (client_id, endpoint_id) pair may appear at "
            "most once",
        )

    clients: dict[str, VariantClient] = {c.client_id: c for c in req.clients}
    endpoints: dict[str, VariantEndpoint] = {
        e.endpoint_id: e for e in req.endpoints
    }

    # -- OID syntax ------------------------------------------------------------
    oid_issues: list[VariantOidIssue] = []
    policies: dict[str, tuple[set[str], set[str], frozenset[str]]] = {}
    for c in req.clients:
        good_oids: set[str] = set()
        for idx, raw in enumerate(c.acceptable_signature_oid):
            oid = raw.strip()
            if len(oid) > _OID_MAX_LEN or not _OID_RE.match(oid):
                oid_issues.append(VariantOidIssue(
                    client_id=c.client_id, index=idx, oid=raw))
            else:
                good_oids.add(oid)
        policies[c.client_id] = (
            set(c.acceptable_leaf_key_types),
            good_oids,
            frozenset(fp.strip().lower() for fp in c.trust_roots),
        )

    # -- fingerprint syntax + chain shape -------------------------------------
    fingerprint_issues: list[NormalizeFingerprintIssue] = []
    chain_issues: list[VariantChainIssue] = []
    for c in req.clients:
        for raw in c.trust_roots:
            fp = raw.strip().lower()
            if not FINGERPRINT_RE.match(fp):
                fingerprint_issues.append(NormalizeFingerprintIssue(
                    fingerprint=raw,
                    referred_by=f"clients['{c.client_id}'].trust_roots",
                ))
    for e in req.endpoints:
        if len(e.candidate_chains) > MAX_VARIANT_CANDIDATES:
            # Defensive: pydantic max_length normally rejects this first.
            raise VariantSelectionError(
                "invalid_request",
                f"endpoints['{e.endpoint_id}']: at most "
                f"{MAX_VARIANT_CANDIDATES} candidate chains are supported",
            )
        for idx, chain in enumerate(e.candidate_chains):
            if not chain:
                chain_issues.append(VariantChainIssue(
                    endpoint_id=e.endpoint_id, index=idx,
                    reason="empty_chain",
                    message="candidate chain must contain at least one "
                            "certificate",
                ))
                continue
            if len(set(chain)) != len(chain):
                chain_issues.append(VariantChainIssue(
                    endpoint_id=e.endpoint_id, index=idx,
                    reason="chain_cycle",
                    message="candidate chain must not contain a certificate "
                            "more than once (chains with cycles are rejected)",
                ))
            for j, raw in enumerate(chain):
                fp = raw.strip().lower()
                if not FINGERPRINT_RE.match(fp):
                    fingerprint_issues.append(NormalizeFingerprintIssue(
                        fingerprint=raw,
                        referred_by=(f"endpoints['{e.endpoint_id}']."
                                     f"candidate_chains[{idx}][{j}]"),
                    ))

    # -- relationship references ----------------------------------------------
    for r in req.relationships:
        if r.client_id not in clients:
            raise VariantSelectionError(
                "unknown_client",
                f"relationships: unknown client_id '{r.client_id}'",
            )
        if r.endpoint_id not in endpoints:
            raise VariantSelectionError(
                "unknown_endpoint",
                f"relationships: unknown endpoint_id '{r.endpoint_id}'",
            )

    if oid_issues:
        raise VariantSelectionError(
            "invalid_oid",
            "one or more acceptable signature algorithm OIDs are not valid "
            "dotted OIDs",
            oid_issues=oid_issues,
            fingerprint_issues=fingerprint_issues,
            chain_issues=chain_issues,
        )
    if fingerprint_issues:
        raise VariantSelectionError(
            "invalid_fingerprint",
            "one or more fingerprints are not 64-character hex SHA-256 values",
            fingerprint_issues=fingerprint_issues,
            chain_issues=chain_issues,
        )
    if chain_issues:
        raise VariantSelectionError(
            "invalid_chain",
            "one or more candidate chains are empty or contain a cycle",
            chain_issues=chain_issues,
        )

    # -- PEM parsing ----------------------------------------------------------
    certs, pem_issues = _load_pem_bundle(req.pem_certificates)
    if pem_issues:
        raise VariantSelectionError(
            "invalid_pem",
            "one or more PEM list elements could not be parsed",
            pem_issues=pem_issues,
        )

    # -- referential integrity ------------------------------------------------
    missing: list[NormalizeFingerprintIssue] = []
    for c in req.clients:
        for raw in c.trust_roots:
            fp = raw.strip().lower()
            if fp not in certs:
                missing.append(NormalizeFingerprintIssue(
                    fingerprint=fp,
                    referred_by=f"clients['{c.client_id}'].trust_roots",
                ))
    for e in req.endpoints:
        for idx, chain in enumerate(e.candidate_chains):
            for j, raw in enumerate(chain):
                fp = raw.strip().lower()
                if fp not in certs:
                    missing.append(NormalizeFingerprintIssue(
                        fingerprint=fp,
                        referred_by=(f"endpoints['{e.endpoint_id}']."
                                     f"candidate_chains[{idx}][{j}]"),
                    ))
    if missing:
        raise VariantSelectionError(
            "unknown_fingerprint",
            "some fingerprints do not match any certificate in the PEM bundle",
            fingerprint_issues=missing,
        )

    # -- declared trust roots must genuinely be self-signed -------------------
    bad_roots: list[NormalizeFingerprintIssue] = []
    for c in req.clients:
        for raw in c.trust_roots:
            fp = raw.strip().lower()
            root = certs[fp]
            if root.subject != root.issuer or not _verify_signature(root, root):
                bad_roots.append(NormalizeFingerprintIssue(
                    fingerprint=fp,
                    referred_by=f"clients['{c.client_id}'].trust_roots",
                ))
    if bad_roots:
        raise VariantSelectionError(
            "trust_root_not_self_signed",
            "every declared client trust root must be a self-signed "
            "certificate (subject == issuer with a valid self-signature)",
            fingerprint_issues=bad_roots,
        )

    # -- normalize candidate chains (dedupe identical chains per endpoint) ----
    normalized: dict[str, list[tuple[str, ...]]] = {}
    for e in req.endpoints:
        unique: set[tuple[str, ...]] = set()
        for chain in e.candidate_chains:
            unique.add(tuple(fp.strip().lower() for fp in chain))
        normalized[e.endpoint_id] = sorted(unique)

    # -- per (client, chain) compatibility ------------------------------------
    # Cache keyed (client_id, chain); reused by the solver and the 409 report.
    compat_cache: dict[tuple[str, tuple[str, ...]], Optional[list[str]]] = {}

    def incompatibilities(client_id: str, chain: tuple[str, ...]) -> list[str]:
        """All reasons ``chain`` fails for this client; [] = compatible."""
        key = (client_id, chain)
        if key in compat_cache:
            return compat_cache[key]
        key_types, accept_oids, roots = policies[client_id]

        reasons: list[str] = []

        # 1. Hop-by-hop real signature verification along the submitted chain.
        hop_ok = True
        for i in range(len(chain) - 1):
            if not _verify_signature(certs[chain[i]], certs[chain[i + 1]]):
                hop_ok = False
                break
        if not hop_ok:
            reasons.append("chain_signature_invalid")

        # 2. The terminal certificate must be among the client's anchors.
        if chain[-1] not in roots:
            reasons.append("root_untrusted")

        # 3. The leaf public key type must be acceptable.
        if leaf_key_type(certs[chain[0]].public_key()) not in key_types:
            reasons.append("leaf_key_type_incompatible")

        # 4. Every non-anchor certificate's signature algorithm OID must be
        #    accepted. The trust root's own signature is never policy-gated.
        chain_oids = [
            oid for i in range(len(chain) - 1)
            if (oid := _signature_oid(certs[chain[i]])) is not None
        ]
        if any(oid not in accept_oids for oid in chain_oids) or len(
            chain_oids
        ) != len(chain) - 1:
            reasons.append("signature_algorithm_incompatible")

        reasons.sort(key=lambda r: VARIANT_REASON_ORDER[r])
        compat_cache[key] = reasons
        return reasons

    def covers(chain: tuple[str, ...], rel: tuple[str, str]) -> bool:
        return not incompatibilities(rel[0], chain)

    # -- exact per-endpoint minimum selection ---------------------------------
    relationships_by_endpoint: dict[str, list[tuple[str, str]]] = {}
    for key in rel_keys:
        relationships_by_endpoint.setdefault(key[1], []).append(key)

    selections: list[VariantSelection] = []
    assignments: list[VariantAssignment] = []
    uncovered: list[VariantIncompatibility] = []

    for endpoint_id in sorted(endpoints):
        variants = normalized[endpoint_id]
        required = sorted(relationships_by_endpoint.get(endpoint_id, []))
        if not required:
            # Nothing must connect to this endpoint: deploying zero variants
            # is the (unique) minimum set.
            continue
        chosen = minimum_variant_set(variants, required, covers)
        if chosen is None:
            # Only relationships this endpoint must serve are unfulfillable;
            # report every candidate chain with every reason it fails for.
            for client_id, ep_id in required:
                for chain in variants:
                    reasons = incompatibilities(client_id, chain)
                    if not reasons:
                        continue
                    leaf = certs[chain[0]]
                    _kt, _so, roots = policies[client_id]
                    uncovered.append(VariantIncompatibility(
                        client_id=client_id,
                        endpoint_id=ep_id,
                        chain=list(chain),
                        reasons=reasons,  # type: ignore[arg-type]
                        leaf_key_type=leaf_key_type(leaf.public_key()),
                        signature_oids=[
                            oid for i in range(len(chain) - 1)
                            if (oid := _signature_oid(
                                certs[chain[i]])) is not None
                        ],
                        trusted_roots=sorted(roots),
                    ))
            continue

        for index, chain in enumerate(chosen):
            selections.append(VariantSelection(
                endpoint_id=endpoint_id,
                variant_index=index,
                chain=list(chain),
            ))
        # First compatible variant of the sorted selected set per relationship.
        for client_id, ep_id in required:
            for index, chain in enumerate(chosen):
                if covers(chain, (client_id, ep_id)):
                    assignments.append(VariantAssignment(
                        client_id=client_id,
                        endpoint_id=ep_id,
                        variant_index=index,
                        chain=list(chain),
                    ))
                    break

    if uncovered:
        uncovered.sort(key=lambda u: (
            u.client_id, u.endpoint_id, u.chain,
            [VARIANT_REASON_ORDER[r] for r in u.reasons],
        ))
        return VariantSelectionConflict(
            reason="uncoverable_relationship",
            message=(
                "one or more required client -> endpoint relationships cannot "
                "be covered by any candidate chain; incompatibilities are "
                "listed per client, endpoint and candidate chain"
            ),
            incompatibilities=uncovered,
        )

    assignments.sort(key=lambda a: (a.client_id, a.endpoint_id))
    return VariantSelectionResult(
        selections=selections,
        assignments=assignments,
    )
