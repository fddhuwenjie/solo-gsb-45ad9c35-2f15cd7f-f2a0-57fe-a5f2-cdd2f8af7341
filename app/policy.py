"""Certificate purpose & path-policy review for current/target chains.

Given the same unordered PEM bag used by ``/scenarios/normalize``, declared
trust roots, one verification instant ``check_time`` and, per endpoint, the
fingerprints of its current/target leaves plus its TLS role (``server`` /
``client``) and the EKUs the serving leaf is required to assert, this module
reconstructs both chains with the normalizer's signature-verification
machinery (issuance edges by real signature verification; exactly one path to
a declared trust root or a structured 422) and audits each chain against the
RFC 5280 path-policy rules:

* **Validity at check_time** — every certificate, including the trust anchor,
  must satisfy notBefore <= check_time <= notAfter (inclusive).
* **BasicConstraints** — every CA-position certificate (intermediates and the
  anchor) must carry a critical basicConstraints extension with cA=TRUE; a
  leaf must not be marked cA.
* **pathLenConstraint** — for every CA, the number of *non-self-issued*
  intermediate certificates below it in the reviewed chain must not exceed
  its pathLenConstraint.
* **CA / keyCertSign authority** — a CA-position certificate that carries a
  KeyUsage extension must assert keyCertSign.
* **Leaf KeyUsage** — a leaf that carries KeyUsage must assert a bit usable
  for the role: digitalSignature always (client always; server for ECDSA/
  EdDSA/DHE key exchange), keyEncipherment accepted additionally for an RSA
  server key-exchange leaf. A server leaf relying on keyEncipherment alone is
  therefore still deployable for the legacy RSA key exchange, while a client
  leaf needs digitalSignature.
* **Leaf / intermediate EKU** — the leaf must assert the role EKU
  (id-kp-serverAuth / id-kp-clientAuth) and every caller-supplied required
  EKU OID; an intermediate CA that constrans usage with an EKU extension must
  also permit each required EKU (RFC 5280 EKU chaining; anyExtendedKeyUsage
  satisfies every requirement). The trust anchor's EKU is not enforced,
  matching anchor handling across the API.
* **Unknown critical extensions** — every critical extension the verifier
  does not recognize fails closed. The recognized-critical set is the full
  RFC 5280 extension catalogue plus the widely deployed CAB/forum and
  Entrust extension OIDs; anything outside it is reported.

Both chains must comply: an endpoint whose *currently served* chain is
already non-compliant at check_time is never passed through, and only an
eligible target chain may be handed to ``/plans``. Results are reported
per endpoint (sorted by endpoint_id) with every participating certificate,
the full conflict list and the first conflicting rule.
"""
from __future__ import annotations

import re
from typing import Optional

from cryptography import x509

from .models import (
    PolicyChainReview,
    PolicyConflict,
    PolicyEkuIssue,
    PolicyReviewCertificate,
    PolicyReviewEndpoint,
    PolicyReviewEndpointResult,
    PolicyReviewRequest,
    PolicyReviewResult,
    POLICY_REASON_ORDER,
)
from .normalize import (
    FINGERPRINT_RE,
    NormalizeChainIssue,
    NormalizeError,
    NormalizeFingerprintIssue,
    _build_issuer_edges,
    _dedupe_paths,
    _dn,
    _enumerate_paths,
    _find_trust_path,
    _has_second_trust_path,
    _load_pem_bundle,
    _validity_utc,
    _verify_signature,
)

# Same dotted-OID grammar/length guard as the variants module.
_OID_RE = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))*$")
_OID_MAX_LEN = 256

_SERVER_AUTH_OID = "1.3.6.1.5.5.7.3.1"  # id-kp-serverAuth
_CLIENT_AUTH_OID = "1.3.6.1.5.5.7.3.2"  # id-kp-clientAuth
_ANY_EKU_OID = "2.5.29.37.0"            # anyExtendedKeyUsage

_ROLE_EKU = {"server": _SERVER_AUTH_OID, "client": _CLIENT_AUTH_OID}

# Extensions a standards-conformant verifier knows how to process. A
# critical extension whose OID is outside this catalogue cannot be honored,
# so the certificate/chain fails closed (RFC 5280 §4.2). The catalogue
# covers every RFC 5280 certificate/CRL extension OID plus the widely
# deployed PKIX/CT/Netscape critical-extension OIDs.
KNOWN_CRITICAL_EXTENSIONS = frozenset({
    "2.5.29.14",  # subjectKeyIdentifier
    "2.5.29.15",  # keyUsage
    "2.5.29.16",  # privateKeyUsagePeriod
    "2.5.29.17",  # subjectAltName
    "2.5.29.18",  # issuerAltName
    "2.5.29.19",  # basicConstraints
    "2.5.29.20",  # cRLNumber (CRL, never a certificate)
    "2.5.29.21",  # reasonCode (CRL entry)
    "2.5.29.22",  # expirationDate (CRL entry)
    "2.5.29.23",  # holdInstructionCode (CRL entry)
    "2.5.29.24",  # invalidityDate (CRL entry)
    "2.5.29.27",  # deltaCRLIndicator (CRL)
    "2.5.29.28",  # issuingDistributionPoint (CRL)
    "2.5.29.29",  # certificateIssuer (CRL entry)
    "2.5.29.30",  # nameConstraints
    "2.5.29.31",  # cRLDistributionPoints
    "2.5.29.32",  # certificatePolicies
    "2.5.29.33",  # policyMappings
    "2.5.29.35",  # authorityKeyIdentifier
    "2.5.29.36",  # policyConstraints
    "2.5.29.37",  # extKeyUsage
    "2.5.29.46",  # freshestCRL
    "2.5.29.54",  # inhibitAnyPolicy
    "1.3.6.1.5.5.7.1.1",   # id-pe-authorityInfoAccess
    "1.3.6.1.5.5.7.1.2",   # id-pe-biometricInfo
    "1.3.6.1.5.5.7.1.3",   # id-pe-qcStatements
    "1.3.6.1.5.5.7.1.4",   # id-pe-auditIdentity
    "1.3.6.1.5.5.7.1.7",   # id-pe-ipAddrBlocks (RFC 3779)
    "1.3.6.1.5.5.7.1.8",   # id-pe-autonomousSysIds (RFC 3779)
    "1.3.6.1.5.5.7.1.9",   # id-pe-subjectDirAttributes
    "1.3.6.1.5.5.7.1.11",  # id-pe-subjectInfoAccess
    "1.3.6.1.5.5.7.1.26",  # id-pe-tlsfeature (RFC 7633)
    "1.3.6.1.4.1.11129.2.4.2",  # SCT list (Certificate Transparency)
    "2.16.840.1.113730.1.1",    # netscape-cert-type (legacy)
})

# KeyUsage bit index -> stable machine-readable name (RFC 5280 §4.2.1.3).
_KU_NAMES = {
    "digital_signature": "digital_signature",
    "content_commitment": "content_commitment",
    "key_encipherment": "key_encipherment",
    "data_encipherment": "data_encipherment",
    "key_agreement": "key_agreement",
    "key_cert_sign": "key_cert_sign",
    "crl_sign": "crl_sign",
    "encipher_only": "encipher_only",
    "decipher_only": "decipher_only",
}


# ---------------------------------------------------------------------------
# Extension introspection
# ---------------------------------------------------------------------------


def _key_usages(cert: x509.Certificate) -> list[str]:
    """Asserted KeyUsage bit names; empty when the extension is absent."""
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return []
    # encipher_only/decipher_only are undefined unless key_agreement is set.
    encipher = decipher = False
    if ku.key_agreement:
        encipher = ku.encipher_only
        decipher = ku.decipher_only
    bits = {
        "digital_signature": ku.digital_signature,
        "content_commitment": ku.content_commitment,
        "key_encipherment": ku.key_encipherment,
        "data_encipherment": ku.data_encipherment,
        "key_agreement": ku.key_agreement,
        "key_cert_sign": ku.key_cert_sign,
        "crl_sign": ku.crl_sign,
        "encipher_only": encipher,
        "decipher_only": decipher,
    }
    return [_KU_NAMES[name] for name, on in bits.items() if on]


def _ekus(cert: x509.Certificate) -> list[str]:
    """Asserted EKU dotted OIDs; empty when the extension is absent."""
    try:
        eku = cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
    except x509.ExtensionNotFound:
        return []
    return sorted(o.dotted_string for o in eku)


def _critical_oids(cert: x509.Certificate) -> list[str]:
    return sorted(
        ext.oid.dotted_string
        for ext in cert.extensions
        if ext.critical
    )


def _basic_constraints(cert: x509.Certificate):
    try:
        return cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound:
        return None


def _is_self_issued(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    """RFC 5280 self-issued: subject DN equals issuer DN (same key in the
    normal case; DN equality is the pathLen carve-out criterion)."""
    return child.subject == issuer.subject


# ---------------------------------------------------------------------------
# Conflict construction
# ---------------------------------------------------------------------------


def _conflict(
    reason: str,
    cert_fp: str,
    position: int,
    message: str,
    **fields,
) -> PolicyConflict:
    base = {
        "not_valid_before": None,
        "not_valid_after": None,
        "path_length_constraint": None,
        "subordinate_ca_count": None,
        "required_eku": None,
        "present_ekus": None,
        "required_key_usages": None,
        "present_key_usages": None,
        "extension_oid": None,
    }
    base.update(fields)
    return PolicyConflict(
        reason=reason,  # type: ignore[arg-type]
        certificate_fingerprint=cert_fp,
        chain_position=position,
        message=message,
        **base,
    )


def _conflict_sort_key(c: PolicyConflict) -> tuple:
    return (
        POLICY_REASON_ORDER[c.reason],
        c.chain_position,
        c.required_eku or "",
        c.extension_oid or "",
        c.certificate_fingerprint,
    )


# ---------------------------------------------------------------------------
# Per-chain audit
# ---------------------------------------------------------------------------


def _audit_chain(
    chain: list[str],
    certs: dict[str, x509.Certificate],
    role: str,
    required_ekus: list[str],
    check_time,
) -> tuple[list[PolicyReviewCertificate], list[PolicyConflict]]:
    conflicts: list[PolicyConflict] = []
    cert_dtos: list[PolicyReviewCertificate] = []
    role_eku = _ROLE_EKU[role]
    all_required = sorted({role_eku, *required_ekus})

    # Pre-extract basic constraints so CA-position logic and DTOs share them.
    bcs = [_basic_constraints(certs[fp]) for fp in chain]

    for position, fp in enumerate(chain):
        cert = certs[fp]
        bc = bcs[position]
        is_ca = bool(bc is not None and bc.ca)
        kus = _key_usages(cert)
        ekus = _ekus(cert)
        critical = _critical_oids(cert)

        role_name = (
            "leaf" if position == 0
            else "trust_root" if position == len(chain) - 1
            else "intermediate"
        )
        cert_dtos.append(PolicyReviewCertificate(
            cert_id=fp,
            subject=_dn(cert.subject),
            issuer=_dn(cert.issuer),
            chain_position=position,
            role=role_name,  # type: ignore[arg-type]
            not_valid_before=_validity_utc(cert, "not_valid_before"),
            not_valid_after=_validity_utc(cert, "not_valid_after"),
            is_ca=is_ca,
            path_length_constraint=(
                bc.path_length if bc is not None else None
            ),
            key_usages=kus,
            extended_key_usages=ekus,
            critical_extension_oids=critical,
        ))

        # 1. Validity at check_time (inclusive bounds), every certificate
        #    including the trust anchor.
        nbf = _validity_utc(cert, "not_valid_before")
        nfa = _validity_utc(cert, "not_valid_after")
        if check_time < nbf:
            conflicts.append(_conflict(
                "certificate_not_yet_valid", fp, position,
                f"certificate '{_dn(cert.subject)}' is not valid before "
                f"{nbf.isoformat()}; check_time is {check_time.isoformat()}",
                not_valid_before=nbf,
            ))
        elif check_time > nfa:
            conflicts.append(_conflict(
                "certificate_expired", fp, position,
                f"certificate '{_dn(cert.subject)}' expired at "
                f"{nfa.isoformat()}; check_time is {check_time.isoformat()}",
                not_valid_after=nfa,
            ))

        # 2. Unknown critical extensions (fail closed).
        unknown_critical = sorted(
            o for o in critical if o not in KNOWN_CRITICAL_EXTENSIONS
        )
        for oid in unknown_critical:
            conflicts.append(_conflict(
                "unknown_critical_extension", fp, position,
                f"certificate '{_dn(cert.subject)}' carries an unrecognized "
                f"critical extension {oid} that the verifier cannot process",
                extension_oid=oid,
            ))

        if position == 0:
            # ---- Leaf: must not be a CA and must fit the TLS purpose. ----
            if bc is not None and bc.ca:
                conflicts.append(_conflict(
                    "leaf_marked_ca", fp, position,
                    f"leaf '{_dn(cert.subject)}' has basicConstraints cA=TRUE; "
                    "an end-entity TLS certificate must not be a CA",
                ))
            else:
                # KeyUsage only constrains when present. A client handshake
                # signs (digitalSignature); a server may additionally use an
                # RSA key-encipherment key exchange.
                if role == "client":
                    needed = ["digital_signature"]
                else:
                    needed = ["digital_signature", "key_encipherment"]
                if kus and not any(b in kus for b in needed):
                    conflicts.append(_conflict(
                        "leaf_key_usage_mismatch", fp, position,
                        f"{role} leaf '{_dn(cert.subject)}' KeyUsage "
                        f"{kus} asserts none of {needed}",
                        required_key_usages=needed,
                        present_key_usages=kus,
                    ))

            # Leaf EKU: role EKU + every caller-required OID; anyEKU implies
            # all. A leaf without an EKU extension certifies no specific
            # purpose and is rejected for a role-scoped deployment.
            leaf_permits = set(ekus)
            if _ANY_EKU_OID in leaf_permits:
                leaf_permits.update(all_required)
            for req in all_required:
                if req not in leaf_permits:
                    conflicts.append(_conflict(
                        "required_eku_missing", fp, position,
                        f"{role} leaf '{_dn(cert.subject)}' does not assert "
                        f"required EKU {req}",
                        required_eku=req,
                        present_ekus=ekus,
                    ))
        else:
            # ---- CA position: BasicConstraints cA=TRUE. ----
            if bc is None:
                conflicts.append(_conflict(
                    "missing_basic_constraints", fp, position,
                    f"CA-position certificate '{_dn(cert.subject)}' has no "
                    "basicConstraints extension",
                ))
            elif not bc.ca:
                conflicts.append(_conflict(
                    "not_ca", fp, position,
                    f"CA-position certificate '{_dn(cert.subject)}' has "
                    "basicConstraints cA=FALSE",
                ))
            else:
                # keyCertSign authority (checked only when KeyUsage present).
                if kus and "key_cert_sign" not in kus:
                    conflicts.append(_conflict(
                        "missing_key_cert_sign", fp, position,
                        f"CA '{_dn(cert.subject)}' KeyUsage {kus} lacks "
                        "keyCertSign",
                    ))

                # pathLen: count non-self-issued intermediate CAs below this
                # certificate in the reviewed chain. Every position strictly
                # below ``position`` (excluding the leaf) is an intermediate
                # subordinate; a self-issued CA (subject DN equal to its
                # issuer's subject DN) does not consume a pathLen unit.
                if bc.path_length is not None:
                    subordinate_count = 0
                    for sub_pos in range(1, position):
                        sub_cert = certs[chain[sub_pos]]
                        issuer_cert = certs[chain[sub_pos + 1]]
                        if not _is_self_issued(sub_cert, issuer_cert):
                            subordinate_count += 1
                    if subordinate_count > bc.path_length:
                        conflicts.append(_conflict(
                            "path_len_violation", fp, position,
                            f"CA '{_dn(cert.subject)}' pathLenConstraint="
                            f"{bc.path_length} but {subordinate_count} "
                            "non-self-issued intermediate CA(s) appear below "
                            "it in the chain",
                            path_length_constraint=bc.path_length,
                            subordinate_ca_count=subordinate_count,
                        ))

            # EKU chaining for intermediates only (anchor constraints are not
            # re-enforced, matching RFC 5280 anchor handling): an intermediate
            # that asserts EKUs must permit every required purpose.
            if position < len(chain) - 1 and ekus:
                permits = set(ekus)
                if _ANY_EKU_OID in permits:
                    permits.update(all_required)
                for req in all_required:
                    if req not in permits:
                        conflicts.append(_conflict(
                            "required_eku_missing", fp, position,
                            f"intermediate CA '{_dn(cert.subject)}' EKU {ekus} "
                            f"does not chain-allow required EKU {req}",
                            required_eku=req,
                            present_ekus=ekus,
                        ))

    conflicts.sort(key=_conflict_sort_key)
    return cert_dtos, conflicts


def _chain_review(
    chain_role: str,
    chain: list[str],
    certs: dict[str, x509.Certificate],
    endpoint: PolicyReviewEndpoint,
    check_time,
) -> PolicyChainReview:
    cert_dtos, conflicts = _audit_chain(
        chain, certs, endpoint.role, endpoint.required_ekus, check_time,
    )
    eligible = not conflicts
    reason = "ok" if eligible else conflicts[0].reason
    return PolicyChainReview(
        chain_role=chain_role,  # type: ignore[arg-type]
        chain=list(chain),
        eligible=eligible,
        reason=reason,
        certificates=cert_dtos,
        conflicts=conflicts,
    )


# ---------------------------------------------------------------------------
# Request-level validation + entry point
# ---------------------------------------------------------------------------


def policy_review(req: PolicyReviewRequest) -> PolicyReviewResult:
    endpoint_ids = [e.endpoint_id for e in req.endpoints]
    if len(set(endpoint_ids)) != len(endpoint_ids):
        raise NormalizeError(
            "invalid_request",
            "endpoints: endpoint_id values must be unique",
        )

    # -- EKU OID syntax -------------------------------------------------------
    eku_issues: list[PolicyEkuIssue] = []
    required_by_endpoint: dict[str, list[str]] = {}
    for e in req.endpoints:
        seen: set[str] = set()
        good: list[str] = []
        for idx, raw in enumerate(e.required_ekus):
            oid = raw.strip()
            if len(oid) > _OID_MAX_LEN or not _OID_RE.match(oid):
                eku_issues.append(PolicyEkuIssue(
                    endpoint_id=e.endpoint_id, index=idx, oid=raw,
                ))
                continue
            if oid not in seen:
                seen.add(oid)
                good.append(oid)
        required_by_endpoint[e.endpoint_id] = good

    # -- fingerprint syntax ---------------------------------------------------
    fingerprint_issues: list[NormalizeFingerprintIssue] = []
    trust_roots: set[str] = set()
    for raw in req.trust_roots:
        fp = raw.strip().lower()
        if not FINGERPRINT_RE.match(fp):
            fingerprint_issues.append(NormalizeFingerprintIssue(
                fingerprint=raw, referred_by="trust_roots"))
        else:
            trust_roots.add(fp)

    leaves: list[tuple[str, str, str]] = []  # (endpoint_id, role, fp)
    for e in req.endpoints:
        for role, raw in (
            ("current", e.current_leaf_fingerprint),
            ("target", e.target_leaf_fingerprint),
        ):
            fp = raw.strip().lower()
            if not FINGERPRINT_RE.match(fp):
                fingerprint_issues.append(NormalizeFingerprintIssue(
                    fingerprint=raw,
                    referred_by=(f"endpoints['{e.endpoint_id}']."
                                 f"{role}_leaf_fingerprint"),
                ))
            leaves.append((e.endpoint_id, role, fp))

    if eku_issues:
        raise NormalizeError(
            "invalid_oid",
            "one or more required_ekus entries are not dotted OIDs",
            eku_issues=eku_issues,
            fingerprint_issues=fingerprint_issues,
        )
    if fingerprint_issues:
        raise NormalizeError(
            "invalid_fingerprint",
            "one or more fingerprints are not 64-character hex SHA-256 values",
            fingerprint_issues=fingerprint_issues,
        )

    # -- PEM parsing ----------------------------------------------------------
    certs, pem_issues = _load_pem_bundle(req.pem_certificates)
    if pem_issues:
        raise NormalizeError(
            "invalid_pem",
            "one or more PEM list elements could not be parsed",
            pem_issues=pem_issues,
        )

    missing: list[NormalizeFingerprintIssue] = []
    for fp in sorted(trust_roots):
        if fp not in certs:
            missing.append(NormalizeFingerprintIssue(
                fingerprint=fp, referred_by="trust_roots"))
    for endpoint_id, role, fp in leaves:
        if fp not in certs:
            missing.append(NormalizeFingerprintIssue(
                fingerprint=fp,
                referred_by=(f"endpoints['{endpoint_id}']."
                             f"{role}_leaf_fingerprint"),
            ))
    if missing:
        raise NormalizeError(
            "unknown_fingerprint",
            "some fingerprints do not match any certificate in the PEM bundle",
            fingerprint_issues=missing,
        )

    bad_roots = sorted(
        fp for fp in trust_roots
        if certs[fp].subject != certs[fp].issuer
        or not _verify_signature(certs[fp], certs[fp])
    )
    if bad_roots:
        raise NormalizeError(
            "trust_root_not_self_signed",
            "every declared trust root must be a self-signed certificate "
            "(subject == issuer with a valid self-signature)",
            fingerprint_issues=[
                NormalizeFingerprintIssue(
                    fingerprint=fp, referred_by="trust_roots")
                for fp in bad_roots
            ],
        )

    # -- unique chain resolution for current + target leaves ------------------
    edges = _build_issuer_edges(certs)
    roots = frozenset(trust_roots)

    resolved: dict[str, tuple[Optional[list[str]], bool]] = {}
    for _endpoint_id, _role, leaf in leaves:
        if leaf not in resolved:
            first = _find_trust_path(leaf, edges, roots)
            ambiguous = first is not None and _has_second_trust_path(
                first, edges, roots)
            resolved[leaf] = (first, ambiguous)

    chain_issues: list[NormalizeChainIssue] = []
    chosen: dict[str, Optional[list[str]]] = {}
    for endpoint_id, role, leaf in leaves:
        first, ambiguous = resolved[leaf]
        if first is not None and not ambiguous:
            chosen[leaf] = first
            continue
        chosen[leaf] = None
        valid, dead_ends = _enumerate_paths(leaf, edges, roots)
        chain_issues.append(NormalizeChainIssue(
            endpoint_id=endpoint_id,
            leaf_role=role,  # type: ignore[arg-type]
            leaf=leaf,
            candidate_issuers=sorted(edges.get(leaf, [])),
            candidate_paths=_dedupe_paths(valid + dead_ends),
            reason="ambiguous_chain" if ambiguous else "no_trust_path",
        ))
    if chain_issues:
        ambiguous = any(i.reason == "ambiguous_chain" for i in chain_issues)
        raise NormalizeError(
            "ambiguous_chain" if ambiguous else "no_trust_path",
            "cross-signing leaves multiple valid paths to a declared trust "
            "root" if ambiguous
            else "no verified signature path from a leaf to any declared "
                 "trust root",
            chain_issues=chain_issues,
        )

    # -- per-endpoint, per-chain policy audit ---------------------------------
    results: list[PolicyReviewEndpointResult] = []
    for e in req.endpoints:
        # Use the de-duplicated OID list but keep audit semantics identical.
        e = e.model_copy(update={"required_ekus": required_by_endpoint[
            e.endpoint_id]})
        current = _chain_review(
            "current",
            chosen[e.current_leaf_fingerprint.strip().lower()],  # type: ignore[arg-type]
            certs, e, req.check_time,
        )
        target = _chain_review(
            "target",
            chosen[e.target_leaf_fingerprint.strip().lower()],  # type: ignore[arg-type]
            certs, e, req.check_time,
        )
        # First conflicting rule: the current (currently served) chain gates
        # before the target; within a chain conflicts are already precedence-
        # sorted.
        if not current.eligible:
            endpoint_reason = current.reason
        elif not target.eligible:
            endpoint_reason = target.reason
        else:
            endpoint_reason = "ok"
        results.append(PolicyReviewEndpointResult(
            endpoint_id=e.endpoint_id,
            role=e.role,
            current_leaf_fingerprint=e.current_leaf_fingerprint.strip().lower(),
            target_leaf_fingerprint=e.target_leaf_fingerprint.strip().lower(),
            eligible=current.eligible and target.eligible,
            reason=endpoint_reason,
            current_chain=current,
            target_chain=target,
        ))

    results.sort(key=lambda r: r.endpoint_id)
    return PolicyReviewResult(check_time=req.check_time, results=results)
