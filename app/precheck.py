"""Deployment identity pre-check for target leaves.

Given the same unordered PEM bag used by ``/scenarios/normalize``, declared
trust roots and, per endpoint, the fingerprint of its *target* leaf plus the
DNS/IP identities the endpoint claims to speak for, this module reconstructs
the target leaf's unique signature-verified chain (reusing the normalizer's
issuance machinery) and decides whether every declared identity is properly
certified.

The identity rules are deliberately strict and narrow:

* **SAN only.** Subject CN is never consulted as a fallback; a claimed
  identity must be covered by an entry of the same type in the leaf's
  subjectAltName extension.
* **DNS normalization.** Claimed names and dNSName SANs are compared after
  stripping a single trailing dot, IDNA A-label encoding (``Straße`` ->
  ``xn--strae-oqa``) and ASCII lower-casing. A wildcard SAN only matches when
  the ``*`` occupies the *whole* left-most label, and it matches exactly one
  label (``*.example.com`` covers ``api.example.com`` but neither
  ``example.com`` nor ``a.b.example.com``).
* **IP is exact.** Claimed IPs must parse as literal IPv4/IPv6 addresses;
  they match an iPAddress SAN only byte-for-byte (family included).
* **Name constraints accumulate along the intermediate CAs** of the
  reconstructed chain (the trust anchor itself is not re-enforced). Excluded
  subtrees take precedence over permitted subtrees; permitted subtrees from
  different CAs are intersected. DNS subtrees are matched on label
  boundaries; iPAddress constraints are networks (address + mask). *Every*
  same-type SAN of the leaf is checked, not only ones referenced by a claim.
  A wildcard SAN is evaluated as its whole coverage set (any single label
  under the suffix), never as a literal name: the SAN is rejected when that
  set intersects any excluded subtree, and the set must be fully contained
  in the permitted union of *every* CA that constrained DNS. Both verdicts
  are derived from the label structure of the suffix and the subtrees, not
  by sampling covered names.

Anything that cannot be evaluated against those rules (a name constraint of
another GeneralName type, or a malformed iPAddress constraint) is a fail-
closed ``unsupported_constraint_type`` result rather than a silent pass.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Callable, Optional, Union

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .models import (
    NormalizeChainIssue,
    NormalizeFingerprintIssue,
    PrecheckEndpoint,
    PrecheckEndpointResult,
    PrecheckIdentityIssue,
    PrecheckIdentityResult,
    PrecheckRequest,
    PrecheckResult,
    PrecheckUnsupportedConstraint,
    PrecheckViolation,
)
from .normalize import (
    FINGERPRINT_RE,
    NormalizeError,
    _build_issuer_edges,
    _dedupe_paths,
    _enumerate_paths,
    _find_trust_path,
    _has_second_trust_path,
    _load_pem_bundle,
    _verify_signature,
)

# ---------------------------------------------------------------------------
# Reason precedence (also used as the stable violation sort order)
# ---------------------------------------------------------------------------

REASON_ORDER = {
    "unsupported_constraint_type": 0,
    "excluded_by_name_constraint": 1,
    "not_within_permitted_subtree": 2,
    "identity_not_covered": 3,
}

# GeneralName tag -> machine-readable name. Only dNSName [2] and iPAddress [7]
# are evaluable for DNS/IP identities; everything else fails closed.
_GENERAL_NAME_TYPES = {
    0: "other_name",
    1: "rfc822_name",
    2: "dns_name",
    3: "x400_address",
    4: "directory_name",
    5: "edi_party_name",
    6: "uri",
    7: "ip_address",
    8: "registered_id",
}


# ---------------------------------------------------------------------------
# DER walking (name constraints): cryptography silently drops GeneralName
# entries it does not understand (otherName, malformed iPAddress, ...), so a
# security-relevant check must inspect the raw extension bytes itself.
# ---------------------------------------------------------------------------


def _der_tlv(buf: bytes, off: int) -> tuple[int, int, int, int]:
    """Return (tag, header_end, content_end, constructed) for one DER TLV."""
    tag = buf[off]
    pos = off + 1
    length = buf[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    return tag, pos, pos + length, tag & 0x20 != 0


def _walk_subtrees(ext_value: bytes) -> tuple[list[tuple[int, bytes]],
                                              list[tuple[int, bytes]]]:
    """Split a NameConstraints extension value into raw GeneralName entries.

    Returns (permitted, excluded); each entry is (general_name_type, content)
    for the base GeneralName of a GeneralSubtree. minimum/maximum distance
    fields are skipped.
    """
    _, pos, end, _ = _der_tlv(ext_value, 0)  # NameConstraints SEQUENCE
    sections: dict[int, list[tuple[int, bytes]]] = {0: [], 1: []}
    while pos < end:
        tag, cstart, cend, _ = _der_tlv(ext_value, pos)
        section = {0xA0: 0, 0xA1: 1}.get(tag)
        if section is None:
            break
        # [0]/[1] are IMPLICIT tags replacing the GeneralSubtrees SEQUENCE:
        # its GeneralSubtree children live directly inside the wrapper.
        q = cstart
        while q < cend:
            _, tp, te, _ = _der_tlv(ext_value, q)  # GeneralSubtree SEQUENCE
            gtag, gp, ge, _ = _der_tlv(ext_value, tp)  # base GeneralName
            sections[section].append((gtag, ext_value[gp:ge]))
            # minimum [0] / maximum [1] distance fields are irrelevant here
            q = te
        pos = cend
    return sections[0], sections[1]

_NAME_CONSTRAINTS_OID = bytes.fromhex("551d1e")


def _raw_extension_value(
    cert: x509.Certificate, oid: bytes
) -> Optional[bytes]:
    """Return an extension's raw OCTET STRING content straight from the DER.

    Walking the certificate's own bytes is required for name constraints:
    cryptography both drops GeneralName kinds it cannot model (otherName,
    x400Address, ...) when re-encoding a parsed extension and raises
    TypeError on some malformed iPAddress trees. A security check must see
    the exact bytes a CA published. Returns None when absent.
    """
    der = cert.public_bytes(serialization.Encoding.DER)
    try:
        _tag, hs, _cert_end, _c = _der_tlv(der, 0)
        _tag, p, tbs_end, _c = _der_tlv(der, hs)
        # version [0], serial, signature, issuer, validity, subject, SPKI
        for _ in range(7):
            _tag, _cs, p, _c = _der_tlv(der, p)
        while p < tbs_end and der[p] in (0x81, 0x82):  # optional UIDs
            _tag, _cs, p, _c = _der_tlv(der, p)
        if p >= tbs_end or der[p] != 0xA3:
            return None
        _tag, wp, _we, _c = _der_tlv(der, p)      # [3] EXPLICIT extensions
        _tag, sp, se, _c = _der_tlv(der, wp)     # SEQUENCE OF Extension
        while sp < se:
            _tag, ep, ee, _c = _der_tlv(der, sp)  # Extension
            m = ep
            _tag, om, oe, _c = _der_tlv(der, m)  # OID
            this_oid = der[om:oe]
            m = oe
            if m < ee and der[m] == 0x01:        # BOOLEAN critical
                _tag, _bs, m, _c = _der_tlv(der, m)
            _tag, oc, oce, _c = _der_tlv(der, m)  # OCTET STRING
            if this_oid == oid:
                return der[oc:oce]
            sp = ee
    except (IndexError, ValueError):
        return None
    return None


# ---------------------------------------------------------------------------
# DNS identity normalization and matching
# ---------------------------------------------------------------------------


def _idna_label(label: str) -> str:
    """IDNA2003 ToASCII for one label, then ASCII lower-case."""
    import encodings.idna as idna

    return idna.ToASCII(label).decode("ascii").lower()


def normalize_dns(value: str) -> str:
    """Normalize a claimed DNS identity.

    Strips a single trailing dot (FQDN root), rejects empty labels, labels
    over 63 octets and names over 253 octets, and A-label encodes non-ASCII
    labels. Any wildcard character is rejected: claimed identities are
    concrete names, never patterns.
    """
    raw = value.strip()
    if raw.endswith("."):
        raw = raw[:-1]
    if not raw:
        raise ValueError("empty DNS name")
    if "*" in raw:
        raise ValueError("claimed DNS identity must not contain a wildcard")
    labels = raw.split(".")
    out: list[str] = []
    for label in labels:
        if not label:
            raise ValueError("empty DNS label")
        asc = _idna_label(label)
        if len(asc) > 63:
            raise ValueError("DNS label longer than 63 octets after A-label")
        out.append(asc)
    name = ".".join(out)
    if len(name) > 253:
        raise ValueError("DNS name longer than 253 octets")
    return name


def normalize_dns_san(value: str) -> Optional[str]:
    """Normalize a dNSName SAN entry.

    A wildcard is retained only when it occupies the *whole* left-most label
    (``*.example.com``); malformed wildcard shapes (``a*.example.com``,
    ``*..example.com``, a bare ``*``) are not identity-bearing and return
    None so they cannot certify a claim.
    """
    raw = value.strip()
    if raw.endswith("."):
        raw = raw[:-1]
    if not raw or raw == "*":
        return None
    if raw.startswith("*."):
        suffix = raw[2:]
        if not suffix or "*" in suffix:
            return None
        try:
            return "*." + normalize_dns(suffix)
        except ValueError:
            return None
    if "*" in raw:
        return None
    try:
        return normalize_dns(raw)
    except ValueError:
        return None


def normalize_dns_constraint(value: str) -> Optional[str]:
    """Normalize a DNS name-constraint subtree.

    Leading dots (sub-domain-only subtrees) are preserved; the rest is
    lower-cased / A-label encoded with a trailing dot stripped. Returns None
    for an empty or otherwise non-normalizable subtree.
    """
    raw = value.strip()
    leading_dot = raw.startswith(".")
    if leading_dot:
        raw = raw[1:]
    if raw.endswith("."):
        raw = raw[:-1]
    if not raw:
        return None
    try:
        body = normalize_dns(raw)
    except ValueError:
        return None
    return ("." + body) if leading_dot else body


def dns_san_covers(claimed: str, san: str) -> bool:
    """Whether SAN entry ``san`` certifies claimed DNS name ``claimed``.

    Both inputs are already normalized. A wildcard matches only when ``*`` is
    the entire left-most label and exactly one claimed label replaces it.
    """
    if san.startswith("*."):
        suffix = san[2:]
        if "." not in claimed:
            return False  # wildcard needs at least the label it replaces + 1
        head, rest = claimed.split(".", 1)
        return rest == suffix and head != ""
    return claimed == san


def dns_constraint_matches(name: str, constraint: str) -> bool:
    """Whether DNS ``name`` falls inside a DNS name-constraint subtree.

    Per RFC 5280: a leading dot (``.example.com``) matches sub-domains only;
    a bare subtree (``example.com``) matches the domain itself and any sub-
    domain. Matching is always on label boundaries, so ``evil-example.com``
    is not inside ``example.com``.
    """
    if constraint.startswith("."):
        suffix = constraint
    elif name == constraint:
        return True
    else:
        suffix = "." + constraint
    return name.endswith(suffix) and len(name) > len(suffix)


def dns_constraint_intersects_wildcard(suffix: str, constraint: str) -> bool:
    """Whether a DNS subtree shares any name with a wildcard's coverage set.

    ``suffix`` is the normalized part after ``*.``; the coverage set is
    ``{<label>.<suffix>}`` for any single DNS label. A leading-dot subtree
    (sub-domains of the body only) intersects the set iff ``suffix`` lies
    inside-or-at the body: then every covered name is a sub-domain of the
    body. A bare subtree (the body plus its sub-domains) additionally
    intersects when the body itself is a covered name, i.e. sits exactly one
    label below ``suffix`` (``blocked.example.com`` meets ``*.example.com``);
    a body two or more labels below can never intersect, because a wildcard
    covers exactly one extra label.
    """
    if constraint.startswith("."):
        return dns_constraint_matches(suffix, constraint[1:])
    if dns_constraint_matches(suffix, constraint):
        return True
    if constraint.endswith("." + suffix):
        head = constraint[: len(constraint) - len(suffix) - 1]
        return "." not in head
    return False


def dns_constraint_contains_wildcard(suffix: str, constraint: str) -> bool:
    """Whether a DNS subtree fully contains a wildcard's coverage set.

    Every covered name ``<label>.<suffix>`` falls inside the subtree iff
    ``suffix`` itself lies inside-or-at the subtree body. A narrower bare
    subtree only covers the individual member equal to its body, and
    finitely many such subtrees can never cover the whole set, so
    containment in a CA's permitted *union* reduces to this single-subtree
    test per member subtree.
    """
    body = constraint[1:] if constraint.startswith(".") else constraint
    return dns_constraint_matches(suffix, body)


def _dns_san_constraint_predicates(
    san: str,
) -> tuple[Callable[[str], bool], Callable[[str], bool]]:
    """Return ``(intersects, contained_in)`` subtree predicates for a SAN.

    Both take a normalized DNS constraint subtree and answer, for the set of
    names the SAN stands for: does the set intersect the subtree, and is the
    set fully contained in the subtree? A literal SAN is a singleton, so
    both collapse to membership; a wildcard SAN ``*.<suffix>`` denotes its
    whole coverage set and needs the set-level reasoning above.
    """
    if san.startswith("*."):
        suffix = san[2:]
        return (
            lambda subtree: dns_constraint_intersects_wildcard(
                suffix, subtree),
            lambda subtree: dns_constraint_contains_wildcard(suffix, subtree),
        )
    return (
        lambda subtree: dns_constraint_matches(san, subtree),
        lambda subtree: dns_constraint_matches(san, subtree),
    )


# ---------------------------------------------------------------------------
# IP normalization
# ---------------------------------------------------------------------------


def normalize_ip(value: str) -> Union[ipaddress.IPv4Address,
                                     ipaddress.IPv6Address]:
    """Parse a claimed IP identity; scoped (zone) literals are rejected."""
    raw = value.strip()
    if "%" in raw or "/" in raw:
        raise ValueError("IP identity must be a bare address (no scope/zone "
                         "or network prefix)")
    addr = ipaddress.ip_address(raw)
    return addr


def _ip_network_from_constraint(content: bytes) -> Optional[
    Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
]:
    """Decode an iPAddress name constraint into a network.

    The constraint form is address bytes followed by mask bytes (8 for IPv4,
    32 for IPv6). Anything else (including a bare address) is a malformed
    name constraint and reported as unsupported rather than guessed at.
    """
    if len(content) == 8:
        addr_bytes, mask_bytes = content[:4], content[4:]
        family = ipaddress.IPv4Address
        network = ipaddress.IPv4Network
    elif len(content) == 32:
        addr_bytes, mask_bytes = content[:16], content[16:]
        family = ipaddress.IPv6Address
        network = ipaddress.IPv6Network
    else:
        return None
    # The mask must be a contiguous run of 1-bits followed by 0-bits.
    prefixlen = 0
    seen_zero = False
    for byte in mask_bytes:
        for bit in range(7, -1, -1):
            if byte >> bit & 1:
                if seen_zero:
                    return None
                prefixlen += 1
            else:
                seen_zero = True
    try:
        return network((family(addr_bytes), prefixlen), strict=False)
    except ValueError:
        return None


def _ip_in_network(addr: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
                   net: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]) -> bool:
    return addr.version == net.version and addr in net


# ---------------------------------------------------------------------------
# Accumulated name constraints along the intermediate CAs
# ---------------------------------------------------------------------------


@dataclass
class NameConstraints:
    """Intersection of permitted subtrees over the intermediate CAs.

    ``permitted_*`` entries are appended per CA in chain order; a name is
    permitted only when *some* subtree of *every* CA that constrained that
    type contains it. ``excluded_*`` exclude on any hit and take precedence.
    """

    permitted_dns: list[list[tuple[str, str]]] = field(default_factory=list)
    excluded_dns: list[tuple[str, str]] = field(default_factory=list)
    permitted_ip: list[list[tuple[Union[ipaddress.IPv4Network,
                                        ipaddress.IPv6Network], str]]] = field(
        default_factory=list)
    excluded_ip: list[tuple[Union[ipaddress.IPv4Network,
                                  ipaddress.IPv6Network], str]] = field(default_factory=list)
    unsupported: list[PrecheckUnsupportedConstraint] = field(default_factory=list)


def _add_gn(entries: list[tuple[int, bytes]], section: str, ca_fp: str,
            nc: NameConstraints) -> None:
    dns: list[tuple[str, str]] = []
    nets: list[tuple[Union[ipaddress.IPv4Network,
                           ipaddress.IPv6Network], str]] = []
    for tag, content in entries:
        # Context-specific tags appear as 0x80|n (primitive) or 0xA0|n
        # (constructed); the GeneralName type is the low 5 bits.
        number = tag & 0x1F
        type_name = _GENERAL_NAME_TYPES.get(number, f"unknown_tag_{number}")
        if number == 2:
            try:
                subtree_raw = content.decode("ascii")
            except UnicodeDecodeError:
                nc.unsupported.append(PrecheckUnsupportedConstraint(
                    ca_fingerprint=ca_fp, section=section,  # type: ignore[arg-type]
                    general_name_type="dns_name"))
                continue
            subtree = normalize_dns_constraint(subtree_raw)
            if subtree is None:
                nc.unsupported.append(PrecheckUnsupportedConstraint(
                    ca_fingerprint=ca_fp, section=section,  # type: ignore[arg-type]
                    general_name_type="dns_name"))
                continue
            dns.append((subtree, ca_fp))
        elif number == 7:
            net = _ip_network_from_constraint(content)
            if net is None:
                nc.unsupported.append(PrecheckUnsupportedConstraint(
                    ca_fingerprint=ca_fp, section=section,  # type: ignore[arg-type]
                    general_name_type="malformed_ip_address"))
            else:
                nets.append((net, ca_fp))
        else:
            nc.unsupported.append(PrecheckUnsupportedConstraint(
                ca_fingerprint=ca_fp, section=section,  # type: ignore[arg-type]
                general_name_type=type_name))
    if section == "permitted":
        if dns:
            nc.permitted_dns.append(dns)
        if nets:
            nc.permitted_ip.append(nets)
    else:
        nc.excluded_dns.extend(dns)
        nc.excluded_ip.extend(nets)


def collect_name_constraints(
    certs: dict[str, x509.Certificate], chain: list[str]
) -> NameConstraints:
    """Accumulate constraints from the intermediate CAs of ``chain``.

    ``chain`` is leaf-first and ends at the trust anchor; only positions
    strictly between leaf and anchor impose name constraints on the leaf.
    """
    nc = NameConstraints()
    for ca_fp in chain[1:-1]:
        cert = certs[ca_fp]
        raw = _raw_extension_value(cert, _NAME_CONSTRAINTS_OID)
        if raw is None:
            continue
        permitted, excluded = _walk_subtrees(raw)
        _add_gn(permitted, "permitted", ca_fp, nc)
        _add_gn(excluded, "excluded", ca_fp, nc)
    return nc


# ---------------------------------------------------------------------------
# Leaf SAN extraction
# ---------------------------------------------------------------------------


@dataclass
class LeafSans:
    dns: list[str]
    ip: list[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]


def _extract_leaf_sans(cert: x509.Certificate) -> LeafSans:
    dns: list[str] = []
    ips: list[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return LeafSans(dns, ips)
    # cryptography raises on odd SAN encodings (e.g. an iPAddress that is not
    # a bare address); such a leaf cannot be certified for a DNS/IP identity.
    try:
        for name in ext.value.get_values_for_type(x509.DNSName):
            dns.append(name)
        for name in ext.value.get_values_for_type(x509.IPAddress):
            if isinstance(name, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                ips.append(name)
    except ValueError:
        pass
    return LeafSans(dns, ips)


# ---------------------------------------------------------------------------
# Per-endpoint evaluation
# ---------------------------------------------------------------------------


def _violation_sort_key(v: PrecheckViolation) -> tuple:
    return (
        REASON_ORDER[v.reason],
        v.identity_type or "",
        v.identity_value or "",
        v.san or "",
        v.constraint or "",
        v.ca_fingerprint or "",
    )


def _dns_violations(
    claimed: list[str],
    sans: list[str],
    nc: NameConstraints,
) -> list[PrecheckViolation]:
    out: list[PrecheckViolation] = []

    # 1. Every DNS SAN must survive the accumulated name constraints, whether
    #    or not a claim references it. A wildcard SAN is checked as its whole
    #    coverage set {<label>.<suffix>}: the SAN dies when that set
    #    intersects any excluded subtree, and each CA that constrained DNS
    #    must admit the entire set. Both are derived from the label
    #    structure, never by enumerating covered names.
    surviving: set[str] = set()
    for san in sans:
        intersects, contained = _dns_san_constraint_predicates(san)
        excluded = next(
            ((sub, ca) for sub, ca in nc.excluded_dns if intersects(sub)),
            None,
        )
        if excluded is not None:
            sub, ca = excluded
            out.append(PrecheckViolation(
                reason="excluded_by_name_constraint",
                identity_type="dns", identity_value=None,
                san=san, constraint=sub, ca_fingerprint=ca,
            ))
            continue
        # Intersection: every CA that constrained DNS must admit this SAN.
        admitted = True
        blocker: Optional[tuple[str, str]] = None
        for ca_trees in nc.permitted_dns:
            hit = next(((t, ca) for t, ca in ca_trees
                        if contained(t)), None)
            if hit is None:
                admitted = False
                # Surface this CA's lexicographically first subtree.
                blocker = sorted(ca_trees, key=lambda tc: tc[0])[0]
                break
        if not admitted:
            out.append(PrecheckViolation(
                reason="not_within_permitted_subtree",
                identity_type="dns", identity_value=None,
                san=san,
                constraint=blocker[0] if blocker else None,
                ca_fingerprint=blocker[1] if blocker else None,
            ))
            continue
        surviving.add(san)

    # 2. Every claimed name must be covered by a surviving SAN.
    for name in claimed:
        if not any(dns_san_covers(name, s) for s in surviving):
            out.append(PrecheckViolation(
                reason="identity_not_covered",
                identity_type="dns", identity_value=name,
                san=None, constraint=None, ca_fingerprint=None,
            ))
    return out


def _ip_violations(
    claimed: list[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]],
    sans: list[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]],
    nc: NameConstraints,
) -> list[PrecheckViolation]:
    out: list[PrecheckViolation] = []

    surviving: set[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = set()
    for san in sans:
        excluded = next(
            ((net, ca) for net, ca in nc.excluded_ip if _ip_in_network(san, net)),
            None,
        )
        if excluded is not None:
            net, ca = excluded
            out.append(PrecheckViolation(
                reason="excluded_by_name_constraint",
                identity_type="ip", identity_value=None,
                san=str(san), constraint=str(net), ca_fingerprint=ca,
            ))
            continue
        admitted = True
        blocker: Optional[tuple[Union[ipaddress.IPv4Network,
                                      ipaddress.IPv6Network], str]] = None
        for ca_nets in nc.permitted_ip:
            # Same family only: a v6 address is not covered by a v4 tree and
            # vice versa.
            hit = next(((n, ca) for n, ca in ca_nets
                        if _ip_in_network(san, n)), None)
            if hit is None:
                admitted = False
                same_family = sorted(
                    ((n, ca) for n, ca in ca_nets
                     if n.version == san.version),
                    key=lambda nc2: (nc2[0].network_address.packed,
                                     nc2[0].prefixlen),
                )
                blocker = same_family[0] if same_family else None
                break
        if not admitted:
            out.append(PrecheckViolation(
                reason="not_within_permitted_subtree",
                identity_type="ip", identity_value=None,
                san=str(san),
                constraint=str(blocker[0]) if blocker is not None else None,
                ca_fingerprint=blocker[1] if blocker is not None else None,
            ))
            continue
        surviving.add(san)

    for addr in claimed:
        if addr not in surviving:
            out.append(PrecheckViolation(
                reason="identity_not_covered",
                identity_type="ip", identity_value=str(addr),
                san=None, constraint=None, ca_fingerprint=None,
            ))
    return out


def _top_reason(violations: list[PrecheckViolation],
                unsupported: list[PrecheckUnsupportedConstraint]) -> str:
    if unsupported:
        return "unsupported_constraint_type"
    if violations:
        return min((v.reason for v in violations),
                   key=lambda r: REASON_ORDER[r])
    return "ok"


def evaluate_endpoint(
    endpoint: PrecheckEndpoint,
    certs: dict[str, x509.Certificate],
    chain: list[str],
    claims: dict[str, object],
) -> PrecheckEndpointResult:
    """Evaluate one endpoint against its resolved target chain."""
    leaf = certs[chain[0]]
    raw_sans = _extract_leaf_sans(leaf)
    nc = collect_name_constraints(certs, chain)

    # Normalize SAN entries. A dNSName that cannot be normalized (including a
    # malformed wildcard shape) cannot certify any valid claim, so it is
    # dropped from the certifiable set.
    norm_dns_sans: list[str] = []
    for entry in raw_sans.dns:
        normed = normalize_dns_san(entry)
        if normed is not None:
            norm_dns_sans.append(normed)
    norm_dns_sans = sorted(set(norm_dns_sans))
    norm_ip_sans = sorted({str(a) for a in raw_sans.ip})

    claimed_dns = claims["dns"]  # type: ignore[assignment]
    claimed_ip = claims["ip"]  # type: ignore[assignment]

    violations: list[PrecheckViolation] = []
    # Only SAN types matching a claimed identity are evaluated ("同类 SAN"):
    # an endpoint that claims no IP identity is not gated by its IP SANs.
    if claimed_dns:
        violations += _dns_violations(claimed_dns, norm_dns_sans, nc)  # type: ignore[arg-type]
    if claimed_ip:
        violations += _ip_violations(claimed_ip, raw_sans.ip, nc)  # type: ignore[arg-type]

    # Unsupported constraints are surfaced as violations too, so every
    # machine-readable reason appears in one list.
    for u in sorted(nc.unsupported,
                    key=lambda u: (u.ca_fingerprint, u.section,
                                   u.general_name_type)):
        violations.append(PrecheckViolation(
            reason="unsupported_constraint_type",
            identity_type=None, identity_value=None, san=None,
            constraint=u.general_name_type, ca_fingerprint=u.ca_fingerprint,
        ))
    violations.sort(key=_violation_sort_key)
    reason = _top_reason(violations, nc.unsupported)
    eligible = reason == "ok"

    # SAN entries killed by an exclusion/permitted violation cannot cover a
    # claim even when their literal value matches.
    blocked_dns_sans = {
        v.san for v in violations
        if v.identity_type == "dns"
        and v.reason in ("excluded_by_name_constraint",
                         "not_within_permitted_subtree")
    }
    blocked_ip_sans = {
        v.san for v in violations
        if v.identity_type == "ip"
        and v.reason in ("excluded_by_name_constraint",
                         "not_within_permitted_subtree")
    }

    identity_results: list[PrecheckIdentityResult] = []
    for name in claimed_dns:
        covered = any(
            dns_san_covers(name, s) and s not in blocked_dns_sans
            for s in norm_dns_sans
        )
        identity_results.append(PrecheckIdentityResult(
            type="dns", value=name, covered=covered))
    for addr in claimed_ip:
        san = str(addr)
        identity_results.append(PrecheckIdentityResult(
            type="ip", value=san,
            covered=san in norm_ip_sans and san not in blocked_ip_sans))
    identity_results.sort(key=lambda r: (r.type, r.value))

    return PrecheckEndpointResult(
        endpoint_id=endpoint.endpoint_id,
        target_leaf_fingerprint=chain[0],
        eligible=eligible,
        reason=reason,  # type: ignore[arg-type]
        chain=list(chain),
        dns_sans=norm_dns_sans,
        ip_sans=norm_ip_sans,
        identities=identity_results,
        violations=violations,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def precheck_identities(req: PrecheckRequest) -> PrecheckResult:
    # -- endpoint / identity request-level validation ------------------------
    endpoint_ids = [e.endpoint_id for e in req.endpoints]
    if len(set(endpoint_ids)) != len(endpoint_ids):
        raise NormalizeError(
            "invalid_request",
            "endpoints: endpoint_id values must be unique",
        )

    identity_issues: list[PrecheckIdentityIssue] = []
    claims_by_endpoint: dict[str, dict[str, object]] = {}
    target_fps: list[str] = []
    for e in req.endpoints:
        dns_seen: set[str] = set()
        ip_seen: set[str] = set()
        claims = {"dns": [], "ip": []}
        for idx, ident in enumerate(e.identities):
            if ident.type == "dns":
                try:
                    name = normalize_dns(ident.value)
                except (UnicodeError, ValueError) as exc:
                    identity_issues.append(PrecheckIdentityIssue(
                        endpoint_id=e.endpoint_id, index=idx,
                        message=f"invalid DNS identity: {exc}",
                    ))
                    continue
                if name in dns_seen:
                    identity_issues.append(PrecheckIdentityIssue(
                        endpoint_id=e.endpoint_id, index=idx,
                        message=f"duplicate DNS identity '{name}'",
                    ))
                    continue
                dns_seen.add(name)
                claims["dns"].append(name)  # type: ignore[union-attr]
            else:
                try:
                    addr = normalize_ip(ident.value)
                except ValueError as exc:
                    identity_issues.append(PrecheckIdentityIssue(
                        endpoint_id=e.endpoint_id, index=idx,
                        message=f"invalid IP identity: {exc}",
                    ))
                    continue
                key = str(addr)
                if key in ip_seen:
                    identity_issues.append(PrecheckIdentityIssue(
                        endpoint_id=e.endpoint_id, index=idx,
                        message=f"duplicate IP identity '{key}'",
                    ))
                    continue
                ip_seen.add(key)
                claims["ip"].append(addr)  # type: ignore[union-attr]
        if not dns_seen and not ip_seen:
            identity_issues.append(PrecheckIdentityIssue(
                endpoint_id=e.endpoint_id, index=0,
                message="endpoint must declare at least one valid DNS/IP "
                        "identity",
            ))
        claims_by_endpoint[e.endpoint_id] = claims
        target_fps.append(e.target_leaf_fingerprint.strip().lower())

    # -- fingerprints --------------------------------------------------------
    fingerprint_issues: list[NormalizeFingerprintIssue] = []
    trust_roots: set[str] = set()
    for raw in req.trust_roots:
        fp = raw.strip().lower()
        if not FINGERPRINT_RE.match(fp):
            fingerprint_issues.append(NormalizeFingerprintIssue(
                fingerprint=raw, referred_by="trust_roots"))
        else:
            trust_roots.add(fp)
    for e in req.endpoints:
        fp = e.target_leaf_fingerprint.strip().lower()
        if not FINGERPRINT_RE.match(fp):
            fingerprint_issues.append(NormalizeFingerprintIssue(
                fingerprint=e.target_leaf_fingerprint,
                referred_by=(f"endpoints['{e.endpoint_id}']."
                             f"target_leaf_fingerprint")))

    if identity_issues:
        raise NormalizeError(
            "invalid_identity",
            "one or more declared identities are invalid or duplicated",
            identity_issues=identity_issues,
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
    for e in req.endpoints:
        fp = e.target_leaf_fingerprint.strip().lower()
        if fp not in certs:
            missing.append(NormalizeFingerprintIssue(
                fingerprint=fp,
                referred_by=(f"endpoints['{e.endpoint_id}']."
                             f"target_leaf_fingerprint")))
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

    # -- chain resolution (same exact zero/unique/ambiguous verdict) ---------
    edges = _build_issuer_edges(certs)
    roots = frozenset(trust_roots)

    # Exact verdict per distinct target leaf, independent of the diagnostic
    # sample cap (same machinery as /scenarios/normalize).
    resolved: dict[str, tuple[Optional[list[str]], bool]] = {}
    for fp in target_fps:
        if fp not in resolved:
            first = _find_trust_path(fp, edges, roots)
            ambiguous = first is not None and _has_second_trust_path(
                first, edges, roots)
            resolved[fp] = (first, ambiguous)

    chain_issues: list[NormalizeChainIssue] = []
    chosen: dict[str, Optional[list[str]]] = {}
    for e in req.endpoints:
        fp = e.target_leaf_fingerprint.strip().lower()
        first, ambiguous = resolved[fp]
        if first is not None and not ambiguous:
            chosen[fp] = first
            continue
        chosen[fp] = None
        valid, dead_ends = _enumerate_paths(fp, edges, roots)
        chain_issues.append(NormalizeChainIssue(
            endpoint_id=e.endpoint_id,
            leaf_role="target",
            leaf=fp,
            candidate_issuers=sorted(edges.get(fp, [])),
            candidate_paths=_dedupe_paths(valid + dead_ends),
            reason="ambiguous_chain" if ambiguous else "no_trust_path",
        ))
    if chain_issues:
        ambiguous = any(i.reason == "ambiguous_chain" for i in chain_issues)
        raise NormalizeError(
            "ambiguous_chain" if ambiguous else "no_trust_path",
            "cross-signing leaves multiple valid paths to a declared trust "
            "root" if ambiguous
            else "no verified signature path from a target leaf to any "
                 "declared trust root",
            chain_issues=chain_issues,
        )

    # -- per-endpoint identity evaluation ------------------------------------
    results = [
        evaluate_endpoint(
            e, certs,
            chosen[e.target_leaf_fingerprint.strip().lower()],  # type: ignore[arg-type]
            claims_by_endpoint[e.endpoint_id],
        )
        for e in req.endpoints
    ]
    results.sort(key=lambda r: r.endpoint_id)
    return PrecheckResult(results=results)
