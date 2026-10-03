"""Chain-wide offline revocation evidence review.

Given the same unordered PEM bag used by ``/scenarios/normalize``, declared
trust roots, per-endpoint target leaf fingerprints, a set of offline OCSP
responses and a set of DER/PEM CRLs, plus one validation instant
``check_time`` (and a clock-skew allowance of at most 300 seconds), this
module decides, per endpoint, whether **every** non-anchor certificate of the
reconstructed chain has revocation evidence that is authentic, fresh at that
exact instant and consistently ``good``.

Chain reconstruction reuses the normalizer's machinery verbatim: issuance
edges are established by signature verification (never by DN matching) and a
target leaf must have exactly one verified path to a declared trust root.

The OCSP evidence rules mirror ``/deployments/ocsp-precheck`` exactly: the
CertID (serial + recomputed issuer name/key hashes) binds the response to a
certificate and its verified issuer, the responder is the issuer itself or a
directly issued id-kp-OCSPSigning delegate valid at ``check_time``, the
signature verifies, and ``check_time`` lies in the
[thisUpdate − skew, nextUpdate + skew] window with producedAt not in the
future and nextUpdate present.

The CRL rules are:

* the CRL must parse (DER or PEM);
* **indirect CRLs** (issuingDistributionPoint.indirectCRL) and **delta CRLs**
  (id-ce-deltaCRLIndicator) are never evaluated — they cannot be bound to
  the single issuing CA the way a full direct CRL can;
* the CRL's issuer DN must name a certificate whose public key verifies the
  CRL signature; no such certificate fails closed (``signer_not_found`` /
  ``signature_invalid``). Binding is unique over the *key*, so re-issued or
  cross-certified copies of the same CA certificate (same DN and key) are
  one issuer and bind deterministically. The signer must also be a CA
  permitted to sign CRLs (basicConstraints CA, keyUsage cRLSign when present);
* the signature must verify;
* nextUpdate is required and ``check_time`` must be within
  [lastUpdate − skew, nextUpdate + skew].

Only **fresh authentic** evidence participates in the status conclusion.
Fresh ``revoked`` always wins; simultaneous fresh ``good`` and fresh
``revoked`` is a conflict; absent, stale or not-yet-valid evidence makes the
certificate ineligible on its own. The trust anchor terminating a chain is
never reviewed (its revocation cannot be established from within the chain).
"""
from __future__ import annotations

import base64
import binascii
import re
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509 import ocsp as x509_ocsp

from .models import (
    CertificateReview,
    CrlEvidence,
    EndpointRevocationResult,
    OcspEvidence,
    RevocationReviewRequest,
    RevocationReviewResult,
    UnattributedEvidence,
)
from .normalize import (
    FINGERPRINT_RE,
    NormalizeChainIssue,
    NormalizeError,
    NormalizeFingerprintIssue,
    _build_issuer_edges,
    _dedupe_paths,
    _enumerate_paths,
    _find_trust_path,
    _has_second_trust_path,
    _load_pem_bundle,
    _verify_signature,
    _verify_signed_data,
    cert_fingerprint,
)
from .ocsp import (
    _cert_id_matches,
    _is_delegated_responder,
    _key_hash,
    _ocsp_time,
    _response_signature_scheme,
)

_PEM_CRL_RE = re.compile(
    rb"-----BEGIN (?:X509 )?CRL-----.*?-----END (?:X509 )?CRL-----",
    re.DOTALL,
)


# ---------------------------------------------------------------------------
# Plain evaluation records (built before the pydantic DTOs)
# ---------------------------------------------------------------------------


@dataclass
class OcspRecord:
    source_index: int
    reason: str
    message: str
    fresh: bool
    this_update: Optional[datetime] = None
    next_update: Optional[datetime] = None
    cert_fp: Optional[str] = None
    issuer_fp: Optional[str] = None
    response_status: Optional[str] = None
    certificate_status: Optional[str] = None
    responder_id_type: Optional[str] = None
    signer_type: Optional[str] = None
    signer_fp: Optional[str] = None
    produced_at: Optional[datetime] = None
    revocation_time: Optional[datetime] = None
    revocation_reason: Optional[str] = None

    def dto(self) -> OcspEvidence:
        return OcspEvidence(
            source_index=self.source_index,
            reason=self.reason,
            message=self.message,
            fresh=self.fresh,
            this_update=self.this_update,
            next_update=self.next_update,
            certificate_fingerprint=self.cert_fp,
            issuer_fingerprint=self.issuer_fp,
            response_status=self.response_status,
            certificate_status=self.certificate_status,
            responder_id_type=self.responder_id_type,  # type: ignore[arg-type]
            signer_type=self.signer_type,  # type: ignore[arg-type]
            signer_fingerprint=self.signer_fp,
            produced_at=self.produced_at,
            revocation_time=self.revocation_time,
            revocation_reason=self.revocation_reason,
        )

    def unattributed(self) -> UnattributedEvidence:
        return UnattributedEvidence(
            kind="ocsp",
            source_index=self.source_index,
            reason=self.reason,
            message=self.message,
            fresh=self.fresh,
            this_update=self.this_update,
            next_update=self.next_update,
            issuer_fingerprint=self.issuer_fp,
        )


@dataclass
class CrlRecord:
    source_index: int
    reason: str
    message: str
    fresh: bool
    this_update: Optional[datetime] = None
    next_update: Optional[datetime] = None
    signer_fp: Optional[str] = None
    crl_number: Optional[int] = None
    is_delta: bool = False
    is_indirect: bool = False
    revoked_serials: list[str] = field(default_factory=list)
    revocation_time: Optional[datetime] = None
    revocation_reason: Optional[str] = None
    parsed: Optional[x509.CertificateRevocationList] = None

    def dto(
        self,
        covered_serials: set[str],
        revocation_time: Optional[datetime] = None,
        revocation_reason: Optional[str] = None,
        reason: Optional[str] = None,
        message: Optional[str] = None,
    ) -> CrlEvidence:
        return CrlEvidence(
            source_index=self.source_index,
            reason=reason or self.reason,
            message=message or self.message,
            fresh=self.fresh,
            this_update=self.this_update,
            next_update=self.next_update,
            issuer_fingerprint=self.signer_fp,
            crl_number=self.crl_number,
            is_delta=self.is_delta,
            is_indirect=self.is_indirect,
            revoked_serial_numbers=sorted(self.revoked_serials),
            covered_serial_numbers=sorted(covered_serials),
            revocation_time=revocation_time,
            revocation_reason=revocation_reason,
        )

    def unattributed(self) -> UnattributedEvidence:
        return UnattributedEvidence(
            kind="crl",
            source_index=self.source_index,
            reason=self.reason,
            message=self.message,
            fresh=self.fresh,
            this_update=self.this_update,
            next_update=self.next_update,
            issuer_fingerprint=self.signer_fp,
            is_delta=self.is_delta,
            is_indirect=self.is_indirect,
            revoked_serial_numbers=sorted(self.revoked_serials),
        )


# ---------------------------------------------------------------------------
# OCSP evaluation
# ---------------------------------------------------------------------------


def _evaluate_ocsp(
    index: int,
    blob: str,
    certs: dict[str, x509.Certificate],
    edges: dict[str, list[str]],
    check_time: datetime,
    skew: timedelta,
    skew_seconds: int,
) -> OcspRecord:
    """Evaluate one offline OCSP response, binding it by CertID.

    Mirrors the fixed precedence of app.ocsp.ocsp_precheck, but the target
    certificate is discovered from the CertID rather than named: for every
    (child, verified issuer) issuance edge whose issuer matches the CertID
    hashes, the child's serial number is compared. All matching edges must
    agree on the same child certificate (a distinct certificate with a
    colliding serial is treated as a mismatch and the response is rejected).
    """
    rec_kwargs: dict[str, Any] = {
        "source_index": index,
    }

    # 1. decode / parse
    try:
        der = base64.b64decode("".join(blob.split()), validate=True)
        response = x509_ocsp.load_der_ocsp_response(der)
    except (ValueError, binascii.Error) as exc:
        return OcspRecord(
            **rec_kwargs,
            fresh=False,
            reason="invalid_ocsp_response",
            message=f"ocsp_responses[{index}] is not a parseable "
                    f"Base64-encoded DER OCSP response: {exc}",
        )

    # 2. response status
    status_name = response.response_status.name.lower()
    rec_kwargs["response_status"] = status_name
    if response.response_status is not x509_ocsp.OCSPResponseStatus.SUCCESSFUL:
        return OcspRecord(
            **rec_kwargs,
            fresh=False,
            reason="response_not_successful",
            message=f"ocsp_responses[{index}]: response status is "
                    f"{status_name}, not successful; it carries no "
                    f"certificate status to evaluate",
        )

    rec_kwargs["produced_at"] = _ocsp_time(response, "produced_at")
    rec_kwargs["this_update"] = _ocsp_time(response, "this_update")
    rec_kwargs["next_update"] = _ocsp_time(response, "next_update")
    cert_status_name = response.certificate_status.name.lower()
    rec_kwargs["certificate_status"] = cert_status_name
    if response.certificate_status is x509_ocsp.OCSPCertStatus.REVOKED:
        rec_kwargs["revocation_time"] = _ocsp_time(response, "revocation_time")
        try:
            reason_flag = response.revocation_reason
        except ValueError:
            reason_flag = None
        if reason_flag is not None:
            rec_kwargs["revocation_reason"] = reason_flag.name

    # 3./4. CertID -> (child, verified issuer) binding
    matched_pairs: list[tuple[str, str]] = []
    for child_fp, issuer_fps in edges.items():
        child = certs[child_fp]
        for issuer_fp in issuer_fps:
            issuer = certs[issuer_fp]
            if _cert_id_matches(response, child, issuer):
                matched_pairs.append((child_fp, issuer_fp))
    # Distinct children with the same serial/nameHash/keyHash cannot both be
    # the subject: the response cannot be bound uniquely to one certificate.
    matched_children = {child for child, _issuer in matched_pairs}
    if not matched_pairs or len(matched_children) != 1:
        return OcspRecord(
            **rec_kwargs,
            fresh=False,
            reason="cert_id_mismatch",
            message=f"ocsp_responses[{index}]: the CertID matches no "
                    f"signature-verified (certificate, issuer) pair in the "
                    f"bundle, or binds ambiguously to several certificates",
        )
    cert_fp = next(iter(matched_children))
    # Prefer an issuer present in the pair set; all issuers share the key
    # matching the CertID hashes (they may be cross-certified copies).
    issuer_fp = matched_pairs[0][1]
    rec_kwargs["cert_fp"] = cert_fp
    rec_kwargs["issuer_fp"] = issuer_fp
    leaf = certs[cert_fp]
    issuer = certs[issuer_fp]

    # 5./6. signer selection
    responder_name = response.responder_name
    responder_key_hash = response.responder_key_hash

    def matches_responder_id(cert: x509.Certificate) -> bool:
        if responder_name is not None:
            return cert.subject.public_bytes() == responder_name.public_bytes()
        try:
            return _key_hash(cert) == responder_key_hash
        except ValueError:
            return False

    if responder_name is not None:
        rec_kwargs["responder_id_type"] = "name"
    elif responder_key_hash is not None:
        rec_kwargs["responder_id_type"] = "key_hash"
    else:
        return OcspRecord(
            **rec_kwargs,
            fresh=False,
            reason="invalid_ocsp_response",
            message=f"ocsp_responses[{index}]: the response carries no "
                    f"responderID (neither byName nor byKey)",
        )

    candidates = [issuer, *response.certificates]
    matching = [c for c in candidates if matches_responder_id(c)]
    if not matching:
        return OcspRecord(
            **rec_kwargs,
            fresh=False,
            reason="responder_not_found",
            message=f"ocsp_responses[{index}]: neither the issuer nor any "
                    f"certificate embedded in the response matches the "
                    f"responderID",
        )

    issuer_der = issuer.public_bytes(serialization.Encoding.DER)
    signer: Optional[x509.Certificate] = None
    signer_type: Optional[str] = None
    for cand in matching:
        if cand.public_bytes(serialization.Encoding.DER) == issuer_der:
            signer, signer_type = cand, "issuer"
            break
    if signer is None:
        for cand in matching:
            if _is_delegated_responder(cand, issuer, check_time):
                signer, signer_type = cand, "responder_certificate"
                break
    if signer is None:
        return OcspRecord(
            **rec_kwargs,
            fresh=False,
            reason="unauthorized_responder",
            message=f"ocsp_responses[{index}]: the responder is neither the "
                    f"issuer nor a responder certificate directly issued by "
                    f"it, valid at check_time and carrying "
                    f"id-kp-OCSPSigning",
        )
    rec_kwargs["signer_type"] = signer_type
    rec_kwargs["signer_fp"] = cert_fingerprint(signer)

    # 7. signature
    scheme = _response_signature_scheme(response, der)
    if scheme is None or not _verify_signed_data(
        signer.public_key(),
        response.signature,
        response.tbs_response_bytes,
        *scheme,
    ):
        return OcspRecord(
            **rec_kwargs,
            fresh=False,
            reason="signature_invalid",
            message=f"ocsp_responses[{index}]: the response signature does "
                    f"not verify with the selected signer's public key, or "
                    f"its signature algorithm parameters are unusable",
        )

    # 8. certificate status
    if response.certificate_status is x509_ocsp.OCSPCertStatus.REVOKED:
        detail = ""
        if rec_kwargs.get("revocation_time") is not None:
            detail += f" at {rec_kwargs['revocation_time'].isoformat()}"
        if rec_kwargs.get("revocation_reason") is not None:
            detail += f" (reason: {rec_kwargs['revocation_reason']})"
        # Freshness still decides whether a revoked verdict counts: a revoked
        # response outside its window cannot establish status at check_time.
        fresh, fresh_reason, fresh_msg = _ocsp_freshness(
            index, rec_kwargs, check_time, skew, skew_seconds
        )
        return OcspRecord(
            **rec_kwargs,
            fresh=fresh,
            reason=fresh_reason or "revoked",
            message=(f"ocsp_responses[{index}]: certificate "
                     f"{cert_fp} is revoked{detail}"
                     if fresh_reason is None else fresh_msg),
        )
    if response.certificate_status is x509_ocsp.OCSPCertStatus.UNKNOWN:
        # Unknown is authentic but is not status evidence either way; it does
        # not have a fresh/good reading.
        return OcspRecord(
            **rec_kwargs,
            fresh=False,
            reason="certificate_unknown",
            message=f"ocsp_responses[{index}]: the responder does not "
                    f"certificate {cert_fp}'s status (unknown)",
        )

    # 9. freshness of a good response
    fresh, fresh_reason, fresh_msg = _ocsp_freshness(
        index, rec_kwargs, check_time, skew, skew_seconds
    )
    if fresh_reason is not None:
        return OcspRecord(**rec_kwargs, fresh=False,
                          reason=fresh_reason, message=fresh_msg)
    return OcspRecord(
        **rec_kwargs,
        fresh=True,
        reason="good",
        message=f"ocsp_responses[{index}]: authentic and fresh at "
                f"check_time, certifying {cert_fp} as good",
    )


def _ocsp_freshness(
    index: int,
    fields: dict[str, Any],
    check_time: datetime,
    skew: timedelta,
    skew_seconds: int,
) -> tuple[bool, Optional[str], Optional[str]]:
    """(fresh, failure_reason, failure_message); reason None when fresh."""
    produced_at = fields.get("produced_at")
    if produced_at is not None and produced_at > check_time + skew:
        return False, "produced_at_in_future", (
            f"ocsp_responses[{index}]: producedAt {produced_at.isoformat()} "
            f"is later than check_time {check_time.isoformat()} plus the "
            f"{skew_seconds}s skew allowance"
        )
    if fields.get("next_update") is None:
        return False, "next_update_missing", (
            f"ocsp_responses[{index}]: the response carries no nextUpdate; "
            f"a freshness bound is required"
        )
    if check_time < fields["this_update"] - skew:
        return False, "not_yet_valid", (
            f"ocsp_responses[{index}]: check_time {check_time.isoformat()} "
            f"is earlier than thisUpdate "
            f"{fields['this_update'].isoformat()} minus the {skew_seconds}s "
            f"skew allowance"
        )
    if check_time > fields["next_update"] + skew:
        return False, "stale", (
            f"ocsp_responses[{index}]: check_time {check_time.isoformat()} "
            f"is later than nextUpdate {fields['next_update'].isoformat()} "
            f"plus the {skew_seconds}s skew allowance"
        )
    return True, None, None


# ---------------------------------------------------------------------------
# CRL decoding and evaluation
# ---------------------------------------------------------------------------


def _decode_crl(blob: str) -> Optional[x509.CertificateRevocationList]:
    """Decode one CRL element that may be PEM or Base64 DER; None if garbage."""
    raw = blob.encode("utf-8", errors="replace")
    blocks = _PEM_CRL_RE.findall(raw)
    try:
        if blocks:
            # One CRL per element, same rule as the PEM certificate bag's
            # individual blocks: parse the first, reject stray blocks.
            if len(blocks) > 1:
                return None
            return x509.load_pem_x509_crl(blocks[0])
        der = base64.b64decode("".join(blob.split()), validate=True)
        return x509.load_der_x509_crl(der)
    except (ValueError, binascii.Error):
        return None


def _crl_flags(
    crl: x509.CertificateRevocationList,
) -> tuple[bool, bool, Optional[int]]:
    """(is_delta, is_indirect, crl_number) from the CRL extensions."""
    is_delta = False
    is_indirect = False
    crl_number: Optional[int] = None
    try:
        crl.extensions.get_extension_for_class(x509.DeltaCRLIndicator)
        is_delta = True
    except x509.ExtensionNotFound:
        pass
    try:
        crl.extensions.get_extension_for_class(x509.CRLNumber)
        crl_number = (
            crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
        )
    except x509.ExtensionNotFound:
        pass
    try:
        idp = crl.extensions.get_extension_for_class(
            x509.IssuingDistributionPoint
        ).value
        is_indirect = bool(idp.indirect_crl)
    except x509.ExtensionNotFound:
        pass
    return is_delta, is_indirect, crl_number


def _crl_naive_or_aware(crl: x509.CertificateRevocationList, attr: str):
    """Read a CRL time via the timezone-aware property when available.

    cryptography >= 42 exposes ``*_utc``; the plain attribute is a naive UTC
    datetime on older versions and emits a deprecation warning on 42+ only
    when the field is None, which the optional caller suppresses.
    """
    aware = getattr(crl, f"{attr}_utc", None)
    if isinstance(aware, datetime):
        return aware
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", (DeprecationWarning,
                                        CryptographyDeprecationWarning))
        value = getattr(crl, attr)
    return value.replace(tzinfo=timezone.utc) if value is not None else None


def _crl_time(crl: x509.CertificateRevocationList, attr: str) -> datetime:
    value = _crl_naive_or_aware(crl, attr)
    assert value is not None
    return value


def _crl_time_optional(
    crl: x509.CertificateRevocationList, attr: str
) -> Optional[datetime]:
    return _crl_naive_or_aware(crl, attr)

def _serial_hex(value: int) -> str:
    return format(value, "X")


def _verify_crl_signature(
    crl: x509.CertificateRevocationList, cert: x509.Certificate
) -> bool:
    """Whether ``cert``'s key signed ``crl``.

    Prefers the library's own check (which understands the CRL's algorithm);
    falls back to the service's shared signed-data verifier so RSA-PSS CRLs
    with library-limited parameters are still handled consistently.
    """
    try:
        if crl.is_signature_valid(cert.public_key()):
            return True
    except (InvalidSignature, TypeError, ValueError):
        pass
    except Exception:  # unsupported algorithms fall through to the manual path
        pass
    return _verify_signed_data(
        cert.public_key(),
        crl.signature,
        crl.tbs_certlist_bytes,
        crl.signature_hash_algorithm,
        crl.signature_algorithm_oid.dotted_string,
        getattr(crl, "signature_algorithm_parameters", None),
    )


def _is_crl_signing_ca(cert: x509.Certificate) -> bool:
    """BasicConstraints CA plus cRLSign when keyUsage is present."""
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if not bc.value.ca:
            return False
    except x509.ExtensionNotFound:
        return False
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage)
        if not ku.value.crl_sign:
            return False
    except x509.ExtensionNotFound:
        pass
    return True


def _evaluate_crl(
    index: int,
    blob: str,
    certs: dict[str, x509.Certificate],
    check_time: datetime,
    skew: timedelta,
    skew_seconds: int,
) -> CrlRecord:
    """Parse, classify and verify one CRL, binding it to its unique signer."""
    crl = _decode_crl(blob)
    if crl is None:
        return CrlRecord(
            source_index=index,
            reason="invalid_crl",
            message=f"crls[{index}] is not a parseable PEM/DER CRL "
                    f"(or bundles more than one PEM CRL block)",
            fresh=False,
        )

    this_update = _crl_time(crl, "last_update")
    next_update = _crl_time_optional(crl, "next_update")
    is_delta, is_indirect, crl_number = _crl_flags(crl)
    revoked_serials = sorted(
        _serial_hex(entry.serial_number) for entry in crl
    )
    base: dict[str, Any] = {
        "source_index": index,
        "this_update": this_update,
        "next_update": next_update,
        "crl_number": crl_number,
        "is_delta": is_delta,
        "is_indirect": is_indirect,
        "revoked_serials": revoked_serials,
        "parsed": crl,
    }

    # Indirect / delta CRLs cannot be bound to one issuer here: unsupported.
    if is_delta or is_indirect:
        which = []
        if is_delta:
            which.append("delta (id-ce-deltaCRLIndicator present)")
        if is_indirect:
            which.append("indirect (issuingDistributionPoint.indirectCRL)")
        return CrlRecord(
            **base,
            reason="indirect_or_delta_crl",
            message=f"crls[{index}]: {' and '.join(which)} CRLs are not "
                    f"supported; only full direct CRLs with a uniquely "
                    f"bindable issuer are evaluated",
            fresh=False,
        )

    # Bind the CRL to its signing key: the issuer DN must name a bundle
    # certificate AND its public key must verify the CRL signature.
    # Uniqueness is over the *key*: re-issued / cross-certified copies of one
    # CA certificate share both DN and key and are the same issuer
    # cryptographically (exactly as OCSP treats cross-certified issuers), so
    # a deterministic first copy is selected. Two genuinely different keys
    # can never both verify one signature, so a verifiable CRL always binds
    # to exactly one key.
    candidates = [
        fp for fp, cert in certs.items()
        if cert.subject.public_bytes() == crl.issuer.public_bytes()
    ]
    signing = sorted(
        fp for fp in candidates if _verify_crl_signature(crl, certs[fp])
    )
    if not signing:
        if not candidates:
            reason = "signer_not_found"
            msg = (f"crls[{index}]: no certificate in the bundle carries the "
                   f"CRL issuer's subject DN, so the issuer cannot be bound")
        else:
            reason = "signature_invalid"
            msg = (f"crls[{index}]: a bundle certificate matches the CRL "
                   f"issuer DN but none verifies the CRL signature")
        return CrlRecord(**base, reason=reason, message=msg, fresh=False)
    signer_fp = signing[0]
    signer = certs[signer_fp]

    if not _is_crl_signing_ca(signer):
        return CrlRecord(
            **base,
            signer_fp=signer_fp,
            reason="signer_not_ca",
            message=f"crls[{index}]: signer {signer_fp} is not a CA allowed "
                    f"to issue CRLs (basicConstraints CA / keyUsage cRLSign)",
            fresh=False,
        )

    # Freshness window (nextUpdate mandatory).
    if next_update is None:
        return CrlRecord(
            **base,
            signer_fp=signer_fp,
            reason="next_update_missing",
            message=f"crls[{index}]: the CRL carries no nextUpdate; a "
                    f"freshness bound is required",
            fresh=False,
        )
    if check_time < this_update - skew:
        return CrlRecord(
            **base,
            signer_fp=signer_fp,
            reason="not_yet_valid",
            message=f"crls[{index}]: check_time {check_time.isoformat()} is "
                    f"earlier than thisUpdate {this_update.isoformat()} "
                    f"minus the {skew_seconds}s skew allowance",
            fresh=False,
        )
    if check_time > next_update + skew:
        return CrlRecord(
            **base,
            signer_fp=signer_fp,
            reason="stale",
            message=f"crls[{index}]: check_time {check_time.isoformat()} is "
                    f"later than nextUpdate {next_update.isoformat()} plus "
                    f"the {skew_seconds}s skew allowance",
            fresh=False,
        )

    # Fresh and authentic: a CRL certifies "not revoked" for every serial it
    # omits; entries that hit chain certs make it revoked evidence.
    return CrlRecord(
        **base,
        signer_fp=signer_fp,
        fresh=True,
        reason="good",
        message=f"crls[{index}]: fresh CRL signed by {signer_fp}",
    )


# ---------------------------------------------------------------------------
# Chain resolution (same exact verdict as /deployments/precheck)
# ---------------------------------------------------------------------------


def _resolve_chains(
    req: RevocationReviewRequest,
    certs: dict[str, x509.Certificate],
    edges: dict[str, list[str]],
    trust_roots: set[str],
) -> dict[str, list[str]]:
    chosen: dict[str, list[str]] = {}
    chain_issues: list[NormalizeChainIssue] = []
    roots = frozenset(trust_roots)
    for e in req.endpoints:
        fp = e.target_leaf_fingerprint.strip().lower()
        if fp in chosen:
            continue
        first = _find_trust_path(fp, edges, roots)
        ambiguous = first is not None and _has_second_trust_path(
            first, edges, roots
        )
        if first is not None and not ambiguous:
            chosen[fp] = first
            continue
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
    return chosen




# ---------------------------------------------------------------------------
# Per-certificate aggregation
# ---------------------------------------------------------------------------

_GOOD = "good"
_REVOKED = "revoked"
# Authentic responses that simply carry no status usable at check_time.
_STALENESS = {"stale", "not_yet_valid", "produced_at_in_future",
              "next_update_missing"}


def _crl_time_entry(entry: x509.RevokedCertificate) -> datetime:
    value = getattr(entry, "revocation_date_utc", None)
    if isinstance(value, datetime):
        return value
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", (DeprecationWarning,
                                        CryptographyDeprecationWarning))
        return entry.revocation_date.replace(tzinfo=timezone.utc)


def _crl_revocation_detail(
    record: CrlRecord,
    cert: x509.Certificate,
) -> tuple[Optional[datetime], Optional[str]]:
    """(revocation date, reason) of this cert's entry on this CRL."""
    for entry in record.parsed:  # type: ignore[union-attr]
        if entry.serial_number == cert.serial_number:
            reason: Optional[str] = None
            try:
                ext = entry.extensions.get_extension_for_class(x509.CRLReason)
                reason = ext.value.reason.name
            except x509.ExtensionNotFound:
                pass
            except (ValueError, TypeError):
                reason = None
            return _crl_time_entry(entry), reason
    return None, None


def _aggregate_certificate(
    cert_fp: str,
    cert: x509.Certificate,
    issuer_fp: Optional[str],
    role: str,
    ocsp_for_cert: list[OcspRecord],
    crls_by_signer: dict[str, list[CrlRecord]],
) -> CertificateReview:
    serial_hex = _serial_hex(cert.serial_number)
    if role == "trust_root":
        return CertificateReview(
            certificate_fingerprint=cert_fp,
            issuer_fingerprint=None,
            role="trust_root",  # type: ignore[arg-type]
            serial_number=serial_hex,
            eligible=True,
            reason="trust_root",
            message="trust anchor; revocation status is not established "
                    "from within its own chain",
            revocation_time=None,
            revocation_reason=None,
            evidence=[],
        )

    # (sort tuple, DTO) plus the fresh good/revoked counters. Each CRL DTO is
    # built for this specific certificate, so its single-cert revocation
    # fields reflect exactly this cert's entry.
    items: list[tuple[tuple[str, int], Any]] = []
    fresh_good = 0
    fresh_revoked: list[tuple[tuple[str, int], Optional[datetime],
                              Optional[str]]] = []
    saw_authentic = False
    saw_stale = False

    for rec in ocsp_for_cert:
        items.append((("ocsp", rec.source_index), rec.dto()))
        if rec.fresh and rec.reason == _GOOD:
            fresh_good += 1
            saw_authentic = True
        elif rec.fresh and rec.reason == _REVOKED:
            fresh_revoked.append((
                ("ocsp", rec.source_index),
                rec.revocation_time,
                rec.revocation_reason,
            ))
            saw_authentic = True
        elif rec.reason in _STALENESS:
            saw_stale = True

    for rec in crls_by_signer.get(issuer_fp, []):
        crl = rec.parsed
        assert crl is not None
        entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        rev_date = rev_reason = None
        cert_reason = None
        cert_message = None
        if entry is not None and rec.fresh:
            rev_date, rev_reason = _crl_revocation_detail(rec, cert)
            detail = ""
            if rev_date is not None:
                detail += f" at {rev_date.isoformat()}"
            if rev_reason is not None:
                detail += f" (reason: {rev_reason})"
            cert_reason = _REVOKED
            cert_message = (f"crls[{rec.source_index}]: fresh CRL lists "
                            f"{cert_fp} as revoked{detail}")
        dto = rec.dto(
            {serial_hex} if (entry is not None and rec.fresh) else set(),
            rev_date, rev_reason, reason=cert_reason, message=cert_message,
        )
        items.append((("crl", rec.source_index), dto))
        if not rec.fresh:
            if rec.reason in _STALENESS:
                saw_stale = True
            continue
        saw_authentic = True
        if entry is not None:
            fresh_revoked.append((
                ("crl", rec.source_index), rev_date, rev_reason,
            ))
        else:
            fresh_good += 1

    items.sort(key=lambda item: item[0])
    evidence = [dto for _key, dto in items]
    fresh_revoked.sort(key=lambda item: item[0])

    # Fresh revoked always wins; simultaneous *fresh* good and revoked is the
    # explicit unresolved conflict cut (stale good never rescues a fresh
    # revocation, nor vice versa).
    if fresh_revoked:
        _key, rev_date, rev_reason = fresh_revoked[0]
        if fresh_good:
            reason = "conflicting_evidence"
            message = (f"fresh good and fresh revoked evidence both exist "
                       f"for {cert_fp} at check_time; the conflict is "
                       f"unresolved, so the certificate is ineligible")
        else:
            reason = "certificate_revoked"
            detail = ""
            if rev_date is not None:
                detail += f" at {rev_date.isoformat()}"
            if rev_reason is not None:
                detail += f" (reason: {rev_reason})"
            message = f"fresh authentic evidence revokes {cert_fp}{detail}"
        return CertificateReview(
            certificate_fingerprint=cert_fp,
            issuer_fingerprint=issuer_fp,
            role=role,  # type: ignore[arg-type]
            serial_number=serial_hex,
            eligible=False,
            reason=reason,  # type: ignore[arg-type]
            message=message,
            revocation_time=rev_date,
            revocation_reason=rev_reason,
            evidence=evidence,
        )

    if fresh_good:
        return CertificateReview(
            certificate_fingerprint=cert_fp,
            issuer_fingerprint=issuer_fp,
            role=role,  # type: ignore[arg-type]
            serial_number=serial_hex,
            eligible=True,
            reason="ok",
            message=f"{fresh_good} fresh authentic good evidence item(s); "
                    f"no fresh revoked evidence",
            revocation_time=None,
            revocation_reason=None,
            evidence=evidence,
        )

    # No fresh status conclusion: distinguish stale evidence from none at all.
    if saw_authentic or saw_stale:
        reason = "evidence_stale"
        message = (f"no fresh good or revoked evidence for {cert_fp} at "
                   f"check_time; available evidence is stale, not yet valid, "
                   f"produced in the future, unbounded, or carries no status "
                   f"(unknown)")
    else:
        reason = "evidence_missing"
        message = (f"no authentic OCSP/CRL evidence covers {cert_fp} at "
                   f"check_time")
    return CertificateReview(
        certificate_fingerprint=cert_fp,
        issuer_fingerprint=issuer_fp,
        role=role,  # type: ignore[arg-type]
        serial_number=serial_hex,
        eligible=False,
        reason=reason,  # type: ignore[arg-type]
        message=message,
        revocation_time=None,
        revocation_reason=None,
        evidence=evidence,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

_ROLLUP_PRECEDENCE = {
    "certificate_revoked": 0,
    "conflicting_evidence": 1,
    "evidence_stale": 2,
    "evidence_missing": 3,
    "ok": 4,
    "trust_root": 5,
}


def revocation_review(req: RevocationReviewRequest) -> RevocationReviewResult:
    # -- request-level validation (422) --------------------------------------
    endpoint_ids = [e.endpoint_id for e in req.endpoints]
    if len(set(endpoint_ids)) != len(endpoint_ids):
        raise NormalizeError(
            "invalid_request",
            "endpoints: endpoint_id values must be unique",
        )

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
    if fingerprint_issues:
        raise NormalizeError(
            "invalid_fingerprint",
            "one or more fingerprints are not 64-character hex SHA-256 values",
            fingerprint_issues=fingerprint_issues,
        )

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

    edges = _build_issuer_edges(certs)
    check_time = req.check_time
    skew = timedelta(seconds=req.max_skew_seconds)

    # -- evaluate every piece of evidence once, globally ---------------------
    ocsp_records = [
        _evaluate_ocsp(i, blob, certs, edges, check_time, skew,
                       req.max_skew_seconds)
        for i, blob in enumerate(req.ocsp_responses)
    ]
    crl_records = [
        _evaluate_crl(i, blob, certs, check_time, skew,
                      req.max_skew_seconds)
        for i, blob in enumerate(req.crls)
    ]

    # -- resolve chains (raises 422 no_trust_path / ambiguous_chain) ----------
    chains = _resolve_chains(req, certs, edges, trust_roots)
    chain_edges = {
        (chain[i], chain[i + 1])
        for chain in chains.values()
        for i in range(len(chain) - 1)
    }
    issuer_positions = {issuer for _child, issuer in chain_edges}

    # OCSP attachment by the exact (cert, issuer) edge used by some chain.
    ocsp_by_pair: dict[tuple[str, str], list[OcspRecord]] = {}
    for rec in ocsp_records:
        pair = (rec.cert_fp, rec.issuer_fp)
        if rec.cert_fp is not None and pair in chain_edges:
            ocsp_by_pair.setdefault(pair, []).append(rec)

    # Usable CRLs (authentic and CA-authorized) keyed by the unique signer;
    # only signers that occupy an issuer position in some reviewed chain bind
    # evidence. Every other CRL — invalid, indirect/delta, signer not found
    # or not authorized, or bound to a non-chain cert — stays unattributed.
    _USABLE_CRL_REASONS = {"good", "revoked", "stale", "not_yet_valid",
                           "next_update_missing"}
    crls_by_signer: dict[str, list[CrlRecord]] = {}
    for rec in crl_records:
        if (rec.signer_fp is not None
                and rec.reason in _USABLE_CRL_REASONS
                and rec.signer_fp in issuer_positions):
            crls_by_signer.setdefault(rec.signer_fp, []).append(rec)

    # -- per endpoint, per certificate ----------------------------------------
    endpoint_results: list[EndpointRevocationResult] = []
    for e in req.endpoints:
        leaf_fp = e.target_leaf_fingerprint.strip().lower()
        chain = chains[leaf_fp]
        cert_reviews: list[CertificateReview] = []
        for pos, cert_fp in enumerate(chain):
            cert = certs[cert_fp]
            if pos == len(chain) - 1:
                role = "trust_root"
                issuer_fp: Optional[str] = None
                ocsp_here: list[OcspRecord] = []
            else:
                role = "leaf" if pos == 0 else "intermediate"
                issuer_fp = chain[pos + 1]
                ocsp_here = list(ocsp_by_pair.get((cert_fp, issuer_fp), []))
            cert_reviews.append(_aggregate_certificate(
                cert_fp, cert, issuer_fp, role, ocsp_here, crls_by_signer,
            ))

        non_root = [r for r in cert_reviews if r.reason != "trust_root"]
        rollup = min(
            (r.reason for r in non_root),
            key=lambda reason: _ROLLUP_PRECEDENCE[reason],
        )
        endpoint_results.append(EndpointRevocationResult(
            endpoint_id=e.endpoint_id,
            target_leaf_fingerprint=leaf_fp,
            eligible=all(r.eligible for r in non_root),
            reason=rollup,  # type: ignore[arg-type]
            chain=list(chain),
            certificates=cert_reviews,
        ))

    endpoint_results.sort(key=lambda r: r.endpoint_id)

    # -- unattributed evidence: nothing submitted disappears from the audit --
    unattributed: list[UnattributedEvidence] = []
    for rec in ocsp_records:
        pair = (rec.cert_fp, rec.issuer_fp)
        if rec.cert_fp is None or pair not in chain_edges:
            unattributed.append(rec.unattributed())
    for rec in crl_records:
        bound = (rec.signer_fp is not None
                 and rec.reason in _USABLE_CRL_REASONS
                 and rec.signer_fp in issuer_positions)
        if not bound:
            unattributed.append(rec.unattributed())
    unattributed.sort(key=lambda u: (u.kind, u.source_index))

    return RevocationReviewResult(
        check_time=check_time,
        max_skew_seconds=req.max_skew_seconds,
        results=endpoint_results,
        unattributed_evidence=unattributed,
    )
