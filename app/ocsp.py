"""Offline pre-check of a stapled OCSP response for one leaf certificate.

Given the same unordered PEM bag used by ``/scenarios/normalize`` (which must
contain the leaf and its issuer), the leaf's SHA-256 fingerprint, a
Base64-encoded DER OCSP response, a validation instant ``check_time`` and a
clock-skew tolerance of at most 300 seconds, this module decides whether the
stapled response may be served for that leaf at that instant.

The pipeline is a fixed precedence of checks; the first failure determines
the stable machine-readable ``reason`` of the 200 response:

1. ``invalid_ocsp_response`` — the blob is not Base64-decodable DER or fails
   to parse as an OCSP response.
2. ``response_not_successful`` — the response status is not ``successful``
   (such responses carry no single-response fields at all).
3. ``issuer_not_found`` — no certificate in the PEM bundle cryptographically
   signed the leaf (issuance is established by signature verification alone,
   reusing the normalizer's machinery; never by DN matching).
4. ``cert_id_mismatch`` — the response CertID matches no verified issuer:
   the serial number differs from the leaf's, or the issuer name/key hashes
   (recomputed with the response's own hash algorithm over the issuer's DER
   Name and subjectPublicKey bit string) do not line up.
5. ``responder_not_found`` — neither the issuer nor any certificate embedded
   in the response matches the responderID (selected by responderName, or by
   responderKeyHash = SHA-1 over the subjectPublicKey bit string).
6. ``unauthorized_responder`` — a certificate matches the responderID but is
   neither the issuer itself nor a delegated responder: directly signed by
   the issuer, valid at ``check_time`` and carrying the id-kp-OCSPSigning
   extended key usage.
7. ``signature_invalid`` — the response signature does not verify with the
   selected signer's public key, or its signature algorithm cannot be
   resolved into concrete verification inputs. RSASSA-PSS responses are
   verified with parameters parsed from the raw DER of the response's
   ``signatureAlgorithm`` (cryptography 44.0.3 cannot read them for OCSP:
   ``signature_hash_algorithm`` raises ``UnsupportedAlgorithm``); malformed
   or unsupported RSASSA-PSS parameters land here too.
8. ``certificate_revoked`` / ``certificate_unknown`` — the (now authentic)
   response does not certify the leaf as good. A revoked verdict also
   surfaces ``revocation_time`` and ``revocation_reason``.
9. Freshness: ``produced_at_in_future`` (producedAt later than check_time +
   skew), ``next_update_missing`` (a nextUpdate freshness bound is required),
   ``response_not_yet_valid`` (check_time before thisUpdate − skew) and
   ``response_stale`` (check_time after nextUpdate + skew).

Only a response passing every check yields ``eligible: true``.
"""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import ocsp as x509_ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID

from .models import (
    NormalizeFingerprintIssue,
    OcspPrecheckRequest,
    OcspPrecheckResult,
)
from .normalize import (
    FINGERPRINT_RE,
    NormalizeError,
    _build_issuer_edges,
    _load_pem_bundle,
    _validity_utc,
    _verify_signature,
    _verify_signed_data,
    cert_fingerprint,
)
from .precheck import _der_tlv


# ---------------------------------------------------------------------------
# Hashing helpers (RFC 6960 CertID / responderID)
# ---------------------------------------------------------------------------


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


_MISSING = object()


def _ocsp_time(response: x509_ocsp.OCSPResponse, attr: str) -> Optional[datetime]:
    """Timezone-aware OCSP timestamp, or None when the field is absent.

    cryptography >= 42 exposes ``*_utc`` variants; older versions return
    naive datetimes that are already expressed in UTC.
    """
    value = getattr(response, f"{attr}_utc", _MISSING)
    if value is _MISSING:
        value = getattr(response, attr)
    if value is None:
        return None
    return _as_utc(value)


def _subject_public_key_bits(cert: x509.Certificate) -> bytes:
    """Raw subjectPublicKey bit-string content of a certificate.

    This is the exact input of the KeyHash digests in RFC 6960 (CertID
    issuerKeyHash and the byKey responderID): the BIT STRING content without
    its tag, length and unused-bits count byte.
    """
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _tag, pos, _end, _c = _der_tlv(spki, 0)          # SEQUENCE
    _tag, _p, alg_end, _c = _der_tlv(spki, pos)      # algorithm SEQUENCE
    tag, start, end, _c = _der_tlv(spki, alg_end)    # BIT STRING
    if tag != 0x03 or end - start < 1:
        raise ValueError("malformed SubjectPublicKeyInfo")
    return spki[start + 1 : end]  # strip the unused-bits count byte


def _key_hash(cert: x509.Certificate, algorithm: str = "sha1") -> bytes:
    digest = hashlib.new(algorithm)
    digest.update(_subject_public_key_bits(cert))
    return digest.digest()


def _name_hash(cert: x509.Certificate, algorithm: str) -> bytes:
    digest = hashlib.new(algorithm)
    digest.update(cert.subject.public_bytes())
    return digest.digest()


def _cert_id_matches(
    response: x509_ocsp.OCSPResponse,
    leaf: x509.Certificate,
    issuer: x509.Certificate,
) -> bool:
    """Whether the response CertID speaks for ``leaf`` issued by ``issuer``."""
    try:
        algorithm = response.hash_algorithm.name
        name_hash = _name_hash(issuer, algorithm)
        key_hash = _key_hash(issuer, algorithm)
    except (TypeError, ValueError):
        return False  # hash algorithm unknown to hashlib: cannot match
    return (
        response.serial_number == leaf.serial_number
        and response.issuer_name_hash == name_hash
        and response.issuer_key_hash == key_hash
    )


# ---------------------------------------------------------------------------
# Signer authorization
# ---------------------------------------------------------------------------


def _is_delegated_responder(
    cert: x509.Certificate,
    issuer: x509.Certificate,
    check_time: datetime,
) -> bool:
    """Whether ``cert`` may sign OCSP responses on ``issuer``'s behalf.

    Requires a verifiable direct issuance by ``issuer``, validity at
    ``check_time`` and the id-kp-OCSPSigning extended key usage.
    """
    if not _verify_signature(cert, issuer):
        return False
    if not (
        _validity_utc(cert, "not_valid_before")
        <= check_time
        <= _validity_utc(cert, "not_valid_after")
    ):
        return False
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    except x509.ExtensionNotFound:
        return False
    return ExtendedKeyUsageOID.OCSP_SIGNING in eku.value


# ---------------------------------------------------------------------------
# RSASSA-PSS signature parameters (RFC 4055)
# ---------------------------------------------------------------------------
#
# cryptography 44.0.3 cannot read the signature hash of an RSASSA-PSS OCSP
# response (``signature_hash_algorithm`` raises UnsupportedAlgorithm) and
# exposes no ``signature_algorithm_parameters`` for OCSP at all, so the PSS
# parameters are parsed here from the raw DER of the response's
# ``signatureAlgorithm``. Every absent field takes its RFC 4055 default:
# SHA-1, MGF1 with SHA-1, salt length 20 and trailerField trailerFieldBC(1).

_RSASSA_PSS_OID = "1.2.840.113549.1.1.10"
_MGF1_OID = "1.2.840.113549.1.1.8"

# Hash algorithms usable in RSASSA-PSS-params (RFC 4055 / RFC 5754 OIDs).
_HASH_ALGORITHM_OIDS = {
    "1.3.14.3.2.26": hashes.SHA1,
    "2.16.840.1.101.3.4.2.4": hashes.SHA224,
    "2.16.840.1.101.3.4.2.1": hashes.SHA256,
    "2.16.840.1.101.3.4.2.2": hashes.SHA384,
    "2.16.840.1.101.3.4.2.3": hashes.SHA512,
}

# saltLength is INTEGER (0..MAX) per RFC 4055; anything not fitting a signed
# 32-bit integer is out of range by construction (no RSA key operation could
# use it, and it cannot be handed to OpenSSL at all).
_MAX_PSS_SALT_LENGTH = 2**31 - 1


class _DerError(ValueError):
    """Malformed DER encountered while walking the PSS parameters."""


def _der_tlv_strict(buf: bytes, off: int, limit: int) -> tuple[int, int, int]:
    """(tag, content_start, content_end) of the DER TLV at ``off``.

    Strict definite-length DER: high-tag-number form, indefinite lengths,
    non-minimal length encodings and content running past ``limit`` are all
    rejected.
    """
    if off >= limit:
        raise _DerError("truncated TLV: missing tag octet")
    tag = buf[off]
    if tag & 0x1F == 0x1F:
        raise _DerError("high-tag-number form does not occur here")
    pos = off + 1
    if pos >= limit:
        raise _DerError("truncated TLV: missing length octet")
    first = buf[pos]
    pos += 1
    if first < 0x80:
        length = first
    else:
        n = first & 0x7F
        if n == 0:
            raise _DerError("indefinite length is not valid DER")
        if n > 8 or pos + n > limit:
            raise _DerError("truncated or oversized length of length")
        if buf[pos] == 0x00:
            raise _DerError("non-minimal length encoding")
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
        if length < 0x80:
            raise _DerError("long-form length used for a short-form value")
    end = pos + length
    if end > limit:
        raise _DerError("TLV content overruns its parent element")
    return tag, pos, end


def _der_oid(content: bytes) -> str:
    """Dotted-string decode of an OID's content octets (strict DER)."""
    if not content:
        raise _DerError("OID content is empty")
    arcs: list[int] = []
    value = 0
    for byte in content:
        if value == 0 and byte == 0x80:
            raise _DerError("non-minimal OID arc encoding")
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    if content[-1] & 0x80:
        raise _DerError("truncated OID arc")
    first = arcs[0]
    if first < 40:
        head = (0, first)
    elif first < 80:
        head = (1, first - 40)
    else:
        head = (2, first - 80)
    return ".".join(str(a) for a in (*head, *arcs[1:]))


def _der_integer(content: bytes) -> int:
    """Signed value of an INTEGER's content octets (strict DER)."""
    if not content:
        raise _DerError("INTEGER content is empty")
    if len(content) > 1:
        if content[0] == 0x00 and not content[1] & 0x80:
            raise _DerError("non-minimal INTEGER encoding")
        if content[0] == 0xFF and content[1] & 0x80:
            raise _DerError("non-minimal INTEGER encoding")
    return int.from_bytes(content, "big", signed=True)


def _parse_hash_algorithm_identifier(der: bytes) -> hashes.HashAlgorithm:
    """One AlgorithmIdentifier TLV naming a supported hash function."""
    tag, pos, end = _der_tlv_strict(der, 0, len(der))
    if tag != 0x30 or end != len(der):
        raise _DerError("hashAlgorithm is not a single SEQUENCE")
    tag, oid_start, oid_end = _der_tlv_strict(der, pos, end)
    if tag != 0x06:
        raise _DerError("hashAlgorithm carries no algorithm OID")
    dotted = _der_oid(der[oid_start:oid_end])
    algorithm = _HASH_ALGORITHM_OIDS.get(dotted)
    if algorithm is None:
        raise _DerError(f"unsupported hash algorithm OID {dotted}")
    if oid_end < end:  # parameters: only NULL (or absent) is defined
        tag, p_start, p_end = _der_tlv_strict(der, oid_end, end)
        if tag != 0x05 or p_start != p_end or p_end != end:
            raise _DerError("hash algorithm parameters must be NULL")
    return algorithm()


def _parse_mask_gen_algorithm(der: bytes) -> hashes.HashAlgorithm:
    """One MaskGenAlgorithm TLV; only MGF1 with a hash parameter is defined."""
    tag, pos, end = _der_tlv_strict(der, 0, len(der))
    if tag != 0x30 or end != len(der):
        raise _DerError("maskGenAlgorithm is not a single SEQUENCE")
    tag, oid_start, oid_end = _der_tlv_strict(der, pos, end)
    if tag != 0x06:
        raise _DerError("maskGenAlgorithm carries no algorithm OID")
    dotted = _der_oid(der[oid_start:oid_end])
    if dotted != _MGF1_OID:
        raise _DerError(f"unsupported mask generation function OID {dotted}")
    if oid_end >= end:
        raise _DerError("MGF1 carries no hash algorithm parameter")
    return _parse_hash_algorithm_identifier(der[oid_end:end])


def _parse_pss_params(
    der: bytes,
) -> tuple[hashes.HashAlgorithm, hashes.HashAlgorithm, int]:
    """Parse the content of an RSASSA-PSS-params SEQUENCE.

    Returns (hash, mgf1_hash, salt_length); absent fields take their
    RFC 4055 defaults (SHA-1, MGF1/SHA-1, 20). trailerField must be
    trailerFieldBC(1) — the only value ever standardized.
    """
    hash_algo: hashes.HashAlgorithm = hashes.SHA1()
    mgf_hash: hashes.HashAlgorithm = hashes.SHA1()
    salt_length = 20
    seen: set[int] = set()
    pos = 0
    while pos < len(der):
        tag, start, end = _der_tlv_strict(der, pos, len(der))
        if tag not in (0xA0, 0xA1, 0xA2, 0xA3):
            raise _DerError(
                f"unexpected field tag 0x{tag:02x} in RSASSA-PSS-params"
            )
        if tag in seen:
            raise _DerError("duplicate field in RSASSA-PSS-params")
        seen.add(tag)
        field = der[start:end]
        if tag == 0xA0:
            hash_algo = _parse_hash_algorithm_identifier(field)
        elif tag == 0xA1:
            mgf_hash = _parse_mask_gen_algorithm(field)
        else:
            itag, istart, iend = _der_tlv_strict(field, 0, len(field))
            if itag != 0x02 or iend != len(field):
                raise _DerError(
                    "saltLength/trailerField is not a single INTEGER"
                )
            value = _der_integer(field[istart:iend])
            if tag == 0xA2:
                if not 0 <= value <= _MAX_PSS_SALT_LENGTH:
                    raise _DerError("saltLength out of range")
                salt_length = value
            elif value != 1:
                raise _DerError("trailerField must be trailerFieldBC (1)")
        pos = end
    return hash_algo, mgf_hash, salt_length


def _pss_signature_scheme(
    der: bytes,
) -> tuple[hashes.HashAlgorithm, padding.PSS]:
    """Verification inputs for an RSASSA-PSS-signed OCSP response.

    Walks OCSPResponse -> responseBytes -> BasicOCSPResponse ->
    signatureAlgorithm in the raw DER and parses the RSASSA-PSS-params.
    """
    tag, pos, outer_end = _der_tlv_strict(der, 0, len(der))
    if tag != 0x30:
        raise _DerError("OCSPResponse is not a SEQUENCE")
    tag, _s, pos = _der_tlv_strict(der, pos, outer_end)
    if tag != 0x0A:
        raise _DerError("OCSPResponse carries no responseStatus")
    tag, pos, rb_end = _der_tlv_strict(der, pos, outer_end)
    if tag != 0xA0:
        raise _DerError("OCSPResponse carries no responseBytes")
    tag, pos, rb_end = _der_tlv_strict(der, pos, rb_end)
    if tag != 0x30:
        raise _DerError("ResponseBytes is not a SEQUENCE")
    tag, _s, pos = _der_tlv_strict(der, pos, rb_end)
    if tag != 0x06:
        raise _DerError("ResponseBytes carries no responseType OID")
    tag, pos, basic_end = _der_tlv_strict(der, pos, rb_end)
    if tag != 0x04:
        raise _DerError("ResponseBytes carries no response OCTET STRING")
    basic = der[pos:basic_end]
    tag, pos, basic_end = _der_tlv_strict(basic, 0, len(basic))
    if tag != 0x30:
        raise _DerError("BasicOCSPResponse is not a SEQUENCE")
    tag, _s, pos = _der_tlv_strict(basic, pos, basic_end)
    if tag != 0x30:
        raise _DerError("BasicOCSPResponse carries no tbsResponseData")
    tag, pos, alg_end = _der_tlv_strict(basic, pos, basic_end)
    if tag != 0x30:
        raise _DerError("BasicOCSPResponse carries no signatureAlgorithm")
    alg = basic[pos:alg_end]
    tag, oid_start, oid_end = _der_tlv_strict(alg, 0, len(alg))
    if tag != 0x06 or _der_oid(alg[oid_start:oid_end]) != _RSASSA_PSS_OID:
        raise _DerError("signatureAlgorithm is not id-RSASSA-PSS")
    if oid_end == len(alg):
        params = b""  # parameters omitted: every field takes its default
    else:
        tag, p_start, p_end = _der_tlv_strict(alg, oid_end, len(alg))
        if tag != 0x30 or p_end != len(alg):
            raise _DerError(
                "RSASSA-PSS parameters are not a single SEQUENCE"
            )
        params = alg[p_start:p_end]
    hash_algo, mgf_hash, salt_length = _parse_pss_params(params)
    return hash_algo, padding.PSS(
        mgf=padding.MGF1(mgf_hash), salt_length=salt_length
    )


def _response_signature_scheme(
    response: x509_ocsp.OCSPResponse, der: bytes
) -> Optional[tuple[Any, str, Any]]:
    """(hash, signature OID, parameters) triple for ``_verify_signed_data``.

    Returns None when the response's signature algorithm cannot be resolved
    into concrete verification inputs (unknown to cryptography, or PSS
    parameters that fail to parse).
    """
    signature_oid = response.signature_algorithm_oid.dotted_string
    if signature_oid == _RSASSA_PSS_OID:
        try:
            hash_algo, pss = _pss_signature_scheme(der)
        except ValueError:
            return None
        return hash_algo, signature_oid, pss
    try:
        hash_algo = response.signature_hash_algorithm
    except UnsupportedAlgorithm:
        return None
    return (
        hash_algo,
        signature_oid,
        getattr(response, "signature_algorithm_parameters", None),
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def ocsp_precheck(req: OcspPrecheckRequest) -> OcspPrecheckResult:
    # -- request-level validation (422, same shape as /scenarios/normalize) --
    leaf_fp = req.leaf_fingerprint.strip().lower()
    if not FINGERPRINT_RE.match(leaf_fp):
        raise NormalizeError(
            "invalid_fingerprint",
            "leaf_fingerprint is not a 64-character hex SHA-256 value",
            fingerprint_issues=[
                NormalizeFingerprintIssue(
                    fingerprint=req.leaf_fingerprint,
                    referred_by="leaf_fingerprint",
                )
            ],
        )

    certs, pem_issues = _load_pem_bundle(req.pem_certificates)
    if pem_issues:
        raise NormalizeError(
            "invalid_pem",
            "one or more PEM list elements could not be parsed",
            pem_issues=pem_issues,
        )

    if leaf_fp not in certs:
        raise NormalizeError(
            "unknown_fingerprint",
            "leaf_fingerprint does not match any certificate in the PEM "
            "bundle",
            fingerprint_issues=[
                NormalizeFingerprintIssue(
                    fingerprint=leaf_fp, referred_by="leaf_fingerprint"
                )
            ],
        )

    leaf = certs[leaf_fp]
    check_time = req.check_time  # normalized to UTC by the request model
    skew = timedelta(seconds=req.max_skew_seconds)

    info: dict[str, Any] = {
        "issuer_fingerprint": None,
        "response_status": None,
        "certificate_status": None,
        "responder_id_type": None,
        "signer_type": None,
        "signer_fingerprint": None,
        "produced_at": None,
        "this_update": None,
        "next_update": None,
        "revocation_time": None,
        "revocation_reason": None,
    }

    def finish(reason: str, message: str, *, eligible: bool = False):
        return OcspPrecheckResult(
            leaf_fingerprint=leaf_fp,
            eligible=eligible,
            reason=reason,  # type: ignore[arg-type]
            message=message,
            **info,
        )

    # -- 1. decode and parse the stapled response -----------------------------
    try:
        der = base64.b64decode(
            "".join(req.ocsp_response.split()), validate=True
        )
        response = x509_ocsp.load_der_ocsp_response(der)
    except ValueError as exc:
        return finish(
            "invalid_ocsp_response",
            f"ocsp_response is not a parseable Base64-encoded DER OCSP "
            f"response: {exc}",
        )

    # -- 2. the response must be successful ------------------------------------
    info["response_status"] = response.response_status.name.lower()
    if response.response_status is not x509_ocsp.OCSPResponseStatus.SUCCESSFUL:
        return finish(
            "response_not_successful",
            f"OCSP response status is {info['response_status']}, not "
            f"successful; it carries no certificate status to evaluate",
        )

    # Single-response fields exist only for successful responses.
    info["produced_at"] = _ocsp_time(response, "produced_at")
    info["this_update"] = _ocsp_time(response, "this_update")
    info["next_update"] = _ocsp_time(response, "next_update")
    info["certificate_status"] = response.certificate_status.name.lower()
    if response.certificate_status is x509_ocsp.OCSPCertStatus.REVOKED:
        info["revocation_time"] = _ocsp_time(response, "revocation_time")
        try:
            reason_flag = response.revocation_reason
        except ValueError:
            reason_flag = None  # unrecognised reason code: report as absent
        if reason_flag is not None:
            info["revocation_reason"] = reason_flag.name

    # -- 3./4. verified issuer + CertID ----------------------------------------
    edges = _build_issuer_edges(certs)
    issuer_fps = sorted(edges.get(leaf_fp, []))
    if not issuer_fps:
        return finish(
            "issuer_not_found",
            "no certificate in the PEM bundle cryptographically signed the "
            "leaf; the issuer is required to validate the CertID and to "
            "authorize the signer",
        )
    issuer_fp = next(
        (cand for cand in issuer_fps
         if _cert_id_matches(response, leaf, certs[cand])),
        None,
    )
    if issuer_fp is None:
        return finish(
            "cert_id_mismatch",
            "the response CertID matches no verified issuer of the leaf: "
            "the serial number differs from the leaf's, or the issuer "
            "name/key hashes do not line up",
        )
    issuer = certs[issuer_fp]
    info["issuer_fingerprint"] = issuer_fp

    # -- 5./6. signer selection by responderID ----------------------------------
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
        info["responder_id_type"] = "name"
    elif responder_key_hash is not None:
        info["responder_id_type"] = "key_hash"
    else:
        return finish(
            "invalid_ocsp_response",
            "the response carries no responderID (neither byName nor byKey)",
        )

    candidates = [issuer, *response.certificates]
    matching = [c for c in candidates if matches_responder_id(c)]
    if not matching:
        return finish(
            "responder_not_found",
            "neither the issuer nor any certificate embedded in the "
            "response matches the responderID",
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
        return finish(
            "unauthorized_responder",
            "the responder is neither the issuer itself nor a responder "
            "certificate directly issued by it, valid at check_time and "
            "carrying the id-kp-OCSPSigning extended key usage",
        )
    info["signer_type"] = signer_type
    info["signer_fingerprint"] = cert_fingerprint(signer)

    # -- 7. the response signature must verify ----------------------------------
    scheme = _response_signature_scheme(response, der)
    if scheme is None:
        return finish(
            "signature_invalid",
            "the response's signature algorithm is unsupported or its "
            "RSASSA-PSS parameters are malformed, so the signature cannot "
            "be verified",
        )
    if not _verify_signed_data(
        signer.public_key(),
        response.signature,
        response.tbs_response_bytes,
        *scheme,
    ):
        return finish(
            "signature_invalid",
            "the response signature does not verify with the selected "
            "signer's public key",
        )

    # -- 8. the leaf must be certified as good -----------------------------------
    if response.certificate_status is x509_ocsp.OCSPCertStatus.REVOKED:
        detail = ""
        if info["revocation_time"] is not None:
            detail += f" at {info['revocation_time'].isoformat()}"
        if info["revocation_reason"] is not None:
            detail += f" (reason: {info['revocation_reason']})"
        return finish(
            "certificate_revoked",
            f"the leaf is revoked{detail}",
        )
    if response.certificate_status is x509_ocsp.OCSPCertStatus.UNKNOWN:
        return finish(
            "certificate_unknown",
            "the responder does not certify the leaf's status (unknown)",
        )

    # -- 9. freshness ------------------------------------------------------------
    produced_at = info["produced_at"]
    if produced_at > check_time + skew:
        return finish(
            "produced_at_in_future",
            f"producedAt {produced_at.isoformat()} is later than check_time "
            f"{check_time.isoformat()} plus the {req.max_skew_seconds}s "
            f"skew allowance",
        )
    if info["next_update"] is None:
        return finish(
            "next_update_missing",
            "the response carries no nextUpdate; a freshness bound is "
            "required for a stapled response to be pre-checkable",
        )
    if check_time < info["this_update"] - skew:
        return finish(
            "response_not_yet_valid",
            f"check_time {check_time.isoformat()} is earlier than "
            f"thisUpdate {info['this_update'].isoformat()} minus the "
            f"{req.max_skew_seconds}s skew allowance",
        )
    if check_time > info["next_update"] + skew:
        return finish(
            "response_stale",
            f"check_time {check_time.isoformat()} is later than nextUpdate "
            f"{info['next_update'].isoformat()} plus the "
            f"{req.max_skew_seconds}s skew allowance",
        )

    return finish(
        "ok",
        "the stapled response is authentic, timely and certifies the leaf "
        "as good at check_time",
        eligible=True,
    )
