"""Tests for POST /deployments/ocsp-precheck (offline OCSP staple check)."""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient

from app.main import app

# Certificate validity is anchored at import time; OCSP response timestamps
# are anchored at real "now" because producedAt is stamped at signing time.
NOW = datetime.now(timezone.utc)

client = TestClient(app)


# ---------------------------------------------------------------------------
# PKI factory
# ---------------------------------------------------------------------------


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _dn(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject_cn, issuer_cn, issuer_key, subject_key, *, ca,
          not_before=None, not_after=None, eku_ocsp_signing=False,
          serial=None):
    builder = (
        x509.CertificateBuilder()
        .subject_name(_dn(subject_cn))
        .issuer_name(_dn(issuer_cn))
        .public_key(subject_key.public_key())
        .serial_number(serial if serial is not None
                       else x509.random_serial_number())
        .not_valid_before(not_before or NOW - timedelta(days=30))
        .not_valid_after(not_after or NOW + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None),
                       critical=True)
    )
    if eku_ocsp_signing:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _root(cn="Root CA"):
    key = _key()
    return _cert(cn, cn, key, key, ca=True), key


def _leaf(issuer_cn, issuer_key, *, serial=None):
    key = _key()
    cert = _cert("api.example.com", issuer_cn, issuer_key, key, ca=False,
                 serial=serial)
    return cert, key


def _responder(issuer_cn, issuer_key, *, eku=True, not_before=None,
               not_after=None):
    key = _key()
    cert = _cert("OCSP Responder", issuer_cn, issuer_key, key, ca=False,
                 eku_ocsp_signing=eku, not_before=not_before,
                 not_after=not_after)
    return cert, key


def pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def fp(cert) -> str:
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()


def _response(issuer, issuer_key, leaf, *, signer_key=None, responder_cert=None,
              responder_encoding=ocsp.OCSPResponderEncoding.NAME,
              cert_status=ocsp.OCSPCertStatus.GOOD,
              this_update=None, next_update="default",
              revocation_time=None, revocation_reason=None,
              embedded=(), cert=None):
    """Build a DER OCSP response; producedAt is stamped at signing time."""
    if this_update is None:
        this_update = NOW - timedelta(hours=1)
    if next_update == "default":
        next_update = NOW + timedelta(days=7)
    builder = ocsp.OCSPResponseBuilder().add_response(
        cert=cert if cert is not None else leaf,
        issuer=issuer,
        algorithm=hashes.SHA1(),
        cert_status=cert_status,
        this_update=this_update.replace(tzinfo=None),
        next_update=(next_update.replace(tzinfo=None)
                     if next_update is not None else None),
        revocation_time=(revocation_time.replace(tzinfo=None)
                         if revocation_time is not None else None),
        revocation_reason=revocation_reason,
    )
    builder = builder.responder_id(
        responder_encoding,
        responder_cert if responder_cert is not None else issuer,
    )
    if embedded:
        builder = builder.certificates(list(embedded))
    return builder.sign(signer_key or issuer_key, hashes.SHA256())


def der_b64(response) -> str:
    return base64.b64encode(
        response.public_bytes(serialization.Encoding.DER)
    ).decode()


def ocsp_precheck(bundle, leaf, response_b64, *, check_time=None, skew=0,
                  leaf_fingerprint=None):
    payload = {
        "pem_certificates": [pem(c) for c in bundle],
        "leaf_fingerprint": (leaf_fingerprint if leaf_fingerprint is not None
                             else fp(leaf)),
        "ocsp_response": response_b64,
        # Default: evaluated right after the response was signed, so
        # producedAt <= check_time holds on the happy path.
        "check_time": (check_time or datetime.now(timezone.utc)).isoformat(),
        "max_skew_seconds": skew,
    }
    return client.post("/deployments/ocsp-precheck", json=payload)


def good_setup(**resp_kwargs):
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    response = _response(root, root_key, leaf, **resp_kwargs)
    return root, leaf, der_b64(response)


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


def test_eligible_issuer_signed_by_name():
    root, leaf, b64 = good_setup()
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is True
    assert body["reason"] == "ok"
    assert body["response_status"] == "successful"
    assert body["certificate_status"] == "good"
    assert body["responder_id_type"] == "name"
    assert body["signer_type"] == "issuer"
    assert body["issuer_fingerprint"] == fp(root)
    assert body["signer_fingerprint"] == fp(root)
    assert body["leaf_fingerprint"] == fp(leaf)
    assert body["produced_at"] is not None
    assert body["this_update"] is not None
    assert body["next_update"] is not None
    assert body["revocation_time"] is None
    assert body["revocation_reason"] is None


def test_eligible_issuer_signed_by_key_hash():
    root, leaf, b64 = good_setup(
        responder_encoding=ocsp.OCSPResponderEncoding.HASH
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is True
    assert body["responder_id_type"] == "key_hash"
    assert body["signer_type"] == "issuer"


def test_eligible_delegated_responder_by_key_hash():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    responder, responder_key = _responder("Root CA", root_key)
    response = _response(
        root, root_key, leaf,
        signer_key=responder_key,
        responder_cert=responder,
        responder_encoding=ocsp.OCSPResponderEncoding.HASH,
        embedded=[responder],
    )
    r = ocsp_precheck([leaf, root], leaf, der_b64(response))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is True
    assert body["responder_id_type"] == "key_hash"
    assert body["signer_type"] == "responder_certificate"
    assert body["signer_fingerprint"] == fp(responder)


def test_eligible_delegated_responder_by_name():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    responder, responder_key = _responder("Root CA", root_key)
    response = _response(
        root, root_key, leaf,
        signer_key=responder_key,
        responder_cert=responder,
        responder_encoding=ocsp.OCSPResponderEncoding.NAME,
        embedded=[responder],
    )
    r = ocsp_precheck([leaf, root], leaf, der_b64(response))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is True
    assert body["responder_id_type"] == "name"
    assert body["signer_type"] == "responder_certificate"


def test_issuer_embedded_in_response_still_counts_as_issuer():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    response = _response(root, root_key, leaf, embedded=[root])
    r = ocsp_precheck([leaf, root], leaf, der_b64(response))
    assert r.status_code == 200, r.text
    assert r.json()["signer_type"] == "issuer"


def test_base64_blob_tolerates_whitespace():
    root, leaf, b64 = good_setup()
    wrapped = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    r = ocsp_precheck([leaf, root], leaf, wrapped)
    assert r.status_code == 200, r.text
    assert r.json()["eligible"] is True


# ---------------------------------------------------------------------------
# CertID / issuer checks
# ---------------------------------------------------------------------------


def test_issuer_not_found():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    b64 = der_b64(_response(root, root_key, leaf))
    r = ocsp_precheck([leaf], leaf, b64)  # bundle lacks the issuer
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "issuer_not_found"
    assert body["issuer_fingerprint"] is None


def test_cert_id_mismatch_serial():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key, serial=1111)
    other_leaf, _ = _leaf("Root CA", root_key, serial=2222)
    # Response speaks for the other leaf's serial number.
    b64 = der_b64(_response(root, root_key, leaf, cert=other_leaf))
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "cert_id_mismatch"
    assert body["issuer_fingerprint"] is None


def test_cert_id_mismatch_issuer_hashes():
    root, root_key = _root()
    other_root, other_root_key = _root("Other Root CA")
    leaf, _ = _leaf("Root CA", root_key)
    # Same serial, but the CertID issuer hashes name the other CA.
    b64 = der_b64(_response(other_root, other_root_key, leaf))
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    assert r.json()["reason"] == "cert_id_mismatch"


# ---------------------------------------------------------------------------
# Signer selection
# ---------------------------------------------------------------------------


def test_responder_not_found():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    stranger, stranger_key = _responder("Root CA", root_key)
    # ResponderID names a certificate that is not embedded in the response.
    b64 = der_b64(_response(root, root_key, leaf,
                            signer_key=stranger_key,
                            responder_cert=stranger))
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "responder_not_found"
    assert body["signer_type"] is None


def test_unauthorized_responder_missing_eku():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    responder, responder_key = _responder("Root CA", root_key, eku=False)
    b64 = der_b64(_response(root, root_key, leaf,
                            signer_key=responder_key,
                            responder_cert=responder,
                            embedded=[responder]))
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "unauthorized_responder"


def test_unauthorized_responder_not_issued_by_issuer():
    root, root_key = _root()
    other_root, other_root_key = _root("Other Root CA")
    leaf, _ = _leaf("Root CA", root_key)
    # Responder cert is issued by a different CA, not by the leaf's issuer.
    responder, responder_key = _responder("Other Root CA", other_root_key)
    b64 = der_b64(_response(root, root_key, leaf,
                            signer_key=responder_key,
                            responder_cert=responder,
                            embedded=[responder]))
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    assert r.json()["reason"] == "unauthorized_responder"


def test_unauthorized_responder_expired_at_check_time():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    responder, responder_key = _responder(
        "Root CA", root_key,
        not_before=NOW - timedelta(days=30),
        not_after=NOW - timedelta(hours=1),
    )
    b64 = der_b64(_response(root, root_key, leaf,
                            signer_key=responder_key,
                            responder_cert=responder,
                            embedded=[responder]))
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    assert r.json()["reason"] == "unauthorized_responder"


def test_signature_invalid():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    response = _response(root, root_key, leaf)
    # Flip the last byte of the DER: with no embedded certs the signature
    # BIT STRING is the final element, so this corrupts the signature while
    # keeping the envelope parseable.
    der = bytearray(response.public_bytes(serialization.Encoding.DER))
    der[-1] ^= 0x01
    r = ocsp_precheck([leaf, root], leaf, base64.b64encode(bytes(der)).decode())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "signature_invalid"
    assert body["signer_type"] == "issuer"


# ---------------------------------------------------------------------------
# Certificate status
# ---------------------------------------------------------------------------


def test_certificate_revoked_carries_time_and_reason():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    revoked_at = NOW - timedelta(hours=2)
    b64 = der_b64(_response(
        root, root_key, leaf,
        cert_status=ocsp.OCSPCertStatus.REVOKED,
        revocation_time=revoked_at,
        revocation_reason=x509.ReasonFlags.key_compromise,
    ))
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "certificate_revoked"
    assert body["certificate_status"] == "revoked"
    assert body["revocation_reason"] == "key_compromise"
    assert body["revocation_time"] is not None
    assert body["revocation_time"].startswith(
        revoked_at.replace(microsecond=0).isoformat()[:19]
    )


def test_certificate_revoked_without_reason():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    b64 = der_b64(_response(
        root, root_key, leaf,
        cert_status=ocsp.OCSPCertStatus.REVOKED,
        revocation_time=NOW - timedelta(hours=2),
    ))
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["reason"] == "certificate_revoked"
    assert body["revocation_reason"] is None
    assert body["revocation_time"] is not None


def test_certificate_unknown():
    root, leaf, b64 = good_setup(cert_status=ocsp.OCSPCertStatus.UNKNOWN)
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "certificate_unknown"
    assert body["certificate_status"] == "unknown"


def test_response_not_successful():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    response = ocsp.OCSPResponseBuilder.build_unsuccessful(
        ocsp.OCSPResponseStatus.UNAUTHORIZED
    )
    r = ocsp_precheck([leaf, root], leaf, der_b64(response))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "response_not_successful"
    assert body["response_status"] == "unauthorized"
    assert body["certificate_status"] is None


def test_invalid_ocsp_response():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    for blob in ("!!!not-base64!!!",
                 base64.b64encode(b"garbage, not DER").decode()):
        r = ocsp_precheck([leaf, root], leaf, blob)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["eligible"] is False
        assert body["reason"] == "invalid_ocsp_response"
        assert body["response_status"] is None


# ---------------------------------------------------------------------------
# Freshness window
# ---------------------------------------------------------------------------


def test_produced_at_in_future():
    root, leaf, b64 = good_setup()
    # producedAt is stamped "now"; a check_time a day in the past rejects it.
    r = ocsp_precheck([leaf, root], leaf, b64,
                      check_time=NOW - timedelta(days=1))
    assert r.status_code == 200, r.text
    assert r.json()["reason"] == "produced_at_in_future"


def test_produced_at_within_skew():
    root, leaf, b64 = good_setup()
    # check_time slightly behind producedAt, covered by the skew allowance.
    r = ocsp_precheck([leaf, root], leaf, b64,
                      check_time=datetime.now(timezone.utc)
                      - timedelta(seconds=100),
                      skew=300)
    assert r.status_code == 200, r.text
    assert r.json()["eligible"] is True


def test_next_update_missing():
    root, leaf, b64 = good_setup(next_update=None)
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "next_update_missing"
    assert body["next_update"] is None


def test_response_not_yet_valid():
    root, leaf, b64 = good_setup(
        this_update=NOW + timedelta(hours=1),
        next_update=NOW + timedelta(days=7),
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    assert r.json()["reason"] == "response_not_yet_valid"


def test_response_not_yet_valid_rescued_by_skew():
    root, leaf, b64 = good_setup(
        this_update=datetime.now(timezone.utc) + timedelta(seconds=100),
        next_update=NOW + timedelta(days=7),
    )
    r = ocsp_precheck([leaf, root], leaf, b64, skew=300)
    assert r.status_code == 200, r.text
    assert r.json()["eligible"] is True


def test_response_stale():
    root, leaf, b64 = good_setup(
        this_update=NOW - timedelta(days=10),
        next_update=NOW - timedelta(hours=1),
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    assert r.json()["reason"] == "response_stale"


def test_response_stale_rescued_by_skew():
    root, leaf, b64 = good_setup(
        this_update=NOW - timedelta(days=10),
        next_update=datetime.now(timezone.utc) - timedelta(seconds=100),
    )
    r = ocsp_precheck([leaf, root], leaf, b64, skew=300)
    assert r.status_code == 200, r.text
    assert r.json()["eligible"] is True


def test_skew_boundary_is_inclusive():
    root, leaf, b64 = good_setup(
        this_update=NOW - timedelta(days=10),
        next_update=NOW,  # exactly check_time-ish; well within any skew
    )
    r = ocsp_precheck([leaf, root], leaf, b64, skew=300)
    assert r.status_code == 200, r.text
    assert r.json()["eligible"] is True


# ---------------------------------------------------------------------------
# Request-level validation (422)
# ---------------------------------------------------------------------------


def test_invalid_fingerprint_format():
    root, leaf, b64 = good_setup()
    r = ocsp_precheck([leaf, root], leaf, b64, leaf_fingerprint="zz" * 32)
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error"] == "invalid_fingerprint"
    assert detail["fingerprint_issues"][0]["referred_by"] == "leaf_fingerprint"
    # The OCSP route shares the normalize error shape (no identity_issues).
    assert "identity_issues" not in detail


def test_unknown_fingerprint():
    root, leaf, b64 = good_setup()
    r = ocsp_precheck([leaf, root], leaf, b64, leaf_fingerprint="0" * 64)
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "unknown_fingerprint"


def test_invalid_pem():
    root, root_key = _root()
    leaf, _ = _leaf("Root CA", root_key)
    payload = {
        "pem_certificates": ["not a pem block"],
        "leaf_fingerprint": fp(leaf),
        "ocsp_response": "AAAA",
        "check_time": NOW.isoformat(),
        "max_skew_seconds": 0,
    }
    r = client.post("/deployments/ocsp-precheck", json=payload)
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error"] == "invalid_pem"
    assert detail["pem_issues"][0]["index"] == 0


def test_skew_capped_at_300_seconds():
    root, leaf, b64 = good_setup()
    r = ocsp_precheck([leaf, root], leaf, b64, skew=301)
    assert r.status_code == 422


def test_naive_check_time_treated_as_utc():
    root, leaf, b64 = good_setup()
    payload = {
        "pem_certificates": [pem(leaf), pem(root)],
        "leaf_fingerprint": fp(leaf),
        "ocsp_response": b64,
        "check_time": datetime.now(timezone.utc)
        .replace(tzinfo=None)
        .isoformat(),
        "max_skew_seconds": 300,
    }
    r = client.post("/deployments/ocsp-precheck", json=payload)
    assert r.status_code == 200, r.text
    assert r.json()["eligible"] is True


def test_uppercase_fingerprint_accepted():
    root, leaf, b64 = good_setup()
    r = ocsp_precheck([leaf, root], leaf, b64,
                      leaf_fingerprint=fp(leaf).upper())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is True
    assert body["leaf_fingerprint"] == fp(leaf)  # normalized to lower-case


# ---------------------------------------------------------------------------
# RSASSA-PSS signed responses
#
# cryptography 44.0.3 can neither emit nor introspect PSS OCSP signatures
# (OCSPResponseBuilder.sign has no PSS option; reading signature_hash_algorithm
# of a PSS response raises UnsupportedAlgorithm). The responses below are
# therefore assembled by hand: a normal response is built, its
# tbsResponseData re-signed with PSS and the BasicOCSPResponse reassembled
# with the chosen signatureAlgorithm parameters.
# ---------------------------------------------------------------------------

_PSS_HASHES = {
    "sha1": (hashes.SHA1, (1, 3, 14, 3, 2, 26)),
    "sha224": (hashes.SHA224, (2, 16, 840, 1, 101, 3, 4, 2, 4)),
    "sha256": (hashes.SHA256, (2, 16, 840, 1, 101, 3, 4, 2, 1)),
    "sha384": (hashes.SHA384, (2, 16, 840, 1, 101, 3, 4, 2, 2)),
    "sha512": (hashes.SHA512, (2, 16, 840, 1, 101, 3, 4, 2, 3)),
}


def _rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _rsa_root(cn="Root CA"):
    key = _rsa_key()
    return _cert(cn, cn, key, key, ca=True), key


def _rsa_leaf(issuer_cn, issuer_key):
    key = _rsa_key()
    return _cert("api.example.com", issuer_cn, issuer_key, key, ca=False), key


def _rsa_responder(issuer_cn, issuer_key):
    key = _rsa_key()
    cert = _cert("OCSP Responder", issuer_cn, issuer_key, key, ca=False,
                 eku_ocsp_signing=True)
    return cert, key


# -- minimal DER assembly ----------------------------------------------------


def _tlv(tag, content):
    if len(content) < 0x80:
        length = bytes([len(content)])
    else:
        raw = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + content


def _oid_der(*arcs):
    out = bytes([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        encoded = [arc & 0x7F]
        arc >>= 7
        while arc:
            encoded.append(0x80 | (arc & 0x7F))
            arc >>= 7
        out += bytes(reversed(encoded))
    return _tlv(0x06, out)


def _int_der(value):
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big",
                         signed=True)
    return _tlv(0x02, raw)


def _hash_alg_id(name):
    return _tlv(0x30, _oid_der(*_PSS_HASHES[name][1]) + b"\x05\x00")


def _mgf1_alg_id(hash_name):
    return _tlv(0x30, _oid_der(1, 2, 840, 113549, 1, 1, 8)
                + _hash_alg_id(hash_name))


def _pss_params_der(hash_name=None, mgf_hash_name=None, salt=None,
                    trailer=None):
    """RSASSA-PSS-params SEQUENCE; None fields are simply omitted."""
    body = b""
    if hash_name is not None:
        body += _tlv(0xA0, _hash_alg_id(hash_name))
    if mgf_hash_name is not None:
        body += _tlv(0xA1, _mgf1_alg_id(mgf_hash_name))
    if salt is not None:
        body += _tlv(0xA2, _int_der(salt))
    if trailer is not None:
        body += _tlv(0xA3, _int_der(trailer))
    return _tlv(0x30, body)


def _pss_sig_alg_der(params_der):
    """id-RSASSA-PSS AlgorithmIdentifier; params_der=None omits parameters."""
    body = _oid_der(1, 2, 840, 113549, 1, 1, 10)
    if params_der is not None:
        body += params_der
    return _tlv(0x30, body)


def _der_children(buf, start=0, end=None):
    """(tag, tlv_start, content_start, content_end) per top-level TLV."""
    end = len(buf) if end is None else end
    out = []
    pos = start
    while pos < end:
        tlv_start = pos
        tag = buf[pos]
        pos += 1
        length = buf[pos]
        pos += 1
        if length & 0x80:
            n = length & 0x7F
            length = int.from_bytes(buf[pos:pos + n], "big")
            pos += n
        out.append((tag, tlv_start, pos, pos + length))
        pos += length
    return out


def _resign_as_pss(response, signer_key, sig_alg_der, hash_alg, mgf_hash_alg,
                   salt_length):
    """Re-emit ``response`` with its tbsResponseData signed by RSASSA-PSS.

    The BasicOCSPResponse is reassembled by hand: same tbsResponseData and
    embedded certs, the given signatureAlgorithm and a fresh PSS signature.
    """
    der = response.public_bytes(serialization.Encoding.DER)
    (envelope,) = _der_children(der)
    children = _der_children(der, envelope[2], envelope[3])
    status_tlv = der[children[0][1]:children[0][3]]       # responseStatus
    (rb_seq,) = _der_children(der, children[1][2], children[1][3])
    rb_children = _der_children(der, rb_seq[2], rb_seq[3])
    oid_tlv = der[rb_children[0][1]:rb_children[0][3]]    # responseType
    octets = rb_children[1]                               # response
    basic = der[octets[2]:octets[3]]
    (basic_seq,) = _der_children(basic)
    parts = _der_children(basic, basic_seq[2], basic_seq[3])
    tbs = basic[parts[0][1]:parts[0][3]]                  # tbsResponseData
    rest = basic[parts[2][3]:basic_seq[3]]                # certs [0], if any
    signature = signer_key.sign(
        tbs,
        padding.PSS(mgf=padding.MGF1(mgf_hash_alg), salt_length=salt_length),
        hash_alg,
    )
    new_basic = _tlv(0x30, tbs + sig_alg_der
                     + _tlv(0x03, b"\x00" + signature) + rest)
    response_bytes = _tlv(0x30, oid_tlv + _tlv(0x04, new_basic))
    return _tlv(0x30, status_tlv + _tlv(0xA0, response_bytes))


def _pss_response_b64(issuer, issuer_key, leaf, *, signer_key=None,
                      responder_cert=None, embedded=(), sig_alg_der,
                      hash_alg, mgf_hash_alg, salt_length, corrupt=False,
                      **resp_kwargs):
    response = _response(issuer, issuer_key, leaf,
                         signer_key=signer_key,
                         responder_cert=responder_cert,
                         embedded=embedded, **resp_kwargs)
    der = _resign_as_pss(response, signer_key or issuer_key, sig_alg_der,
                         hash_alg, mgf_hash_alg, salt_length)
    if corrupt:
        # No embedded certs here, so the signature BIT STRING is the last
        # element: flipping the final byte corrupts the signature only.
        der = der[:-1] + bytes([der[-1] ^ 0x01])
    return base64.b64encode(der).decode()


def pss_setup(sig_alg_der, hash_name, mgf_hash_name, salt_length, **kwargs):
    """(root, leaf, b64) for an RSA issuer and a PSS-signed OCSP response."""
    root, root_key = _rsa_root()
    leaf, _ = _rsa_leaf("Root CA", root_key)
    b64 = _pss_response_b64(
        root, root_key, leaf,
        sig_alg_der=sig_alg_der,
        hash_alg=_PSS_HASHES[hash_name][0](),
        mgf_hash_alg=_PSS_HASHES[mgf_hash_name][0](),
        salt_length=salt_length,
        **kwargs,
    )
    return root, leaf, b64


# -- happy paths ---------------------------------------------------------------


def test_pss_explicit_params_end_to_end():
    # The regression itself: a legitimate PSS response must get a verdict
    # instead of an unhandled exception.
    root, leaf, b64 = pss_setup(
        _pss_sig_alg_der(_pss_params_der("sha256", "sha256", 32, 1)),
        "sha256", "sha256", 32,
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is True
    assert body["reason"] == "ok"
    assert body["signer_type"] == "issuer"
    assert body["issuer_fingerprint"] == fp(root)


@pytest.mark.parametrize("hash_name,mgf_name,salt", [
    ("sha256", "sha256", 32),   # hash == MGF1 hash, salt == digest size
    ("sha256", "sha384", 0),    # different MGF1 hash, empty salt
    ("sha384", "sha256", 48),
    ("sha512", "sha256", 64),
    ("sha224", "sha512", 28),
    ("sha512", "sha384", 100),  # salt larger than any digest
])
def test_pss_hash_mgf1_combinations(hash_name, mgf_name, salt):
    root, leaf, b64 = pss_setup(
        _pss_sig_alg_der(_pss_params_der(hash_name, mgf_name, salt, 1)),
        hash_name, mgf_name, salt,
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    assert r.json()["eligible"] is True


def test_pss_non_default_salt_length_is_enforced():
    # Params declare salt 48 but the signature used the RFC 4055 default 20.
    root, root_key = _rsa_root()
    leaf, _ = _rsa_leaf("Root CA", root_key)
    b64 = _pss_response_b64(
        root, root_key, leaf,
        sig_alg_der=_pss_sig_alg_der(_pss_params_der("sha256", "sha256", 48, 1)),
        hash_alg=hashes.SHA256(), mgf_hash_alg=hashes.SHA256(), salt_length=20,
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "signature_invalid"


def test_pss_default_params_omitted():
    # No parameters at all: RFC 4055 defaults (SHA-1, MGF1/SHA-1, salt 20).
    root, leaf, b64 = pss_setup(_pss_sig_alg_der(None), "sha1", "sha1", 20)
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    assert r.json()["eligible"] is True


def test_pss_default_params_empty_sequence():
    root, leaf, b64 = pss_setup(_pss_sig_alg_der(_pss_params_der()),
                                "sha1", "sha1", 20)
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    assert r.json()["eligible"] is True


def test_pss_default_params_explicitly_encoded_rejected():
    # DER (X.690 11.5) forbids encoding a field at its DEFAULT value, so
    # sha1/mgf1-sha1/salt-20 spelled out explicitly is malformed and the
    # response never reaches the signature check.
    root, leaf, b64 = pss_setup(
        _pss_sig_alg_der(_pss_params_der("sha1", "sha1", 20, 1)),
        "sha1", "sha1", 20,
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "invalid_ocsp_response"


def test_pss_partial_params_filled_with_defaults():
    # Only hashAlgorithm explicit: MGF1/SHA-1 and salt 20 are defaulted.
    root, leaf, b64 = pss_setup(
        _pss_sig_alg_der(_pss_params_der(hash_name="sha256")),
        "sha256", "sha1", 20,
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    assert r.json()["eligible"] is True
    # Only maskGenAlgorithm explicit: SHA-1 hash and salt 20 are defaulted.
    root, leaf, b64 = pss_setup(
        _pss_sig_alg_der(_pss_params_der(mgf_hash_name="sha256")),
        "sha1", "sha256", 20,
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    assert r.json()["eligible"] is True
    # Only saltLength explicit: SHA-1 and MGF1/SHA-1 are defaulted.
    root, leaf, b64 = pss_setup(
        _pss_sig_alg_der(_pss_params_der(salt=32)),
        "sha1", "sha1", 32,
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    assert r.json()["eligible"] is True


def test_pss_delegated_responder_with_embedded_cert():
    root, root_key = _rsa_root()
    leaf, _ = _rsa_leaf("Root CA", root_key)
    responder, responder_key = _rsa_responder("Root CA", root_key)
    b64 = _pss_response_b64(
        root, root_key, leaf,
        signer_key=responder_key, responder_cert=responder,
        embedded=[responder],
        sig_alg_der=_pss_sig_alg_der(_pss_params_der("sha256", "sha256", 32, 1)),
        hash_alg=hashes.SHA256(), mgf_hash_alg=hashes.SHA256(), salt_length=32,
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is True
    assert body["signer_type"] == "responder_certificate"
    assert body["signer_fingerprint"] == fp(responder)


# -- signature failures --------------------------------------------------------


def test_pss_signature_hash_mismatch():
    # Params declare SHA-256 but the signature was produced with SHA-512.
    root, root_key = _rsa_root()
    leaf, _ = _rsa_leaf("Root CA", root_key)
    b64 = _pss_response_b64(
        root, root_key, leaf,
        sig_alg_der=_pss_sig_alg_der(_pss_params_der("sha256", "sha256", 32, 1)),
        hash_alg=hashes.SHA512(), mgf_hash_alg=hashes.SHA256(), salt_length=32,
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "signature_invalid"


def test_pss_corrupted_signature():
    root, leaf, b64 = pss_setup(
        _pss_sig_alg_der(_pss_params_der("sha256", "sha256", 32, 1)),
        "sha256", "sha256", 32, corrupt=True,
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    assert r.json()["reason"] == "signature_invalid"


def test_pss_revoked_status_still_evaluated():
    # A verified PSS signature lets the pipeline reach the status checks.
    root, root_key = _rsa_root()
    leaf, _ = _rsa_leaf("Root CA", root_key)
    b64 = _pss_response_b64(
        root, root_key, leaf,
        sig_alg_der=_pss_sig_alg_der(_pss_params_der("sha256", "sha256", 32, 1)),
        hash_alg=hashes.SHA256(), mgf_hash_alg=hashes.SHA256(), salt_length=32,
        cert_status=ocsp.OCSPCertStatus.REVOKED,
        revocation_time=NOW - timedelta(hours=2),
        revocation_reason=x509.ReasonFlags.key_compromise,
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "certificate_revoked"
    assert body["certificate_status"] == "revoked"
    assert body["revocation_reason"] == "key_compromise"


# -- malformed / unsupported parameters ----------------------------------------
#
# Every case must yield a stable machine-readable reason, never an unhandled
# exception. Structurally malformed encodings are already rejected by
# cryptography's strict ASN.1 parse of the response (check 1,
# invalid_ocsp_response); structurally valid but unusable parameters reach
# the signature check and fail there (signature_invalid).


def _unknown_hash_oid_params():
    alg = _tlv(0x30, _oid_der(1, 3, 14, 3, 2, 99) + b"\x05\x00")
    return _tlv(0x30, _tlv(0xA0, alg))


def _unknown_mgf_oid_params():
    alg = _tlv(0x30, _oid_der(1, 2, 840, 113549, 1, 1, 9)
               + _hash_alg_id("sha256"))
    return _tlv(0x30, _tlv(0xA1, alg))


def _mgf1_without_params():
    alg = _tlv(0x30, _oid_der(1, 2, 840, 113549, 1, 1, 8))
    return _tlv(0x30, _tlv(0xA1, alg))


def _mgf1_params_not_hash():
    alg = _tlv(0x30, _oid_der(1, 2, 840, 113549, 1, 1, 8) + b"\x05\x00")
    return _tlv(0x30, _tlv(0xA1, alg))


def _duplicate_hash_field_params():
    field = _tlv(0xA0, _hash_alg_id("sha256"))
    return _tlv(0x30, field + field)


def _unknown_field_tag_params():
    return _tlv(0x30, _tlv(0xA4, _int_der(1)))


def _hash_params_not_null():
    alg = _tlv(0x30, _oid_der(*_PSS_HASHES["sha256"][1]) + _int_der(5))
    return _tlv(0x30, _tlv(0xA0, alg))


def _truncated_field_params():
    # The [0] field declares 6 content octets; only 4 remain in the params.
    return bytes.fromhex("3006a00630040602")


def _indefinite_length_params():
    # [0] wraps a SEQUENCE encoded with an indefinite length (not DER).
    return bytes.fromhex("3004a00230800000")


def _nonminimal_integer_params():
    # saltLength 20 encoded with a redundant leading zero octet.
    return _tlv(0x30, _tlv(0xA2, b"\x02\x02\x00\x14"))


def _negative_salt_params():
    return _tlv(0x30, _tlv(0xA2, _int_der(-1)))


def _oversized_salt_params():
    return _tlv(0x30, _tlv(0xA2, _int_der(2**31)))


def _salt_not_integer_params():
    return _tlv(0x30, _tlv(0xA2, b"\x05\x00"))


def _salt_two_integers_params():
    return _tlv(0x30, _tlv(0xA2, _int_der(20) + _int_der(1)))


# Structurally valid but unusable parameters: the response parses, the
# signature check cannot be performed -> signature_invalid.
_UNSUPPORTED_PSS_PARAMS = {
    "unknown_hash_oid": _unknown_hash_oid_params(),
    "unknown_mgf_oid": _unknown_mgf_oid_params(),
    "trailer_not_bc": _pss_params_der("sha256", "sha256", 32, 2),
}


@pytest.mark.parametrize("params_der", _UNSUPPORTED_PSS_PARAMS.values(),
                         ids=_UNSUPPORTED_PSS_PARAMS.keys())
def test_pss_unsupported_params(params_der):
    root, leaf, b64 = pss_setup(
        _pss_sig_alg_der(params_der), "sha256", "sha256", 32,
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "signature_invalid"
    assert body["signer_type"] == "issuer"


# Structurally malformed encodings: rejected while parsing the response
# itself -> invalid_ocsp_response.
_UNPARSEABLE_PSS_PARAMS = {
    "mgf1_without_params": _mgf1_without_params(),
    "mgf1_params_not_hash": _mgf1_params_not_hash(),
    "duplicate_hash_field": _duplicate_hash_field_params(),
    "unknown_field_tag": _unknown_field_tag_params(),
    "hash_params_not_null": _hash_params_not_null(),
    "truncated_field": _truncated_field_params(),
    "indefinite_length": _indefinite_length_params(),
    "nonminimal_integer": _nonminimal_integer_params(),
    "negative_salt": _negative_salt_params(),
    "oversized_salt": _oversized_salt_params(),
    "salt_not_integer": _salt_not_integer_params(),
    "salt_two_integers": _salt_two_integers_params(),
    "params_not_a_sequence": b"\x05\x00",
}


@pytest.mark.parametrize("params_der", _UNPARSEABLE_PSS_PARAMS.values(),
                         ids=_UNPARSEABLE_PSS_PARAMS.keys())
def test_pss_unparseable_params(params_der):
    root, leaf, b64 = pss_setup(
        _pss_sig_alg_der(params_der), "sha256", "sha256", 32,
    )
    r = ocsp_precheck([leaf, root], leaf, b64)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["eligible"] is False
    assert body["reason"] == "invalid_ocsp_response"


# -- the RSASSA-PSS-params parser itself ---------------------------------------
#
# cryptography's loader rejects some malformed encodings before the endpoint's
# own parser ever runs; these unit tests pin the parser's rejections
# independently of that load-time behaviour.


def _params_content(params_der):
    """Strip the outer SEQUENCE TLV from a params DER fragment."""
    (seq,) = _der_children(params_der)
    assert seq[0] == 0x30 and seq[1] == 0 and seq[3] == len(params_der)
    return params_der[seq[2]:seq[3]]


def test_parse_pss_params_defaults():
    from app.ocsp import _parse_pss_params

    hash_algo, mgf_hash, salt = _parse_pss_params(b"")
    assert isinstance(hash_algo, hashes.SHA1)
    assert isinstance(mgf_hash, hashes.SHA1)
    assert salt == 20


def test_parse_pss_params_explicit():
    from app.ocsp import _parse_pss_params

    hash_algo, mgf_hash, salt = _parse_pss_params(
        _params_content(_pss_params_der("sha384", "sha512", 48, 1))
    )
    assert isinstance(hash_algo, hashes.SHA384)
    assert isinstance(mgf_hash, hashes.SHA512)
    assert salt == 48


@pytest.mark.parametrize(
    "params_der",
    [*_UNSUPPORTED_PSS_PARAMS.values(),
     *[v for k, v in _UNPARSEABLE_PSS_PARAMS.items()
       if k != "params_not_a_sequence"]],
    ids=[*_UNSUPPORTED_PSS_PARAMS.keys(),
         *[k for k in _UNPARSEABLE_PSS_PARAMS.keys()
           if k != "params_not_a_sequence"]],
)
def test_parse_pss_params_rejects(params_der):
    from app.ocsp import _parse_pss_params

    with pytest.raises(ValueError):
        _parse_pss_params(_params_content(params_der))
