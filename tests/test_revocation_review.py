"""Tests for POST /deployments/revocation-review (chain-wide revocation evidence)."""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient

from app.main import app

NOW = datetime.now(timezone.utc)
WINDOW_START = datetime(2024, 1, 1)
WINDOW_END = datetime(2035, 1, 1)
CHECK_TIME = "2030-06-01T00:00:00Z"

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
          serial=None, key_usage=None):
    builder = (
        x509.CertificateBuilder()
        .subject_name(_dn(subject_cn))
        .issuer_name(_dn(issuer_cn))
        .public_key(subject_key.public_key())
        .serial_number(serial if serial is not None
                       else x509.random_serial_number())
        .not_valid_before(not_before or datetime(2024, 1, 1))
        .not_valid_after(not_after or datetime(2035, 1, 1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None),
                       critical=True)
    )
    if key_usage is not None:
        builder = builder.add_extension(key_usage, critical=True)
    if eku_ocsp_signing:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _fp(cert) -> str:
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()


def _ocsp(cert_, issuer, issuer_key, *, status=ocsp.OCSPCertStatus.GOOD,
          this_update=WINDOW_START, next_update=WINDOW_END,
          revocation_time=None, revocation_reason=None,
          responder_encoding=ocsp.OCSPResponderEncoding.NAME,
          signer_key=None, responder_cert=None, embedded=(),
          produced_at=None):
    builder = ocsp.OCSPResponseBuilder().add_response(
        cert=cert_, issuer=issuer, algorithm=hashes.SHA1(),
        cert_status=status,
        this_update=this_update,
        next_update=next_update,
        revocation_time=revocation_time,
        revocation_reason=revocation_reason,
    )
    builder = builder.responder_id(
        responder_encoding, responder_cert or issuer)
    if embedded:
        builder = builder.certificates(list(embedded))
    return builder.sign(signer_key or issuer_key, hashes.SHA256())


def _ocsp_b64(*args, **kwargs) -> str:
    return base64.b64encode(
        _ocsp(*args, **kwargs).public_bytes(serialization.Encoding.DER)
    ).decode()


def _crl(issuer_cert, issuer_key, *, entries=(), last_update=WINDOW_START,
         next_update=WINDOW_END, delta=False, indirect=False, crl_number=None,
         key_usage_test=False, signer_key=None):
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(last_update)
        .next_update(next_update)
    )
    if crl_number is not None:
        builder = builder.add_extension(
            x509.CRLNumber(crl_number), critical=False)
    if delta:
        builder = builder.add_extension(
            x509.DeltaCRLIndicator(crl_number or 1), critical=False)
    if indirect:
        builder = builder.add_extension(
            x509.IssuingDistributionPoint(
                full_name=None, relative_name=None,
                only_contains_user_certs=False,
                only_contains_ca_certs=False, only_some_reasons=None,
                indirect_crl=True, only_contains_attribute_certs=False),
            critical=False)
    for serial, date, *reason in entries:
        rb = (x509.RevokedCertificateBuilder()
              .serial_number(serial).revocation_date(date))
        if reason:
            rb = rb.add_extension(x509.CRLReason(reason[0]), critical=False)
        builder = builder.add_revoked_certificate(rb.build())
    return builder.sign(signer_key or issuer_key, hashes.SHA256())


@pytest.fixture
def pki():
    root_key = _key()
    root = _cert("Root CA", "Root CA", root_key, root_key, ca=True)
    inter_key = _key()
    inter = _cert("Intermediate CA", "Root CA", root_key, inter_key, ca=True)
    leaf_key = _key()
    leaf = _cert("api.example.com", "Intermediate CA", inter_key, leaf_key,
                 ca=False)
    return {
        "root": root, "root_key": root_key,
        "inter": inter, "inter_key": inter_key,
        "leaf": leaf, "leaf_key": leaf_key,
    }


def _bundle(pki):
    return [_pem(pki["leaf"]), _pem(pki["inter"]), _pem(pki["root"])]


def _review(pki, *, ocsps=None, crls=None, endpoints=None, trust_roots=None,
            check_time=CHECK_TIME, skew=300, bundle=None):
    payload = {
        "pem_certificates": bundle or _bundle(pki),
        "trust_roots": trust_roots or [_fp(pki["root"])],
        "endpoints": endpoints or [{
            "endpoint_id": "api.example.com",
            "target_leaf_fingerprint": _fp(pki["leaf"]),
        }],
        "ocsp_responses": ocsps or [],
        "crls": crls or [],
        "check_time": check_time,
        "max_skew_seconds": skew,
    }
    return client.post("/deployments/revocation-review", json=payload)


def _good_evidence(pki):
    """Full consistent-good evidence set: 2 OCSP + 2 CRL."""
    ocsps = [
        _ocsp_b64(pki["leaf"], pki["inter"], pki["inter_key"]),
        _ocsp_b64(pki["inter"], pki["root"], pki["root_key"]),
    ]
    crls = [
        _crl(pki["inter"], pki["inter_key"])
        .public_bytes(serialization.Encoding.PEM).decode(),
        base64.b64encode(
            _crl(pki["root"], pki["root_key"])
            .public_bytes(serialization.Encoding.DER)).decode(),
    ]
    return ocsps, crls


def _cert_result(body, role):
    ep = body["results"][0]
    return next(c for c in ep["certificates"] if c["role"] == role)


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_eligible_full_chain_ocsp_and_crl(pki):
    ocsps, crls = _good_evidence(pki)
    r = _review(pki, ocsps=ocsps, crls=crls)
    assert r.status_code == 200, r.text
    body = r.json()
    ep = body["results"][0]
    assert ep["eligible"] is True
    assert ep["reason"] == "ok"
    assert ep["chain"] == [_fp(pki["leaf"]), _fp(pki["inter"]),
                           _fp(pki["root"])]
    roles = [c["role"] for c in ep["certificates"]]
    assert roles == ["leaf", "intermediate", "trust_root"]
    for cert in ep["certificates"]:
        assert cert["eligible"] is True
    root_review = _cert_result(body, "trust_root")
    assert root_review["reason"] == "trust_root"
    assert root_review["evidence"] == []
    leaf = _cert_result(body, "leaf")
    kinds = sorted((e["kind"], e["source_index"]) for e in leaf["evidence"])
    assert kinds == [("crl", 0), ("ocsp", 0)]
    inter = _cert_result(body, "intermediate")
    assert sorted((e["kind"], e["source_index"]) for e in inter["evidence"]) == [
        ("crl", 1), ("ocsp", 1)]
    assert body["unattributed_evidence"] == []
    assert body["check_time"].startswith("2030-06-01")


def test_eligible_ocsp_only(pki):
    ocsps, _crls = _good_evidence(pki)
    r = _review(pki, ocsps=ocsps)
    assert r.status_code == 200, r.text
    assert r.json()["results"][0]["eligible"] is True


def test_eligible_crl_only(pki):
    _ocsps, crls = _good_evidence(pki)
    r = _review(pki, crls=crls)
    assert r.status_code == 200, r.text
    assert r.json()["results"][0]["eligible"] is True


def test_evidence_echoes_context_fields(pki):
    ocsps, crls = _good_evidence(pki)
    r = _review(pki, ocsps=ocsps, crls=crls)
    body = r.json()
    leaf = _cert_result(body, "leaf")
    ocsp_ev = next(e for e in leaf["evidence"] if e["kind"] == "ocsp")
    assert ocsp_ev["certificate_fingerprint"] == _fp(pki["leaf"])
    assert ocsp_ev["issuer_fingerprint"] == _fp(pki["inter"])
    assert ocsp_ev["certificate_status"] == "good"
    assert ocsp_ev["response_status"] == "successful"
    assert ocsp_ev["signer_type"] == "issuer"
    assert ocsp_ev["signer_fingerprint"] == _fp(pki["inter"])
    assert ocsp_ev["this_update"] is not None
    assert ocsp_ev["next_update"] is not None
    crl_ev = next(e for e in leaf["evidence"] if e["kind"] == "crl")
    assert crl_ev["issuer_fingerprint"] == _fp(pki["inter"])
    assert crl_ev["reason"] == "good"
    assert crl_ev["fresh"] is True
    assert crl_ev["revoked_serial_numbers"] == []
    assert crl_ev["covered_serial_numbers"] == []


def test_der_crl_and_pem_crl_both_accepted(pki):
    # First CRL as base64 DER, second as PEM (order swapped).
    der_leaf = base64.b64encode(
        _crl(pki["inter"], pki["inter_key"])
        .public_bytes(serialization.Encoding.DER)).decode()
    pem_root = _crl(pki["root"], pki["root_key"]) \
        .public_bytes(serialization.Encoding.PEM).decode()
    r = _review(pki, crls=[der_leaf, pem_root])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["results"][0]["eligible"] is True
    inter = _cert_result(body, "intermediate")
    assert any(e["kind"] == "crl" and e["source_index"] == 1
               for e in inter["evidence"])


def test_whitespace_in_ocsp_blob_tolerated(pki):
    ocsps, _crls = _good_evidence(pki)
    wrapped = "\n".join(ocsps[0][i:i + 64]
                        for i in range(0, len(ocsps[0]), 64))
    r = _review(pki, ocsps=[wrapped, ocsps[1]])
    assert r.status_code == 200, r.text
    assert r.json()["results"][0]["eligible"] is True


def test_multiple_endpoints_share_global_evidence_sorted(pki):
    endpoints = [
        {"endpoint_id": "zeta", "target_leaf_fingerprint": _fp(pki["leaf"])},
        {"endpoint_id": "alpha", "target_leaf_fingerprint": _fp(pki["leaf"])},
    ]
    ocsps, crls = _good_evidence(pki)
    r = _review(pki, ocsps=ocsps, crls=crls, endpoints=endpoints)
    assert r.status_code == 200, r.text
    body = r.json()
    assert [e["endpoint_id"] for e in body["results"]] == ["alpha", "zeta"]
    assert all(e["eligible"] for e in body["results"])


# ---------------------------------------------------------------------------
# Revoked evidence (fresh revoked always wins)
# ---------------------------------------------------------------------------


def test_fresh_revoked_ocsp_on_leaf(pki):
    revoked_at = datetime(2029, 6, 1)
    ocsps = [
        _ocsp_b64(pki["leaf"], pki["inter"], pki["inter_key"],
                  status=ocsp.OCSPCertStatus.REVOKED,
                  revocation_time=revoked_at,
                  revocation_reason=x509.ReasonFlags.key_compromise),
        _ocsp_b64(pki["inter"], pki["root"], pki["root_key"]),
    ]
    # A stale good CRL for the leaf must NOT rescue it: fresh revoked wins.
    stale_crl = _crl(pki["inter"], pki["inter_key"],
                     last_update=datetime(2020, 1, 1),
                     next_update=datetime(2021, 1, 1)) \
        .public_bytes(serialization.Encoding.PEM).decode()
    r = _review(pki, ocsps=ocsps, crls=[
        stale_crl,
        base64.b64encode(_crl(pki["root"], pki["root_key"])
                         .public_bytes(serialization.Encoding.DER)).decode(),
    ])
    assert r.status_code == 200, r.text
    body = r.json()
    ep = body["results"][0]
    assert ep["eligible"] is False
    assert ep["reason"] == "certificate_revoked"
    leaf = _cert_result(body, "leaf")
    assert leaf["reason"] == "certificate_revoked"
    assert leaf["revocation_reason"] == "key_compromise"
    assert leaf["revocation_time"].startswith("2029-06-01")


def test_fresh_revoked_crl_entry_on_intermediate(pki):
    # Root's CRL lists the intermediate as revoked (ca_compromise).
    rev_date = datetime(2030, 1, 15)
    root_crl = _crl(
        pki["root"], pki["root_key"],
        entries=[(pki["inter"].serial_number, rev_date,
                  x509.ReasonFlags.ca_compromise)])
    leaf_good_crl = _crl(pki["inter"], pki["inter_key"])
    r = _review(pki, ocsps=[
        _ocsp_b64(pki["leaf"], pki["inter"], pki["inter_key"]),
    ], crls=[
        leaf_good_crl.public_bytes(serialization.Encoding.PEM).decode(),
        base64.b64encode(root_crl.public_bytes(serialization.Encoding.DER))
        .decode(),
    ])
    assert r.status_code == 200, r.text
    body = r.json()
    ep = body["results"][0]
    assert ep["eligible"] is False
    assert ep["reason"] == "certificate_revoked"
    inter = _cert_result(body, "intermediate")
    assert inter["reason"] == "certificate_revoked"
    assert inter["revocation_reason"] == "ca_compromise"
    crl_ev = next(e for e in inter["evidence"] if e["kind"] == "crl")
    assert crl_ev["covered_serial_numbers"] == [
        format(pki["inter"].serial_number, "X")]
    assert crl_ev["revocation_reason"] == "ca_compromise"
    leaf = _cert_result(body, "leaf")
    # Leaf's own evidence remains good; the chain endpoint still fails on the
    # intermediate.
    assert leaf["reason"] == "ok"


def test_revocation_reason_defaults_none_when_crl_entry_omits_it(pki):
    root_crl = _crl(
        pki["root"], pki["root_key"],
        entries=[(pki["inter"].serial_number, datetime(2030, 1, 15))])
    r = _review(pki, crls=[
        _crl(pki["inter"], pki["inter_key"])
        .public_bytes(serialization.Encoding.PEM).decode(),
        base64.b64encode(root_crl.public_bytes(serialization.Encoding.DER))
        .decode(),
    ])
    body = r.json()
    inter = _cert_result(body, "intermediate")
    assert inter["reason"] == "certificate_revoked"
    assert inter["revocation_reason"] is None
    assert inter["revocation_time"] is not None


# ---------------------------------------------------------------------------
# Good/revoked conflict
# ---------------------------------------------------------------------------


def test_fresh_good_and_fresh_revoked_conflict(pki):
    ocsps = [
        _ocsp_b64(pki["leaf"], pki["inter"], pki["inter_key"],
                  status=ocsp.OCSPCertStatus.REVOKED,
                  revocation_time=datetime(2029, 6, 1)),
        _ocsp_b64(pki["inter"], pki["root"], pki["root_key"]),
    ]
    # Fresh good CRL from the same intermediate issuer.
    good_crl = _crl(pki["inter"], pki["inter_key"]) \
        .public_bytes(serialization.Encoding.PEM).decode()
    r = _review(pki, ocsps=ocsps, crls=[good_crl, base64.b64encode(
        _crl(pki["root"], pki["root_key"])
        .public_bytes(serialization.Encoding.DER)).decode()])
    assert r.status_code == 200, r.text
    body = r.json()
    ep = body["results"][0]
    assert ep["eligible"] is False
    assert ep["reason"] == "conflicting_evidence"
    leaf = _cert_result(body, "leaf")
    assert leaf["reason"] == "conflicting_evidence"
    reasons = {e["kind"]: e["reason"] for e in leaf["evidence"]}
    assert reasons == {"ocsp": "revoked", "crl": "good"}


def test_two_revoked_items_agree_no_conflict(pki):
    ocsps = [
        _ocsp_b64(pki["leaf"], pki["inter"], pki["inter_key"],
                  status=ocsp.OCSPCertStatus.REVOKED,
                  revocation_time=datetime(2029, 6, 1)),
        _ocsp_b64(pki["inter"], pki["root"], pki["root_key"]),
    ]
    rev_crl = _crl(pki["inter"], pki["inter_key"],
                   entries=[(pki["leaf"].serial_number, datetime(2029, 6, 1))])
    r = _review(pki, ocsps=ocsps, crls=[
        rev_crl.public_bytes(serialization.Encoding.PEM).decode(),
        base64.b64encode(_crl(pki["root"], pki["root_key"])
                         .public_bytes(serialization.Encoding.DER)).decode(),
    ])
    body = r.json()
    leaf = _cert_result(body, "leaf")
    assert leaf["reason"] == "certificate_revoked"


# ---------------------------------------------------------------------------
# Missing / stale evidence
# ---------------------------------------------------------------------------


def test_no_evidence_at_all_is_missing(pki):
    r = _review(pki)
    body = r.json()
    ep = body["results"][0]
    assert ep["eligible"] is False
    assert ep["reason"] == "evidence_missing"
    for role in ("leaf", "intermediate"):
        cert = _cert_result(body, role)
        assert cert["reason"] == "evidence_missing"
        assert cert["evidence"] == []


def test_leaf_covered_intermediate_missing(pki):
    r = _review(pki, ocsps=[
        _ocsp_b64(pki["leaf"], pki["inter"], pki["inter_key"])])
    body = r.json()
    ep = body["results"][0]
    assert ep["eligible"] is False
    assert ep["reason"] == "evidence_missing"
    assert _cert_result(body, "leaf")["reason"] == "ok"
    assert _cert_result(body, "intermediate")["reason"] == "evidence_missing"


def test_stale_ocsp_means_evidence_stale(pki):
    stale = _ocsp_b64(
        pki["leaf"], pki["inter"], pki["inter_key"],
        this_update=datetime(2020, 1, 1), next_update=datetime(2021, 1, 1))
    r = _review(pki, ocsps=[
        stale, _ocsp_b64(pki["inter"], pki["root"], pki["root_key"])],
        crls=[base64.b64encode(
            _crl(pki["root"], pki["root_key"])
            .public_bytes(serialization.Encoding.DER)).decode()])
    body = r.json()
    leaf = _cert_result(body, "leaf")
    assert leaf["eligible"] is False
    assert leaf["reason"] == "evidence_stale"
    assert leaf["evidence"][0]["reason"] == "stale"
    assert body["results"][0]["reason"] == "evidence_stale"


def test_stale_rescued_by_skew(pki):
    boundary = datetime(2030, 6, 1, 0, 0, 0)
    stale = _ocsp_b64(
        pki["leaf"], pki["inter"], pki["inter_key"],
        this_update=datetime(2024, 1, 1),
        next_update=boundary - timedelta(seconds=200))
    r = _review(pki, ocsps=[
        stale, _ocsp_b64(pki["inter"], pki["root"], pki["root_key"])],
        crls=[base64.b64encode(
            _crl(pki["root"], pki["root_key"])
            .public_bytes(serialization.Encoding.DER)).decode()])
    assert r.status_code == 200, r.text
    assert r.json()["results"][0]["eligible"] is True


def test_stale_crl_with_fresh_ocsp_still_eligible(pki):
    stale = _crl(pki["inter"], pki["inter_key"],
                 last_update=datetime(2020, 1, 1),
                 next_update=datetime(2021, 1, 1))
    r = _review(pki, ocsps=[
        _ocsp_b64(pki["leaf"], pki["inter"], pki["inter_key"]),
        _ocsp_b64(pki["inter"], pki["root"], pki["root_key"]),
    ], crls=[
        stale.public_bytes(serialization.Encoding.PEM).decode(),
        base64.b64encode(_crl(pki["root"], pki["root_key"])
                         .public_bytes(serialization.Encoding.DER)).decode(),
    ])
    body = r.json()
    assert body["results"][0]["eligible"] is True
    leaf = _cert_result(body, "leaf")
    crl_ev = next(e for e in leaf["evidence"] if e["kind"] == "crl")
    assert crl_ev["reason"] == "stale"
    assert crl_ev["fresh"] is False


def test_not_yet_valid_crl(pki):
    future_crl = _crl(pki["inter"], pki["inter_key"],
                      last_update=datetime(2031, 1, 1),
                      next_update=datetime(2036, 1, 1))
    r = _review(pki, crls=[
        future_crl.public_bytes(serialization.Encoding.PEM).decode(),
        base64.b64encode(_crl(pki["root"], pki["root_key"])
                         .public_bytes(serialization.Encoding.DER)).decode(),
    ])
    body = r.json()
    leaf = _cert_result(body, "leaf")
    assert leaf["reason"] == "evidence_stale"
    assert leaf["evidence"][0]["reason"] == "not_yet_valid"


def test_crl_without_next_update_is_unbounded(pki):
    # cryptography's builder requires nextUpdate; hand-assemble a v1 TBSCertList
    # SEQUENCE carrying only the optional signature algorithm, issuer and
    # thisUpdate, then sign it with the intermediate key.
    def _tlv(tag, content):
        n = len(content)
        length = (bytes([n]) if n < 0x80
                  else bytes([0x80 | (n.bit_length() + 7) // 8])
                  + n.to_bytes((n.bit_length() + 7) // 8, "big"))
        return bytes([tag]) + length + content

    alg = _tlv(0x30, bytes.fromhex("06082a8648ce3d040302"))  # ecdsa-with-SHA256
    issuer = pki["inter"].subject.public_bytes()
    this_update = _tlv(0x17, b"240101000000Z")  # UTCTime 2024-01-01
    tbs = _tlv(0x30, alg + issuer + this_update)
    signature = pki["inter_key"].sign(tbs, ec.ECDSA(hashes.SHA256()))
    crl_der = _tlv(0x30, tbs + alg + _tlv(0x03, b"\x00" + signature))
    r = _review(pki, crls=[
        base64.b64encode(crl_der).decode(),
        base64.b64encode(_crl(pki["root"], pki["root_key"])
                         .public_bytes(serialization.Encoding.DER)).decode(),
    ])
    body = r.json()
    leaf = _cert_result(body, "leaf")
    assert leaf["reason"] == "evidence_stale"
    assert leaf["evidence"][0]["reason"] == "next_update_missing"


def test_ocsp_unknown_is_not_good_evidence(pki):
    unknown = _ocsp_b64(pki["leaf"], pki["inter"], pki["inter_key"],
                        status=ocsp.OCSPCertStatus.UNKNOWN)
    r = _review(pki, ocsps=[
        unknown, _ocsp_b64(pki["inter"], pki["root"], pki["root_key"])],
        crls=[base64.b64encode(
            _crl(pki["root"], pki["root_key"])
            .public_bytes(serialization.Encoding.DER)).decode()])
    body = r.json()
    leaf = _cert_result(body, "leaf")
    assert leaf["reason"] == "evidence_missing"
    assert leaf["evidence"][0]["reason"] == "certificate_unknown"


# ---------------------------------------------------------------------------
# OCSP authentication / binding (mirrors the single-leaf precheck)
# ---------------------------------------------------------------------------


def test_ocsp_signature_invalid(pki):
    response = _ocsp(pki["leaf"], pki["inter"], pki["inter_key"])
    der = bytearray(response.public_bytes(serialization.Encoding.DER))
    der[-1] ^= 0x01
    bad = base64.b64encode(bytes(der)).decode()
    r = _review(pki, ocsps=[
        bad, _ocsp_b64(pki["inter"], pki["root"], pki["root_key"])],
        crls=[base64.b64encode(
            _crl(pki["root"], pki["root_key"])
            .public_bytes(serialization.Encoding.DER)).decode()])
    body = r.json()
    leaf = _cert_result(body, "leaf")
    assert leaf["reason"] == "evidence_missing"
    assert leaf["evidence"][0]["reason"] == "signature_invalid"


def test_ocsp_cert_id_mismatch_is_unattributed(pki):
    # Second root in the bundle and a response naming it as issuer: the leaf
    # has no verified issuance edge from that root, so the CertID binds to
    # nothing and the response is unattributed.
    other_root_key = _key()
    other_root = _cert("Other Root CA", "Other Root CA", other_root_key,
                       other_root_key, ca=True)
    response = _ocsp_b64(pki["leaf"], other_root, other_root_key)
    bundle = _bundle(pki) + [_pem(other_root)]
    r = _review(pki, ocsps=[response], bundle=bundle)
    body = r.json()
    unatt = body["unattributed_evidence"]
    assert len(unatt) == 1
    assert unatt[0]["kind"] == "ocsp"
    assert unatt[0]["reason"] == "cert_id_mismatch"
    leaf = _cert_result(body, "leaf")
    assert leaf["evidence"] == []


def test_ocsp_delegated_responder_accepted(pki):
    resp_key = _key()
    responder = _cert("OCSP Responder", "Intermediate CA", pki["inter_key"],
                      resp_key, ca=False, eku_ocsp_signing=True)
    response = _ocsp_b64(
        pki["leaf"], pki["inter"], pki["inter_key"],
        signer_key=resp_key, responder_cert=responder,
        responder_encoding=ocsp.OCSPResponderEncoding.HASH,
        embedded=[responder])
    r = _review(pki, ocsps=[
        response, _ocsp_b64(pki["inter"], pki["root"], pki["root_key"])],
        crls=[base64.b64encode(
            _crl(pki["root"], pki["root_key"])
            .public_bytes(serialization.Encoding.DER)).decode()])
    assert r.status_code == 200, r.text
    body = r.json()
    leaf = _cert_result(body, "leaf")
    ev = leaf["evidence"][0]
    assert ev["reason"] == "good"
    assert ev["signer_type"] == "responder_certificate"
    assert ev["signer_fingerprint"] == _fp(responder)


def test_ocsp_responder_not_found(pki):
    # Embedded cert missing: responderID names something not present.
    stray_key = _key()
    stray = _cert("OCSP Responder", "Intermediate CA", pki["inter_key"],
                  stray_key, ca=False, eku_ocsp_signing=True)
    response = _ocsp_b64(
        pki["leaf"], pki["inter"], pki["inter_key"],
        signer_key=stray_key, responder_cert=stray)  # not embedded
    r = _review(pki, ocsps=[
        response, _ocsp_b64(pki["inter"], pki["root"], pki["root_key"])],
        crls=[base64.b64encode(
            _crl(pki["root"], pki["root_key"])
            .public_bytes(serialization.Encoding.DER)).decode()])
    body = r.json()
    leaf = _cert_result(body, "leaf")
    assert leaf["evidence"][0]["reason"] == "responder_not_found"
    assert leaf["reason"] == "evidence_missing"


def test_malformed_ocsp_is_unattributed(pki):
    r = _review(pki, ocsps=["!!!not-base64!!!"])
    body = r.json()
    unatt = body["unattributed_evidence"]
    assert len(unatt) == 1
    assert unatt[0]["kind"] == "ocsp"
    assert unatt[0]["reason"] == "invalid_ocsp_response"


def test_unsuccessful_ocsp_response(pki):
    built = ocsp.OCSPResponseBuilder.build_unsuccessful(
        ocsp.OCSPResponseStatus.UNAUTHORIZED)
    b64 = base64.b64encode(
        built.public_bytes(serialization.Encoding.DER)).decode()
    r = _review(pki, ocsps=[b64])
    body = r.json()
    unatt = body["unattributed_evidence"]
    assert unatt[0]["reason"] == "response_not_successful"


# ---------------------------------------------------------------------------
# CRL signer binding
# ---------------------------------------------------------------------------


def test_crl_signer_not_found(pki):
    stranger_key = _key()
    stranger = _cert("Stranger CA", "Stranger CA", stranger_key,
                     stranger_key, ca=True)
    # CRL claims an issuer name absent from the bundle.
    crl_obj = _crl(stranger, stranger_key)
    r = _review(pki, crls=[
        crl_obj.public_bytes(serialization.Encoding.PEM).decode()])
    body = r.json()
    unatt = body["unattributed_evidence"]
    assert unatt[0]["reason"] == "signer_not_found"
    assert unatt[0]["issuer_fingerprint"] is None


def test_crl_signature_invalid_when_dn_matches(pki):
    # Subject matches the intermediate but the CRL is signed by another key.
    other_key = _key()
    other = _cert("Intermediate CA", "Root CA", pki["root_key"], other_key,
                  ca=True)
    crl_obj = _crl(other, other_key)  # DN "Intermediate CA", wrong key
    bundle = _bundle(pki)
    r = _review(pki, crls=[
        crl_obj.public_bytes(serialization.Encoding.PEM).decode()],
        bundle=bundle)
    body = r.json()
    unatt = body["unattributed_evidence"]
    assert unatt[0]["reason"] == "signature_invalid"


def test_crl_same_key_reissued_ca_copies_bind_as_one_issuer(pki):
    # The same CA key wrapped in a second DER certificate (re-issued copy,
    # same subject DN) is cryptographically one issuer: the CRL binds to it,
    # and attaches to the chain position via the fingerprint actually used by
    # the resolved chain. Such copies cannot form a second trust path unless
    # they also terminate at a second trust root; here the copy is dangling,
    # which the normalizer's path search tolerates because it never reaches a
    # root -- so instead exercise the bind with a copy issued by the same
    # root (same subject, same key, different serial/validity): the leaf still
    # has one path, and the CRL is usable rather than rejected.
    reissued = _cert("Intermediate CA", "Root CA", pki["root_key"],
                     pki["inter_key"], ca=True,
                     not_before=datetime(2025, 1, 1))
    crl_obj = _crl(pki["inter"], pki["inter_key"])
    # The bundle containing the reissued same-key copy actually gives two
    # signature edges, but both wrappers end at the same single trust root via
    # one wrapper; verify the service's treatment directly against the
    # evaluator when the chain wrapper is the original.
    from app.normalize import _load_pem_bundle
    certs, _issues = _load_pem_bundle(
        _bundle(pki) + [_pem(reissued)])
    from app.revocation import _evaluate_crl
    from datetime import timedelta
    record = _evaluate_crl(
        0, crl_obj.public_bytes(serialization.Encoding.PEM).decode(),
        certs, datetime(2030, 6, 1, tzinfo=timezone.utc),
        timedelta(seconds=300), 300)
    assert record.reason == "good"
    # Bound to exactly one fingerprint: the sort-stable first matching cert.
    assert record.signer_fp in {_fp(pki["inter"]), _fp(reissued)}


def test_crl_signer_missing_crl_sign_key_usage(pki):
    ku = x509.KeyUsage(
        digital_signature=False, content_commitment=False,
        key_encipherment=False, data_encipherment=False,
        key_agreement=False, key_cert_sign=True, crl_sign=False,
        encipher_only=False, decipher_only=False)
    root_key = pki["root_key"]
    restricted_inter = _cert("Intermediate CA", "Root CA", root_key,
                             pki["inter_key"], ca=True, key_usage=ku)
    crl_obj = _crl(restricted_inter, pki["inter_key"])
    # Use a bundle where the intermediate is the restricted one but the leaf
    # is still verifiably issued by its key (same key).
    bundle = [_pem(pki["leaf"]), _pem(restricted_inter), _pem(pki["root"])]
    r = _review(pki, crls=[
        crl_obj.public_bytes(serialization.Encoding.PEM).decode()],
        bundle=bundle)
    body = r.json()
    unatt = body["unattributed_evidence"]
    assert unatt[0]["reason"] == "signer_not_ca"


def test_delta_crl_unsupported_and_unattributed(pki):
    delta = _crl(pki["inter"], pki["inter_key"], delta=True, crl_number=2)
    r = _review(pki, ocsps=[
        _ocsp_b64(pki["leaf"], pki["inter"], pki["inter_key"]),
        _ocsp_b64(pki["inter"], pki["root"], pki["root_key"])],
        crls=[
        delta.public_bytes(serialization.Encoding.PEM).decode(),
        base64.b64encode(_crl(pki["root"], pki["root_key"])
                         .public_bytes(serialization.Encoding.DER)).decode(),
    ])
    body = r.json()
    unatt = body["unattributed_evidence"]
    assert len(unatt) == 1
    assert unatt[0]["reason"] == "indirect_or_delta_crl"
    assert unatt[0]["is_delta"] is True
    # Endpoint still eligible on OCSP evidence alone.
    assert body["results"][0]["eligible"] is True


def test_indirect_crl_unsupported(pki):
    indirect = _crl(pki["inter"], pki["inter_key"], indirect=True)
    r = _review(pki, ocsps=[
        _ocsp_b64(pki["leaf"], pki["inter"], pki["inter_key"]),
        _ocsp_b64(pki["inter"], pki["root"], pki["root_key"])],
        crls=[
        indirect.public_bytes(serialization.Encoding.PEM).decode(),
        base64.b64encode(_crl(pki["root"], pki["root_key"])
                         .public_bytes(serialization.Encoding.DER)).decode(),
    ])
    body = r.json()
    unatt = body["unattributed_evidence"]
    assert unatt[0]["reason"] == "indirect_or_delta_crl"
    assert unatt[0]["is_indirect"] is True


def test_invalid_crl_blob_is_unattributed(pki):
    r = _review(pki, crls=["not a crl at all"])
    body = r.json()
    unatt = body["unattributed_evidence"]
    assert unatt[0]["kind"] == "crl"
    assert unatt[0]["reason"] == "invalid_crl"


def test_two_pem_crl_blocks_in_one_element_rejected(pki):
    good = _crl(pki["inter"], pki["inter_key"]) \
        .public_bytes(serialization.Encoding.PEM).decode()
    r = _review(pki, crls=[good + good])
    body = r.json()
    assert body["unattributed_evidence"][0]["reason"] == "invalid_crl"


def test_crl_serial_numbers_are_hex(pki):
    serial = 0xABCDEF123
    rev_cert_key = _key()
    rev_cert = _cert("revoked.example.com", "Intermediate CA",
                     pki["inter_key"], rev_cert_key, ca=False, serial=serial)
    crl_obj = _crl(pki["inter"], pki["inter_key"],
                   entries=[(serial, datetime(2030, 1, 1))])
    r = _review(pki, ocsps=[
        _ocsp_b64(pki["leaf"], pki["inter"], pki["inter_key"]),
        _ocsp_b64(pki["inter"], pki["root"], pki["root_key"])],
        crls=[
        crl_obj.public_bytes(serialization.Encoding.PEM).decode(),
        base64.b64encode(_crl(pki["root"], pki["root_key"])
                         .public_bytes(serialization.Encoding.DER)).decode(),
    ])
    body = r.json()
    leaf = _cert_result(body, "leaf")
    crl_ev = next(e for e in leaf["evidence"] if e["kind"] == "crl")
    # The revoked serial belongs to a DIFFERENT child of the same issuer: it
    # stays in revoked_serial_numbers but is not covered for this leaf.
    assert crl_ev["revoked_serial_numbers"] == ["ABCDEF123"]
    assert crl_ev["covered_serial_numbers"] == []
    assert leaf["reason"] == "ok"


# ---------------------------------------------------------------------------
# Chain reconstruction (422 family, same as precheck)
# ---------------------------------------------------------------------------


def test_unknown_fingerprint_422(pki):
    r = _review(pki, endpoints=[{
        "endpoint_id": "x", "target_leaf_fingerprint": "0" * 64}])
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "unknown_fingerprint"


def test_invalid_fingerprint_format_422(pki):
    r = _review(pki, endpoints=[{
        "endpoint_id": "x", "target_leaf_fingerprint": "zz" * 32}])
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "invalid_fingerprint"


def test_invalid_pem_422(pki):
    r = _review(pki, bundle=["not a pem block"])
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error"] == "invalid_pem"
    assert detail["pem_issues"][0]["index"] == 0


def test_no_trust_path_422(pki):
    # Trust root declared but absent from the bundle and not reachable:
    # include it in trust_roots while omitting it from the PEM bag is
    # unknown_fingerprint; to reach no_trust_path the root cert must be in
    # the bundle yet fail to terminate (leaf/inter only provided, plus an
    # unrelated self-signed root that is declared as the anchor).
    other_root_key = _key()
    other_root = _cert("Other Root CA", "Other Root CA", other_root_key,
                       other_root_key, ca=True)
    bundle = [_pem(pki["leaf"]), _pem(pki["inter"]), _pem(other_root)]
    r = _review(pki, bundle=bundle, trust_roots=[_fp(other_root)])
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error"] == "no_trust_path"
    assert detail["chain_issues"][0]["reason"] == "no_trust_path"


def test_ambiguous_chain_422(pki):
    # Cross-sign: a second self-signed root also certifies the intermediate's
    # key under a distinct certificate, creating two verified paths.
    root2_key = _key()
    root2 = _cert("Root Two CA", "Root Two CA", root2_key, root2_key, ca=True)
    inter2 = _cert("Intermediate CA", "Root Two CA", root2_key,
                   pki["inter_key"], ca=True)
    bundle = _bundle(pki) + [_pem(inter2), _pem(root2)]
    r = _review(pki, bundle=bundle,
                trust_roots=[_fp(pki["root"]), _fp(root2)])
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "ambiguous_chain"


def test_duplicate_endpoint_ids_422(pki):
    r = _review(pki, endpoints=[
        {"endpoint_id": "same", "target_leaf_fingerprint": _fp(pki["leaf"])},
        {"endpoint_id": "same", "target_leaf_fingerprint": _fp(pki["leaf"])},
    ])
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "invalid_request"


def test_skew_capped_at_300(pki):
    payload = {
        "pem_certificates": _bundle(pki),
        "trust_roots": [_fp(pki["root"])],
        "endpoints": [{"endpoint_id": "x",
                       "target_leaf_fingerprint": _fp(pki["leaf"])}],
        "check_time": CHECK_TIME,
        "max_skew_seconds": 301,
    }
    r = client.post("/deployments/revocation-review", json=payload)
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Stable output shape
# ---------------------------------------------------------------------------


def test_evidence_sorted_by_kind_then_source(pki):
    # Deliberately shuffle: CRL first/second and OCSP order.
    ocsps = [
        _ocsp_b64(pki["inter"], pki["root"], pki["root_key"]),
        _ocsp_b64(pki["leaf"], pki["inter"], pki["inter_key"]),
    ]
    crls = [
        base64.b64encode(_crl(pki["root"], pki["root_key"])
                         .public_bytes(serialization.Encoding.DER)).decode(),
        _crl(pki["inter"], pki["inter_key"])
        .public_bytes(serialization.Encoding.PEM).decode(),
    ]
    r = _review(pki, ocsps=ocsps, crls=crls)
    body = r.json()
    leaf = _cert_result(body, "leaf")
    # Source indices are preserved as submitted; ordering is crl before ocsp.
    assert [(e["kind"], e["source_index"]) for e in leaf["evidence"]] == [
        ("crl", 1), ("ocsp", 1)]
    inter = _cert_result(body, "intermediate")
    assert [(e["kind"], e["source_index"]) for e in inter["evidence"]] == [
        ("crl", 0), ("ocsp", 0)]


def test_ocsp_produced_at_in_future_is_stale(pki):
    # producedAt is stamped "now"; a check_time far in the past puts it in
    # the future beyond the skew allowance.
    r = _review(pki, ocsps=[
        _ocsp_b64(pki["leaf"], pki["inter"], pki["inter_key"]),
        _ocsp_b64(pki["inter"], pki["root"], pki["root_key"]),
    ], crls=[base64.b64encode(
        _crl(pki["root"], pki["root_key"])
        .public_bytes(serialization.Encoding.DER)).decode()],
        check_time="2000-01-01T00:00:00Z", skew=0)
    body = r.json()
    leaf = _cert_result(body, "leaf")
    assert leaf["reason"] == "evidence_stale"
    assert leaf["evidence"][0]["reason"] == "produced_at_in_future"


def test_single_cert_chain_reviews_only_leaf(pki):
    # Leaf issued directly by the trust root (no intermediate).
    direct_key = _key()
    direct = _cert("direct.example.com", "Root CA", pki["root_key"],
                   direct_key, ca=False)
    bundle = [_pem(direct), _pem(pki["root"])]
    ocsps = [_ocsp_b64(direct, pki["root"], pki["root_key"])]
    crls = [base64.b64encode(
        _crl(pki["root"], pki["root_key"])
        .public_bytes(serialization.Encoding.DER)).decode()]
    r = _review(pki, ocsps=ocsps, crls=crls, bundle=bundle,
                endpoints=[{"endpoint_id": "direct",
                            "target_leaf_fingerprint": _fp(direct)}])
    assert r.status_code == 200, r.text
    body = r.json()
    ep = body["results"][0]
    assert ep["eligible"] is True
    assert [c["role"] for c in ep["certificates"]] == ["leaf", "trust_root"]
    assert _cert_result(body, "leaf")["reason"] == "ok"


def test_rsa_pki_crl_signature_verified():
    from cryptography.hazmat.primitives.asymmetric import rsa as rsa_mod
    root_key = rsa_mod.generate_private_key(public_exponent=65537, key_size=2048)
    root = _cert("RSA Root", "RSA Root", root_key, root_key, ca=True)
    leaf_key = rsa_mod.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = _cert("rsa.example.com", "RSA Root", root_key, leaf_key, ca=False)
    ocsps = [_ocsp_b64(leaf, root, root_key)]
    crls = [base64.b64encode(
        _crl(root, root_key).public_bytes(serialization.Encoding.DER)).decode()]
    r = _review(pki, ocsps=ocsps, crls=crls,
                bundle=[_pem(leaf), _pem(root)],
                trust_roots=[_fp(root)],
                endpoints=[{"endpoint_id": "rsa",
                            "target_leaf_fingerprint": _fp(leaf)}])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["results"][0]["eligible"] is True


def test_evidence_attached_even_when_not_consumed_for_status(pki):
    # A fresh good OCSP makes the leaf eligible; a fresh CRL from the same
    # issuer that revokes a *different* serial is still attached and shows the
    # revoked serial without covering this leaf.
    other_key = _key()
    other = _cert("other.example.com", "Intermediate CA", pki["inter_key"],
                  other_key, ca=False)
    rev_crl = _crl(pki["inter"], pki["inter_key"],
                   entries=[(other.serial_number, datetime(2030, 1, 1))])
    r = _review(pki, ocsps=[
        _ocsp_b64(pki["leaf"], pki["inter"], pki["inter_key"]),
        _ocsp_b64(pki["inter"], pki["root"], pki["root_key"]),
    ], crls=[
        rev_crl.public_bytes(serialization.Encoding.PEM).decode(),
        base64.b64encode(_crl(pki["root"], pki["root_key"])
                         .public_bytes(serialization.Encoding.DER)).decode(),
    ], bundle=_bundle(pki) + [_pem(other)])
    body = r.json()
    leaf = _cert_result(body, "leaf")
    # The CRL revokes only `other`; for the reviewed leaf it is fresh *good*
    # evidence (serial not listed), so the leaf stays eligible.
    assert leaf["reason"] == "ok"
    crl_ev = next(e for e in leaf["evidence"] if e["kind"] == "crl")
    assert crl_ev["revoked_serial_numbers"] == [
        format(other.serial_number, "X")]
    assert crl_ev["covered_serial_numbers"] == []
    assert crl_ev["reason"] == "good"


def test_serial_number_echo(pki):
    r = _review(pki)
    body = r.json()
    leaf = _cert_result(body, "leaf")
    assert leaf["serial_number"] == format(pki["leaf"].serial_number, "X")
    assert leaf["issuer_fingerprint"] == _fp(pki["inter"])
