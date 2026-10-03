#!/usr/bin/env python3
"""Regenerate examples/revocation_review_request.json from fresh PKI material.

The bundle is a two-tier PKI plus two endpoint leaves:

    Root CA (self-signed) -> Intermediate CA -> api.example.com     (leaf 1)
                                           \\-> billing.example.com (leaf 2)

The submitted offline evidence is evaluated at a fixed check_time
(2030-01-01) against a wide freshness window (2024 -> 2035), so the example
keeps its verdicts for years no matter when it is regenerated:

* OCSP: a fresh issuer-signed good response for api.example.com and one for
  the intermediate CA (billing.example.com deliberately gets no OCSP).
* CRLs: a fresh PEM CRL from the intermediate CA that revokes
  billing.example.com, a fresh Base64-DER (empty) CRL from the root, and a
  delta CRL that the service refuses to evaluate (reported under
  unattributed_evidence as indirect_or_delta_crl).

Result shape demonstrated:

* api.example.com: fresh good OCSP + a fresh CRL that does not list it ->
  every non-anchor cert is consistently good -> eligible: true (its chain is
  ready to hand to /plans);
* billing.example.com: the only status evidence for its leaf is the fresh
  intermediate CRL entry -> certificate_revoked -> eligible: false.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

NOT_BEFORE = datetime(2024, 1, 1, tzinfo=timezone.utc)
NOT_AFTER = datetime(2035, 1, 1, tzinfo=timezone.utc)
THIS_UPDATE = datetime(2024, 1, 1)
NEXT_UPDATE = datetime(2035, 1, 1)
CHECK_TIME = "2030-01-01T00:00:00Z"
REVOKED_AT = datetime(2029, 6, 15)


def dn(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def issue(subject_cn, issuer_name, issuer_key, subject_key, *, is_ca):
    return (
        x509.CertificateBuilder()
        .subject_name(dn(subject_cn))
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None),
                       critical=True)
        .sign(issuer_key, hashes.SHA256())
    )


def pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def fingerprint(cert: x509.Certificate) -> str:
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()


def good_ocsp(cert_, issuer, issuer_key) -> str:
    response = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=cert_, issuer=issuer, algorithm=hashes.SHA1(),
            cert_status=ocsp.OCSPCertStatus.GOOD,
            this_update=THIS_UPDATE, next_update=NEXT_UPDATE,
            revocation_time=None, revocation_reason=None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.NAME, issuer)
        .sign(issuer_key, hashes.SHA256())
    )
    return base64.b64encode(
        response.public_bytes(serialization.Encoding.DER)
    ).decode()


def crl(issuer_cert, issuer_key, *, revoked_serials=(), delta=False) -> str:
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(THIS_UPDATE)
        .next_update(NEXT_UPDATE)
        .add_extension(x509.CRLNumber(2 if delta else 1), critical=False)
    )
    if delta:
        # id-ce-deltaCRLIndicator referencing base CRL number 1.
        builder = builder.add_extension(
            x509.DeltaCRLIndicator(1), critical=False)
    for serial in revoked_serials:
        entry = (
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(REVOKED_AT)
            .add_extension(
                x509.CRLReason(x509.ReasonFlags.key_compromise),
                critical=False,
            )
            .build()
        )
        builder = builder.add_revoked_certificate(entry)
    crl_obj = builder.sign(issuer_key, hashes.SHA256())
    return crl_obj.public_bytes(serialization.Encoding.PEM).decode()


def der_b64_crl(issuer_cert, issuer_key, **kwargs) -> str:
    text = crl(issuer_cert, issuer_key, **kwargs)
    return base64.b64encode(
        x509.load_pem_x509_crl(text.encode())
        .public_bytes(serialization.Encoding.DER)
    ).decode()


def main() -> None:
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = issue("Example Root CA", dn("Example Root CA"), root_key,
                 root_key, is_ca=True)
    inter_key = ec.generate_private_key(ec.SECP256R1())
    inter = issue("Example Intermediate CA", dn("Example Root CA"), root_key,
                  inter_key, is_ca=True)
    api_key = ec.generate_private_key(ec.SECP256R1())
    api_leaf = issue("api.example.com", dn("Example Intermediate CA"),
                     inter_key, api_key, is_ca=False)
    billing_key = ec.generate_private_key(ec.SECP256R1())
    billing_leaf = issue("billing.example.com", dn("Example Intermediate CA"),
                         inter_key, billing_key, is_ca=False)

    payload = {
        "pem_certificates": [
            pem(api_leaf), pem(billing_leaf), pem(inter), pem(root),
        ],
        "trust_roots": [fingerprint(root)],
        "endpoints": [
            {"endpoint_id": "api.example.com",
             "target_leaf_fingerprint": fingerprint(api_leaf)},
            {"endpoint_id": "billing.example.com",
             "target_leaf_fingerprint": fingerprint(billing_leaf)},
        ],
        "ocsp_responses": [
            good_ocsp(api_leaf, inter, inter_key),
            good_ocsp(inter, root, root_key),
        ],
        "crls": [
            # Intermediate CRL (PEM): revokes the billing leaf. The api leaf
            # is not listed, so for it this is fresh good evidence.
            crl(inter, inter_key, revoked_serials=[billing_leaf.serial_number]),
            # Empty root CRL supplied as Base64 DER (format is caller's choice).
            der_b64_crl(root, root_key),
            # A delta CRL: never evaluated, reported as unattributed evidence.
            crl(inter, inter_key, delta=True),
        ],
        "check_time": CHECK_TIME,
        "max_skew_seconds": 300,
    }

    out = Path(__file__).with_name("revocation_review_request.json")
    out.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"wrote {out}")
    print(f"  api leaf fingerprint:     {fingerprint(api_leaf)}")
    print(f"  billing leaf fingerprint: {fingerprint(billing_leaf)} (revoked)")
    print(f"  intermediate fingerprint: {fingerprint(inter)}")
    print(f"  root fingerprint:         {fingerprint(root)}")


if __name__ == "__main__":
    main()
