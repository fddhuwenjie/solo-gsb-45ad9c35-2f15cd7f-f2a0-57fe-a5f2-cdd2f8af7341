#!/usr/bin/env python3
"""Regenerate examples/ocsp_precheck_request.json from fresh PKI material.

The scenario: a leaf (api.example.com) issued by a root CA, plus a delegated
OCSP responder certificate (issued by the same root, carrying the
id-kp-OCSPSigning EKU). The stapled response is signed by the responder key,
names it by key hash, and embeds the responder certificate:

    Root CA (self-signed) -> api.example.com (leaf)
                          -> OCSP Responder (id-kp-OCSPSigning)

The response window (thisUpdate 2024 -> nextUpdate 2035) and the fixed
check_time (2030-01-01) keep the example eligible for years no matter when
it is regenerated (producedAt is stamped at generation time).
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

NOT_BEFORE = datetime(2024, 1, 1, tzinfo=timezone.utc)
NOT_AFTER = datetime(2035, 1, 1, tzinfo=timezone.utc)
THIS_UPDATE = datetime(2024, 1, 1)
NEXT_UPDATE = datetime(2035, 1, 1)
CHECK_TIME = "2030-01-01T00:00:00Z"


def dn(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def issue(subject_cn, issuer_name, issuer_key, subject_key, *, is_ca,
          ocsp_signing=False):
    builder = (
        x509.CertificateBuilder()
        .subject_name(dn(subject_cn))
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None),
                       critical=True)
    )
    if ocsp_signing:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


def pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def fingerprint(cert: x509.Certificate) -> str:
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()


def main() -> None:
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = issue("Example Root CA", dn("Example Root CA"), root_key, root_key,
                 is_ca=True)
    leaf = issue(
        "api.example.com", dn("Example Root CA"), root_key,
        ec.generate_private_key(ec.SECP256R1()), is_ca=False,
    )
    responder_key = ec.generate_private_key(ec.SECP256R1())
    responder = issue(
        "Example OCSP Responder", dn("Example Root CA"), root_key,
        responder_key, is_ca=False, ocsp_signing=True,
    )

    response = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=leaf,
            issuer=root,
            algorithm=hashes.SHA1(),
            cert_status=ocsp.OCSPCertStatus.GOOD,
            this_update=THIS_UPDATE,
            next_update=NEXT_UPDATE,
            revocation_time=None,
            revocation_reason=None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.HASH, responder)
        .certificates([responder])
        .sign(responder_key, hashes.SHA256())
    )
    response_b64 = base64.b64encode(
        response.public_bytes(serialization.Encoding.DER)
    ).decode()

    payload = {
        "pem_certificates": [pem(leaf), pem(responder), pem(root)],
        "leaf_fingerprint": fingerprint(leaf),
        "ocsp_response": response_b64,
        "check_time": CHECK_TIME,
        "max_skew_seconds": 300,
    }

    out = Path(__file__).with_name("ocsp_precheck_request.json")
    out.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"wrote {out}")
    print(f"  leaf fingerprint: {fingerprint(leaf)}")
    print(f"  root fingerprint: {fingerprint(root)}")


if __name__ == "__main__":
    main()
