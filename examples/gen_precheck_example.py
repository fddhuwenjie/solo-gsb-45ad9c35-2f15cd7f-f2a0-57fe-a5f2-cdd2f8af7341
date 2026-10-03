#!/usr/bin/env python3
"""Regenerate examples/precheck_request.json from freshly built PKI material.

The example mirrors the normalize example (old root -> new root rotation)
but adds a name-constrained intermediate on the target chain:

    Old Root (self-signed) -> api.example.com (current leaf)
    New Root (self-signed) -> New Intermediate (permitted: .example.com,
                                10.0.0.0/8; excluded: legacy.example.com)
                           -> api.example.com + 10.0.0.7 (target leaf)

Two endpoints are declared: one eligible (claims inside the SANs and the
constraints) and one ineligible (claims a name no SAN covers).
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

NOT_BEFORE = datetime(2024, 1, 1, tzinfo=timezone.utc)
NOT_AFTER = datetime(2035, 1, 1, tzinfo=timezone.utc)


def dn(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def issue(subject_cn, issuer_name, issuer_key, subject_key, *, is_ca,
          name_constraints=None, sans=None):
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
    if name_constraints is not None:
        builder = builder.add_extension(name_constraints, critical=True)
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(sans), critical=False
        )
    return builder.sign(issuer_key, hashes.SHA256())


def pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def fingerprint(cert: x509.Certificate) -> str:
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()


def main() -> None:
    old_root_key = ec.generate_private_key(ec.SECP256R1())
    old_root = issue("Old Root CA", dn("Old Root CA"), old_root_key,
                     old_root_key, is_ca=True)
    leaf_old = issue(
        "api.example.com", dn("Old Root CA"), old_root_key,
        ec.generate_private_key(ec.SECP256R1()), is_ca=False,
        sans=[x509.DNSName("api.example.com")],
    )

    new_root_key = ec.generate_private_key(ec.SECP256R1())
    new_root = issue("New Root CA", dn("New Root CA"), new_root_key,
                     new_root_key, is_ca=True)
    inter_key = ec.generate_private_key(ec.SECP256R1())
    inter = issue(
        "New Intermediate CA", dn("New Root CA"), new_root_key, inter_key,
        is_ca=True,
        name_constraints=x509.NameConstraints(
            permitted_subtrees=[
                x509.DNSName(".example.com"),
                x509.IPAddress(ipaddress.ip_network("10.0.0.0/8")),
            ],
            excluded_subtrees=[x509.DNSName("legacy.example.com")],
        ),
    )
    leaf_new = issue(
        "api.example.com", dn("New Intermediate CA"), inter_key,
        ec.generate_private_key(ec.SECP256R1()), is_ca=False,
        sans=[x509.DNSName("api.example.com"),
              x509.DNSName("*.svc.example.com"),
              x509.IPAddress(ipaddress.ip_address("10.0.0.7"))],
    )

    # Shuffled bundle, like the normalize example.
    bundle = [
        pem(leaf_new),
        pem(old_root),
        pem(leaf_old),
        pem(inter),
        pem(new_root),
    ]

    payload = {
        "pem_certificates": bundle,
        "trust_roots": [fingerprint(old_root), fingerprint(new_root)],
        "endpoints": [
            {
                "endpoint_id": "api.example.com",
                "target_leaf_fingerprint": fingerprint(leaf_new),
                "identities": [
                    {"type": "dns", "value": "API.Example.COM."},
                    {"type": "dns", "value": "grpc.svc.example.com"},
                    {"type": "ip", "value": "10.0.0.7"},
                ],
            },
            {
                "endpoint_id": "ghost.example.com",
                "target_leaf_fingerprint": fingerprint(leaf_new),
                "identities": [
                    {"type": "dns", "value": "ghost.example.com"},
                ],
            },
        ],
    }

    out = Path(__file__).with_name("precheck_request.json")
    out.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"wrote {out}")
    print(f"  target leaf: {fingerprint(leaf_new)}")


if __name__ == "__main__":
    main()
