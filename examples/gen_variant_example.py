#!/usr/bin/env python3
"""Regenerate examples/variant_request.json from freshly built PKI material.

Scenario: one endpoint ``api.example.com`` with three deployable candidate
chains and three heterogeneous clients that must all keep connecting:

    Root R (RSA)   -> leaf-rsa      (RSA key, PKCS#1 v1.5 SHA-256 signature)
                    -> leaf-rsa-pss (RSA key, RSASSA-PSS SHA-256 signature)
    Root E (EC)    -> leaf-ec       (EC key, ECDSA-with-SHA-256 signature)

Clients:

    legacy-java-8  trusts Root R; accepts RSA leaves; PKCS#1 v1.5 SHA-256 OID
                   only (no PSS, no EC)            -> needs leaf-rsa
    modern-go      trusts Root E; accepts EC leaves; ECDSA-with-SHA-256 OID
                                                  -> needs leaf-ec
    api-gateway    trusts both roots; accepts RSA+EC and every listed OID
                                                  -> either chain

The minimum deployment set is 2 variants {leaf-ec, leaf-rsa}; leaf-rsa-pss
is never needed (it covers nothing the plain RSA chain does not). The
exhaustive solver finds the global optimum; the api-gateway relationship is
mapped to the first compatible variant of the lexicographically sorted set.

The example request can be POSTed as-is:

    curl -s http://localhost:8080/deployments/variants \
      -H 'Content-Type: application/json' \
      --data @examples/variant_request.json
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

NOT_BEFORE = datetime(2024, 1, 1, tzinfo=timezone.utc)
NOT_AFTER = datetime(2035, 1, 1, tzinfo=timezone.utc)

OID_RSA_SHA256 = "1.2.840.113549.1.1.11"
OID_RSA_PSS = "1.2.840.113549.1.1.10"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"


def dn(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def issue(subject_key, subject_cn, issuer_name, issuer_key, *, is_ca,
          pss=False):
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
    if pss:
        return builder.sign(
            issuer_key,
            hashes.SHA256(),
            rsa_padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=hashes.SHA256().digest_size,
            ),
        )
    return builder.sign(issuer_key, hashes.SHA256())


def pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def fingerprint(cert: x509.Certificate) -> str:
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()


def main() -> None:
    root_r_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_r = issue(root_r_key, "RSA Root CA", dn("RSA Root CA"), root_r_key,
                   is_ca=True)
    leaf_rsa = issue(
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "api.example.com", dn("RSA Root CA"), root_r_key, is_ca=False)
    leaf_rsa_pss = issue(
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "api.example.com", dn("RSA Root CA"), root_r_key, is_ca=False,
        pss=True)

    root_e_key = ec.generate_private_key(ec.SECP256R1())
    root_e = issue(root_e_key, "EC Root CA", dn("EC Root CA"), root_e_key,
                   is_ca=True)
    leaf_ec = issue(
        ec.generate_private_key(ec.SECP256R1()), "api.example.com",
        dn("EC Root CA"), root_e_key, is_ca=False)

    # Deliberately shuffled, with a duplicate DER copy, like the normalize
    # example: parsing/dedup are shared machinery.
    bundle = [
        pem(leaf_rsa),
        pem(root_e),
        pem(leaf_rsa_pss),
        pem(root_r),
        pem(leaf_ec),
        pem(leaf_rsa),  # duplicate, must be deduped
    ]

    chain_rsa = [fingerprint(leaf_rsa), fingerprint(root_r)]
    chain_pss = [fingerprint(leaf_rsa_pss), fingerprint(root_r)]
    chain_ec = [fingerprint(leaf_ec), fingerprint(root_e)]

    payload = {
        "pem_certificates": bundle,
        "clients": [
            {
                "client_id": "legacy-java-8",
                "trust_roots": [fingerprint(root_r)],
                "acceptable_leaf_key_types": ["rsa"],
                "acceptable_signature_oid": [OID_RSA_SHA256],
            },
            {
                "client_id": "modern-go",
                "trust_roots": [fingerprint(root_e)],
                "acceptable_leaf_key_types": ["ec"],
                "acceptable_signature_oid": [OID_ECDSA_SHA256],
            },
            {
                "client_id": "api-gateway",
                "trust_roots": [fingerprint(root_r), fingerprint(root_e)],
                "acceptable_leaf_key_types": ["rsa", "ec"],
                "acceptable_signature_oid": [
                    OID_RSA_SHA256, OID_RSA_PSS, OID_ECDSA_SHA256],
            },
        ],
        "endpoints": [
            {
                "endpoint_id": "api.example.com",
                "candidate_chains": [chain_rsa, chain_pss, chain_ec],
            }
        ],
        "relationships": [
            {"client_id": "legacy-java-8", "endpoint_id": "api.example.com"},
            {"client_id": "modern-go", "endpoint_id": "api.example.com"},
            {"client_id": "api-gateway", "endpoint_id": "api.example.com"},
        ],
    }

    out = Path(__file__).with_name("variant_request.json")
    out.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"wrote {out}")
    print(f"  rsa root: {fingerprint(root_r)}")
    print(f"  ec root:  {fingerprint(root_e)}")


if __name__ == "__main__":
    main()
