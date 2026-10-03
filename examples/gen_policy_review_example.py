#!/usr/bin/env python3
"""Regenerate examples/policy_review_request.json from fresh PKI material.

The bundle reconstructs to one root per endpoint family; at check_time
2030-01-01 (all certs valid 2024-2035 unless noted) the declared endpoints
exercise every review outcome:

    api.example.com      server, current+target fully compliant
    mtls.example.com     client (mTLS), clientAuth + custom-purpose EKU
    rsa-legacy.example.com
                         server leaf with keyEncipherment-only KeyUsage
                         (still deployable for an RSA key exchange)
    billing.example.com  server whose CURRENT leaf only carries id-kp-
                         clientAuth -> required_eku_missing (role mismatch);
                         its target chain is compliant
    pathlen.example.com  target chain Root -> intermediate(pathLen 0) ->
                         intermediate -> leaf -> path_len_violation
    expired.example.com  CURRENT leaf already expired at check_time
    ext.example.com      CURRENT leaf carries an unknown critical extension

Run: python3 examples/gen_policy_review_example.py
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

NOT_BEFORE = "2024-01-01T00:00:00Z"
NOT_AFTER = "2035-01-01T00:00:00Z"
CHECK_TIME = "2030-01-01T00:00:00Z"

SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
# An arbitrary deployment-specific client purpose EKU.
MTLS_PURPOSE_OID = "1.3.6.1.4.1.55000.7.1"
# OID no verifier recognizes, used to build an unknown critical extension.
MYSTERY_CRITICAL_OID = "1.2.3.4.5.6.7.8.1"


def _dt(value: str):
    from datetime import datetime, timezone

    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
        timezone.utc)


def dn(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def issue(subject_cn, issuer_name, issuer_key, subject_key, *,
         is_ca=False, path_length=None, key_usage=None, ekus=(),
         dns_names=(), not_before=NOT_BEFORE, not_after=NOT_AFTER,
         extra_extensions=()):
    key = subject_key
    builder = (
        x509.CertificateBuilder()
        .subject_name(dn(subject_cn))
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt(not_before))
        .not_valid_after(_dt(not_after))
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=path_length),
            critical=True,
        )
    )
    if key_usage is not None:
        builder = builder.add_extension(key_usage, critical=True)
    if ekus:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([
                x509.ObjectIdentifier(o) for o in ekus
            ]),
            critical=False,
        )
    if dns_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(n) for n in dns_names]
            ),
            critical=False,
        )
    for ext, critical in extra_extensions:
        builder = builder.add_extension(ext, critical=critical)
    return builder.sign(issuer_key, hashes.SHA256()), key


def ca(*args, path_length=None, **kwargs):
    return issue(*args, is_ca=True, path_length=path_length,
                 key_usage=x509.KeyUsage(
                     digital_signature=True, content_commitment=False,
                     key_encipherment=False, data_encipherment=False,
                     key_agreement=False, key_cert_sign=True,
                     crl_sign=True, encipher_only=False,
                     decipher_only=False,
                 ), **kwargs)


def eckey():
    return ec.generate_private_key(ec.SECP256R1())


def pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def fingerprint(cert) -> str:
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()


def server_leaf_ku():
    return x509.KeyUsage(
        digital_signature=True, content_commitment=False,
        key_encipherment=False, data_encipherment=False,
        key_agreement=False, key_cert_sign=False, crl_sign=False,
        encipher_only=False, decipher_only=False,
    )


def main() -> None:
    certs = {}

    def root(name):
        k = eckey()
        c, k = ca(name, dn(name), k, k)
        certs[name] = c
        return c, k

    # ---- Clean family: good server, mTLS client ---------------------------
    clean_root, clean_root_k = root("Clean Root CA")
    clean_inter_k = eckey()
    clean_inter, _ = ca(
        "Clean Intermediate CA", dn("Clean Root CA"), clean_root_k,
        clean_inter_k)
    certs["Clean Intermediate CA"] = clean_inter

    leaf_api_k = eckey()
    leaf_api, _ = issue(
        "api.example.com", dn("Clean Intermediate CA"), clean_inter_k,
        leaf_api_k, key_usage=server_leaf_ku(), ekus=[SERVER_AUTH],
        dns_names=["api.example.com"])
    certs["api.example.com"] = leaf_api

    leaf_mtls_k = eckey()
    leaf_mtls, _ = issue(
        "mtls.example.com", dn("Clean Intermediate CA"), clean_inter_k,
        leaf_mtls_k, key_usage=server_leaf_ku(),
        ekus=[CLIENT_AUTH, MTLS_PURPOSE_OID],
        dns_names=["mtls.example.com"])
    certs["mtls.example.com"] = leaf_mtls

    # ---- RSA legacy family: keyEncipherment-only server leaf --------------
    rsa_root_k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_root, rsa_root_k = ca(
        "RSA Legacy Root CA", dn("RSA Legacy Root CA"), rsa_root_k,
        rsa_root_k)
    certs["RSA Legacy Root CA"] = rsa_root
    rsa_leaf_k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_leaf, _ = issue(
        "rsa-legacy.example.com", dn("RSA Legacy Root CA"), rsa_root_k,
        rsa_leaf_k,
        key_usage=x509.KeyUsage(
            digital_signature=False, content_commitment=False,
            key_encipherment=True, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=False,
            encipher_only=False, decipher_only=False,
        ),
        ekus=[SERVER_AUTH], dns_names=["rsa-legacy.example.com"])
    certs["rsa-legacy.example.com"] = rsa_leaf

    # ---- Billing family: current server leaf carries clientAuth only ------
    billing_root, billing_root_k = root("Billing Root CA")
    billing_cur_k = eckey()
    billing_cur, _ = issue(
        "billing.example.com-current", dn("Billing Root CA"),
        billing_root_k, billing_cur_k, key_usage=server_leaf_ku(),
        ekus=[CLIENT_AUTH], dns_names=["billing.example.com"])
    certs["billing-current"] = billing_cur
    billing_new_k = eckey()
    billing_new, _ = issue(
        "billing.example.com", dn("Billing Root CA"), billing_root_k,
        billing_new_k, key_usage=server_leaf_ku(), ekus=[SERVER_AUTH],
        dns_names=["billing.example.com"])
    certs["billing-new"] = billing_new

    # ---- pathLen family: pathLen 0 CA has a CA below it -------------------
    pl_root, pl_root_k = root("PathLen Root CA")
    pl_p0_k = eckey()
    pl_p0, _ = ca(
        "PathLen Zero CA", dn("PathLen Root CA"), pl_root_k, pl_p0_k,
        path_length=0)
    certs["PathLen Zero CA"] = pl_p0
    pl_sub_k = eckey()
    pl_sub, _ = ca(
        "PathLen Sub CA", dn("PathLen Zero CA"), pl_p0_k, pl_sub_k)
    certs["PathLen Sub CA"] = pl_sub
    pl_leaf_k = eckey()
    pl_leaf, _ = issue(
        "pathlen.example.com", dn("PathLen Sub CA"), pl_sub_k, pl_leaf_k,
        key_usage=server_leaf_ku(), ekus=[SERVER_AUTH],
        dns_names=["pathlen.example.com"])
    certs["pathlen"] = pl_leaf
    # Compliant current leaf: issued directly by the root.
    pl_cur_k = eckey()
    pl_cur, _ = issue(
        "pathlen.example.com-current", dn("PathLen Root CA"), pl_root_k,
        pl_cur_k, key_usage=server_leaf_ku(), ekus=[SERVER_AUTH],
        dns_names=["pathlen.example.com"])
    certs["pathlen-current"] = pl_cur

    # ---- Expired family: current leaf expired in 2028 ---------------------
    exp_root, exp_root_k = root("Expired Root CA")
    exp_cur_k = eckey()
    exp_cur, _ = issue(
        "expired.example.com-current", dn("Expired Root CA"), exp_root_k,
        exp_cur_k, key_usage=server_leaf_ku(), ekus=[SERVER_AUTH],
        dns_names=["expired.example.com"],
        not_before="2024-01-01T00:00:00Z", not_after="2028-01-01T00:00:00Z")
    certs["expired-current"] = exp_cur
    exp_new_k = eckey()
    exp_new, _ = issue(
        "expired.example.com", dn("Expired Root CA"), exp_root_k, exp_new_k,
        key_usage=server_leaf_ku(), ekus=[SERVER_AUTH],
        dns_names=["expired.example.com"])
    certs["expired-new"] = exp_new

    # ---- Unknown critical extension family --------------------------------
    ext_root, ext_root_k = root("Extension Root CA")
    mystery = x509.UnrecognizedExtension(
        x509.ObjectIdentifier(MYSTERY_CRITICAL_OID), b"\x04\x03abc")
    ext_cur_k = eckey()
    ext_cur, _ = issue(
        "ext.example.com-current", dn("Extension Root CA"), ext_root_k,
        ext_cur_k, key_usage=server_leaf_ku(), ekus=[SERVER_AUTH],
        dns_names=["ext.example.com"],
        extra_extensions=[(mystery, True)])
    certs["ext-current"] = ext_cur
    ext_new_k = eckey()
    ext_new, _ = issue(
        "ext.example.com", dn("Extension Root CA"), ext_root_k, ext_new_k,
        key_usage=server_leaf_ku(), ekus=[SERVER_AUTH],
        dns_names=["ext.example.com"])
    certs["ext-new"] = ext_new

    # ---- Bundle (shuffled) -------------------------------------------------
    order = [
        leaf_api, leaf_mtls, rsa_leaf, billing_cur, billing_new, pl_leaf,
        pl_cur, pl_p0, pl_sub, exp_cur, exp_new, ext_cur, ext_new,
        clean_inter,
        clean_root, rsa_root, billing_root, pl_root, exp_root, ext_root,
    ]
    bundle = [pem(c) for c in order]

    payload = {
        "pem_certificates": bundle,
        "trust_roots": [
            fingerprint(clean_root), fingerprint(rsa_root),
            fingerprint(billing_root), fingerprint(pl_root),
            fingerprint(exp_root), fingerprint(ext_root),
        ],
        "check_time": CHECK_TIME,
        "endpoints": [
            {
                "endpoint_id": "api.example.com",
                "current_leaf_fingerprint": fingerprint(leaf_api),
                "target_leaf_fingerprint": fingerprint(leaf_api),
                "role": "server",
                "required_ekus": [],
            },
            {
                "endpoint_id": "mtls.example.com",
                "current_leaf_fingerprint": fingerprint(leaf_mtls),
                "target_leaf_fingerprint": fingerprint(leaf_mtls),
                "role": "client",
                "required_ekus": [MTLS_PURPOSE_OID],
            },
            {
                "endpoint_id": "rsa-legacy.example.com",
                "current_leaf_fingerprint": fingerprint(rsa_leaf),
                "target_leaf_fingerprint": fingerprint(rsa_leaf),
                "role": "server",
                "required_ekus": [],
            },
            {
                "endpoint_id": "billing.example.com",
                "current_leaf_fingerprint": fingerprint(billing_cur),
                "target_leaf_fingerprint": fingerprint(billing_new),
                "role": "server",
                "required_ekus": [],
            },
            {
                "endpoint_id": "pathlen.example.com",
                "current_leaf_fingerprint": fingerprint(pl_cur),
                "target_leaf_fingerprint": fingerprint(pl_leaf),
                "role": "server",
                "required_ekus": [],
            },
            {
                "endpoint_id": "expired.example.com",
                "current_leaf_fingerprint": fingerprint(exp_cur),
                "target_leaf_fingerprint": fingerprint(exp_new),
                "role": "server",
                "required_ekus": [],
            },
            {
                "endpoint_id": "ext.example.com",
                "current_leaf_fingerprint": fingerprint(ext_cur),
                "target_leaf_fingerprint": fingerprint(ext_new),
                "role": "server",
                "required_ekus": [],
            },
        ],
    }

    out = Path(__file__).with_name("policy_review_request.json")
    out.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
