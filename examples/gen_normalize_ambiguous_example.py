#!/usr/bin/env python3
"""Regenerate examples/normalize_ambiguous_request.json.

One intermediate key is cross-certified by two independent self-signed roots,
so the leaf's signature is valid under both: the leaf has two verified
leaf-first paths and /scenarios/normalize answers 422 ambiguous_chain.
"""
from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from gen_normalize_example import dn, fingerprint, issue, pem


def main() -> None:
    root_a_key = ec.generate_private_key(ec.SECP256R1())
    root_b_key = ec.generate_private_key(ec.SECP256R1())
    root_a = issue("Root A", dn("Root A"), root_a_key, root_a_key, is_ca=True)
    root_b = issue("Root B", dn("Root B"), root_b_key, root_b_key, is_ca=True)

    inter_key = ec.generate_private_key(ec.SECP256R1())
    # The same intermediate public key gets wrapped twice, by different roots.
    inter_a = issue("Shared Intermediate", dn("Root A"), root_a_key,
                    inter_key, is_ca=True)
    inter_b = issue("Shared Intermediate", dn("Root B"), root_b_key,
                    inter_key, is_ca=True)
    leaf = issue("api.example.com", dn("Shared Intermediate"), inter_key,
                 ec.generate_private_key(ec.SECP256R1()), is_ca=False)

    payload = {
        "pem_certificates": [
            pem(leaf), pem(inter_a), pem(inter_b), pem(root_a), pem(root_b),
        ],
        "trust_roots": [fingerprint(root_a), fingerprint(root_b)],
        "endpoints": [
            {
                "endpoint_id": "api.example.com",
                "current_leaf_fingerprint": fingerprint(leaf),
                "target_leaf_fingerprint": fingerprint(leaf),
            }
        ],
    }

    out = Path(__file__).with_name("normalize_ambiguous_request.json")
    out.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
