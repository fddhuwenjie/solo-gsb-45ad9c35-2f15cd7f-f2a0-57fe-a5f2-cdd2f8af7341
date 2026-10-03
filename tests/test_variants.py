"""Tests for POST /deployments/variants (minimum variant selection)."""
from __future__ import annotations

import hashlib
import itertools
import random
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.main import app
from app.variants import minimum_variant_set

NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)

client = TestClient(app)

OID_RSA_SHA1 = "1.2.840.113549.1.1.5"
OID_RSA_SHA256 = "1.2.840.113549.1.1.11"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_RSA_PSS = "1.2.840.113549.1.1.10"
OID_ED25519 = "1.3.101.112"


# ---------------------------------------------------------------------------
# Certificate factory
# ---------------------------------------------------------------------------


def _key(kind="ec"):
    if kind == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if kind == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    return ec.generate_private_key(ec.SECP256R1())


def _dn(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_cert(
    subject_key,
    subject_cn,
    issuer_cn,
    issuer_key,
    *,
    is_ca=False,
    pss=False,
):
    """Build a cert. Ed25519 keys sign with algorithm=None; RSA optionally PSS."""
    builder = (
        x509.CertificateBuilder()
        .subject_name(_dn(subject_cn))
        .issuer_name(_dn(issuer_cn))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=365))
        .not_valid_after(NOW + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None), critical=True
        )
    )
    if isinstance(issuer_key, ed25519.Ed25519PrivateKey):
        return builder.sign(issuer_key, None)
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


def pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def fp(cert) -> str:
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()


@pytest.fixture(scope="module")
def pki():
    # Root A: EC P-256
    root_a_key = _key("ec")
    root_a = make_cert(root_a_key, "Root A", "Root A", root_a_key, is_ca=True)
    inter_a_key = _key("ec")
    inter_a = make_cert(inter_a_key, "Inter A", "Root A", root_a_key, is_ca=True)
    leaf_ec = make_cert(_key("ec"), "svc.example", "Root A", root_a_key)
    leaf_eci = make_cert(_key("ec"), "svc.example", "Inter A", inter_a_key)

    # Root B: RSA
    root_b_key = _key("rsa")
    root_b = make_cert(root_b_key, "Root B", "Root B", root_b_key, is_ca=True)
    leaf_rsa = make_cert(_key("rsa"), "svc.example", "Root B", root_b_key)
    leaf_pss = make_cert(
        _key("rsa"), "svc.example", "Root B", root_b_key, pss=True
    )
    # EC leaf key but signed by the RSA root: valid hop, cross-algorithm.
    leaf_ec_by_b = make_cert(_key("ec"), "svc.example", "Root B", root_b_key)

    # Root C: Ed25519
    root_c_key = _key("ed25519")
    root_c = make_cert(root_c_key, "Root C", "Root C", root_c_key, is_ca=True)
    leaf_ed = make_cert(_key("ed25519"), "svc.example", "Root C", root_c_key)

    # A leaf signed by an unrelated key: chaining it onto any root fails the
    # hop-by-hop signature check.
    stranger_key = _key("ec")
    leaf_stranger = make_cert(
        stranger_key, "svc.example", "stranger", stranger_key
    )

    # A non-self-signed cert someone wrongly declares as a trust root.
    fake_root_key = _key("ec")
    fake_root = make_cert(fake_root_key, "Fake Root", "Root A", root_a_key,
                          is_ca=True)

    certs = {
        "root_a": root_a, "inter_a": inter_a,
        "leaf_ec": leaf_ec, "leaf_eci": leaf_eci,
        "root_b": root_b, "leaf_rsa": leaf_rsa, "leaf_pss": leaf_pss,
        "leaf_ec_by_b": leaf_ec_by_b,
        "root_c": root_c, "leaf_ed": leaf_ed,
        "leaf_stranger": leaf_stranger, "fake_root": fake_root,
    }
    return certs


def bundle(pki, *names):
    # Include a duplicate DER copy on purpose to exercise PEM dedup reuse.
    out = [pem(pki[n]) for n in names]
    if names:
        out.append(pem(pki[names[0]]))
    return out


CHAIN_LEAF_RSA = lambda p: [fp(p["leaf_rsa"]), fp(p["root_b"])]  # noqa: E731
CHAIN_LEAF_PSS = lambda p: [fp(p["leaf_pss"]), fp(p["root_b"])]  # noqa: E731
CHAIN_LEAF_EC = lambda p: [fp(p["leaf_ec"]), fp(p["root_a"])]  # noqa: E731
CHAIN_LEAF_ECI = lambda p: [  # noqa: E731
    fp(p["leaf_eci"]), fp(p["inter_a"]), fp(p["root_a"])]
CHAIN_LEAF_EC_BY_B = lambda p: [  # noqa: E731
    fp(p["leaf_ec_by_b"]), fp(p["root_b"])]
CHAIN_LEAF_ED = lambda p: [fp(p["leaf_ed"]), fp(p["root_c"])]  # noqa: E731
CHAIN_BROKEN = lambda p: [fp(p["leaf_stranger"]), fp(p["root_a"])]  # noqa: E731


def client_spec(cid, roots, key_types, oids):
    return {"client_id": cid, "trust_roots": roots,
            "acceptable_leaf_key_types": key_types,
            "acceptable_signature_oid": oids}


def endpoint_spec(eid, chains):
    return {"endpoint_id": eid, "candidate_chains": chains}


def rel(cid, eid):
    return {"client_id": cid, "endpoint_id": eid}


def payload(pki, clients, endpoints, relationships, *bundle_names):
    return {
        "pem_certificates": bundle(pki, *bundle_names),
        "clients": clients,
        "endpoints": endpoints,
        "relationships": relationships,
    }


# ---------------------------------------------------------------------------
# Happy path: minimum set, global optimum, deterministic mapping
# ---------------------------------------------------------------------------


def test_minimum_two_variants_for_heterogeneous_clients(pki):
    # legacy accepts only the PSS-signed RSA chain (RSA-SHA256 OID is *not*
    # accepted); modern accepts only EC/Ed25519 chains rooted at A/C.
    legacy = client_spec(
        "legacy", [fp(pki["root_b"])], ["rsa"], [OID_RSA_PSS])
    modern = client_spec(
        "modern", [fp(pki["root_a"])], ["ec", "ed25519"],
        [OID_ECDSA_SHA256, OID_ED25519])
    anycast = client_spec(
        "anycast",
        [fp(pki["root_a"]), fp(pki["root_b"]), fp(pki["root_c"])],
        ["rsa", "ec", "ed25519"],
        [OID_RSA_SHA256, OID_RSA_PSS, OID_ECDSA_SHA256, OID_ED25519])
    chains = [
        CHAIN_LEAF_RSA(pki), CHAIN_LEAF_PSS(pki), CHAIN_LEAF_EC(pki),
        CHAIN_LEAF_ECI(pki), CHAIN_LEAF_ED(pki),
    ]
    body = payload(
        pki,
        [legacy, modern, anycast],
        [endpoint_spec("svc", chains)],
        [rel("legacy", "svc"), rel("modern", "svc"),
         rel("anycast", "svc")],
        "root_a", "leaf_ec", "inter_a", "leaf_eci",
        "root_b", "leaf_rsa", "leaf_pss",
        "root_c", "leaf_ed",
    )
    r = client.post("/deployments/variants", json=body)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["status"] == "ok"

    sel = data["selections"]
    selected_chains = sorted(s["chain"] for s in sel)
    assert len(selected_chains) == 2
    # Legacy is forced onto the PSS chain; the RSA-SHA256 chain cannot be in
    # the optimum (it covers nothing the PSS chain doesn't).
    assert CHAIN_LEAF_PSS(pki) in selected_chains
    modern_chain = next(
        c for c in selected_chains if c != CHAIN_LEAF_PSS(pki))
    assert modern_chain in (
        CHAIN_LEAF_EC(pki), CHAIN_LEAF_ECI(pki), CHAIN_LEAF_ED(pki))

    # variant_index follows the sorted-chain order.
    assert [s["variant_index"] for s in sel] == [0, 1]

    assignments = {(a["client_id"], a["endpoint_id"]): a
                   for a in data["assignments"]}
    assert assignments["legacy", "svc"]["chain"] == CHAIN_LEAF_PSS(pki)
    assert assignments["modern", "svc"]["chain"] == modern_chain
    # anycast: the first compatible variant of the sorted selected set.
    expected_for_anycast = min(selected_chains)
    assert assignments["anycast", "svc"]["chain"] == expected_for_anycast
    assert set(assignments) == {
        ("legacy", "svc"), ("modern", "svc"), ("anycast", "svc")}


def test_result_is_independent_of_input_order(pki):
    legacy = client_spec(
        "legacy", [fp(pki["root_b"])], ["rsa"], [OID_RSA_PSS])
    modern = client_spec(
        "modern", [fp(pki["root_a"])], ["ec"], [OID_ECDSA_SHA256])
    chains = [
        CHAIN_LEAF_PSS(pki), CHAIN_LEAF_RSA(pki), CHAIN_LEAF_EC(pki),
        CHAIN_LEAF_ECI(pki),
    ]
    rels = [rel("modern", "svc"), rel("legacy", "svc")]
    base = payload(
        pki, [modern, legacy], [endpoint_spec("svc", chains)], rels,
        "root_a", "leaf_ec", "inter_a", "leaf_eci",
        "root_b", "leaf_rsa", "leaf_pss",
    )
    r1 = client.post("/deployments/variants", json=base)
    shuffled = {
        **base,
        "clients": list(reversed(base["clients"])),
        "relationships": list(reversed(rels)),
        "endpoints": [endpoint_spec(
            "svc", list(reversed(chains)))],
    }
    r2 = client.post("/deployments/variants", json=shuffled)
    assert r1.status_code == r2.status_code == 200
    assert r1.json() == r2.json()


def test_single_variant_covers_everyone(pki):
    # All clients trust both roots A and B and accept everything: one variant
    # must suffice, and it is the lexicographically smallest chain.
    spec = client_spec(
        "c", [fp(pki["root_a"]), fp(pki["root_b"])],
        ["rsa", "ec"], [OID_RSA_SHA256, OID_ECDSA_SHA256])
    chains = [CHAIN_LEAF_RSA(pki), CHAIN_LEAF_EC(pki),
              CHAIN_LEAF_ECI(pki), CHAIN_LEAF_EC_BY_B(pki)]
    body = payload(
        pki, [spec], [endpoint_spec("svc", chains)],
        [rel("c", "svc")],
        "root_a", "inter_a", "leaf_ec", "leaf_eci",
        "root_b", "leaf_rsa", "leaf_ec_by_b",
    )
    r = client.post("/deployments/variants", json=body)
    assert r.status_code == 200, r.text
    data = r.json()
    assert len(data["selections"]) == 1
    assert data["selections"][0]["chain"] == min(chains)
    assert data["assignments"][0]["chain"] == min(chains)
    assert data["assignments"][0]["variant_index"] == 0


def test_duplicate_candidate_chains_are_collapsed(pki):
    spec = client_spec(
        "c", [fp(pki["root_a"])], ["ec"], [OID_ECDSA_SHA256])
    chains = [CHAIN_LEAF_EC(pki), CHAIN_LEAF_EC(pki)]
    body = payload(
        pki, [spec], [endpoint_spec("svc", chains)],
        [rel("c", "svc")], "root_a", "leaf_ec")
    r = client.post("/deployments/variants", json=body)
    assert r.status_code == 200, r.text
    data = r.json()
    assert len(data["selections"]) == 1
    assert data["selections"][0]["chain"] == CHAIN_LEAF_EC(pki)


def test_endpoint_without_relationships_deploys_nothing(pki):
    spec = client_spec(
        "c", [fp(pki["root_a"]), fp(pki["root_b"])],
        ["rsa", "ec"], [OID_RSA_SHA256, OID_ECDSA_SHA256])
    body = payload(
        pki, [spec],
        [endpoint_spec("lonely", [CHAIN_LEAF_EC(pki)]),
         endpoint_spec("svc", [CHAIN_LEAF_RSA(pki)])],
        [rel("c", "svc")],
        "root_a", "leaf_ec", "root_b", "leaf_rsa",
    )
    r = client.post("/deployments/variants", json=body)
    assert r.status_code == 200, r.text
    data = r.json()
    assert {s["endpoint_id"] for s in data["selections"]} == {"svc"}
    assert {a["endpoint_id"] for a in data["assignments"]} == {"svc"}


def test_endpoints_are_optimized_independently(pki):
    spec_a = client_spec(
        "ca", [fp(pki["root_a"])], ["ec"], [OID_ECDSA_SHA256])
    spec_b = client_spec(
        "cb", [fp(pki["root_b"])], ["rsa"], [OID_RSA_SHA256])
    body = payload(
        pki, [spec_a, spec_b],
        [endpoint_spec("sa", [CHAIN_LEAF_EC(pki)]),
         endpoint_spec("sb", [CHAIN_LEAF_RSA(pki)])],
        [rel("ca", "sa"), rel("cb", "sb")],
        "root_a", "leaf_ec", "root_b", "leaf_rsa",
    )
    r = client.post("/deployments/variants", json=body)
    assert r.status_code == 200, r.text
    data = r.json()
    by_ep = {s["endpoint_id"]: s["chain"] for s in data["selections"]}
    assert by_ep == {"sa": CHAIN_LEAF_EC(pki), "sb": CHAIN_LEAF_RSA(pki)}
    assert [s["endpoint_id"] for s in data["selections"]] == ["sa", "sb"]


def test_root_signature_oid_is_not_gated(pki):
    # The leaf is RSA-PSS (accepted); root B is self-signed with plain
    # RSA-SHA256, whose OID is NOT in the client's accept list. The chain
    # must still cover, because a trust anchor's own signature algorithm is
    # never policy-checked.
    spec = client_spec(
        "legacy", [fp(pki["root_b"])], ["rsa"], [OID_RSA_PSS])
    body = payload(
        pki, [spec], [endpoint_spec("svc", [CHAIN_LEAF_PSS(pki)])],
        [rel("legacy", "svc")], "root_b", "leaf_pss")
    r = client.post("/deployments/variants", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["selections"][0]["chain"] == CHAIN_LEAF_PSS(pki)


# ---------------------------------------------------------------------------
# 409: uncoverable relationship with stable, complete reasons
# ---------------------------------------------------------------------------


def test_409_reports_all_reasons_per_candidate_chain(pki):
    # legacy: RSA-only, root B only, PSS OID only.
    legacy = client_spec(
        "legacy", [fp(pki["root_b"])], ["rsa"], [OID_RSA_PSS])
    # Also include a permissive-but-unrooted client proving a chain can fail
    # with exactly the root+OID pair while the leaf key type is accepted:
    broad = client_spec(
        "broad", [fp(pki["root_b"])], ["rsa", "ec"], [OID_RSA_PSS])
    # EC chain rooted at A: root untrusted + signature OID incompatible;
    # broad accepts the ec key type, so that reason must NOT appear for it.
    ec_chain = CHAIN_LEAF_EC(pki)
    # Broken chain: stranger leaf chained onto root A -> bad hop; root A
    # untrusted; ec leaf key rejected; ECDSA OID rejected: all four reasons.
    broken = CHAIN_BROKEN(pki)
    body = payload(
        pki, [legacy, broad],
        [endpoint_spec("svc2", [ec_chain, broken])],
        [rel("legacy", "svc2"), rel("broad", "svc2")],
        "root_a", "root_b", "leaf_ec", "leaf_stranger",
    )
    r = client.post("/deployments/variants", json=body)
    assert r.status_code == 409, r.text
    data = r.json()
    assert data["status"] == "conflict"
    assert data["reason"] == "uncoverable_relationship"
    entries = data["incompatibilities"]
    assert len(entries) == 4
    lookup = {(e["client_id"], tuple(e["chain"])): e for e in entries}

    e_broad_ec = lookup[("broad", tuple(ec_chain))]
    assert e_broad_ec["reasons"] == [
        "root_untrusted", "signature_algorithm_incompatible"]
    assert e_broad_ec["leaf_key_type"] == "ec"
    assert e_broad_ec["signature_oids"] == [OID_ECDSA_SHA256]
    assert e_broad_ec["trusted_roots"] == [fp(pki["root_b"])]

    e_ec = lookup[("legacy", tuple(ec_chain))]
    # legacy accepts RSA keys only, so the EC leaf also fails the key type.
    assert e_ec["reasons"] == [
        "root_untrusted",
        "leaf_key_type_incompatible",
        "signature_algorithm_incompatible",
    ]
    assert e_ec["leaf_key_type"] == "ec"

    e_broken = lookup[("legacy", tuple(broken))]
    assert e_broken["reasons"] == [
        "chain_signature_invalid",
        "root_untrusted",
        "leaf_key_type_incompatible",
        "signature_algorithm_incompatible",
    ]
    assert e_broken["leaf_key_type"] == "ec"
    # stable order: (client, endpoint, chain)
    assert [(e["client_id"], tuple(e["chain"])) for e in entries] == sorted(
        (e["client_id"], tuple(e["chain"])) for e in entries)


def test_409_chain_signature_invalid_only(pki):
    # Client trusts root A and accepts ec/ECDSA; the only defect is the hop
    # signature, so exactly one reason must be reported.
    spec = client_spec(
        "c", [fp(pki["root_a"])], ["ec"], [OID_ECDSA_SHA256])
    body = payload(
        pki, [spec], [endpoint_spec("svc", [CHAIN_BROKEN(pki)])],
        [rel("c", "svc")], "root_a", "leaf_stranger")
    r = client.post("/deployments/variants", json=body)
    assert r.status_code == 409
    inc = r.json()["incompatibilities"]
    assert len(inc) == 1
    assert inc[0]["reasons"] == ["chain_signature_invalid"]


def test_409_leaf_key_type_incompatible(pki):
    # Root B is trusted and signed the EC-key leaf; only the leaf key type
    # fails for the RSA-only client (the leaf signature is RSA-SHA256, which
    # this client accepts).
    spec = client_spec(
        "c", [fp(pki["root_b"])], ["rsa"], [OID_RSA_SHA256])
    body = payload(
        pki, [spec], [endpoint_spec("svc", [CHAIN_LEAF_EC_BY_B(pki)])],
        [rel("c", "svc")], "root_b", "leaf_ec_by_b")
    r = client.post("/deployments/variants", json=body)
    assert r.status_code == 409
    inc = r.json()["incompatibilities"]
    assert inc[0]["reasons"] == ["leaf_key_type_incompatible"]
    assert inc[0]["leaf_key_type"] == "ec"


def test_409_signature_algorithm_incompatible(pki):
    # RSA leaf signed with PSS; client accepts plain RSA-SHA256 only. Key
    # type and root are fine.
    spec = client_spec(
        "c", [fp(pki["root_b"])], ["rsa"], [OID_RSA_SHA256])
    body = payload(
        pki, [spec], [endpoint_spec("svc", [CHAIN_LEAF_PSS(pki)])],
        [rel("c", "svc")], "root_b", "leaf_pss")
    r = client.post("/deployments/variants", json=body)
    assert r.status_code == 409
    inc = r.json()["incompatibilities"]
    assert inc[0]["reasons"] == ["signature_algorithm_incompatible"]
    assert inc[0]["signature_oids"] == [OID_RSA_PSS]


def test_409_ed25519_classification(pki):
    spec = client_spec(
        "c", [fp(pki["root_c"])], ["ec"], [OID_ED25519])
    body = payload(
        pki, [spec], [endpoint_spec("svc", [CHAIN_LEAF_ED(pki)])],
        [rel("c", "svc")], "root_c", "leaf_ed")
    r = client.post("/deployments/variants", json=body)
    assert r.status_code == 409
    inc = r.json()["incompatibilities"][0]
    assert inc["reasons"] == ["leaf_key_type_incompatible"]
    assert inc["leaf_key_type"] == "ed25519"
    assert inc["signature_oids"] == [OID_ED25519]


def test_409_stable_sort_by_client_endpoint(pki):
    spec_a = client_spec(
        "za", [fp(pki["root_b"])], ["rsa"], [OID_RSA_SHA256])
    spec_b = client_spec(
        "ma", [fp(pki["root_b"])], ["rsa"], [OID_RSA_SHA256])
    body = payload(
        pki, [spec_a, spec_b],
        [endpoint_spec("ze", [CHAIN_LEAF_EC(pki)]),
         endpoint_spec("me", [CHAIN_LEAF_EC(pki)])],
        [rel("za", "ze"), rel("ma", "me")],
        "root_a", "leaf_ec", "root_b",
    )
    r = client.post("/deployments/variants", json=body)
    assert r.status_code == 409
    pairs = [(i["client_id"], i["endpoint_id"])
             for i in r.json()["incompatibilities"]]
    assert pairs == sorted(pairs) == [("ma", "me"), ("za", "ze")]


# ---------------------------------------------------------------------------
# 422: request-level errors
# ---------------------------------------------------------------------------


def _good_payload(pki):
    spec = client_spec(
        "c", [fp(pki["root_a"])], ["ec"], [OID_ECDSA_SHA256])
    return payload(
        pki, [spec], [endpoint_spec("svc", [CHAIN_LEAF_EC(pki)])],
        [rel("c", "svc")], "root_a", "leaf_ec")


def test_422_invalid_pem(pki):
    body = _good_payload(pki)
    body["pem_certificates"] = ["not a pem at all"]
    r = client.post("/deployments/variants", json=body)
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error"] == "invalid_pem"
    assert detail["pem_issues"][0]["index"] == 0


def test_422_invalid_fingerprint(pki):
    body = _good_payload(pki)
    body["clients"][0]["trust_roots"] = ["XYZ-not-hex"]
    r = client.post("/deployments/variants", json=body)
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error"] == "invalid_fingerprint"
    assert "clients['c'].trust_roots" in (
        detail["fingerprint_issues"][0]["referred_by"])


def test_422_unknown_fingerprint(pki):
    body = _good_payload(pki)
    body["clients"][0]["trust_roots"] = ["a" * 64]
    r = client.post("/deployments/variants", json=body)
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "unknown_fingerprint"


def test_422_invalid_oid(pki):
    body = _good_payload(pki)
    body["clients"][0]["acceptable_signature_oid"] = ["1.2.foo"]
    r = client.post("/deployments/variants", json=body)
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error"] == "invalid_oid"
    assert detail["oid_issues"][0]["oid"] == "1.2.foo"
    assert detail["oid_issues"][0]["client_id"] == "c"


def test_422_empty_chain(pki):
    body = _good_payload(pki)
    body["endpoints"][0]["candidate_chains"] = [[]]
    r = client.post("/deployments/variants", json=body)
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error"] == "invalid_chain"
    assert detail["chain_issues"][0]["reason"] == "empty_chain"


def test_422_cyclic_chain(pki):
    body = _good_payload(pki)
    chain = CHAIN_LEAF_ECI(pki)
    body["endpoints"][0]["candidate_chains"] = [chain + [chain[1]]]
    body["pem_certificates"] = bundle(
        pki, "root_a", "inter_a", "leaf_eci")
    r = client.post("/deployments/variants", json=body)
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error"] == "invalid_chain"
    assert detail["chain_issues"][0]["reason"] == "chain_cycle"


def test_422_trust_root_must_be_self_signed(pki):
    body = _good_payload(pki)
    body["pem_certificates"] = bundle(pki, "root_a", "leaf_ec", "fake_root")
    body["clients"][0]["trust_roots"] = [fp(pki["fake_root"])]
    r = client.post("/deployments/variants", json=body)
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "trust_root_not_self_signed"


def test_422_unknown_client_or_endpoint(pki):
    body = _good_payload(pki)
    body["relationships"] = [rel("ghost", "svc")]
    r = client.post("/deployments/variants", json=body)
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "unknown_client"

    body = _good_payload(pki)
    body["relationships"] = [rel("c", "ghost")]
    r = client.post("/deployments/variants", json=body)
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "unknown_endpoint"


def test_422_duplicate_ids_and_relationships(pki):
    spec = client_spec(
        "c", [fp(pki["root_a"])], ["ec"], [OID_ECDSA_SHA256])
    body = payload(
        pki, [spec, spec],
        [endpoint_spec("svc", [CHAIN_LEAF_EC(pki)])],
        [rel("c", "svc")], "root_a", "leaf_ec")
    r = client.post("/deployments/variants", json=body)
    assert r.status_code == 422
    assert "unique" in r.json()["detail"]["message"]

    body = _good_payload(pki)
    body["endpoints"] = [
        endpoint_spec("svc", [CHAIN_LEAF_EC(pki)]),
        endpoint_spec("svc", [CHAIN_LEAF_EC(pki)]),
    ]
    r = client.post("/deployments/variants", json=body)
    assert r.status_code == 422
    assert "unique" in r.json()["detail"]["message"]

    body = _good_payload(pki)
    body["relationships"] = [rel("c", "svc"), rel("c", "svc")]
    r = client.post("/deployments/variants", json=body)
    assert r.status_code == 422
    assert "at most once" in r.json()["detail"]["message"]


def test_422_too_many_candidates_rejected_by_schema(pki):
    spec = client_spec(
        "c", [fp(pki["root_a"])], ["ec"], [OID_ECDSA_SHA256])
    body = payload(
        pki, [spec],
        [endpoint_spec("svc", [CHAIN_LEAF_EC(pki)] * 13)],
        [rel("c", "svc")], "root_a", "leaf_ec")
    r = client.post("/deployments/variants", json=body)
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Exact-solver differential tests against brute-force set enumeration
# ---------------------------------------------------------------------------


def _brute_minimum(cands, required, covers):
    """Reference minimum set cover with the same lexicographic tie-break."""
    best = None
    for size in range(1, len(cands) + 1):
        for combo in itertools.combinations(sorted(cands), size):
            if all(any(covers(v, r) for v in combo) for r in required):
                chosen = list(combo)
                if best is None or chosen < best:
                    best = chosen
        if best is not None:
            return best
    return None


@pytest.mark.parametrize("seed", range(200))
def test_minimum_variant_set_matches_brute_force(seed):
    rng = random.Random(seed)
    n_clients = rng.randint(1, 6)
    n_variants = rng.randint(1, 6)
    required = [f"client{i}" for i in range(n_clients)]
    variants = [tuple(f"v{j}") for j in range(n_variants)]
    # Random coverage matrix; bias some rows/columns to all-covered/uncovered.
    matrix = {
        (v, c): rng.random() < rng.choice((0.15, 0.4, 0.7, 1.0))
        for v in variants for c in required
    }

    def covers(v, c):
        return matrix[v, c]

    expected = _brute_minimum(variants, required, covers)
    got = minimum_variant_set(variants, required, covers)
    assert got == expected


def test_minimum_variant_set_lexicographic_tie_break():
    # Two equally sized sets ({a,c}, {b,d}) cover everything; {a,c} wins.
    cands = [("a",), ("b",), ("c",), ("d",)]
    required = ["x", "y"]
    coverage = {
        ("a",): {"x"},
        ("b",): {"x"},
        ("c",): {"y"},
        ("d",): {"y"},
    }
    got = minimum_variant_set(
        cands, required, lambda v, r: r in coverage[v])
    assert got == [("a",), ("c",)]

    # Input order must not change the result.
    got_rev = minimum_variant_set(
        list(reversed(cands)), required, lambda v, r: r in coverage[v])
    assert got_rev == [("a",), ("c",)]


def test_minimum_variant_set_none_when_uncoverable():
    assert minimum_variant_set(
        [("a",), ("b",)], ["x", "y"],
        lambda v, r: (v == ("a",) and r == "x")) is None


def test_greedy_would_fail_but_exact_solver_wins():
    # A concrete set-cover instance where "cover the most uncovered first"
    # greedy is suboptimal:
    #   required {1,2,3,4}; v1 covers {1,2,3}, v2 covers {1}, v3 covers
    #   {2}, v4 covers {3,4}. Greedy picks v1 then v4 = 2 (optimal here),
    # so use the classic: v* covers {1,2}, a={1,3}, b={2,4}, c={3},
    # d={4}. Greedy starting with the biggest set v* then needs a and b = 3
    # variants; the optimum is {a,b} = 2.
    cands = [("vstar",), ("a",), ("b",), ("c",), ("d",)]
    required = ["1", "2", "3", "4"]
    coverage = {
        ("vstar",): {"1", "2"},
        ("a",): {"1", "3"},
        ("b",): {"2", "4"},
        ("c",): {"3"},
        ("d",): {"4"},
    }
    got = minimum_variant_set(
        cands, required, lambda v, r: r in coverage[v])
    assert got == [("a",), ("b",)]
