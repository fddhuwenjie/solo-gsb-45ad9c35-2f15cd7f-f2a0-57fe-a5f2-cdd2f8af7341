"""Tests for POST /scenarios/normalize."""
from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.main import app
from app.normalize import _find_trust_path, _has_second_trust_path

NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)

client = TestClient(app)


# ---------------------------------------------------------------------------
# Certificate factory
# ---------------------------------------------------------------------------


def _key(kind="ec"):
    if kind == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return ec.generate_private_key(ec.SECP256R1())


def _dn(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_cert(
    subject_cn,
    issuer_cn,
    issuer_key,
    *,
    subject_key=None,
    self_signed=False,
    not_before=None,
    not_after=None,
    is_ca=True,
    hash_alg=None,
):
    """Build a certificate; when self_signed, subject_key == issuer_key."""
    if self_signed:
        subject_key = issuer_key
        issuer_name = _dn(subject_cn)
    else:
        subject_key = subject_key or _key()
        issuer_name = _dn(issuer_cn)
    not_before = not_before or NOW - timedelta(days=365)
    not_after = not_after or NOW + timedelta(days=365)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_dn(subject_cn))
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None), critical=True
        )
    )
    return builder.sign(issuer_key, hash_alg or hashes.SHA256())


def pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def fp(cert) -> str:
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()


@pytest.fixture
def simple_pki():
    """old/root -> old/leaf and new/root -> inter -> new/leaf."""
    root_old_key = _key()
    root_old = make_cert("Old Root", None, root_old_key, self_signed=True)
    leaf_old = make_cert("svc.example", "Old Root", root_old_key, is_ca=False)

    root_new_key = _key()
    root_new = make_cert("New Root", None, root_new_key, self_signed=True)
    inter_new_key = _key()
    inter_new = make_cert("New Inter", "New Root", root_new_key,
                          subject_key=inter_new_key)
    leaf_new = make_cert("svc.example", "New Inter", inter_new_key, is_ca=False)
    return {
        "root_old": (root_old, root_old_key),
        "leaf_old": leaf_old,
        "root_new": (root_new, root_new_key),
        "inter_new": (inter_new, inter_new_key),
        "leaf_new": leaf_new,
    }


def _bundle(pki, *names):
    out = []
    for n in names:
        item = pki[n]
        out.append(pem(item[0] if isinstance(item, tuple) else item))
    return out


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_normalize_happy_path_reorders_and_verifies(simple_pki):
    pki = simple_pki
    # deliberately shuffled, with a duplicate DER copy in its own element
    pems = _bundle(pki, "leaf_new", "root_old", "inter_new", "leaf_old",
                   "root_new") + [pem(pki["inter_new"][0])]
    body = {
        "pem_certificates": pems,
        "trust_roots": [fp(pki["root_old"][0]), fp(pki["root_new"][0])],
        "endpoints": [{
            "endpoint_id": "svc.example",
            "current_leaf_fingerprint": fp(pki["leaf_old"]),
            "target_leaf_fingerprint": fp(pki["leaf_new"]),
        }],
    }
    r = client.post("/scenarios/normalize", json=body)
    assert r.status_code == 200, r.text
    data = r.json()

    assert {c["cert_id"] for c in data["certificates"]} == {
        fp(pki["root_old"][0]), fp(pki["leaf_old"]),
        fp(pki["root_new"][0]), fp(pki["inter_new"][0]),
        fp(pki["leaf_new"]),
    }  # duplicate DER collapsed
    by_id = {c["cert_id"]: c for c in data["certificates"]}
    ro = by_id[fp(pki["root_old"][0])]
    assert ro["subject"] == ro["issuer"] == "CN=Old Root"
    lo = by_id[fp(pki["leaf_old"])]
    assert lo["subject"] == "CN=svc.example"
    assert lo["issuer"] == "CN=Old Root"
    assert "not_valid_before" in ro and "not_valid_after" in ro

    ep = data["endpoints"][0]
    assert ep["endpoint_id"] == "svc.example"
    assert ep["current_chain"] == [
        fp(pki["leaf_old"]), fp(pki["root_old"][0])
    ]
    assert ep["target_chain"] == [
        fp(pki["leaf_new"]),
        fp(pki["inter_new"][0]),
        fp(pki["root_new"][0]),
    ]


def test_normalize_accepts_concatenated_pem_blocks_and_uppercase_fp(simple_pki):
    pki = simple_pki
    blob = "".join(_bundle(pki, "leaf_new", "inter_new", "root_new"))
    body = {
        "pem_certificates": [blob, pem(pki["leaf_old"]),
                             pem(pki["root_old"][0])],
        "trust_roots": [fp(pki["root_old"][0]).upper(),
                        fp(pki["root_new"][0])],
        "endpoints": [{
            "endpoint_id": "svc.example",
            "current_leaf_fingerprint": "  " + fp(pki["leaf_old"]) + "  ",
            "target_leaf_fingerprint": fp(pki["leaf_new"]).upper(),
        }],
    }
    r = client.post("/scenarios/normalize", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["endpoints"][0]["current_chain"][0] == fp(pki["leaf_old"])


def test_normalize_chain_ids_feed_planner(simple_pki):
    """The normalized payload is directly usable as planner input."""
    pki = simple_pki
    r = client.post("/scenarios/normalize", json={
        "pem_certificates": _bundle(
            pki, "leaf_new", "inter_new", "root_new",
            "leaf_old", "root_old"),
        "trust_roots": [fp(pki["root_old"][0]), fp(pki["root_new"][0])],
        "endpoints": [{
            "endpoint_id": "svc.example",
            "current_leaf_fingerprint": fp(pki["leaf_old"]),
            "target_leaf_fingerprint": fp(pki["leaf_new"]),
        }],
    })
    assert r.status_code == 200
    norm = r.json()

    plan_body = {
        "certificates": norm["certificates"],
        "trust_anchors": [
            {"client_id": "billing", "cert_id": norm["endpoints"][0]
             ["current_chain"][-1]},
        ],
        "endpoints": [{
            "endpoint_id": "svc.example",
            "current_chain": norm["endpoints"][0]["current_chain"],
            "target_chain": norm["endpoints"][0]["target_chain"],
        }],
        "relationships": [{"client_id": "billing",
                           "endpoint_id": "svc.example"}],
        "actions": [
            {"action_id": "add-new", "type": "add_trust",
             "client_id": "billing",
             "anchor_cert_id": norm["endpoints"][0]["target_chain"][-1],
             "allowed_stages": [1, 2]},
            {"action_id": "replace", "type": "replace_cert",
             "endpoint_id": "svc.example",
             "new_chain": norm["endpoints"][0]["target_chain"],
             "allowed_stages": [2]},
            {"action_id": "remove-old", "type": "remove_trust",
             "client_id": "billing",
             "anchor_cert_id": norm["endpoints"][0]["current_chain"][-1],
             "allowed_stages": [1, 2]},
        ],
        "plan_time": NOW.isoformat(),
    }
    r2 = client.post("/plans", json=plan_body)
    assert r2.status_code == 200, r2.text
    assert r2.json()["stage_count"] == 2


# ---------------------------------------------------------------------------
# 422: no trust path
# ---------------------------------------------------------------------------


def test_normalize_422_when_chain_does_not_reach_trust_root(simple_pki):
    pki = simple_pki
    r = client.post("/scenarios/normalize", json={
        # bundle has no root for the old leaf
        "pem_certificates": _bundle(
            pki, "leaf_old", "leaf_new", "inter_new", "root_new"),
        "trust_roots": [fp(pki["root_new"][0])],
        "endpoints": [{
            "endpoint_id": "svc.example",
            "current_leaf_fingerprint": fp(pki["leaf_old"]),
            "target_leaf_fingerprint": fp(pki["leaf_new"]),
        }],
    })
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error"] == "no_trust_path"
    issue = detail["chain_issues"][0]
    assert issue["endpoint_id"] == "svc.example"
    assert issue["leaf_role"] == "current"
    assert issue["leaf"] == fp(pki["leaf_old"])
    # leaf_old was genuinely signed by root_old, which is absent: nothing in
    # the bundle can verify its signature
    assert issue["candidate_issuers"] == []
    assert issue["candidate_paths"] == [[fp(pki["leaf_old"])]]


def test_normalize_422_lists_path_ending_before_root(simple_pki):
    pki = simple_pki
    # leaf + intermediate present, but the New Root that signs the intermediate
    # is neither in the bundle nor in trust_roots (the unrelated Old Root is)
    r = client.post("/scenarios/normalize", json={
        "pem_certificates": _bundle(
            pki, "leaf_new", "inter_new", "root_old"),
        "trust_roots": [fp(pki["root_old"][0])],
        "endpoints": [{
            "endpoint_id": "svc.example",
            "current_leaf_fingerprint": fp(pki["leaf_new"]),
            "target_leaf_fingerprint": fp(pki["leaf_new"]),
        }],
    })
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error"] == "no_trust_path"
    issue = detail["chain_issues"][0]
    assert issue["candidate_issuers"] == [fp(pki["inter_new"][0])]
    # dead-end path stops at the intermediate (it is not itself a trust root)
    assert issue["candidate_paths"] == [[
        fp(pki["leaf_new"]), fp(pki["inter_new"][0])
    ]]


def test_normalize_signature_check_not_dn_based():
    """A cert with matching issuer DN but wrong key must not become an edge."""
    root_key = _key()
    root = make_cert("Root CA", None, root_key, self_signed=True)
    imposter_key = _key()
    # same subject DN as the real root, but a different key pair
    imposter = make_cert("Root CA", None, imposter_key, self_signed=True)
    leaf = make_cert("svc", "Root CA", root_key, is_ca=False)

    r = client.post("/scenarios/normalize", json={
        "pem_certificates": [pem(leaf), pem(imposter)],
        "trust_roots": [fp(imposter)],
        "endpoints": [{
            "endpoint_id": "svc",
            "current_leaf_fingerprint": fp(leaf),
            "target_leaf_fingerprint": fp(leaf),
        }],
    })
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error"] == "no_trust_path"
    issue = detail["chain_issues"][0]
    # DN matches but imposter's key does not verify the leaf -> not a candidate
    assert issue["candidate_issuers"] == []


def test_normalize_accepts_cross_issuer_with_unmatched_dn():
    """A cert may be signed by a key whose certificate subject does NOT equal
    the issuer DN (cross-certification): signature verification is what counts.
    Both issuer-certificates are present; only the one that actually signed is
    picked, regardless of DN mismatch."""
    root_key = _key()
    root = make_cert("Real Root", None, root_key, self_signed=True)
    other_key = _key()
    other = make_cert("Other CA", None, other_key, self_signed=True)
    # leaf's issuer DN is 'Real Root', but sign it with the other CA's key
    leaf = make_cert("svc", "Real Root", other_key, is_ca=False)

    r = client.post("/scenarios/normalize", json={
        "pem_certificates": [pem(leaf), pem(other), pem(root)],
        "trust_roots": [fp(other), fp(root)],
        "endpoints": [{
            "endpoint_id": "svc",
            "current_leaf_fingerprint": fp(leaf),
            "target_leaf_fingerprint": fp(leaf),
        }],
    })
    assert r.status_code == 200, r.text
    # the DN-naive pre-filter skips 'Other CA', but signature verification
    # still establishes leaf -> Other CA as the unique valid edge
    assert r.json()["endpoints"][0]["current_chain"] == [fp(leaf), fp(other)]


def test_normalize_tampered_signature_rejected(simple_pki):
    pki = simple_pki
    leaf = pki["leaf_old"]
    der = bytearray(leaf.public_bytes(serialization.Encoding.DER))
    # flip a bit near the end (signature bytes) and re-encode as PEM
    der[-1] ^= 0x01
    tampered = x509.load_der_x509_certificate(bytes(der))
    r = client.post("/scenarios/normalize", json={
        "pem_certificates": [pem(tampered), pem(pki["root_old"][0])],
        "trust_roots": [fp(pki["root_old"][0])],
        "endpoints": [{
            "endpoint_id": "svc.example",
            "current_leaf_fingerprint": fp(tampered),
            "target_leaf_fingerprint": fp(tampered),
        }],
    })
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "no_trust_path"


# ---------------------------------------------------------------------------
# 422: cross-signing ambiguity
# ---------------------------------------------------------------------------


def test_normalize_422_on_cross_signing_ambiguity():
    """Two distinct roots both legitimately sign the same intermediate, so the
    leaf has two verified paths; normalization must refuse to pick one."""
    root_a_key, root_b_key = _key(), _key()
    root_a = make_cert("Root A", None, root_a_key, self_signed=True)
    root_b = make_cert("Root B", None, root_b_key, self_signed=True)
    inter_key = _key()
    # cross-certification: one inter key wrapped in two different issuer certs
    inter_a = make_cert("Shared Inter", "Root A", root_a_key,
                        subject_key=inter_key)
    inter_b = make_cert("Shared Inter", "Root B", root_b_key,
                        subject_key=inter_key)
    leaf = make_cert("svc", "Shared Inter", inter_key, is_ca=False)

    r = client.post("/scenarios/normalize", json={
        "pem_certificates": [pem(c) for c in
                             (leaf, inter_a, inter_b, root_a, root_b)],
        "trust_roots": [fp(root_a), fp(root_b)],
        "endpoints": [{
            "endpoint_id": "svc",
            "current_leaf_fingerprint": fp(leaf),
            "target_leaf_fingerprint": fp(leaf),
        }],
    })
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error"] == "ambiguous_chain"
    issue = detail["chain_issues"][0]
    assert issue["leaf"] == fp(leaf)
    # both cross-certified intermediates verify the leaf's signature
    assert set(issue["candidate_issuers"]) == {fp(inter_a), fp(inter_b)}
    path_tuples = {tuple(p) for p in issue["candidate_paths"]}
    assert (fp(leaf), fp(inter_a), fp(root_a)) in path_tuples
    assert (fp(leaf), fp(inter_b), fp(root_b)) in path_tuples


def test_normalize_unambiguous_when_only_one_root_trusted():
    """Same cross-signed bundle, but only Root A is declared: exactly one
    acceptable path -> success even though both edges verify."""
    root_a_key, root_b_key = _key(), _key()
    root_a = make_cert("Root A", None, root_a_key, self_signed=True)
    root_b = make_cert("Root B", None, root_b_key, self_signed=True)
    inter_key = _key()
    inter_a = make_cert("Shared Inter", "Root A", root_a_key,
                        subject_key=inter_key)
    inter_b = make_cert("Shared Inter", "Root B", root_b_key,
                        subject_key=inter_key)
    leaf = make_cert("svc", "Shared Inter", inter_key, is_ca=False)

    r = client.post("/scenarios/normalize", json={
        "pem_certificates": [pem(c) for c in
                             (leaf, inter_a, inter_b, root_a, root_b)],
        "trust_roots": [fp(root_a)],
        "endpoints": [{
            "endpoint_id": "svc",
            "current_leaf_fingerprint": fp(leaf),
            "target_leaf_fingerprint": fp(leaf),
        }],
    })
    assert r.status_code == 200, r.text
    chain = r.json()["endpoints"][0]["current_chain"]
    assert chain == [fp(leaf), fp(inter_a), fp(root_a)]


# ---------------------------------------------------------------------------
# 422: malformed input
# ---------------------------------------------------------------------------


def test_normalize_invalid_pem_reported_with_index():
    r = client.post("/scenarios/normalize", json={
        "pem_certificates": ["not a certificate at all"],
        "trust_roots": ["a" * 64],
        "endpoints": [{
            "endpoint_id": "svc",
            "current_leaf_fingerprint": "b" * 64,
            "target_leaf_fingerprint": "b" * 64,
        }],
    })
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error"] == "invalid_pem"
    assert detail["pem_issues"][0]["index"] == 0


def test_normalize_bad_fingerprint_format():
    key = _key()
    root = make_cert("Root", None, key, self_signed=True)
    r = client.post("/scenarios/normalize", json={
        "pem_certificates": [pem(root)],
        "trust_roots": ["ZZ" + "0" * 62],
        "endpoints": [{
            "endpoint_id": "svc",
            "current_leaf_fingerprint": fp(root),
            "target_leaf_fingerprint": fp(root),
        }],
    })
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error"] == "invalid_fingerprint"
    assert detail["fingerprint_issues"][0]["referred_by"] == "trust_roots"


def test_normalize_unknown_fingerprint(simple_pki):
    pki = simple_pki
    missing = "11" * 32
    r = client.post("/scenarios/normalize", json={
        "pem_certificates": _bundle(
            pki, "root_old", "root_new", "leaf_old",
            "leaf_new", "inter_new"),
        "trust_roots": [fp(pki["root_old"][0]), fp(pki["root_new"][0])],
        "endpoints": [{
            "endpoint_id": "svc.example",
            "current_leaf_fingerprint": missing,
            "target_leaf_fingerprint": fp(pki["leaf_new"]),
        }],
    })
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error"] == "unknown_fingerprint"
    issue = detail["fingerprint_issues"][0]
    assert issue["fingerprint"] == missing
    assert "current_leaf_fingerprint" in issue["referred_by"]


def test_normalize_trust_root_must_be_self_signed(simple_pki):
    pki = simple_pki
    r = client.post("/scenarios/normalize", json={
        "pem_certificates": _bundle(
            pki, "leaf_old", "root_old", "leaf_new",
            "inter_new", "root_new"),
        # intermediate declared as a root
        "trust_roots": [fp(pki["inter_new"][0])],
        "endpoints": [{
            "endpoint_id": "svc.example",
            "current_leaf_fingerprint": fp(pki["leaf_old"]),
            "target_leaf_fingerprint": fp(pki["leaf_new"]),
        }],
    })
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error"] == "trust_root_not_self_signed"
    assert detail["fingerprint_issues"][0]["fingerprint"] == fp(
        pki["inter_new"][0])


def test_normalize_duplicate_endpoint_ids_rejected(simple_pki):
    pki = simple_pki
    body = {
        "pem_certificates": _bundle(
            pki, "leaf_old", "root_old", "leaf_new",
            "inter_new", "root_new"),
        "trust_roots": [fp(pki["root_old"][0]), fp(pki["root_new"][0])],
        "endpoints": [
            {"endpoint_id": "svc",
             "current_leaf_fingerprint": fp(pki["leaf_old"]),
             "target_leaf_fingerprint": fp(pki["leaf_new"])},
            {"endpoint_id": "svc",
             "current_leaf_fingerprint": fp(pki["leaf_old"]),
             "target_leaf_fingerprint": fp(pki["leaf_new"])},
        ],
    }
    r = client.post("/scenarios/normalize", json=body)
    assert r.status_code == 422


def test_normalize_multiple_endpoints_and_sharing(simple_pki):
    pki = simple_pki
    r = client.post("/scenarios/normalize", json={
        "pem_certificates": _bundle(
            pki, "leaf_old", "root_old", "leaf_new",
            "inter_new", "root_new"),
        "trust_roots": [fp(pki["root_old"][0]), fp(pki["root_new"][0])],
        "endpoints": [
            {"endpoint_id": "a",
             "current_leaf_fingerprint": fp(pki["leaf_old"]),
             "target_leaf_fingerprint": fp(pki["leaf_new"])},
            {"endpoint_id": "b",
             "current_leaf_fingerprint": fp(pki["leaf_new"]),
             "target_leaf_fingerprint": fp(pki["leaf_new"])},
        ],
    })
    assert r.status_code == 200, r.text
    eps = r.json()["endpoints"]
    assert [e["endpoint_id"] for e in eps] == ["a", "b"]
    assert eps[1]["current_chain"][0] == fp(pki["leaf_new"])


def test_normalize_rsa_signed_chain():
    root_key = _key("rsa")
    root = make_cert("RSA Root", None, root_key, self_signed=True)
    leaf = make_cert("rsa-svc", "RSA Root", root_key, is_ca=False)
    r = client.post("/scenarios/normalize", json={
        "pem_certificates": [pem(leaf), pem(root)],
        "trust_roots": [fp(root)],
        "endpoints": [{
            "endpoint_id": "rsa-svc",
            "current_leaf_fingerprint": fp(leaf),
            "target_leaf_fingerprint": fp(leaf),
        }],
    })
    assert r.status_code == 200, r.text
    assert r.json()["endpoints"][0]["current_chain"] == [fp(leaf), fp(root)]


# ---------------------------------------------------------------------------
# Regression: the 64-entry diagnostic cap must not drive the verdict
# ---------------------------------------------------------------------------
#
# candidate_paths in a 422 response is a bounded diagnostic sample (at most
# 64 paths). The zero/unique/ambiguous verdict itself must stay exact even
# when a bundle contains more dead-end cross-signing branches than that:
# a trusted path sorted behind the truncation point is still found, and a
# second trusted path behind it still flips the verdict to ambiguous_chain.


def _regenerate_until(make, predicate):
    """Rebuild a cert (random serial => random fingerprint) until predicate
    holds for its fingerprint. Used to deterministically place a certificate
    after/before another one in the fingerprint-sorted traversal order."""
    while True:
        cert = make()
        if predicate(fp(cert)):
            return cert


def _dead_end_fanout(leaf_key, count=70):
    """One issuer of the leaf whose own issuer key is wrapped by ``count``
    cross-certified certs that lead nowhere: ``count`` dead-end paths of the
    shape leaf -> dead -> wrapper_i (more than the 64-path diagnostic cap)."""
    k0 = _key()
    dead = make_cert("Dead Branch", "K0 Wrappers", k0, subject_key=leaf_key)
    wrappers = [
        make_cert(f"K0 Wrapper {i}", f"Throwaway {i}", _key(), subject_key=k0)
        for i in range(count)
    ]
    return dead, wrappers


def test_normalize_valid_path_beyond_diagnostic_cap():
    """The only trusted path sorts behind >64 dead-end branches; the bounded
    diagnostic traversal must not truncate the search and report no_trust_path."""
    leaf_key = _key()
    leaf = make_cert("svc", "Leaf Issuer", leaf_key, is_ca=False)
    dead, wrappers = _dead_end_fanout(leaf_key)

    root_key = _key()
    root = make_cert("Root", None, root_key, self_signed=True)
    # valid issuer deterministically sorts after the dead-end branch
    valid = _regenerate_until(
        lambda: make_cert("Valid Issuer", "Root", root_key,
                          subject_key=leaf_key),
        lambda f: f > fp(dead),
    )

    r = client.post("/scenarios/normalize", json={
        "pem_certificates": [pem(c) for c in
                             [leaf, dead, *wrappers, valid, root]],
        "trust_roots": [fp(root)],
        "endpoints": [{
            "endpoint_id": "svc",
            "current_leaf_fingerprint": fp(leaf),
            "target_leaf_fingerprint": fp(leaf),
        }],
    })
    assert r.status_code == 200, r.text
    assert r.json()["endpoints"][0]["current_chain"] == [
        fp(leaf), fp(valid), fp(root)
    ]


def test_normalize_ambiguity_beyond_diagnostic_cap():
    """A second trusted path hidden behind >64 dead-end branches must still
    flip the verdict to ambiguous_chain instead of silently returning 200."""
    leaf_key = _key()
    leaf = make_cert("svc", "Leaf Issuer", leaf_key, is_ca=False)
    dead, wrappers = _dead_end_fanout(leaf_key)

    root_a_key, root_b_key = _key(), _key()
    root_a = make_cert("Root A", None, root_a_key, self_signed=True)
    root_b = make_cert("Root B", None, root_b_key, self_signed=True)
    # valid_a sorts before the dead-end fan-out, valid_b after it
    valid_a = _regenerate_until(
        lambda: make_cert("Valid A", "Root A", root_a_key,
                          subject_key=leaf_key),
        lambda f: f < fp(dead),
    )
    valid_b = _regenerate_until(
        lambda: make_cert("Valid B", "Root B", root_b_key,
                          subject_key=leaf_key),
        lambda f: f > fp(dead),
    )

    r = client.post("/scenarios/normalize", json={
        "pem_certificates": [pem(c) for c in
                             [leaf, dead, *wrappers,
                              valid_a, valid_b, root_a, root_b]],
        "trust_roots": [fp(root_a), fp(root_b)],
        "endpoints": [{
            "endpoint_id": "svc",
            "current_leaf_fingerprint": fp(leaf),
            "target_leaf_fingerprint": fp(leaf),
        }],
    })
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error"] == "ambiguous_chain"
    issue = detail["chain_issues"][0]
    assert issue["leaf"] == fp(leaf)
    assert set(issue["candidate_issuers"]) == {
        fp(dead), fp(valid_a), fp(valid_b)
    }


def test_normalize_no_trust_path_with_dead_end_fanout():
    """Only dead-end branches: still no_trust_path, and the diagnostic
    candidate_paths stay bounded by the 64-entry cap."""
    leaf_key = _key()
    leaf = make_cert("svc", "Leaf Issuer", leaf_key, is_ca=False)
    dead, wrappers = _dead_end_fanout(leaf_key)
    root_key = _key()
    root = make_cert("Root", None, root_key, self_signed=True)

    r = client.post("/scenarios/normalize", json={
        "pem_certificates": [pem(c) for c in [leaf, dead, *wrappers, root]],
        "trust_roots": [fp(root)],
        "endpoints": [{
            "endpoint_id": "svc",
            "current_leaf_fingerprint": fp(leaf),
            "target_leaf_fingerprint": fp(leaf),
        }],
    })
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error"] == "no_trust_path"
    issue = detail["chain_issues"][0]
    assert issue["candidate_issuers"] == [fp(dead)]
    paths = issue["candidate_paths"]
    assert 0 < len(paths) <= 64
    assert all(p[0] == fp(leaf) for p in paths)


# ---------------------------------------------------------------------------
# Regression: cycles and shared intermediates in the issuance graph
# ---------------------------------------------------------------------------


def test_normalize_cycle_with_single_exit_is_unique():
    """A cross-signed cycle (A <-> B) with exactly one exit to a trust root
    yields one valid path plus a cyclic dead-end: unique, not ambiguous."""
    leaf_key = _key()
    leaf = make_cert("svc", "A", leaf_key, is_ca=False)
    key_b = _key()
    cert_a = make_cert("A", "B", key_b, subject_key=leaf_key)
    cert_b = make_cert("B", "A", leaf_key, subject_key=key_b)  # A <-> B cycle
    root_key = _key()
    root = make_cert("Root", None, root_key, self_signed=True)
    # second wrapper of B's key, this one issued by the trusted root
    cert_b2 = make_cert("B", "Root", root_key, subject_key=key_b)

    r = client.post("/scenarios/normalize", json={
        "pem_certificates": [pem(c) for c in
                             (leaf, cert_a, cert_b, cert_b2, root)],
        "trust_roots": [fp(root)],
        "endpoints": [{
            "endpoint_id": "svc",
            "current_leaf_fingerprint": fp(leaf),
            "target_leaf_fingerprint": fp(leaf),
        }],
    })
    assert r.status_code == 200, r.text
    assert r.json()["endpoints"][0]["current_chain"] == [
        fp(leaf), fp(cert_a), fp(cert_b2), fp(root)
    ]


def test_normalize_cycle_without_exit_has_no_trust_path():
    """A cycle with no exit at all must terminate with no_trust_path, not hang."""
    leaf_key = _key()
    leaf = make_cert("svc", "A", leaf_key, is_ca=False)
    key_b = _key()
    cert_a = make_cert("A", "B", key_b, subject_key=leaf_key)
    cert_b = make_cert("B", "A", leaf_key, subject_key=key_b)
    root_key = _key()
    root = make_cert("Root", None, root_key, self_signed=True)

    r = client.post("/scenarios/normalize", json={
        "pem_certificates": [pem(c) for c in (leaf, cert_a, cert_b, root)],
        "trust_roots": [fp(root)],
        "endpoints": [{
            "endpoint_id": "svc",
            "current_leaf_fingerprint": fp(leaf),
            "target_leaf_fingerprint": fp(leaf),
        }],
    })
    assert r.status_code == 422
    assert r.json()["detail"]["error"] == "no_trust_path"


def test_normalize_shared_intermediate_diamond_is_ambiguous():
    """Two leaf issuers converge on one shared intermediate: two distinct
    verified paths through the shared node -> ambiguous_chain."""
    leaf_key = _key()
    leaf = make_cert("svc", "Shared CA", leaf_key, is_ca=False)
    shared_key = _key()
    inter_1 = make_cert("Inter 1", "Shared CA", shared_key,
                        subject_key=leaf_key)
    inter_2 = make_cert("Inter 2", "Shared CA", shared_key,
                        subject_key=leaf_key)
    root_key = _key()
    root = make_cert("Root", None, root_key, self_signed=True)
    shared = make_cert("Shared CA", "Root", root_key, subject_key=shared_key)

    r = client.post("/scenarios/normalize", json={
        "pem_certificates": [pem(c) for c in
                             (leaf, inter_1, inter_2, shared, root)],
        "trust_roots": [fp(root)],
        "endpoints": [{
            "endpoint_id": "svc",
            "current_leaf_fingerprint": fp(leaf),
            "target_leaf_fingerprint": fp(leaf),
        }],
    })
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error"] == "ambiguous_chain"
    issue = detail["chain_issues"][0]
    path_tuples = {tuple(p) for p in issue["candidate_paths"]}
    assert (fp(leaf), fp(inter_1), fp(shared), fp(root)) in path_tuples
    assert (fp(leaf), fp(inter_2), fp(shared), fp(root)) in path_tuples


# ---------------------------------------------------------------------------
# Differential: exact verdict vs brute-force simple-path enumeration
# ---------------------------------------------------------------------------


def _brute_force_trust_paths(leaf, edges, trust_roots):
    """Oracle: the set of ALL simple leaf-first paths ending at a trust root."""
    out = set()

    def walk(node, path, visited):
        if node in trust_roots:
            out.add(tuple(path))
            return
        for nxt in edges.get(node, []):
            if nxt in visited:
                continue
            visited.add(nxt)
            path.append(nxt)
            walk(nxt, path, visited)
            path.pop()
            visited.remove(nxt)

    walk(leaf, [leaf], {leaf})
    return out


@pytest.mark.parametrize("seed", range(200))
def test_trust_path_verdict_matches_brute_force(seed):
    """Random graphs (cycles, self-loops, shared nodes, sparse/dense): the
    exact zero/unique/ambiguous verdict must match full enumeration."""
    rng = random.Random(seed)
    n = rng.randint(1, 9)
    nodes = [f"c{i}" for i in range(n)]
    edges = {c: [] for c in nodes}
    density = rng.choice([0.1, 0.25, 0.5])
    for child in nodes:
        for issuer in nodes:
            if rng.random() < density:
                edges[child].append(issuer)
        edges[child].sort()
    trust_roots = frozenset(c for c in nodes if rng.random() < 0.3)
    leaf = rng.choice(nodes)

    expected = _brute_force_trust_paths(leaf, edges, trust_roots)
    first = _find_trust_path(leaf, edges, trust_roots)
    if not expected:
        assert first is None
        return
    assert first is not None
    assert tuple(first) in expected
    assert _has_second_trust_path(first, edges, trust_roots) == (
        len(expected) > 1
    )
