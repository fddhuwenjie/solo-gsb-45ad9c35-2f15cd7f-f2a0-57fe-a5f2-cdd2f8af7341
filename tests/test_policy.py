"""Tests for POST /deployments/policy-review (purpose & path-policy review)."""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.main import app
from app.policy import (
    KNOWN_CRITICAL_EXTENSIONS,
    _key_usages,
)

NOW = datetime(2030, 1, 1, tzinfo=timezone.utc)

SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
ANY_EKU = "2.5.29.37.0"
CUSTOM_EKU = "1.3.6.1.4.1.99999.1.1"
UNKNOWN_CRIT_OID = "1.2.3.4.5.6.7.8.99"

client = TestClient(app)


# ---------------------------------------------------------------------------
# PKI factory
# ---------------------------------------------------------------------------


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _dn(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _issue(
    subject_cn, issuer_name, issuer_key, subject_key=None,
    *, is_ca=False, path_length=None, key_usage="default",
    ekus=(), not_before=None, not_after=None, extra=(),
    omit_basic_constraints=False, dns_names=(),
):
    """Sign a certificate.

    key_usage: "default" -> CA KU for CAs / digitalSignature for leaves;
               None -> omit KeyUsage; otherwise an x509.KeyUsage instance.
    """
    subject_key = subject_key or _key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(_dn(subject_cn))
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or NOW - timedelta(days=365))
        .not_valid_after(not_after or NOW + timedelta(days=3650))
    )
    if not omit_basic_constraints:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=path_length),
            critical=True,
        )
    if key_usage == "default":
        if is_ca:
            ku = x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            )
        else:
            ku = x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            )
        builder = builder.add_extension(ku, critical=True)
    elif key_usage is not None:
        builder = builder.add_extension(key_usage, critical=True)
    if ekus:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(
                [x509.ObjectIdentifier(o) for o in ekus]),
            critical=False,
        )
    if dns_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(n) for n in dns_names]),
            critical=False,
        )
    for ext, critical in extra:
        builder = builder.add_extension(ext, critical=critical)
    return builder.sign(issuer_key, hashes.SHA256()), subject_key


def _root(cn="Root CA", **kwargs):
    key = _key()
    cert, _ = _issue(cn, _dn(cn), key, key, is_ca=True, **kwargs)
    return cert, key


def pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def fp(cert) -> str:
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def _call(bundle, roots, endpoints, check_time=NOW):
    return client.post("/deployments/policy-review", json={
        "pem_certificates": [pem(c) for c in bundle],
        "trust_roots": [fp(r) for r in roots],
        "check_time": check_time.isoformat(),
        "endpoints": endpoints,
    })


def _ep(endpoint_id, cur, tgt, role="server", required_ekus=()):
    return {
        "endpoint_id": endpoint_id,
        "current_leaf_fingerprint": fp(cur),
        "target_leaf_fingerprint": fp(tgt),
        "role": role,
        "required_ekus": list(required_ekus),
    }


@pytest.fixture
def clean_chain():
    root, rk = _root()
    inter, ik = _issue("Intermediate CA", _dn("Root CA"), rk, is_ca=True)
    leaf, _ = _issue("svc.example", _dn("Intermediate CA"), ik,
                     ekus=[SERVER_AUTH], dns_names=["svc.example"])
    return root, inter, leaf


# ---------------------------------------------------------------------------
# Happy path + DTO
# ---------------------------------------------------------------------------


class TestHappyPath:
    def test_compliant_chains_eligible(self, clean_chain):
        root, inter, leaf = clean_chain
        r = _call([root, inter, leaf], [root],
                  [_ep("svc.example", leaf, leaf)])
        assert r.status_code == 200, r.text
        res = r.json()["results"][0]
        assert res["eligible"] is True
        assert res["reason"] == "ok"
        for ch in ("current_chain", "target_chain"):
            assert res[ch]["eligible"] is True
            assert res[ch]["reason"] == "ok"
            assert res[ch]["conflicts"] == []
            positions = [c["chain_position"] for c in res[ch]["certificates"]]
            assert positions == [0, 1, 2]
            roles = [c["role"] for c in res[ch]["certificates"]]
            assert roles == ["leaf", "intermediate", "trust_root"]

    def test_leaf_metadata_reflects_extensions(self, clean_chain):
        root, inter, leaf = clean_chain
        r = _call([root, inter, leaf], [root],
                  [_ep("svc.example", leaf, leaf)])
        certs = r.json()["results"][0]["target_chain"]["certificates"]
        leaf_dto, inter_dto, root_dto = certs
        assert leaf_dto["is_ca"] is False
        assert leaf_dto["key_usages"] == ["digital_signature"]
        assert leaf_dto["extended_key_usages"] == [SERVER_AUTH]
        assert leaf_dto["path_length_constraint"] is None
        assert inter_dto["is_ca"] is True
        assert "key_cert_sign" in inter_dto["key_usages"]
        assert root_dto["role"] == "trust_root"
        # basicConstraints is critical on all factory certs.
        assert "2.5.29.19" in root_dto["critical_extension_oids"]

    def test_results_sorted_by_endpoint_id(self, clean_chain):
        root, inter, leaf = clean_chain
        eps = [_ep(name, leaf, leaf) for name in ("z.example", "a.example")]
        r = _call([root, inter, leaf], [root], eps)
        names = [x["endpoint_id"] for x in r.json()["results"]]
        assert names == ["a.example", "z.example"]


# ---------------------------------------------------------------------------
# Validity
# ---------------------------------------------------------------------------


class TestValidity:
    def test_expired_leaf(self):
        root, rk = _root()
        inter, ik = _issue("Intermediate CA", _dn("Root CA"), rk,
                           is_ca=True)
        old_leaf, _ = _issue(
            "old.example", _dn("Intermediate CA"), ik,
            not_after=NOW - timedelta(days=1), ekus=[SERVER_AUTH])
        new_leaf, _ = _issue(
            "new.example", _dn("Intermediate CA"), ik,
            ekus=[SERVER_AUTH])
        r = _call([root, inter, old_leaf, new_leaf], [root],
                  [_ep("old.example", old_leaf, new_leaf)])
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert res["reason"] == "certificate_expired"
        c = res["current_chain"]["conflicts"][0]
        assert c["reason"] == "certificate_expired"
        assert c["chain_position"] == 0
        assert c["not_valid_after"] is not None

    def test_not_yet_valid_intermediate(self):
        root, rk = _root()
        inter, ik = _issue(
            "Future CA", _dn("Root CA"), rk, is_ca=True,
            not_before=NOW + timedelta(days=10))
        leaf, _ = _issue("svc.example", _dn("Future CA"), ik,
                         ekus=[SERVER_AUTH])
        r = _call([root, inter, leaf], [root],
                  [_ep("svc.example", leaf, leaf)])
        conflict = r.json()["results"][0]["current_chain"]["conflicts"][0]
        assert conflict["reason"] == "certificate_not_yet_valid"
        assert conflict["chain_position"] == 1
        assert conflict["not_valid_before"] is not None

    def test_expired_trust_root_fails(self):
        root, rk = _root(not_after=NOW - timedelta(days=1))
        inter, ik = _issue("Inter CA", _dn("Root CA"), rk, is_ca=True)
        leaf, _ = _issue("svc.example", _dn("Inter CA"), ik,
                         ekus=[SERVER_AUTH])
        r = _call([root, inter, leaf], [root],
                  [_ep("svc.example", leaf, leaf)])
        conflicts = r.json()["results"][0]["current_chain"]["conflicts"]
        assert any(
            x["reason"] == "certificate_expired"
            and x["chain_position"] == 2 for x in conflicts)
        assert r.json()["results"][0]["eligible"] is False

    def test_validity_inclusive_bounds(self):
        # A certificate exactly at its notAfter still passes.
        root, rk = _root()
        inter, ik = _issue("Inter CA", _dn("Root CA"), rk, is_ca=True)
        edge_leaf, _ = _issue(
            "edge.example", _dn("Inter CA"), ik,
            not_after=NOW, ekus=[SERVER_AUTH])
        r = _call([root, inter, edge_leaf], [root],
                  [_ep("edge.example", edge_leaf, edge_leaf)])
        assert r.json()["results"][0]["eligible"] is True


# ---------------------------------------------------------------------------
# BasicConstraints / CA / pathLen
# ---------------------------------------------------------------------------


class TestBasicConstraints:
    def test_missing_basic_constraints_on_intermediate(self):
        root, rk = _root()
        inter, ik = _issue("Inter CA", _dn("Root CA"), rk, is_ca=True,
                           omit_basic_constraints=True)
        leaf, _ = _issue("svc.example", _dn("Inter CA"), ik,
                         ekus=[SERVER_AUTH])
        r = _call([root, inter, leaf], [root],
                  [_ep("svc.example", leaf, leaf)])
        conflicts = r.json()["results"][0]["current_chain"]["conflicts"]
        assert any(x["reason"] == "missing_basic_constraints"
                   and x["chain_position"] == 1 for x in conflicts)

    def test_not_ca_intermediate(self):
        root, rk = _root()
        # is_ca=False but still issues a leaf -> not_ca
        inter, ik = _issue("Inter CA", _dn("Root CA"), rk, is_ca=False)
        leaf, _ = _issue("svc.example", _dn("Inter CA"), ik,
                         ekus=[SERVER_AUTH])
        r = _call([root, inter, leaf], [root],
                  [_ep("svc.example", leaf, leaf)])
        reasons = [x["reason"] for x in
                   r.json()["results"][0]["current_chain"]["conflicts"]]
        assert "not_ca" in reasons

    def test_missing_basic_constraints_on_root(self):
        # A self-signed anchor without basicConstraints must still fail the
        # CA-position review.
        key = _key()
        root, key = _issue("Root CA", _dn("Root CA"), key, key,
                           is_ca=True, omit_basic_constraints=True)
        leaf, _ = _issue("svc.example", _dn("Root CA"), key,
                         ekus=[SERVER_AUTH])
        r = _call([root, leaf], [root],
                  [_ep("svc.example", leaf, leaf)])
        conflicts = r.json()["results"][0]["current_chain"]["conflicts"]
        assert any(x["reason"] == "missing_basic_constraints"
                   and x["chain_position"] == 1 for x in conflicts)

    def test_leaf_marked_ca(self):
        root, rk = _root()
        leaf_key = _key()
        leaf, _ = _issue("svc.example", _dn("Root CA"), rk, leaf_key,
                         is_ca=True, ekus=[SERVER_AUTH])
        r = _call([root, leaf], [root],
                  [_ep("svc.example", leaf, leaf)])
        conflicts = r.json()["results"][0]["current_chain"]["conflicts"]
        assert any(x["reason"] == "leaf_marked_ca" for x in conflicts)


class TestPathLen:
    def _depth_chain(self, root_pl=None, inter_pl=None):
        root_key = _key()
        root, _ = _issue("Root CA", _dn("Root CA"), root_key, root_key,
                         is_ca=True, path_length=root_pl)
        i1_key = _key()
        i1, _ = _issue("I1 CA", _dn("Root CA"), root_key, i1_key,
                       is_ca=True, path_length=inter_pl)
        i2_key = _key()
        i2, _ = _issue("I2 CA", _dn("I1 CA"), i1_key, i2_key, is_ca=True)
        leaf, _ = _issue("svc.example", _dn("I2 CA"), i2_key,
                         ekus=[SERVER_AUTH])
        return root, i1, i2, leaf

    def test_pathlen_zero_root_with_direct_leaf_is_fine(self):
        # root pl=0, the leaf is issued directly by the root: 0 subordinate
        # intermediate CAs below the anchor.
        root, rk = _root(path_length=0)
        leaf, _ = _issue("svc.example", _dn("Root CA"), rk,
                         ekus=[SERVER_AUTH])
        r = _call([root, leaf], [root],
                  [_ep("svc.example", leaf, leaf)])
        assert r.json()["results"][0]["eligible"] is True

    def test_pathlen_zero_root_with_one_intermediate_violates(self):
        # RFC 5280: pathLen counts the non-self-issued intermediates that
        # *follow* the CA toward the leaf, so root pl=0 forbids any.
        root, rk = _root(path_length=0)
        inter, ik = _issue("I CA", _dn("Root CA"), rk, is_ca=True)
        leaf, _ = _issue("svc.example", _dn("I CA"), ik,
                         ekus=[SERVER_AUTH])
        r = _call([root, inter, leaf], [root],
                  [_ep("svc.example", leaf, leaf)])
        conflicts = r.json()["results"][0]["current_chain"]["conflicts"]
        hit = [x for x in conflicts if x["reason"] == "path_len_violation"]
        assert hit and hit[0]["chain_position"] == 2
        assert hit[0]["subordinate_ca_count"] == 1

    def test_pathlen_zero_root_with_two_intermediates_violates(self):
        root, i1, i2, leaf = self._depth_chain(root_pl=0)
        r = _call([root, i1, i2, leaf], [root],
                  [_ep("svc.example", leaf, leaf)])
        conflicts = r.json()["results"][0]["current_chain"]["conflicts"]
        hit = [x for x in conflicts if x["reason"] == "path_len_violation"]
        # leaf-first chain = [leaf, i2, i1, root]; root is at position 3
        # with two subordinate intermediate CAs.
        assert hit and hit[0]["chain_position"] == 3
        assert hit[0]["path_length_constraint"] == 0
        assert hit[0]["subordinate_ca_count"] == 2

    def test_pathlen_one_root_with_two_intermediates_violates(self):
        root, i1, i2, leaf = self._depth_chain(root_pl=1)
        r = _call([root, i1, i2, leaf], [root],
                  [_ep("svc.example", leaf, leaf)])
        conflicts = r.json()["results"][0]["current_chain"]["conflicts"]
        hit = [x for x in conflicts if x["reason"] == "path_len_violation"]
        assert len(hit) == 1
        assert hit[0]["chain_position"] == 3
        assert hit[0]["subordinate_ca_count"] == 2

    def test_intermediate_pathlen_zero_with_below_ca_violates(self):
        # leaf-first chain = [leaf, i2, i1, root]; i1 sits at position 2 and
        # i2 is one subordinate intermediate below it.
        root, i1, i2, leaf = self._depth_chain(inter_pl=0)
        r = _call([root, i1, i2, leaf], [root],
                  [_ep("svc.example", leaf, leaf)])
        conflicts = r.json()["results"][0]["current_chain"]["conflicts"]
        hit = [x for x in conflicts if x["reason"] == "path_len_violation"]
        assert hit and hit[0]["chain_position"] == 2
        assert hit[0]["path_length_constraint"] == 0
        assert hit[0]["subordinate_ca_count"] == 1

    def test_self_issued_intermediate_does_not_consume_pathlen(self):
        # Root(pl=0) -> I (same SUBJECT DN as root -> self-issued) -> leaf.
        root_key = _key()
        root, _ = _issue("CA X", _dn("CA X"), root_key, root_key,
                         is_ca=True, path_length=0)
        i_key = _key()
        # Self-issued: subject DN equals issuer DN ("CA X").
        inter, _ = _issue("CA X", _dn("CA X"), root_key, i_key,
                          is_ca=True)
        leaf, _ = _issue("svc.example", _dn("CA X"), i_key,
                         ekus=[SERVER_AUTH])
        r = _call([root, inter, leaf], [root],
                  [_ep("svc.example", leaf, leaf)])
        conflicts = r.json()["results"][0]["current_chain"]["conflicts"]
        assert not any(x["reason"] == "path_len_violation" for x in conflicts)


class TestKeyCertSign:
    def test_intermediate_without_keycertsign(self):
        root, rk = _root()
        no_kcs = x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, crl_sign=True,
            encipher_only=False, decipher_only=False)
        inter, ik = _issue("Inter CA", _dn("Root CA"), rk, is_ca=True,
                           key_usage=no_kcs)
        leaf, _ = _issue("svc.example", _dn("Inter CA"), ik,
                         ekus=[SERVER_AUTH])
        r = _call([root, inter, leaf], [root],
                  [_ep("svc.example", leaf, leaf)])
        conflicts = r.json()["results"][0]["current_chain"]["conflicts"]
        assert any(x["reason"] == "missing_key_cert_sign"
                   and x["chain_position"] == 1 for x in conflicts)

    def test_intermediate_without_keyusage_extension_is_allowed(self):
        # Absent KU imposes no bit requirement.
        root, rk = _root()
        inter, ik = _issue("Inter CA", _dn("Root CA"), rk, is_ca=True,
                           key_usage=None)
        leaf, _ = _issue("svc.example", _dn("Inter CA"), ik,
                         ekus=[SERVER_AUTH], key_usage=None)
        r = _call([root, inter, leaf], [root],
                  [_ep("svc.example", leaf, leaf)])
        assert r.json()["results"][0]["eligible"] is True


# ---------------------------------------------------------------------------
# Leaf purpose: KeyUsage / EKU
# ---------------------------------------------------------------------------


def _ku(**bits):
    defaults = dict(
        digital_signature=False, content_commitment=False,
        key_encipherment=False, data_encipherment=False,
        key_agreement=False, key_cert_sign=False, crl_sign=False,
        encipher_only=False, decipher_only=False)
    defaults.update(bits)
    return x509.KeyUsage(**defaults)


class TestLeafKeyUsage:
    def _root_leaf(self, ku, role="server"):
        root, rk = _root()
        eku = SERVER_AUTH if role == "server" else CLIENT_AUTH
        leaf, _ = _issue("svc.example", _dn("Root CA"), rk, key_usage=ku,
                         ekus=[eku])
        return root, leaf

    def test_server_key_encipherment_only_accepted(self):
        root, leaf = self._root_leaf(_ku(key_encipherment=True), "server")
        r = _call([root, leaf], [root], [_ep("s", leaf, leaf)])
        assert r.json()["results"][0]["eligible"] is True

    def test_server_digital_signature_accepted(self):
        root, leaf = self._root_leaf(_ku(digital_signature=True), "server")
        r = _call([root, leaf], [root], [_ep("s", leaf, leaf)])
        assert r.json()["results"][0]["eligible"] is True

    def test_server_data_encipherment_only_rejected(self):
        root, leaf = self._root_leaf(_ku(data_encipherment=True), "server")
        r = _call([root, leaf], [root], [_ep("s", leaf, leaf)])
        conflicts = r.json()["results"][0]["current_chain"]["conflicts"]
        hit = [x for x in conflicts if x["reason"]
               == "leaf_key_usage_mismatch"]
        assert hit
        assert hit[0]["required_key_usages"] == [
            "digital_signature", "key_encipherment"]
        assert hit[0]["present_key_usages"] == ["data_encipherment"]

    def test_client_needs_digital_signature(self):
        root, leaf = self._root_leaf(_ku(key_encipherment=True), "client")
        r = _call([root, leaf], [root],
                  [_ep("s", leaf, leaf, role="client")])
        conflicts = r.json()["results"][0]["current_chain"]["conflicts"]
        hit = [x for x in conflicts if x["reason"]
               == "leaf_key_usage_mismatch"]
        assert hit and hit[0]["required_key_usages"] == ["digital_signature"]

    def test_client_digital_signature_ok(self):
        root, leaf = self._root_leaf(_ku(digital_signature=True), "client")
        r = _call([root, leaf], [root],
                  [_ep("s", leaf, leaf, role="client")])
        assert r.json()["results"][0]["eligible"] is True

    def test_absent_keyusage_does_not_gate(self):
        root, rk = _root()
        leaf, _ = _issue("svc.example", _dn("Root CA"), rk, key_usage=None,
                         ekus=[SERVER_AUTH])
        r = _call([root, leaf], [root], [_ep("s", leaf, leaf)])
        assert r.json()["results"][0]["eligible"] is True


class TestEku:
    def test_server_leaf_without_server_auth(self):
        root, rk = _root()
        leaf, _ = _issue("svc.example", _dn("Root CA"), rk,
                         ekus=[CLIENT_AUTH])
        r = _call([root, leaf], [root], [_ep("s", leaf, leaf)])
        conflicts = r.json()["results"][0]["current_chain"]["conflicts"]
        hit = [x for x in conflicts if x["reason"]
               == "required_eku_missing"]
        assert hit and hit[0]["required_eku"] == SERVER_AUTH
        assert hit[0]["present_ekus"] == [CLIENT_AUTH]

    def test_client_leaf_without_client_auth(self):
        root, rk = _root()
        leaf, _ = _issue("svc.example", _dn("Root CA"), rk,
                         ekus=[SERVER_AUTH])
        r = _call([root, leaf], [root],
                  [_ep("s", leaf, leaf, role="client")])
        conflicts = r.json()["results"][0]["current_chain"]["conflicts"]
        hit = [x for x in conflicts if x["reason"]
               == "required_eku_missing"]
        assert hit and hit[0]["required_eku"] == CLIENT_AUTH

    def test_leaf_without_eku_extension_rejected(self):
        root, rk = _root()
        leaf, _ = _issue("svc.example", _dn("Root CA"), rk, ekus=())
        r = _call([root, leaf], [root], [_ep("s", leaf, leaf)])
        conflicts = r.json()["results"][0]["current_chain"]["conflicts"]
        assert any(x["reason"] == "required_eku_missing"
                   and x["present_ekus"] == [] for x in conflicts)

    def test_required_caller_eku_missing(self):
        root, rk = _root()
        leaf, _ = _issue("svc.example", _dn("Root CA"), rk,
                         ekus=[SERVER_AUTH])
        r = _call([root, leaf], [root],
                  [_ep("s", leaf, leaf, required_ekus=[CUSTOM_EKU])])
        conflicts = r.json()["results"][0]["current_chain"]["conflicts"]
        assert any(x["required_eku"] == CUSTOM_EKU for x in conflicts
                   if x["reason"] == "required_eku_missing")

    def test_required_caller_eku_present(self):
        root, rk = _root()
        leaf, _ = _issue("svc.example", _dn("Root CA"), rk,
                         ekus=[SERVER_AUTH, CUSTOM_EKU])
        r = _call([root, leaf], [root],
                  [_ep("s", leaf, leaf, required_ekus=[CUSTOM_EKU])])
        assert r.json()["results"][0]["eligible"] is True

    def test_any_eku_satisfies_all_purposes(self):
        root, rk = _root()
        leaf, _ = _issue("svc.example", _dn("Root CA"), rk,
                         ekus=[ANY_EKU])
        r = _call([root, leaf], [root],
                  [_ep("s", leaf, leaf, required_ekus=[CUSTOM_EKU])])
        assert r.json()["results"][0]["eligible"] is True

    def test_intermediate_eku_must_chain_allow_purpose(self):
        root, rk = _root()
        inter, ik = _issue("Inter CA", _dn("Root CA"), rk, is_ca=True,
                           ekus=[CLIENT_AUTH])
        leaf, _ = _issue("svc.example", _dn("Inter CA"), ik,
                         ekus=[SERVER_AUTH])
        r = _call([root, inter, leaf], [root],
                  [_ep("s", leaf, leaf)])
        conflicts = r.json()["results"][0]["current_chain"]["conflicts"]
        hit = [x for x in conflicts if x["reason"]
               == "required_eku_missing" and x["chain_position"] == 1]
        assert hit and hit[0]["required_eku"] == SERVER_AUTH

    def test_intermediate_any_eku_chains(self):
        root, rk = _root()
        inter, ik = _issue("Inter CA", _dn("Root CA"), rk, is_ca=True,
                           ekus=[ANY_EKU])
        leaf, _ = _issue("svc.example", _dn("Inter CA"), ik,
                         ekus=[SERVER_AUTH, CUSTOM_EKU])
        r = _call([root, inter, leaf], [root],
                  [_ep("s", leaf, leaf, required_ekus=[CUSTOM_EKU])])
        assert r.json()["results"][0]["eligible"] is True

    def test_trust_anchor_eku_not_enforced(self):
        # An anchor asserting only clientAuth must not invalidate a server
        # chain below it.
        root, rk = _root(ekus=[CLIENT_AUTH])
        leaf, _ = _issue("svc.example", _dn("Root CA"), rk,
                         ekus=[SERVER_AUTH])
        r = _call([root, leaf], [root], [_ep("s", leaf, leaf)])
        assert r.json()["results"][0]["eligible"] is True


# ---------------------------------------------------------------------------
# Unknown critical extensions
# ---------------------------------------------------------------------------


class TestUnknownCriticalExtensions:
    def test_unknown_critical_extension_on_leaf(self):
        root, rk = _root()
        mystery = x509.UnrecognizedExtension(
            x509.ObjectIdentifier(UNKNOWN_CRIT_OID), b"\x04\x03abc")
        leaf, _ = _issue("svc.example", _dn("Root CA"), rk,
                         ekus=[SERVER_AUTH], extra=[(mystery, True)])
        r = _call([root, leaf], [root], [_ep("s", leaf, leaf)])
        conflicts = r.json()["results"][0]["current_chain"]["conflicts"]
        hit = [x for x in conflicts if x["reason"]
               == "unknown_critical_extension"]
        assert hit and hit[0]["extension_oid"] == UNKNOWN_CRIT_OID
        assert hit[0]["chain_position"] == 0

    def test_unknown_critical_extension_on_intermediate(self):
        root, rk = _root()
        mystery = x509.UnrecognizedExtension(
            x509.ObjectIdentifier(UNKNOWN_CRIT_OID), b"\x04\x03abc")
        inter, ik = _issue("Inter CA", _dn("Root CA"), rk, is_ca=True,
                           extra=[(mystery, True)])
        leaf, _ = _issue("svc.example", _dn("Inter CA"), ik,
                         ekus=[SERVER_AUTH])
        r = _call([root, inter, leaf], [root],
                  [_ep("s", leaf, leaf)])
        conflicts = r.json()["results"][0]["current_chain"]["conflicts"]
        assert any(x["reason"] == "unknown_critical_extension"
                   and x["chain_position"] == 1 for x in conflicts)

    def test_known_critical_extensions_pass(self):
        # nameConstraints is a recognized critical extension.
        import ipaddress
        root, rk = _root()
        nc = x509.NameConstraints(
            permitted_subtrees=[x509.DNSName(".example.com")],
            excluded_subtrees=None)
        inter, ik = _issue("Inter CA", _dn("Root CA"), rk, is_ca=True,
                           extra=[(nc, True)])
        leaf, _ = _issue("svc.example", _dn("Inter CA"), ik,
                         ekus=[SERVER_AUTH])
        r = _call([root, inter, leaf], [root],
                  [_ep("s", leaf, leaf)])
        conflicts = r.json()["results"][0]["current_chain"]["conflicts"]
        assert not any(x["reason"] == "unknown_critical_extension"
                       for x in conflicts)

    def test_catalogue_contains_core_rfc5280_oids(self):
        for oid in ("2.5.29.19", "2.5.29.15", "2.5.29.17", "2.5.29.30",
                    "2.5.29.32", "2.5.29.37", "2.5.29.54",
                    "1.3.6.1.5.5.7.1.1"):
            assert oid in KNOWN_CRITICAL_EXTENSIONS


# ---------------------------------------------------------------------------
# Both-chain gating / first conflict rule / stability
# ---------------------------------------------------------------------------


class TestEndpointGating:
    def test_current_bad_target_good_is_ineligible(self):
        root, rk = _root()
        cur, _ = _issue("svc.example", _dn("Root CA"), rk,
                        ekus=[CLIENT_AUTH])          # role mismatch
        tgt, _ = _issue("svc.example", _dn("Root CA"), rk,
                        ekus=[SERVER_AUTH])
        r = _call([root, cur, tgt], [root],
                  [_ep("svc.example", cur, tgt)])
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert res["reason"] == "required_eku_missing"
        assert res["current_chain"]["eligible"] is False
        assert res["target_chain"]["eligible"] is True

    def test_current_good_target_bad_is_ineligible(self):
        root, rk = _root()
        cur, _ = _issue("svc.example", _dn("Root CA"), rk,
                        ekus=[SERVER_AUTH])
        tgt, _ = _issue("svc.example", _dn("Root CA"), rk,
                        ekus=[CLIENT_AUTH])
        r = _call([root, cur, tgt], [root],
                  [_ep("svc.example", cur, tgt)])
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert res["reason"] == "required_eku_missing"
        assert res["current_chain"]["eligible"] is True
        assert res["target_chain"]["eligible"] is False

    def test_first_conflict_prefers_validity_over_extension(self):
        # A leaf both expired and carrying an unknown critical extension:
        # validity precedes unknown_critical_extension.
        root, rk = _root()
        mystery = x509.UnrecognizedExtension(
            x509.ObjectIdentifier(UNKNOWN_CRIT_OID), b"\x04\x03abc")
        leaf, _ = _issue(
            "svc.example", _dn("Root CA"), rk, ekus=[SERVER_AUTH],
            not_after=NOW - timedelta(days=1),
            extra=[(mystery, True)])
        r = _call([root, leaf], [root], [_ep("s", leaf, leaf)])
        conflicts = r.json()["results"][0]["current_chain"]["conflicts"]
        reasons = [x["reason"] for x in conflicts]
        assert reasons[0] == "certificate_expired"
        assert "unknown_critical_extension" in reasons
        # the chain's reported reason is the precedence-first rule
        assert r.json()["results"][0]["current_chain"]["reason"] == \
            "certificate_expired"

    def test_multiple_conflicts_stably_sorted(self):
        # CA-position intermediate missing basic constraints AND an expired
        # leaf: validity (pos 0) sorts before missing_basic_constraints by
        # reason precedence regardless of position.
        root, rk = _root()
        inter, ik = _issue("Inter CA", _dn("Root CA"), rk, is_ca=True,
                           omit_basic_constraints=True)
        leaf, _ = _issue("svc.example", _dn("Inter CA"), ik,
                         ekus=[SERVER_AUTH],
                         not_after=NOW - timedelta(days=1))
        r = _call([root, inter, leaf], [root],
                  [_ep("s", leaf, leaf)])
        conflicts = r.json()["results"][0]["current_chain"]["conflicts"]
        assert conflicts[0]["reason"] == "certificate_expired"
        assert conflicts[0]["chain_position"] == 0
        assert conflicts[1]["reason"] == "missing_basic_constraints"
        assert conflicts[1]["chain_position"] == 1

    def test_chains_are_independent_results(self, clean_chain):
        root, inter, leaf = clean_chain
        r = _call([root, inter, leaf], [root],
                  [_ep("svc.example", leaf, leaf)])
        cc = r.json()["results"][0]["current_chain"]
        tc = r.json()["results"][0]["target_chain"]
        assert cc["chain"] == tc["chain"] == [fp(leaf), fp(inter), fp(root)]


# ---------------------------------------------------------------------------
# Request-level errors -> 422
# ---------------------------------------------------------------------------


class TestRequestErrors:
    def test_invalid_eku_oid(self, clean_chain):
        root, inter, leaf = clean_chain
        r = _call([root, inter, leaf], [root],
                  [_ep("s", leaf, leaf, required_ekus=["9.x"])])
        assert r.status_code == 422
        d = r.json()["detail"]
        assert d["error"] == "invalid_oid"
        assert d["eku_issues"][0]["index"] == 0
        assert d["eku_issues"][0]["oid"] == "9.x"

    def test_invalid_fingerprint(self, clean_chain):
        root, inter, leaf = clean_chain
        ep = _ep("s", leaf, leaf)
        ep["target_leaf_fingerprint"] = "z" * 64
        r = _call([root, inter, leaf], [root], [ep])
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_fingerprint"

    def test_unknown_fingerprint(self, clean_chain):
        root, inter, leaf = clean_chain
        ep = _ep("s", leaf, leaf)
        ep["target_leaf_fingerprint"] = "a" * 64
        r = _call([root, inter, leaf], [root], [ep])
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "unknown_fingerprint"

    def test_bad_pem(self):
        r = client.post("/deployments/policy-review", json={
            "pem_certificates": ["not a pem"],
            "trust_roots": ["a" * 64],
            "check_time": NOW.isoformat(),
            "endpoints": [{
                "endpoint_id": "s",
                "current_leaf_fingerprint": "b" * 64,
                "target_leaf_fingerprint": "b" * 64,
                "role": "server", "required_ekus": []}],
        })
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_pem"

    def test_duplicate_endpoint_ids(self, clean_chain):
        root, inter, leaf = clean_chain
        r = _call([root, inter, leaf], [root],
                  [_ep("s", leaf, leaf), _ep("s", leaf, leaf)])
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_request"

    def test_no_trust_path_422(self):
        root, rk = _root()
        other_key = _key()
        leaf, _ = _issue("orphan.example", _dn("Unknown CA"), other_key,
                         ekus=[SERVER_AUTH])
        r = _call([root, leaf], [root],
                  [_ep("orphan.example", leaf, leaf)])
        assert r.status_code == 422
        d = r.json()["detail"]
        assert d["error"] == "no_trust_path"
        assert d["chain_issues"][0]["candidate_issuers"] == []

    def test_ambiguous_chain_422(self):
        rk1 = _key()
        r1, _ = _issue("R1", _dn("R1"), rk1, rk1, is_ca=True)
        rk2 = _key()
        r2, _ = _issue("R2", _dn("R2"), rk2, rk2, is_ca=True)
        ik = _key()
        i1, _ = _issue("I", _dn("R1"), rk1, ik, is_ca=True)
        i2, _ = _issue("I", _dn("R2"), rk2, ik, is_ca=True)
        leaf, _ = _issue("svc.example", _dn("I"), ik, ekus=[SERVER_AUTH])
        r = _call([r1, r2, i1, i2, leaf], [r1, r2],
                  [_ep("svc.example", leaf, leaf)])
        assert r.status_code == 422
        d = r.json()["detail"]
        assert d["error"] == "ambiguous_chain"
        paths = d["chain_issues"][0]["candidate_paths"]
        assert len(paths) >= 2

    def test_trust_root_not_self_signed_422(self, clean_chain):
        root, inter, leaf = clean_chain
        # Declare the intermediate as a trust root.
        r = _call([root, inter, leaf], [inter],
                  [_ep("s", leaf, leaf)])
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "trust_root_not_self_signed"


# ---------------------------------------------------------------------------
# Direct module call + naive check_time
# ---------------------------------------------------------------------------


def test_naive_check_time_treated_as_utc(clean_chain):
    root, inter, leaf = clean_chain
    r = client.post("/deployments/policy-review", json={
        "pem_certificates": [pem(c) for c in (root, inter, leaf)],
        "trust_roots": [fp(root)],
        "check_time": "2030-01-01T00:00:00",
        "endpoints": [_ep("svc.example", leaf, leaf)],
    })
    assert r.status_code == 200
    assert r.json()["results"][0]["eligible"] is True


def test_key_usage_helper(clean_chain):
    _, inter, _ = clean_chain
    assert "key_cert_sign" in _key_usages(inter)
