"""Tests for POST /deployments/precheck (deployment identity pre-check)."""
from __future__ import annotations

import hashlib
import ipaddress
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.main import app
from app.precheck import (
    dns_constraint_contains_wildcard,
    dns_constraint_intersects_wildcard,
    dns_constraint_matches,
    dns_san_covers,
    normalize_dns,
    normalize_dns_constraint,
    normalize_dns_san,
)

NOW = datetime(2026, 9, 1, tzinfo=timezone.utc)

client = TestClient(app)


# ---------------------------------------------------------------------------
# PKI factory
# ---------------------------------------------------------------------------


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _dn(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca(subject_cn, issuer_cn, issuer_key, subject_key=None,
        name_constraints=None):
    subject_key = subject_key or _key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(_dn(subject_cn))
        .issuer_name(_dn(issuer_cn))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=365))
        .not_valid_after(NOW + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                       critical=True)
    )
    if name_constraints is not None:
        builder = builder.add_extension(name_constraints, critical=True)
    return builder.sign(issuer_key, hashes.SHA256()), subject_key


def _root(cn):
    key = _key()
    cert, _ = _ca(cn, cn, key, key)
    return cert, key


def _leaf(issuer_cn, issuer_key, *, dns_names=(), ips=(), cn="svc",
          include_cn_san=True):
    key = _key()
    builder = (
        x509.CertificateBuilder()
        .subject_name(_dn(cn))
        .issuer_name(_dn(issuer_cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=365))
        .not_valid_after(NOW + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                       critical=True)
    )
    sans = [x509.DNSName(n) for n in dns_names]
    sans += [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(sans), critical=False
        )
    return builder.sign(issuer_key, hashes.SHA256())


def pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def fp(cert) -> str:
    return hashlib.sha256(
        cert.public_bytes(serialization.Encoding.DER)
    ).hexdigest()


def dns_constraint(*, permitted=None, excluded=None):
    return x509.NameConstraints(
        permitted_subtrees=[x509.DNSName(n) for n in (permitted or [])] or None,
        excluded_subtrees=[x509.DNSName(n) for n in (excluded or [])] or None,
    )


def ip_constraint(*, permitted=None, excluded=None):
    return x509.NameConstraints(
        permitted_subtrees=[
            x509.IPAddress(ipaddress.ip_network(n)) for n in (permitted or [])
        ] or None,
        excluded_subtrees=[
            x509.IPAddress(ipaddress.ip_network(n)) for n in (excluded or [])
        ] or None,
    )


def precheck(bundle, roots, endpoints):
    return client.post("/deployments/precheck", json={
        "pem_certificates": [pem(c) for c in bundle],
        "trust_roots": [fp(r) for r in roots],
        "endpoints": endpoints,
    })


def ep(endpoint_id, leaf, *identities):
    return {
        "endpoint_id": endpoint_id,
        "target_leaf_fingerprint": fp(leaf),
        "identities": [{"type": t, "value": v} for t, v in identities],
    }


# ---------------------------------------------------------------------------
# Pure normalization / matching rules
# ---------------------------------------------------------------------------


class TestDnsNormalization:
    def test_case_trailing_dot_and_idna(self):
        assert normalize_dns("API.Example.COM.") == "api.example.com"
        assert normalize_dns("BÜCHER.Example") == "xn--bcher-kva.example"
        # an already A-labeled name stays stable
        assert normalize_dns("xn--bcher-kva.example") == "xn--bcher-kva.example"

    def test_wildcard_rejected_in_claim(self):
        import pytest
        for bad in ("*.example.com", "a*.example.com", "*", "a.*.com"):
            with pytest.raises(ValueError):
                normalize_dns(bad)

    def test_empty_and_overlong(self):
        import pytest
        for bad in ("", ".", "example..com", ".example.com",
                    "a" * 64 + ".example.com"):
            with pytest.raises(ValueError):
                normalize_dns(bad)

    def test_san_wildcard_only_whole_leftmost_label(self):
        assert normalize_dns_san("*.example.com") == "*.example.com"
        assert normalize_dns_san("*.EXAMPLE.com.") == "*.example.com"
        for bad in ("*", "*.", "a*.example.com", "a.*.com",
                    "*.*.example.com", "*..com"):
            assert normalize_dns_san(bad) is None

    def test_constraint_normalization(self):
        assert normalize_dns_constraint(".Example.COM.") == ".example.com"
        assert normalize_dns_constraint("example.com") == "example.com"
        assert normalize_dns_constraint(".") is None
        assert normalize_dns_constraint("") is None


class TestWildcardMatching:
    def test_matches_exactly_one_leftmost_label(self):
        assert dns_san_covers("api.example.com", "*.example.com")
        assert not dns_san_covers("example.com", "*.example.com")
        assert not dns_san_covers("a.b.example.com", "*.example.com")

    def test_non_wildcard_is_exact(self):
        assert dns_san_covers("api.example.com", "api.example.com")
        assert not dns_san_covers("xapi.example.com", "api.example.com")


class TestConstraintMatching:
    def test_label_boundary(self):
        # bare subtree: the subtree itself and subdomains
        assert dns_constraint_matches("example.com", "example.com")
        assert dns_constraint_matches("api.example.com", "example.com")
        assert not dns_constraint_matches("evilexample.com", "example.com")
        assert not dns_constraint_matches("evil-example.com", "example.com")

    def test_leading_dot_is_subdomains_only(self):
        assert dns_constraint_matches("api.example.com", ".example.com")
        assert not dns_constraint_matches("example.com", ".example.com")


# ---------------------------------------------------------------------------
# End-to-end: eligible
# ---------------------------------------------------------------------------


class TestEligible:
    def test_simple_eligible_chain(self):
        root, root_key = _root("Root")
        inter, inter_key = _ca("Inter", "Root", root_key)
        leaf = _leaf("Inter", inter_key,
                     dns_names=["API.Example.COM", "api2.example.com"],
                     ips=["10.0.0.1", "2001:db8::1"])
        r = precheck(
            [root, inter, leaf], [root],
            [ep("e1", leaf, ("dns", "api.example.com."),
                ("dns", "API2.Example.COM"), ("ip", "10.0.0.1"),
                ("ip", "2001:db8::1"))],
        )
        assert r.status_code == 200, r.text
        res = r.json()["results"][0]
        assert res["eligible"] is True
        assert res["reason"] == "ok"
        assert res["dns_sans"] == ["api.example.com", "api2.example.com"]
        assert res["ip_sans"] == ["10.0.0.1", "2001:db8::1"]
        assert res["chain"] == [fp(leaf), fp(inter), fp(root)]
        assert {i["value"]: i["covered"] for i in res["identities"]} == {
            "10.0.0.1": True, "2001:db8::1": True,
            "api.example.com": True, "api2.example.com": True,
        }
        assert res["violations"] == []

    def test_idna_alabel_claim_and_san(self):
        root, root_key = _root("Root")
        inter, inter_key = _ca("Inter", "Root", root_key)
        leaf = _leaf("Inter", inter_key, dns_names=["xn--bcher-kva.example"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "bücher.example"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["eligible"] is True
        assert res["identities"][0]["value"] == "xn--bcher-kva.example"

    def test_wildcard_san_covers_one_label(self):
        root, root_key = _root("Root")
        inter, inter_key = _ca("Inter", "Root", root_key)
        leaf = _leaf("Inter", inter_key, dns_names=["*.example.com"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "api.example.com"))])
        assert r.status_code == 200
        assert r.json()["results"][0]["eligible"] is True

    def test_cn_is_not_a_fallback_identity(self):
        root, root_key = _root("Root")
        inter, inter_key = _ca("Inter", "Root", root_key)
        # CN says the name, but there is no SAN at all
        leaf = _leaf("Inter", inter_key, cn="api.example.com")
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "api.example.com"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert res["dns_sans"] == []
        assert res["violations"][0]["reason"] == "identity_not_covered"

    def test_ipv4_does_not_match_ipv6_san(self):
        root, root_key = _root("Root")
        inter, inter_key = _ca("Inter", "Root", root_key)
        leaf = _leaf("Inter", inter_key, ips=["10.0.0.1"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("ip", "::ffff:10.0.0.1"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert res["violations"][0]["reason"] == "identity_not_covered"


# ---------------------------------------------------------------------------
# identity_not_covered
# ---------------------------------------------------------------------------


class TestNotCovered:
    def test_claim_not_in_sans(self):
        root, root_key = _root("Root")
        inter, inter_key = _ca("Inter", "Root", root_key)
        leaf = _leaf("Inter", inter_key, dns_names=["api.example.com"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "other.example.com"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert res["reason"] == "identity_not_covered"
        v = res["violations"][0]
        assert v["reason"] == "identity_not_covered"
        assert v["identity_type"] == "dns"
        assert v["identity_value"] == "other.example.com"

    def test_wildcard_does_not_span_labels_or_apex(self):
        root, root_key = _root("Root")
        inter, inter_key = _ca("Inter", "Root", root_key)
        leaf = _leaf("Inter", inter_key, dns_names=["*.example.com"])
        for claim in ("example.com", "a.b.example.com"):
            r = precheck([root, inter, leaf], [root],
                         [ep("e", leaf, ("dns", claim))])
            assert r.status_code == 200
            res = r.json()["results"][0]
            assert res["eligible"] is False
            assert res["reason"] == "identity_not_covered"


# ---------------------------------------------------------------------------
# Excluded subtrees take precedence
# ---------------------------------------------------------------------------


class TestExcluded:
    def test_excluded_dns_wins(self):
        root, root_key = _root("Root")
        nc = dns_constraint(permitted=[".example.com"],
                            excluded=["bad.example.com"])
        inter, inter_key = _ca("Inter", "Root", root_key, name_constraints=nc)
        leaf = _leaf("Inter", inter_key, dns_names=["bad.example.com"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "bad.example.com"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert res["reason"] == "excluded_by_name_constraint"
        v = res["violations"][0]
        assert v["reason"] == "excluded_by_name_constraint"
        assert v["san"] == "bad.example.com"
        assert v["constraint"] == "bad.example.com"
        assert v["ca_fingerprint"] == fp(inter)

    def test_excluded_ip_wins(self):
        root, root_key = _root("Root")
        nc = ip_constraint(permitted=["10.0.0.0/8"],
                           excluded=["10.5.0.0/16"])
        inter, inter_key = _ca("Inter", "Root", root_key, name_constraints=nc)
        leaf = _leaf("Inter", inter_key, ips=["10.5.0.9"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("ip", "10.5.0.9"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["reason"] == "excluded_by_name_constraint"
        assert res["violations"][0]["constraint"] == "10.5.0.0/16"


# ---------------------------------------------------------------------------
# Permitted intersection
# ---------------------------------------------------------------------------


class TestPermittedIntersection:
    def _two_inters(self, nc1, nc2):
        root, root_key = _root("Root")
        inter1, i1_key = _ca("Inter1", "Root", root_key, name_constraints=nc1)
        inter2, i2_key = _ca("Inter2", "Inter1", i1_key, name_constraints=nc2)
        return root, inter1, inter2, i2_key

    def test_intersection_admits_overlap(self):
        root, i1, i2, i2_key = self._two_inters(
            dns_constraint(permitted=[".example.com"]),
            dns_constraint(permitted=[".api.example.com", "example.org"]),
        )
        leaf = _leaf("Inter2", i2_key, dns_names=["host.api.example.com"])
        r = precheck([root, i1, i2, leaf], [root],
                     [ep("e", leaf, ("dns", "host.api.example.com"))])
        assert r.status_code == 200
        assert r.json()["results"][0]["eligible"] is True

    def test_intersection_rejects_outside_second_ca(self):
        root, i1, i2, i2_key = self._two_inters(
            dns_constraint(permitted=[".example.com"]),
            dns_constraint(permitted=[".api.example.com"]),
        )
        leaf = _leaf("Inter2", i2_key, dns_names=["web.example.com"])
        r = precheck([root, i1, i2, leaf], [root],
                     [ep("e", leaf, ("dns", "web.example.com"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert res["reason"] == "not_within_permitted_subtree"
        v = res["violations"][0]
        assert v["san"] == "web.example.com"
        assert v["constraint"] == ".api.example.com"
        assert v["ca_fingerprint"] == fp(i2)

    def test_ip_intersection(self):
        root, i1, i2, i2_key = self._two_inters(
            ip_constraint(permitted=["10.0.0.0/8"]),
            ip_constraint(permitted=["10.2.0.0/16"]),
        )
        good = _leaf("Inter2", i2_key, ips=["10.2.0.7"])
        bad = _leaf("Inter2", i2_key, ips=["10.3.0.7"])
        r = precheck([root, i1, i2, good, bad], [root], [
            ep("g", good, ("ip", "10.2.0.7")),
            ep("b", bad, ("ip", "10.3.0.7")),
        ])
        assert r.status_code == 200
        by = {x["endpoint_id"]: x for x in r.json()["results"]}
        assert by["g"]["eligible"] is True
        assert by["b"]["eligible"] is False
        assert by["b"]["reason"] == "not_within_permitted_subtree"
        assert by["b"]["violations"][0]["constraint"] == "10.2.0.0/16"

    def test_permitted_ip_family_isolation(self):
        root, root_key = _root("Root")
        nc = ip_constraint(permitted=["10.0.0.0/8"])
        inter, inter_key = _ca("Inter", "Root", root_key, name_constraints=nc)
        leaf = _leaf("Inter", inter_key, ips=["2001:db8::1"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("ip", "2001:db8::1"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["reason"] == "not_within_permitted_subtree"
        # no same-family subtree to quote
        assert res["violations"][0]["constraint"] is None


# ---------------------------------------------------------------------------
# Every same-type SAN is checked
# ---------------------------------------------------------------------------


class TestAllSansChecked:
    def test_extra_dns_san_outside_permitted_fails_endpoint(self):
        root, root_key = _root("Root")
        nc = dns_constraint(permitted=[".example.com"])
        inter, inter_key = _ca("Inter", "Root", root_key, name_constraints=nc)
        # one claimed SAN is fine; an unclaimed extra SAN violates constraints
        leaf = _leaf("Inter", inter_key,
                     dns_names=["api.example.com", "leak.example.org"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "api.example.com"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert res["reason"] == "not_within_permitted_subtree"
        sans = [v["san"] for v in res["violations"]]
        assert "leak.example.org" in sans

    def test_extra_excluded_dns_san_fails(self):
        root, root_key = _root("Root")
        nc = dns_constraint(excluded=["revoked.example.com"])
        inter, inter_key = _ca("Inter", "Root", root_key, name_constraints=nc)
        leaf = _leaf("Inter", inter_key,
                     dns_names=["api.example.com", "revoked.example.com"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "api.example.com"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["reason"] == "excluded_by_name_constraint"

    def test_extra_ip_san_outside_permitted_fails(self):
        root, root_key = _root("Root")
        nc = ip_constraint(permitted=["10.0.0.0/8"])
        inter, inter_key = _ca("Inter", "Root", root_key, name_constraints=nc)
        leaf = _leaf("Inter", inter_key,
                     ips=["10.0.0.1", "192.168.0.1"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("ip", "10.0.0.1"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert "192.168.0.1" in [v["san"] for v in res["violations"]]

    def test_other_type_sans_do_not_gate(self):
        # Only same-type SANs are checked: an endpoint claiming no IP identity
        # is not gated by IP SANs outside the permitted subtrees.
        root, root_key = _root("Root")
        nc = ip_constraint(permitted=["10.0.0.0/8"])
        inter, inter_key = _ca("Inter", "Root", root_key, name_constraints=nc)
        leaf = _leaf("Inter", inter_key,
                     dns_names=["api.example.com"], ips=["192.168.0.1"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "api.example.com"))])
        assert r.status_code == 200
        assert r.json()["results"][0]["eligible"] is True


# ---------------------------------------------------------------------------
# Unsupported constraint types
# ---------------------------------------------------------------------------


class TestUnsupportedConstraints:
    def _leaf_under_constraint(self, nc):
        root, root_key = _root("Root")
        inter, inter_key = _ca("Inter", "Root", root_key, name_constraints=nc)
        leaf = _leaf("Inter", inter_key, dns_names=["api.example.com"])
        return root, inter, leaf

    def test_rfc822_constraint_is_unsupported(self):
        nc = x509.NameConstraints(
            permitted_subtrees=[x509.RFC822Name("example.com")],
            excluded_subtrees=None)
        root, inter, leaf = self._leaf_under_constraint(nc)
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "api.example.com"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert res["reason"] == "unsupported_constraint_type"
        v = res["violations"][0]
        assert v["constraint"] == "rfc822_name"
        assert v["ca_fingerprint"] == fp(inter)

    def test_uri_constraint_is_unsupported(self):
        nc = x509.NameConstraints(
            permitted_subtrees=[
                x509.UniformResourceIdentifier("https://example.com/")],
            excluded_subtrees=None)
        root, inter, leaf = self._leaf_under_constraint(nc)
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "api.example.com"))])
        res = r.json()["results"][0]
        assert res["reason"] == "unsupported_constraint_type"
        assert res["violations"][0]["constraint"] == "uri"

    def test_directory_name_constraint_is_unsupported(self):
        nc = x509.NameConstraints(
            permitted_subtrees=[x509.DirectoryName(_dn("CA Dept"))],
            excluded_subtrees=None)
        root, inter, leaf = self._leaf_under_constraint(nc)
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "api.example.com"))])
        res = r.json()["results"][0]
        assert res["reason"] == "unsupported_constraint_type"
        assert res["violations"][0]["constraint"] == "directory_name"


# ---------------------------------------------------------------------------
# Stable ordering
# ---------------------------------------------------------------------------


class TestOrdering:
    def test_results_sorted_by_endpoint_id_regardless_of_input(self):
        root, root_key = _root("Root")
        inter, inter_key = _ca("Inter", "Root", root_key)
        lz = _leaf("Inter", inter_key, dns_names=["z.example.com"])
        la = _leaf("Inter", inter_key, dns_names=["a.example.com"])
        endpoints = [ep("zeta", lz, ("dns", "z.example.com")),
                     ep("alpha", la, ("dns", "a.example.com"))]
        r = precheck([root, inter, la, lz], [root], endpoints)
        assert r.status_code == 200
        ids = [x["endpoint_id"] for x in r.json()["results"]]
        assert ids == ["alpha", "zeta"]

    def test_violations_stably_sorted(self):
        root, root_key = _root("Root")
        nc = dns_constraint(permitted=[".example.com"],
                            excluded=["bad.example.com"])
        inter, inter_key = _ca("Inter", "Root", root_key, name_constraints=nc)
        leaf = _leaf("Inter", inter_key,
                     dns_names=["bad.example.com", "out.example.org"])
        r = precheck([root, inter, leaf], [root], [
            ep("e", leaf, ("dns", "bad.example.com"),
               ("dns", "out.example.org"), ("dns", "unclaimed.example.net")),
        ])
        res = r.json()["results"][0]
        reasons = [v["reason"] for v in res["violations"]]
        # excluded first, then permitted, then not covered
        assert reasons.index("excluded_by_name_constraint") < \
            reasons.index("not_within_permitted_subtree")
        assert reasons.index("not_within_permitted_subtree") < \
            reasons.index("identity_not_covered")


# ---------------------------------------------------------------------------
# Trust anchor name constraints are NOT re-enforced
# ---------------------------------------------------------------------------


class TestTrustAnchorExcluded:
    def test_root_constraints_not_applied(self):
        # Per RFC 5280 the trust anchor's name constraints are not part of the
        # chain validation the leaf must satisfy here.
        root_key = _key()
        nc = dns_constraint(permitted=[".only-root.example"])
        root = (
            x509.CertificateBuilder()
            .subject_name(_dn("Root")).issuer_name(_dn("Root"))
            .public_key(root_key.public_key())
            .serial_number(1)
            .not_valid_before(NOW - timedelta(days=365))
            .not_valid_after(NOW + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                           critical=True)
            .add_extension(nc, critical=True)
            .sign(root_key, hashes.SHA256())
        )
        inter, inter_key = _ca("Inter", "Root", root_key)
        leaf = _leaf("Inter", inter_key, dns_names=["api.example.com"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "api.example.com"))])
        assert r.status_code == 200
        assert r.json()["results"][0]["eligible"] is True


# ---------------------------------------------------------------------------
# 422 errors
# ---------------------------------------------------------------------------


class Test422:
    def test_invalid_pem(self):
        root, _ = _root("Root")
        r = client.post("/deployments/precheck", json={
            "pem_certificates": ["nonsense"],
            "trust_roots": [fp(root)],
            "endpoints": [{"endpoint_id": "e",
                           "target_leaf_fingerprint": fp(root),
                           "identities": [{"type": "dns", "value": "a"}]}]})
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_pem"

    def test_bad_fingerprint_format(self):
        root, _ = _root("Root")
        r = precheck([root], [root],
                     [{"endpoint_id": "e",
                       "target_leaf_fingerprint": "zz" + "0" * 62,
                       "identities": [{"type": "dns", "value": "a.example"}]}])
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_fingerprint"

    def test_unknown_fingerprint(self):
        root, _ = _root("Root")
        missing = "11" * 32
        r = precheck([root], [root],
                     [{"endpoint_id": "e",
                       "target_leaf_fingerprint": missing,
                       "identities": [{"type": "dns", "value": "a.example"}]}])
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "unknown_fingerprint"

    def test_no_trust_path(self):
        root, root_key = _root("Root")
        other, other_key = _root("Other")
        leaf = _leaf("Root", root_key, dns_names=["api.example.com"])
        # leaf signed by root_key, but trust root is unrelated Other
        r = precheck([other, leaf], [other],
                     [ep("e", leaf, ("dns", "api.example.com"))])
        assert r.status_code == 422
        detail = r.json()["detail"]
        assert detail["error"] == "no_trust_path"
        assert detail["chain_issues"][0]["leaf_role"] == "target"
        assert detail["chain_issues"][0]["candidate_paths"]

    def test_ambiguous_chain(self):
        ra_key, rb_key = _key(), _key()
        root_a = (x509.CertificateBuilder()
                  .subject_name(_dn("A")).issuer_name(_dn("A"))
                  .public_key(ra_key.public_key()).serial_number(1)
                  .not_valid_before(NOW - timedelta(days=1))
                  .not_valid_after(NOW + timedelta(days=3650))
                  .add_extension(x509.BasicConstraints(ca=True,
                                                       path_length=None),
                                 critical=True)
                  .sign(ra_key, hashes.SHA256()))
        root_b = (x509.CertificateBuilder()
                  .subject_name(_dn("B")).issuer_name(_dn("B"))
                  .public_key(rb_key.public_key()).serial_number(2)
                  .not_valid_before(NOW - timedelta(days=1))
                  .not_valid_after(NOW + timedelta(days=3650))
                  .add_extension(x509.BasicConstraints(ca=True,
                                                       path_length=None),
                                 critical=True)
                  .sign(rb_key, hashes.SHA256()))
        inter_key = _key()
        inter_a, _ = _ca("Shared", "A", ra_key, inter_key)
        inter_b, _ = _ca("Shared", "B", rb_key, inter_key)
        leaf = _leaf("Shared", inter_key, dns_names=["api.example.com"])
        r = precheck([leaf, inter_a, inter_b, root_a, root_b],
                     [root_a, root_b],
                     [ep("e", leaf, ("dns", "api.example.com"))])
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "ambiguous_chain"

    def test_invalid_dns_identity(self):
        root, root_key = _root("Root")
        inter, inter_key = _ca("Inter", "Root", root_key)
        leaf = _leaf("Inter", inter_key, dns_names=["api.example.com"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "*.example.com"))])
        assert r.status_code == 422
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_identity"
        assert detail["identity_issues"][0]["endpoint_id"] == "e"
        assert detail["identity_issues"][0]["index"] == 0

    def test_invalid_ip_identity(self):
        root, root_key = _root("Root")
        inter, inter_key = _ca("Inter", "Root", root_key)
        leaf = _leaf("Inter", inter_key, ips=["10.0.0.1"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("ip", "10.0.0.0/8"))])
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_identity"

    def test_duplicate_endpoint_ids(self):
        root, root_key = _root("Root")
        inter, inter_key = _ca("Inter", "Root", root_key)
        leaf = _leaf("Inter", inter_key, dns_names=["api.example.com"])
        e = ep("same", leaf, ("dns", "api.example.com"))
        r = precheck([root, inter, leaf], [root], [e, dict(e)])
        assert r.status_code == 422

    def test_trust_root_must_be_self_signed(self):
        root, root_key = _root("Root")
        inter, inter_key = _ca("Inter", "Root", root_key)
        leaf = _leaf("Inter", inter_key, dns_names=["api.example.com"])
        r = precheck([root, inter, leaf], [inter],
                     [ep("e", leaf, ("dns", "api.example.com"))])
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "trust_root_not_self_signed"


# ---------------------------------------------------------------------------
# Raw-DER constraint edge cases (cryptography cannot model these)
# ---------------------------------------------------------------------------


def _der_len(n):
    if n < 0x80:
        return bytes([n])
    out = []
    while n:
        out.append(n & 0xFF)
        n >>= 8
    out.reverse()
    return bytes([0x80 | len(out)]) + bytes(out)


def _tlv(tag, content):
    return bytes([tag]) + _der_len(len(content)) + content


def _ca_with_raw_nc(subject_cn, issuer_cn, issuer_key, nc_der):
    """Build an intermediate CA whose NameConstraints is raw DER.

    cryptography cannot model otherName or malformed iPAddress constraints,
    so the extension is attached as an UnrecognizedExtension with the exact
    bytes a CA would publish.
    """
    key = _key()
    cert = (
        x509.CertificateBuilder()
        .subject_name(_dn(subject_cn))
        .issuer_name(_dn(issuer_cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=365))
        .not_valid_after(NOW + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                       critical=True)
        .add_extension(
            x509.UnrecognizedExtension(
                x509.oid.ExtensionOID.NAME_CONSTRAINTS, nc_der),
            critical=True)
        .sign(issuer_key, hashes.SHA256())
    )
    return cert, key


class TestRawConstraintEdgeCases:
    def test_other_name_constraint_is_unsupported(self):
        other_name = _tlv(0xA0, _tlv(0x06, bytes([1, 2, 3, 4]))
                          + _tlv(0xA0, b"\x13\x03abc"))
        dns = _tlv(0x82, b".example.com")
        nc = _tlv(0x30, _tlv(0xA0, _tlv(0x30, other_name) + _tlv(0x30, dns)))
        root, root_key = _root("Root")
        inter, inter_key = _ca_with_raw_nc("Inter", "Root", root_key, nc)
        leaf = _leaf("Inter", inter_key, dns_names=["api.example.com"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "api.example.com"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert res["reason"] == "unsupported_constraint_type"
        types = [v["constraint"] for v in res["violations"]
                 if v["reason"] == "unsupported_constraint_type"]
        assert "other_name" in types
        # the DNS constraint alongside it still applies and passes
        assert all(v["reason"] == "unsupported_constraint_type"
                   for v in res["violations"])

    def test_malformed_ip_constraint_is_unsupported(self):
        # iPAddress constraint that is a bare 4-byte address, not addr+mask
        bad_ip = _tlv(0x87, b"\x0a\x00\x00\x01")
        dns = _tlv(0x82, b".example.com")
        nc = _tlv(0x30, _tlv(0xA0, _tlv(0x30, bad_ip) + _tlv(0x30, dns)))
        root, root_key = _root("Root")
        inter, inter_key = _ca_with_raw_nc("Inter", "Root", root_key, nc)
        leaf = _leaf("Inter", inter_key, dns_names=["api.example.com"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "api.example.com"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["reason"] == "unsupported_constraint_type"
        types = [v["constraint"] for v in res["violations"]]
        assert "malformed_ip_address" in types

    def test_ipv6_constraint_enforced(self):
        net = ipaddress.ip_network("2001:db8::/32")
        ip6 = _tlv(0x87, net.network_address.packed + net.netmask.packed)
        nc = _tlv(0x30, _tlv(0xA0, _tlv(0x30, ip6)))
        root, root_key = _root("Root")
        inter, inter_key = _ca_with_raw_nc("Inter", "Root", root_key, nc)
        leaf_ok = _leaf("Inter", inter_key, ips=["2001:db8::5"])
        leaf_bad = _leaf("Inter", inter_key, ips=["2001:db9::5"])
        r = precheck([root, inter, leaf_ok, leaf_bad], [root], [
            ep("ok", leaf_ok, ("ip", "2001:db8::5")),
            ep("bad", leaf_bad, ("ip", "2001:db9::5")),
        ])
        assert r.status_code == 200
        by = {x["endpoint_id"]: x for x in r.json()["results"]}
        assert by["ok"]["eligible"] is True
        assert by["bad"]["reason"] == "not_within_permitted_subtree"
        assert by["bad"]["violations"][0]["constraint"] == "2001:db8::/32"


class TestWildcardVsConstraints:
    def test_wildcard_san_checked_against_constraints(self):
        root, root_key = _root("Root")
        nc = dns_constraint(permitted=[".example.com"])
        inter, inter_key = _ca("Inter", "Root", root_key,
                               name_constraints=nc)
        leaf = _leaf("Inter", inter_key, dns_names=["*.example.org"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "api.example.org"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert res["reason"] == "not_within_permitted_subtree"
        assert res["violations"][0]["san"] == "*.example.org"

    def test_wildcard_san_within_constraints_is_eligible(self):
        root, root_key = _root("Root")
        nc = dns_constraint(permitted=[".example.com"])
        inter, inter_key = _ca("Inter", "Root", root_key,
                               name_constraints=nc)
        leaf = _leaf("Inter", inter_key, dns_names=["*.example.com"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "api.example.com"))])
        assert r.status_code == 200
        assert r.json()["results"][0]["eligible"] is True


# ---------------------------------------------------------------------------
# Wildcard coverage sets vs name constraints (set algebra, not sampling)
# ---------------------------------------------------------------------------


class TestWildcardCoverageSetAlgebra:
    """A wildcard SAN stands for {<label>.<suffix>}; the constraint checks
    reason about that whole set instead of comparing the literal ``*.`` name.
    """

    def test_intersection_pure(self):
        # bare subtree whose body sits exactly one label below the suffix:
        # the body itself is a member of the coverage set
        assert dns_constraint_intersects_wildcard(
            "example.com", "blocked.example.com")
        assert dns_constraint_intersects_wildcard(
            "svc.example.com", "x.svc.example.com")
        # a subtree at or above the suffix swallows the whole set
        assert dns_constraint_intersects_wildcard("example.com", "example.com")
        assert dns_constraint_intersects_wildcard("example.com", ".example.com")
        assert dns_constraint_intersects_wildcard("example.com", "com")
        assert dns_constraint_intersects_wildcard("example.com", ".com")
        assert dns_constraint_intersects_wildcard("svc.example.com",
                                                  "example.com")

    def test_disjoint_pure(self):
        # leading-dot subtree one label below excludes only *deeper* names
        assert not dns_constraint_intersects_wildcard(
            "example.com", ".blocked.example.com")
        # a bare subtree two or more labels below never meets a set of
        # names with exactly one label under the suffix
        assert not dns_constraint_intersects_wildcard(
            "example.com", "a.b.example.com")
        assert not dns_constraint_intersects_wildcard(
            "svc.example.com", "a.x.svc.example.com")
        # unrelated names and label-boundary lookalikes
        assert not dns_constraint_intersects_wildcard(
            "example.com", "other.org")
        assert not dns_constraint_intersects_wildcard("example.com", "ample.com")
        assert not dns_constraint_intersects_wildcard(
            "example.com", "evil-example.com")

    def test_containment_pure(self):
        # wide subtrees contain every covered name
        assert dns_constraint_contains_wildcard("example.com", ".example.com")
        assert dns_constraint_contains_wildcard("example.com", "example.com")
        assert dns_constraint_contains_wildcard("example.com", "com")
        assert dns_constraint_contains_wildcard("svc.example.com",
                                                ".example.com")
        # narrow subtrees only permit individual members, never the set
        assert not dns_constraint_contains_wildcard(
            "example.com", "api.example.com")
        assert not dns_constraint_contains_wildcard(
            "example.com", ".api.example.com")
        assert not dns_constraint_contains_wildcard("example.com", "ample.com")


class TestWildcardExcludedIntersection:
    def test_excluded_member_of_coverage_set_rejects(self):
        # Regression: the wildcard used to be checked as a literal name, so
        # an excluded subtree inside its coverage set was missed and the
        # endpoint came out eligible.
        root, root_key = _root("Root")
        nc = dns_constraint(permitted=[".example.com"],
                            excluded=["blocked.example.com"])
        inter, inter_key = _ca("Inter", "Root", root_key, name_constraints=nc)
        leaf = _leaf("Inter", inter_key, dns_names=["*.example.com"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "blocked.example.com"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert res["reason"] == "excluded_by_name_constraint"
        v = res["violations"][0]
        assert v["reason"] == "excluded_by_name_constraint"
        assert v["san"] == "*.example.com"
        assert v["constraint"] == "blocked.example.com"
        assert v["ca_fingerprint"] == fp(inter)
        # the claim is left uncovered once its only SAN is killed
        assert res["identities"] == [
            {"type": "dns", "value": "blocked.example.com", "covered": False}]
        assert any(x["reason"] == "identity_not_covered"
                   for x in res["violations"])

    def test_excluded_kills_wildcard_even_for_unexcluded_claim(self):
        # The coverage set as a whole intersects the excluded subtree, so
        # the SAN dies even when the claimed name itself is not excluded.
        root, root_key = _root("Root")
        nc = dns_constraint(permitted=[".example.com"],
                            excluded=["blocked.example.com"])
        inter, inter_key = _ca("Inter", "Root", root_key, name_constraints=nc)
        leaf = _leaf("Inter", inter_key, dns_names=["*.example.com"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "api.example.com"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert res["reason"] == "excluded_by_name_constraint"
        assert res["violations"][0]["san"] == "*.example.com"

    def test_excluded_apex_of_wildcard_suffix(self):
        # A bare excluded subtree at the suffix itself contains every
        # covered name.
        root, root_key = _root("Root")
        nc = dns_constraint(excluded=["example.com"])
        inter, inter_key = _ca("Inter", "Root", root_key, name_constraints=nc)
        leaf = _leaf("Inter", inter_key, dns_names=["*.example.com"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "api.example.com"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["reason"] == "excluded_by_name_constraint"
        assert res["violations"][0]["constraint"] == "example.com"

    def test_disjoint_exclusions_leave_wildcard_eligible(self):
        # .blocked.example.com excludes only deeper names (leading dot);
        # a.b.example.com sits two labels below the suffix; the third
        # subtree is unrelated. None meets {<label>.example.com}.
        root, root_key = _root("Root")
        nc = dns_constraint(
            permitted=[".example.com"],
            excluded=[".blocked.example.com", "a.b.example.com",
                      "sibling.example.org"])
        inter, inter_key = _ca("Inter", "Root", root_key, name_constraints=nc)
        leaf = _leaf("Inter", inter_key, dns_names=["*.example.com"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "blocked.example.com"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["eligible"] is True, res["violations"]
        assert res["identities"] == [
            {"type": "dns", "value": "blocked.example.com", "covered": True}]

    def test_idna_excluded_member_intersects(self):
        # IDNA: constraints and SANs meet as A-labels; a unicode claim
        # normalizes to the same excluded member of the coverage set.
        root, root_key = _root("Root")
        nc = dns_constraint(permitted=[".xn--bcher-kva.example"],
                            excluded=["blocked.xn--bcher-kva.example"])
        inter, inter_key = _ca("Inter", "Root", root_key, name_constraints=nc)
        leaf = _leaf("Inter", inter_key,
                     dns_names=["*.xn--bcher-kva.example"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "blocked.bücher.example"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert res["reason"] == "excluded_by_name_constraint"
        v = res["violations"][0]
        assert v["san"] == "*.xn--bcher-kva.example"
        assert v["constraint"] == "blocked.xn--bcher-kva.example"
        assert v["ca_fingerprint"] == fp(inter)


class TestWildcardPermittedContainment:
    def test_bare_apex_permitted_admits_wildcard(self):
        root, root_key = _root("Root")
        nc = dns_constraint(permitted=["example.com"])
        inter, inter_key = _ca("Inter", "Root", root_key, name_constraints=nc)
        leaf = _leaf("Inter", inter_key, dns_names=["*.example.com"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "api.example.com"))])
        assert r.status_code == 200
        assert r.json()["results"][0]["eligible"] is True

    def test_single_name_permitted_does_not_admit_wildcard(self):
        # Narrow permission: only api.example.com itself is allowed, but the
        # wildcard spans every label under example.com.
        root, root_key = _root("Root")
        nc = dns_constraint(permitted=["api.example.com"])
        inter, inter_key = _ca("Inter", "Root", root_key, name_constraints=nc)
        leaf = _leaf("Inter", inter_key, dns_names=["*.example.com"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "api.example.com"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert res["reason"] == "not_within_permitted_subtree"
        v = res["violations"][0]
        assert v["san"] == "*.example.com"
        assert v["constraint"] == "api.example.com"
        assert v["ca_fingerprint"] == fp(inter)

    def test_subdomain_only_permitted_too_narrow(self):
        root, root_key = _root("Root")
        nc = dns_constraint(permitted=[".api.example.com"])
        inter, inter_key = _ca("Inter", "Root", root_key, name_constraints=nc)
        leaf = _leaf("Inter", inter_key, dns_names=["*.example.com"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "api.example.com"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["reason"] == "not_within_permitted_subtree"
        assert res["violations"][0]["constraint"] == ".api.example.com"

    def test_union_of_narrow_permits_never_covers_wildcard(self):
        # Finitely many single-name subtrees cannot cover the set; the
        # verdict must not be reached by sampling member names.
        root, root_key = _root("Root")
        nc = dns_constraint(permitted=["api.example.com", "www.example.com",
                                       "blocked.example.com"])
        inter, inter_key = _ca("Inter", "Root", root_key, name_constraints=nc)
        leaf = _leaf("Inter", inter_key, dns_names=["*.example.com"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "api.example.com"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert res["reason"] == "not_within_permitted_subtree"
        # stable blocker: the CA's lexicographically first subtree
        assert res["violations"][0]["constraint"] == "api.example.com"

    def test_wide_member_of_permitted_union_admits(self):
        root, root_key = _root("Root")
        nc = dns_constraint(permitted=["unrelated.org", ".example.com"])
        inter, inter_key = _ca("Inter", "Root", root_key, name_constraints=nc)
        leaf = _leaf("Inter", inter_key, dns_names=["*.example.com"])
        r = precheck([root, inter, leaf], [root],
                     [ep("e", leaf, ("dns", "api.example.com"))])
        assert r.status_code == 200
        assert r.json()["results"][0]["eligible"] is True


class TestWildcardMultiLevelConstraints:
    def _chain(self, nc1, nc2):
        root, root_key = _root("Root")
        inter1, i1_key = _ca("Inter1", "Root", root_key, name_constraints=nc1)
        inter2, i2_key = _ca("Inter2", "Inter1", i1_key, name_constraints=nc2)
        return root, inter1, inter2, i2_key

    def test_wildcard_contained_at_every_level(self):
        root, i1, i2, i2_key = self._chain(
            dns_constraint(permitted=[".example.com"]),
            dns_constraint(permitted=[".svc.example.com"]),
        )
        leaf = _leaf("Inter2", i2_key, dns_names=["*.svc.example.com"])
        r = precheck([root, i1, i2, leaf], [root],
                     [ep("e", leaf, ("dns", "api.svc.example.com"))])
        assert r.status_code == 200
        assert r.json()["results"][0]["eligible"] is True

    def test_wildcard_outside_lower_level_permitted(self):
        root, i1, i2, i2_key = self._chain(
            dns_constraint(permitted=[".example.com"]),
            dns_constraint(permitted=[".svc.example.com"]),
        )
        leaf = _leaf("Inter2", i2_key, dns_names=["*.example.com"])
        r = precheck([root, i1, i2, leaf], [root],
                     [ep("e", leaf, ("dns", "api.example.com"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert res["reason"] == "not_within_permitted_subtree"
        v = res["violations"][0]
        assert v["san"] == "*.example.com"
        assert v["constraint"] == ".svc.example.com"
        assert v["ca_fingerprint"] == fp(i2)

    def test_excluded_at_upper_level_intersects(self):
        root, i1, i2, i2_key = self._chain(
            dns_constraint(permitted=[".example.com"],
                           excluded=["blocked.svc.example.com"]),
            dns_constraint(permitted=[".svc.example.com"]),
        )
        leaf = _leaf("Inter2", i2_key, dns_names=["*.svc.example.com"])
        r = precheck([root, i1, i2, leaf], [root],
                     [ep("e", leaf, ("dns", "api.svc.example.com"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert res["reason"] == "excluded_by_name_constraint"
        v = res["violations"][0]
        assert v["san"] == "*.svc.example.com"
        assert v["constraint"] == "blocked.svc.example.com"
        assert v["ca_fingerprint"] == fp(i1)

    def test_excluded_at_lower_level_intersects(self):
        root, i1, i2, i2_key = self._chain(
            dns_constraint(permitted=[".example.com"]),
            dns_constraint(permitted=[".svc.example.com"],
                           excluded=["blocked.svc.example.com"]),
        )
        leaf = _leaf("Inter2", i2_key, dns_names=["*.svc.example.com"])
        r = precheck([root, i1, i2, leaf], [root],
                     [ep("e", leaf, ("dns", "blocked.svc.example.com"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["eligible"] is False
        assert res["reason"] == "excluded_by_name_constraint"
        v = res["violations"][0]
        assert v["san"] == "*.svc.example.com"
        assert v["constraint"] == "blocked.svc.example.com"
        assert v["ca_fingerprint"] == fp(i2)


# ---------------------------------------------------------------------------
# Eligible result feeds /plans
# ---------------------------------------------------------------------------


class TestPlannerIntegration:
    def test_eligible_chain_used_in_plan(self):
        root, root_key = _root("Root")
        new_root, new_root_key = _root("New Root")
        inter, inter_key = _ca("Inter", "New Root", new_root_key)
        target = _leaf("Inter", inter_key, dns_names=["api.example.com"],
                       ips=["10.0.0.1"])
        current = _leaf("Root", root_key, dns_names=["api.example.com"])
        r = precheck([root, new_root, inter, target, current],
                     [root, new_root],
                     [ep("api", target, ("dns", "api.example.com"),
                         ("ip", "10.0.0.1"))])
        assert r.status_code == 200
        res = r.json()["results"][0]
        assert res["eligible"] is True
        target_chain = res["chain"]
        assert target_chain == [fp(target), fp(inter), fp(new_root)]

        plan = client.post("/plans", json={
            "certificates": [
                {"cert_id": fp(root), "subject": "CN=Root",
                 "issuer": "CN=Root",
                 "not_valid_before": (NOW - timedelta(days=365)).isoformat(),
                 "not_valid_after": (NOW + timedelta(days=3650)).isoformat()},
                {"cert_id": fp(new_root), "subject": "CN=New Root",
                 "issuer": "CN=New Root",
                 "not_valid_before": (NOW - timedelta(days=365)).isoformat(),
                 "not_valid_after": (NOW + timedelta(days=3650)).isoformat()},
                {"cert_id": fp(inter), "subject": "CN=Inter",
                 "issuer": "CN=New Root",
                 "not_valid_before": (NOW - timedelta(days=365)).isoformat(),
                 "not_valid_after": (NOW + timedelta(days=3650)).isoformat()},
                {"cert_id": fp(current), "subject": "CN=svc",
                 "issuer": "CN=Root",
                 "not_valid_before": (NOW - timedelta(days=365)).isoformat(),
                 "not_valid_after": (NOW + timedelta(days=365)).isoformat()},
                {"cert_id": fp(target), "subject": "CN=svc",
                 "issuer": "CN=Inter",
                 "not_valid_before": (NOW - timedelta(days=365)).isoformat(),
                 "not_valid_after": (NOW + timedelta(days=365)).isoformat()},
            ],
            "trust_anchors": [{"client_id": "c", "cert_id": fp(root)}],
            "endpoints": [{
                "endpoint_id": "api",
                "current_chain": [fp(current), fp(root)],
                "target_chain": target_chain,
            }],
            "relationships": [{"client_id": "c", "endpoint_id": "api"}],
            "actions": [
                {"action_id": "add", "type": "add_trust",
                 "client_id": "c", "anchor_cert_id": fp(new_root),
                 "allowed_stages": [1, 2]},
                {"action_id": "replace", "type": "replace_cert",
                 "endpoint_id": "api", "new_chain": target_chain,
                 "allowed_stages": [2]},
                {"action_id": "remove", "type": "remove_trust",
                 "client_id": "c", "anchor_cert_id": fp(root),
                 "allowed_stages": [2]},
            ],
            "plan_time": NOW.isoformat(),
        })
        assert plan.status_code == 200, plan.text
        assert plan.json()["stage_count"] == 2
