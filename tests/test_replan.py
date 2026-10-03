"""Tests for POST /plans/replan: safe continuation after a mid-plan revocation."""
import itertools
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)

client = TestClient(app)


def cert(cid, subject, issuer):
    return {
        "cert_id": cid,
        "subject": subject,
        "issuer": issuer,
        "not_valid_before": (NOW - timedelta(days=1)).isoformat(),
        "not_valid_after": (NOW + timedelta(days=365)).isoformat(),
    }


def make_actions(a2_stages=(1, 2, 3)):
    return [
        {"action_id": "a1-add", "type": "add_trust",
         "client_id": "c", "anchor_cert_id": "root-new",
         "allowed_stages": [1, 2, 3]},
        {"action_id": "a2-replace", "type": "replace_cert",
         "endpoint_id": "svc", "new_chain": ["leaf-new", "root-new"],
         "allowed_stages": list(a2_stages)},
        {"action_id": "a3-remove", "type": "remove_trust",
         "client_id": "c", "anchor_cert_id": "root-old",
         "allowed_stages": [1, 2, 3]},
    ]


def scenario(**overrides):
    payload = {
        "certificates": [
            cert("root-old", "CN=Old Root", "CN=Old Root"),
            cert("root-new", "CN=New Root", "CN=New Root"),
            cert("leaf-old", "CN=svc", "CN=Old Root"),
            cert("leaf-new", "CN=svc", "CN=New Root"),
            cert("leaf-alt", "CN=svc", "CN=New Root"),
            cert("leaf-alt2", "CN=svc", "CN=New Root"),
        ],
        "trust_anchors": [{"client_id": "c", "cert_id": "root-old"}],
        "endpoints": [{
            "endpoint_id": "svc",
            "current_chain": ["leaf-old", "root-old"],
            "target_chain": ["leaf-new", "root-new"],
        }],
        "relationships": [{"client_id": "c", "endpoint_id": "svc"}],
        "actions": make_actions(),
        "plan_time": NOW.isoformat(),
    }
    payload.update(overrides)
    return payload


def revoked(cid, fresh=True):
    return {"cert_id": cid, "status": "revoked", "fresh": fresh}


def good(cid, fresh=True):
    return {"cert_id": cid, "status": "good", "fresh": fresh}


def replan(payload):
    return client.post("/plans/replan", json=payload)


# ---------------------------------------------------------------------------
# Happy path: the continuation re-targets the pending replace_cert
# ---------------------------------------------------------------------------


def test_target_revoked_picks_clean_candidate():
    r = replan(scenario(
        completed_action_ids=["a1-add"],
        live_chains=[{"endpoint_id": "svc", "chain": ["leaf-old", "root-old"]}],
        candidates=[{"endpoint_id": "svc",
                     "candidate_chains": [["leaf-alt", "root-new"]]}],
        revocation_evidence=[revoked("leaf-new")],
    ))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    # a1 is done (root-new trusted): replace onto the clean candidate and
    # drop the old root in a single continuation stage.
    assert body["stage_count"] == 1
    assert body["stages"] == [
        {"stage": 1, "action_ids": ["a2-replace", "a3-remove"]}
    ]
    assert body["chain_selections"] == [
        {"endpoint_id": "svc", "action_id": "a2-replace",
         "chain": ["leaf-alt", "root-new"]}
    ]
    assert body["excluded_chains"] == [
        {"endpoint_id": "svc", "role": "target",
         "chain": ["leaf-new", "root-new"],
         "blocking_certificate": "leaf-new", "reason": "certificate_revoked"}
    ]


def test_unreported_live_chain_defaults_to_current_chain():
    # No live_chains: the endpoint is assumed to serve current_chain.
    r = replan(scenario(
        completed_action_ids=["a1-add"],
        candidates=[{"endpoint_id": "svc",
                     "candidate_chains": [["leaf-alt", "root-new"]]}],
        revocation_evidence=[revoked("leaf-new")],
    ))
    assert r.status_code == 200, r.text
    assert r.json()["stages"] == [
        {"stage": 1, "action_ids": ["a2-replace", "a3-remove"]}
    ]


def test_clean_target_needs_no_candidates():
    r = replan(scenario(completed_action_ids=["a1-add"]))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["chain_selections"] == [
        {"endpoint_id": "svc", "action_id": "a2-replace",
         "chain": ["leaf-new", "root-new"]}
    ]
    assert body["excluded_chains"] == []


def test_current_chain_revoked_forces_rotation():
    r = replan(scenario(
        completed_action_ids=["a1-add"],
        candidates=[{"endpoint_id": "svc",
                     "candidate_chains": [["leaf-alt", "root-new"]]}],
        revocation_evidence=[revoked("leaf-old")],
    ))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["chain_selections"][0]["chain"] == ["leaf-alt", "root-new"]
    assert body["excluded_chains"] == [
        {"endpoint_id": "svc", "role": "current",
         "chain": ["leaf-old", "root-old"],
         "blocking_certificate": "leaf-old", "reason": "certificate_revoked"}
    ]


def test_candidate_equal_to_current_chain_means_stay():
    # The declared target is revoked; re-serving the (clean) current chain is
    # offered as a candidate. No remove_trust action exists here, so staying
    # on the old chain is a complete continuation.
    actions = [
        {"action_id": "a1-add", "type": "add_trust",
         "client_id": "c", "anchor_cert_id": "root-new",
         "allowed_stages": [1]},
        {"action_id": "a2-replace", "type": "replace_cert",
         "endpoint_id": "svc", "new_chain": ["leaf-new", "root-new"],
         "allowed_stages": [1]},
    ]
    r = replan(scenario(
        actions=actions,
        candidates=[{"endpoint_id": "svc",
                     "candidate_chains": [["leaf-old", "root-old"]]}],
        revocation_evidence=[revoked("leaf-new")],
    ))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["stages"] == [
        {"stage": 1, "action_ids": ["a1-add", "a2-replace"]}
    ]
    assert body["chain_selections"] == [
        {"endpoint_id": "svc", "action_id": "a2-replace",
         "chain": ["leaf-old", "root-old"]}
    ]


def test_all_actions_completed_and_clean_is_empty_continuation():
    r = replan(scenario(completed_action_ids=["a1-add", "a2-replace",
                                              "a3-remove"]))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["stage_count"] == 0
    assert body["stages"] == []
    assert body["chain_selections"] == []
    assert body["excluded_chains"] == []


def test_multi_endpoint_continuation():
    payload = scenario(
        endpoints=[
            {"endpoint_id": "svc1",
             "current_chain": ["leaf-old", "root-old"],
             "target_chain": ["leaf-new", "root-new"]},
            {"endpoint_id": "svc2",
             "current_chain": ["leaf-old", "root-old"],
             "target_chain": ["leaf-alt", "root-new"]},
        ],
        relationships=[
            {"client_id": "c", "endpoint_id": "svc1"},
            {"client_id": "c", "endpoint_id": "svc2"},
        ],
        actions=[
            {"action_id": "a1-add", "type": "add_trust",
             "client_id": "c", "anchor_cert_id": "root-new",
             "allowed_stages": [1, 2]},
            {"action_id": "a2-replace-1", "type": "replace_cert",
             "endpoint_id": "svc1", "new_chain": ["leaf-new", "root-new"],
             "allowed_stages": [1, 2]},
            {"action_id": "a3-replace-2", "type": "replace_cert",
             "endpoint_id": "svc2", "new_chain": ["leaf-alt", "root-new"],
             "allowed_stages": [1, 2]},
            {"action_id": "a4-remove", "type": "remove_trust",
             "client_id": "c", "anchor_cert_id": "root-old",
             "allowed_stages": [1, 2]},
        ],
        completed_action_ids=["a1-add"],
        candidates=[{"endpoint_id": "svc1",
                     "candidate_chains": [["leaf-alt2", "root-new"]]}],
        revocation_evidence=[revoked("leaf-new")],
    )
    r = replan(payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["stages"] == [
        {"stage": 1,
         "action_ids": ["a2-replace-1", "a3-replace-2", "a4-remove"]}
    ]
    assert body["chain_selections"] == [
        {"endpoint_id": "svc1", "action_id": "a2-replace-1",
         "chain": ["leaf-alt2", "root-new"]},
        {"endpoint_id": "svc2", "action_id": "a3-replace-2",
         "chain": ["leaf-alt", "root-new"]},
    ]
    assert body["excluded_chains"] == [
        {"endpoint_id": "svc1", "role": "target",
         "chain": ["leaf-new", "root-new"],
         "blocking_certificate": "leaf-new", "reason": "certificate_revoked"}
    ]


# ---------------------------------------------------------------------------
# Evidence semantics
# ---------------------------------------------------------------------------


def test_conflicting_good_and_revoked_evidence_excludes_chain():
    r = replan(scenario(
        completed_action_ids=["a1-add"],
        candidates=[{"endpoint_id": "svc",
                     "candidate_chains": [["leaf-alt", "root-new"]]}],
        revocation_evidence=[revoked("leaf-new"), good("leaf-new")],
    ))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["excluded_chains"] == [
        {"endpoint_id": "svc", "role": "target",
         "chain": ["leaf-new", "root-new"],
         "blocking_certificate": "leaf-new", "reason": "conflicting_evidence"}
    ]
    assert body["chain_selections"][0]["chain"] == ["leaf-alt", "root-new"]


def test_stale_revoked_evidence_does_not_taint():
    r = replan(scenario(
        completed_action_ids=["a1-add"],
        revocation_evidence=[revoked("leaf-new", fresh=False)],
    ))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["excluded_chains"] == []
    assert body["chain_selections"][0]["chain"] == ["leaf-new", "root-new"]


def test_unknown_status_does_not_taint():
    r = replan(scenario(
        completed_action_ids=["a1-add"],
        revocation_evidence=[{"cert_id": "leaf-new", "status": "unknown",
                              "fresh": True}],
    ))
    assert r.status_code == 200, r.text
    assert r.json()["excluded_chains"] == []


def test_revoked_root_taints_every_chain_containing_it():
    r = replan(scenario(
        completed_action_ids=["a1-add"],
        candidates=[{"endpoint_id": "svc",
                     "candidate_chains": [["leaf-alt", "root-new"]]}],
        revocation_evidence=[revoked("root-new")],
    ))
    assert r.status_code == 409, r.text
    body = r.json()
    # Target and candidate both terminate at the revoked root: the pending
    # replace_cert has no clean chain to deploy.
    assert body["status"] == "infeasible"
    assert body["blocking_certificate"] == "root-new"
    assert body["reason"] == "certificate_revoked"
    assert [c["cert_id"] for c in body["chain"]] == ["leaf-new", "root-new"]


# ---------------------------------------------------------------------------
# Tie-breaking: action_id stage vector, then complete chain fingerprints
# ---------------------------------------------------------------------------


def test_chain_choice_tie_break_by_full_fingerprint():
    # Both candidates terminate at root-new (identical trust behaviour), so
    # the lexicographically smaller complete chain wins regardless of the
    # order the candidates are submitted in.
    for chains in (
        [["leaf-alt2", "root-new"], ["leaf-alt", "root-new"]],
        [["leaf-alt", "root-new"], ["leaf-alt2", "root-new"]],
    ):
        r = replan(scenario(
            completed_action_ids=["a1-add"],
            candidates=[{"endpoint_id": "svc", "candidate_chains": chains}],
            revocation_evidence=[revoked("leaf-new")],
        ))
        assert r.status_code == 200, r.text
        assert r.json()["chain_selections"] == [
            {"endpoint_id": "svc", "action_id": "a2-replace",
             "chain": ["leaf-alt", "root-new"]}
        ]


def test_continuation_stages_are_renumbered_with_noop_gaps():
    # a2 is only eligible at absolute stages 2-3 of its declaration; the
    # continuation renumbers from 1 and keeps an explicit no-op stage 1.
    r = replan(scenario(
        actions=make_actions(a2_stages=(2, 3)),
        completed_action_ids=["a1-add"],
        candidates=[{"endpoint_id": "svc",
                     "candidate_chains": [["leaf-alt", "root-new"]]}],
        revocation_evidence=[revoked("leaf-new")],
    ))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["stage_count"] == 2
    assert body["stages"] == [
        {"stage": 1, "action_ids": []},
        {"stage": 2, "action_ids": ["a2-replace", "a3-remove"]},
    ]


def test_remove_trust_never_precedes_chain_still_in_use():
    # Nothing completed and no evidence: the classic rotation order is
    # reproduced — the old root may only be dropped once the new chain is
    # served (both land in stage 2, after the add in stage 1).
    r = replan(scenario(actions=make_actions(a2_stages=(2, 3))))
    assert r.status_code == 200, r.text
    assert r.json()["stages"] == [
        {"stage": 1, "action_ids": ["a1-add"]},
        {"stage": 2, "action_ids": ["a2-replace", "a3-remove"]},
    ]


def test_infeasible_chain_choice_is_skipped_despite_smaller_fingerprint():
    # leaf-aaa sorts before leaf-alt, but its chain terminates at root-old,
    # which the remaining a3-remove must drop: that combo can never finish.
    # The planner must skip it and pick the feasible (larger) chain.
    payload = scenario(
        certificates=[
            cert("root-old", "CN=Old Root", "CN=Old Root"),
            cert("root-new", "CN=New Root", "CN=New Root"),
            cert("leaf-old", "CN=svc", "CN=Old Root"),
            cert("leaf-new", "CN=svc", "CN=New Root"),
            cert("leaf-alt", "CN=svc", "CN=New Root"),
            cert("leaf-aaa", "CN=svc", "CN=Old Root"),
        ],
        completed_action_ids=["a1-add"],
        candidates=[{"endpoint_id": "svc",
                     "candidate_chains": [["leaf-aaa", "root-old"],
                                          ["leaf-alt", "root-new"]]}],
        revocation_evidence=[revoked("leaf-new")],
    )
    r = replan(payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["chain_selections"] == [
        {"endpoint_id": "svc", "action_id": "a2-replace",
         "chain": ["leaf-alt", "root-new"]}
    ]
    # add done; replace onto the new-root chain and drop the old root.
    assert body["stages"] == [
        {"stage": 1, "action_ids": ["a2-replace", "a3-remove"]}
    ]


# ---------------------------------------------------------------------------
# Infeasible / invalid continuations -> 409
# ---------------------------------------------------------------------------


def test_target_revoked_without_candidates_is_infeasible():
    r = replan(scenario(
        completed_action_ids=["a1-add"],
        revocation_evidence=[revoked("leaf-new")],
    ))
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["status"] == "infeasible"
    assert body["relationship"] == {"client_id": "c", "endpoint_id": "svc"}
    assert body["blocking_certificate"] == "leaf-new"
    assert body["blocking_action"] == "a2-replace"
    assert body["reason"] == "certificate_revoked"
    assert [c["cert_id"] for c in body["chain"]] == ["leaf-new", "root-new"]


def test_current_revoked_without_clean_replacement_is_infeasible():
    r = replan(scenario(
        completed_action_ids=["a1-add"],
        revocation_evidence=[revoked("leaf-old"), revoked("leaf-new")],
    ))
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["status"] == "infeasible"
    assert body["blocking_certificate"] == "leaf-old"
    assert body["reason"] == "certificate_revoked"
    assert [c["cert_id"] for c in body["chain"]] == ["leaf-old", "root-old"]


def test_completed_replace_to_tainted_target_cannot_be_undone():
    # The replace already executed (non-revertible) and the chain it deployed
    # is now known to be revoked: no pending replace_cert can fix that.
    r = replan(scenario(
        completed_action_ids=["a1-add", "a2-replace", "a3-remove"],
        revocation_evidence=[revoked("leaf-new")],
    ))
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["status"] == "infeasible"
    assert body["blocking_certificate"] == "leaf-new"
    assert body["blocking_action"] is None
    assert body["reason"] == "certificate_revoked"


def test_conflicting_evidence_on_current_chain_is_infeasible():
    r = replan(scenario(
        completed_action_ids=["a1-add", "a2-replace", "a3-remove"],
        revocation_evidence=[revoked("leaf-new"), good("leaf-new")],
    ))
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["reason"] == "conflicting_evidence"
    assert body["blocking_certificate"] == "leaf-new"


def test_resumption_state_already_broken_is_invalid():
    # The old root was already dropped while the old chain is still served:
    # the completed prefix itself destroyed the only trust path.
    r = replan(scenario(completed_action_ids=["a3-remove"]))
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["status"] == "invalid"
    assert body["stage"] == 0
    assert body["blocking_action"] is None
    assert body["blocking_certificate"] == "root-old"
    assert body["reason"] == "untrusted_root"
    assert body["relationship"] == {"client_id": "c", "endpoint_id": "svc"}


def test_unschedulable_remaining_actions_report_first_broken_relationship():
    # The remove is forced into continuation stage 1 while add/replace can
    # only happen at stage 2: dropping the old root first strands the old
    # chain, and no continuation exists.
    r = replan(scenario(actions=[
        {"action_id": "a1-add", "type": "add_trust",
         "client_id": "c", "anchor_cert_id": "root-new",
         "allowed_stages": [2]},
        {"action_id": "a2-replace", "type": "replace_cert",
         "endpoint_id": "svc", "new_chain": ["leaf-new", "root-new"],
         "allowed_stages": [2]},
        {"action_id": "a3-remove", "type": "remove_trust",
         "client_id": "c", "anchor_cert_id": "root-old",
         "allowed_stages": [1]},
    ]))
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["status"] == "infeasible"
    assert body["stage"] == 1
    assert body["relationship"] == {"client_id": "c", "endpoint_id": "svc"}
    assert body["blocking_action"] == "a3-remove"
    assert body["blocking_certificate"] == "root-old"
    assert body["reason"] == "untrusted_root"
    assert [c["cert_id"] for c in body["chain"]] == ["leaf-old", "root-old"]


def test_contradictory_add_remove_same_anchor_is_action_level_failure():
    payload = {
        "certificates": [
            cert("root-old", "CN=Old Root", "CN=Old Root"),
            cert("leaf-old", "CN=svc", "CN=Old Root"),
        ],
        "trust_anchors": [{"client_id": "c", "cert_id": "root-old"}],
        "endpoints": [{
            "endpoint_id": "svc",
            "current_chain": ["leaf-old", "root-old"],
            "target_chain": ["leaf-old", "root-old"],
        }],
        "relationships": [{"client_id": "c", "endpoint_id": "svc"}],
        "actions": [
            {"action_id": "a-add-old", "type": "add_trust",
             "client_id": "c", "anchor_cert_id": "root-old",
             "allowed_stages": [1]},
            {"action_id": "b-rem-old", "type": "remove_trust",
             "client_id": "c", "anchor_cert_id": "root-old",
             "allowed_stages": [1]},
        ],
        "plan_time": NOW.isoformat(),
    }
    r = replan(payload)
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["reason"] == "contradictory_actions_same_stage"
    assert body["blocking_action"] == "b-rem-old"
    assert body["blocking_certificate"] is None


# ---------------------------------------------------------------------------
# Validation -> 422
# ---------------------------------------------------------------------------


def test_unknown_completed_action_rejected():
    r = replan(scenario(completed_action_ids=["a9-nope"]))
    assert r.status_code == 422
    assert "unknown action_id" in r.json()["detail"]


def test_duplicate_completed_action_rejected():
    r = replan(scenario(completed_action_ids=["a1-add", "a1-add"]))
    assert r.status_code == 422


def test_live_chain_contradicting_completed_replace_rejected():
    r = replan(scenario(
        completed_action_ids=["a2-replace"],
        live_chains=[{"endpoint_id": "svc", "chain": ["leaf-old", "root-old"]}],
    ))
    assert r.status_code == 422
    assert "contradicts" in r.json()["detail"]


def test_live_chain_matching_completed_replace_accepted():
    r = replan(scenario(
        completed_action_ids=["a1-add", "a2-replace"],
        live_chains=[{"endpoint_id": "svc", "chain": ["leaf-new", "root-new"]}],
    ))
    assert r.status_code == 200, r.text


def test_unknown_live_endpoint_rejected():
    r = replan(scenario(
        live_chains=[{"endpoint_id": "ghost",
                      "chain": ["leaf-old", "root-old"]}],
    ))
    assert r.status_code == 422
    assert "unknown endpoint_id" in r.json()["detail"]


def test_duplicate_live_endpoint_rejected():
    r = replan(scenario(live_chains=[
        {"endpoint_id": "svc", "chain": ["leaf-old", "root-old"]},
        {"endpoint_id": "svc", "chain": ["leaf-new", "root-new"]},
    ]))
    assert r.status_code == 422


def test_live_chain_must_be_well_formed():
    r = replan(scenario(
        live_chains=[{"endpoint_id": "svc", "chain": ["leaf-old", "leaf-new"]}],
    ))
    assert r.status_code == 422


def test_more_than_12_candidates_rejected():
    r = replan(scenario(candidates=[{
        "endpoint_id": "svc",
        "candidate_chains": [["leaf-alt", "root-new"]] * 13,
    }]))
    assert r.status_code == 422


def test_unknown_candidate_endpoint_rejected():
    r = replan(scenario(candidates=[{
        "endpoint_id": "ghost",
        "candidate_chains": [["leaf-alt", "root-new"]],
    }]))
    assert r.status_code == 422
    assert "unknown endpoint_id" in r.json()["detail"]


def test_duplicate_candidate_endpoint_rejected():
    r = replan(scenario(candidates=[
        {"endpoint_id": "svc", "candidate_chains": [["leaf-alt", "root-new"]]},
        {"endpoint_id": "svc", "candidate_chains": [["leaf-alt2", "root-new"]]},
    ]))
    assert r.status_code == 422


def test_candidate_chain_with_unknown_certificate_rejected():
    r = replan(scenario(candidates=[{
        "endpoint_id": "svc",
        "candidate_chains": [["leaf-ghost", "root-new"]],
    }]))
    assert r.status_code == 422
    assert "unknown certificate" in r.json()["detail"]


def test_candidate_chain_must_end_at_self_signed_root():
    r = replan(scenario(candidates=[{
        "endpoint_id": "svc",
        "candidate_chains": [["leaf-alt"]],
    }]))
    assert r.status_code == 422
    assert "self-signed root" in r.json()["detail"]


def test_evidence_for_unknown_certificate_rejected():
    r = replan(scenario(revocation_evidence=[revoked("leaf-ghost")]))
    assert r.status_code == 422
    assert "unknown certificate" in r.json()["detail"]


# ---------------------------------------------------------------------------
# README example stays honest
# ---------------------------------------------------------------------------


def test_readme_example_response():
    payload = json.loads(
        Path("examples/replan_request.json").read_text()
    )
    r = replan(payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert body["stage_count"] == 2
    assert body["stages"] == [
        {"stage": 1, "action_ids": []},
        {"stage": 2, "action_ids": ["a2-serve-new-leaf", "a3-remove-old-root"]},
    ]
    assert body["chain_selections"] == [
        {"endpoint_id": "api.example.com", "action_id": "a2-serve-new-leaf",
         "chain": ["leaf-alt", "root-new"]}
    ]
    assert body["excluded_chains"] == [
        {"endpoint_id": "api.example.com", "role": "candidate",
         "chain": ["leaf-alt2", "root-new"],
         "blocking_certificate": "leaf-alt2", "reason": "certificate_revoked"},
        {"endpoint_id": "api.example.com", "role": "target",
         "chain": ["leaf-new", "root-new"],
         "blocking_certificate": "leaf-new", "reason": "certificate_revoked"},
    ]


# ---------------------------------------------------------------------------
# Differential test: endpoint result vs independent exhaustive enumeration
# ---------------------------------------------------------------------------


def _bf_trust_ok(anchors_by_client, chains, relationships):
    for rel in relationships:
        trusted = anchors_by_client[rel["client_id"]]
        if not any(cid in trusted for cid in chains[rel["endpoint_id"]]):
            return False
    return True


def _brute_force_replan(payload):
    """Independent minimum over (chain choice x stage assignment).

    Returns the best (stage_count, stage_vector, chain_vector) key, or None
    when the request is blocked or infeasible. Mirrors the documented
    semantics only through simple, direct simulation.
    """
    anchors = {}
    for a in payload.get("trust_anchors", []):
        anchors.setdefault(a["client_id"], set()).add(a["cert_id"])
    for rel in payload["relationships"]:
        anchors.setdefault(rel["client_id"], set())
    actions = sorted(payload.get("actions", []),
                     key=lambda a: a["action_id"])
    completed = set(payload.get("completed_action_ids", []))
    for a in actions:
        if a["action_id"] not in completed:
            continue
        if a["type"] == "add_trust":
            anchors.setdefault(a["client_id"], set()).add(a["anchor_cert_id"])
        elif a["type"] == "remove_trust":
            anchors.setdefault(a["client_id"], set()).discard(
                a["anchor_cert_id"])

    endpoints = {e["endpoint_id"]: e for e in payload["endpoints"]}
    live = {l["endpoint_id"]: l["chain"]
            for l in payload.get("live_chains", [])}
    served = {}
    for ep, e in endpoints.items():
        replace = next((a for a in actions
                        if a["type"] == "replace_cert"
                        and a["endpoint_id"] == ep), None)
        if replace and replace["action_id"] in completed:
            served[ep] = list(e["target_chain"])
        elif ep in live:
            served[ep] = list(live[ep])
        else:
            served[ep] = list(e["current_chain"])

    fresh_revoked = {
        i["cert_id"] for i in payload.get("revocation_evidence", [])
        if i["fresh"] and i["status"] == "revoked"
    }

    def tainted(chain):
        return any(cid in fresh_revoked for cid in chain)

    remaining = [a for a in actions if a["action_id"] not in completed]
    cand = {c["endpoint_id"]: {tuple(x) for x in c["candidate_chains"]}
            for c in payload.get("candidates", [])}
    pending = {}
    for a in remaining:
        if a["type"] == "replace_cert":
            ep = a["endpoint_id"]
            opts = {tuple(endpoints[ep]["target_chain"])} | cand.get(ep, set())
            pending[ep] = sorted(o for o in opts if not tainted(o))

    for ep in endpoints:
        if tainted(served[ep]) and (ep not in pending or not pending[ep]):
            return None
        if ep in pending and not pending[ep]:
            return None
    if not _bf_trust_ok(anchors, served, payload["relationships"]):
        return None

    eps = sorted(pending)
    best = None
    for combo in itertools.product(*(pending[ep] for ep in eps)):
        override = dict(zip(eps, combo))
        choices = [sorted(set(a["allowed_stages"])) for a in remaining]
        for assignment in itertools.product(*choices):
            stage_of = dict(zip((a["action_id"] for a in remaining),
                                assignment))
            m = max(assignment) if assignment else 0
            cur_anchors = {c: set(v) for c, v in anchors.items()}
            cur_chains = {ep: list(ch) for ep, ch in served.items()}
            ok = True
            for st in range(1, m + 1):
                batch = [a for a in remaining
                         if stage_of[a["action_id"]] == st]
                touched = {}
                for a in batch:
                    if a["type"] in ("add_trust", "remove_trust"):
                        edge = (a["client_id"], a["anchor_cert_id"])
                        kinds = touched.setdefault(edge, set())
                        kinds.add(a["type"])
                if any(len(k) > 1 for k in touched.values()):
                    ok = False
                    break
                for a in batch:
                    if a["type"] == "add_trust":
                        cur_anchors.setdefault(a["client_id"], set()).add(
                            a["anchor_cert_id"])
                    elif a["type"] == "remove_trust":
                        cur_anchors.setdefault(a["client_id"], set()).discard(
                            a["anchor_cert_id"])
                    else:
                        cur_chains[a["endpoint_id"]] = list(
                            override[a["endpoint_id"]])
                if not _bf_trust_ok(cur_anchors, cur_chains,
                                    payload["relationships"]):
                    ok = False
                    break
            if not ok:
                continue
            key = (m,
                   tuple(stage_of[a["action_id"]] for a in remaining),
                   combo)
            if best is None or key < best:
                best = key
    return best


def _random_replan_scenario(rng):
    certs = [
        cert("root-old", "CN=Old Root", "CN=Old Root"),
        cert("root-new", "CN=New Root", "CN=New Root"),
        cert("leaf-old", "CN=svc", "CN=Old Root"),
        cert("leaf-new", "CN=svc", "CN=New Root"),
        cert("leaf-alt", "CN=svc", "CN=New Root"),
        cert("leaf-alt2", "CN=svc", "CN=New Root"),
    ]
    chain_pool = [
        ["leaf-new", "root-new"],
        ["leaf-alt", "root-new"],
        ["leaf-alt2", "root-new"],
        ["leaf-old", "root-old"],
    ]
    actions = []
    if rng.random() < 0.9:
        actions.append({
            "action_id": "a1-add", "type": "add_trust", "client_id": "c",
            "anchor_cert_id": "root-new",
            "allowed_stages": sorted(rng.sample([1, 2, 3],
                                                rng.randint(1, 3)))})
    if rng.random() < 0.9:
        actions.append({
            "action_id": "a2-replace", "type": "replace_cert",
            "endpoint_id": "svc", "new_chain": ["leaf-new", "root-new"],
            "allowed_stages": sorted(rng.sample([1, 2, 3],
                                                rng.randint(1, 3)))})
    if rng.random() < 0.7:
        actions.append({
            "action_id": "a3-remove", "type": "remove_trust",
            "client_id": "c", "anchor_cert_id": "root-old",
            "allowed_stages": sorted(rng.sample([1, 2, 3],
                                                rng.randint(1, 3)))})
    completed = [a["action_id"] for a in actions
                 if rng.random() < 0.4 and a["type"] != "replace_cert"]
    candidates = rng.sample(chain_pool, rng.randint(0, len(chain_pool)))
    evidence = []
    for c in certs:
        roll = rng.random()
        if roll < 0.25:
            evidence.append({"cert_id": c["cert_id"], "status": "revoked",
                             "fresh": rng.random() < 0.8})
        elif roll < 0.4:
            evidence.append({"cert_id": c["cert_id"], "status": "good",
                             "fresh": True})
    return {
        "certificates": certs,
        "trust_anchors": [{"client_id": "c", "cert_id": "root-old"}],
        "endpoints": [{
            "endpoint_id": "svc",
            "current_chain": ["leaf-old", "root-old"],
            "target_chain": ["leaf-new", "root-new"],
        }],
        "relationships": [{"client_id": "c", "endpoint_id": "svc"}],
        "actions": actions,
        "plan_time": NOW.isoformat(),
        "completed_action_ids": completed,
        "candidates": ([{"endpoint_id": "svc", "candidate_chains": candidates}]
                       if candidates else []),
        "revocation_evidence": evidence,
    }


@pytest.mark.parametrize("seed", range(60))
def test_replan_matches_brute_force(seed):
    rng = random.Random(seed)
    payload = _random_replan_scenario(rng)
    expected = _brute_force_replan(payload)
    r = replan(payload)
    if expected is None:
        assert r.status_code == 409, (seed, r.status_code, r.text)
        return
    assert r.status_code == 200, (seed, r.status_code, r.text)
    body = r.json()
    m, stage_vector, combo = expected
    assert body["stage_count"] == m
    stage_of = {}
    for st in body["stages"]:
        for aid in st["action_ids"]:
            stage_of[aid] = st["stage"]
    remaining_ids = sorted(
        a["action_id"] for a in payload["actions"]
        if a["action_id"] not in set(payload["completed_action_ids"])
    )
    assert tuple(stage_of[aid] for aid in remaining_ids) == stage_vector
    selections = sorted(body["chain_selections"],
                        key=lambda s: s["endpoint_id"])
    assert tuple(tuple(s["chain"]) for s in selections) == combo
