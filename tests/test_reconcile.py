"""Tests for POST /plans/reconcile: safe resumption after an outage."""
from datetime import datetime, timedelta, timezone

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


SCENARIO = {
    "certificates": [
        cert("root-old", "CN=Old Root", "CN=Old Root"),
        cert("root-new", "CN=New Root", "CN=New Root"),
        cert("leaf-old", "CN=svc", "CN=Old Root"),
        cert("leaf-new", "CN=svc", "CN=New Root"),
    ],
    "trust_anchors": [{"client_id": "c", "cert_id": "root-old"}],
    "endpoints": [
        {
            "endpoint_id": "svc",
            "current_chain": ["leaf-old", "root-old"],
            "target_chain": ["leaf-new", "root-new"],
        }
    ],
    "relationships": [{"client_id": "c", "endpoint_id": "svc"}],
    "actions": [
        {"action_id": "a1-add", "type": "add_trust",
         "client_id": "c", "anchor_cert_id": "root-new",
         "allowed_stages": [1, 2, 3]},
        {"action_id": "a2-replace", "type": "replace_cert",
         "endpoint_id": "svc",
         "new_chain": ["leaf-new", "root-new"],
         "allowed_stages": [2, 3]},
        {"action_id": "a3-remove", "type": "remove_trust",
         "client_id": "c", "anchor_cert_id": "root-old",
         "allowed_stages": [1, 2, 3]},
    ],
    "plan_time": NOW.isoformat(),
}

PLAN = [
    {"stage": 1, "action_ids": ["a1-add"]},
    {"stage": 2, "action_ids": ["a2-replace", "a3-remove"]},
]


def reconcile(payload):
    return client.post("/plans/reconcile", json=payload)


# ---------------------------------------------------------------------------
# State enumeration
# ---------------------------------------------------------------------------


def test_no_observations_lists_all_plan_ordered_healthy_states():
    r = reconcile({**SCENARIO, "stages": PLAN})
    assert r.status_code == 200, r.text
    body = r.json()
    progress = body["possible_progress"]
    # {} before stage 1; {a1} ended stage 1; {a1,a2} partial stage 2
    # ({a1,a3} breaks the path and is removed); full mask finished.
    assert progress == [
        {"completed_stages": 0, "current_stage": 1,
         "completed_action_ids": []},
        {"completed_stages": 1, "current_stage": 2,
         "completed_action_ids": ["a1-add"]},
        {"completed_stages": 1, "current_stage": 2,
         "completed_action_ids": ["a1-add", "a2-replace"]},
        {"completed_stages": 2, "current_stage": None,
         "completed_action_ids": ["a1-add", "a2-replace", "a3-remove"]},
    ]
    # Nothing is safe in every possible state (including the initial one).
    assert body["safe_next_actions"] == []


def test_later_stage_actions_never_execute_early():
    # a2 can only run from stage 2, so the only stage-1 partial states are
    # {} and {a1}; observing the new chain is impossible before stage 2.
    r = reconcile({
        **SCENARIO, "stages": PLAN,
        "chain_observations": [
            {"endpoint_id": "svc", "chain": ["leaf-new", "root-new"]}
        ],
    })
    assert r.status_code == 200
    for p in r.json()["possible_progress"]:
        assert p["completed_stages"] >= 1
        assert "a2-replace" in p["completed_action_ids"]


def test_unknown_is_not_treated_as_absent_or_unexecuted():
    # No observations at all: the finished deployment is among the possible
    # progresses even though nothing was confirmed.
    r = reconcile({**SCENARIO, "stages": PLAN})
    assert r.status_code == 200
    assert r.json()["possible_progress"][-1]["completed_stages"] == 2


def test_ended_stages_are_complete():
    # Observing the new leaf means stage 1 has fully ended: a1 must appear in
    # every reported progress (no {}- or add-less state survives).
    r = reconcile({
        **SCENARIO, "stages": PLAN,
        "chain_observations": [
            {"endpoint_id": "svc", "chain": ["leaf-new", "root-new"]}
        ],
    })
    assert r.status_code == 200
    for p in r.json()["possible_progress"]:
        assert "a1-add" in p["completed_action_ids"]


# ---------------------------------------------------------------------------
# Observations narrow the possibilities
# ---------------------------------------------------------------------------


def test_anchor_present_observation_pins_add_as_done():
    r = reconcile({
        **SCENARIO, "stages": PLAN,
        "anchor_observations": [
            {"client_id": "c", "anchor_cert_id": "root-new", "present": True}
        ],
    })
    assert r.status_code == 200
    done_sets = [
        tuple(p["completed_action_ids"])
        for p in r.json()["possible_progress"]
    ]
    assert done_sets == [
        ("a1-add",),
        ("a1-add", "a2-replace"),
        ("a1-add", "a2-replace", "a3-remove"),
    ]


def test_old_chain_and_old_anchor_restrict_to_stage_one():
    r = reconcile({
        **SCENARIO, "stages": PLAN,
        "anchor_observations": [
            {"client_id": "c", "anchor_cert_id": "root-old", "present": True}
        ],
        "chain_observations": [
            {"endpoint_id": "svc", "chain": ["leaf-old", "root-old"]}
        ],
    })
    assert r.status_code == 200
    progress = r.json()["possible_progress"]
    assert [tuple(p["completed_action_ids"]) for p in progress] == [
        (), ("a1-add",)
    ]


def test_new_chain_old_anchor_still_trusted_gives_unique_safe_remove():
    r = reconcile({
        **SCENARIO, "stages": PLAN,
        "anchor_observations": [
            {"client_id": "c", "anchor_cert_id": "root-old", "present": True}
        ],
        "chain_observations": [
            {"endpoint_id": "svc", "chain": ["leaf-new", "root-new"]}
        ],
    })
    assert r.status_code == 200
    body = r.json()
    assert body["possible_progress"] == [
        {"completed_stages": 1, "current_stage": 2,
         "completed_action_ids": ["a1-add", "a2-replace"]}
    ]
    # Applying the remove alone keeps both (here: the new) trust path valid.
    assert body["safe_next_actions"] == ["a3-remove"]


def test_anchor_absent_observation_implies_finished():
    r = reconcile({
        **SCENARIO, "stages": PLAN,
        "anchor_observations": [
            {"client_id": "c", "anchor_cert_id": "root-old", "present": False}
        ],
    })
    assert r.status_code == 200
    body = r.json()
    assert body["possible_progress"] == [
        {"completed_stages": 2, "current_stage": None,
         "completed_action_ids": ["a1-add", "a2-replace", "a3-remove"]}
    ]
    assert body["safe_next_actions"] == []


def test_absent_observation_is_narrow_not_unknown():
    # present=false on the NEW anchor rules out the finished state as long as
    # the new leaf chain is the only one trusting it; but unlike an omitted
    # observation it must also rule out every state in which the add ran.
    r = reconcile({
        **SCENARIO, "stages": PLAN,
        "anchor_observations": [
            {"client_id": "c", "anchor_cert_id": "root-new", "present": False}
        ],
    })
    assert r.status_code == 200
    for p in r.json()["possible_progress"]:
        assert "a1-add" not in p["completed_action_ids"]


# ---------------------------------------------------------------------------
# safe_next_actions
# ---------------------------------------------------------------------------


def test_safe_next_requires_singleton_to_keep_all_relationships():
    # Stage 1 ended (new root trusted), old leaf still served. a2 alone is
    # safe (new chain verified by the new root); a3 alone would strand the
    # old leaf and must not be suggested.
    r = reconcile({
        **SCENARIO, "stages": PLAN,
        "anchor_observations": [
            {"client_id": "c", "anchor_cert_id": "root-new", "present": True}
        ],
        "chain_observations": [
            {"endpoint_id": "svc", "chain": ["leaf-old", "root-old"]}
        ],
    })
    assert r.status_code == 200
    assert r.json()["safe_next_actions"] == ["a2-replace"]


def test_safe_next_must_be_current_stage_in_every_state():
    # Nothing observed: the deployment could still be at stage 1. a2 is not a
    # stage-1 action there, so nothing qualifies across all states.
    r = reconcile({**SCENARIO, "stages": PLAN})
    assert r.status_code == 200
    assert r.json()["safe_next_actions"] == []


# ---------------------------------------------------------------------------
# Conflicts -> 409
# ---------------------------------------------------------------------------


def test_impossible_observation_returns_409_with_stable_conflict():
    # New chain served, but the only anchor that validates it is absent.
    r = reconcile({
        **SCENARIO, "stages": PLAN,
        "anchor_observations": [
            {"client_id": "c", "anchor_cert_id": "root-new", "present": False}
        ],
        "chain_observations": [
            {"endpoint_id": "svc", "chain": ["leaf-new", "root-new"]}
        ],
    })
    assert r.status_code == 409
    body = r.json()
    assert body["status"] == "conflict"
    assert body["reason"] == "observation_conflict"
    (conflict,) = body["conflicts"]
    assert conflict["kind"] == "endpoint_chain"
    assert conflict["endpoint_id"] == "svc"
    assert conflict["chain"] == ["leaf-new", "root-new"]
    assert conflict["reason"] == "endpoint_chain_mismatch"


def test_anchor_conflict_observation_shape():
    # Old leaf still served while BOTH roots are untrusted. Greedy stable
    # cut: root-new absence first narrows the healthy states down to the
    # initial one (old root trusted), then root-old absence contradicts it.
    r = reconcile({
        **SCENARIO, "stages": PLAN,
        "anchor_observations": [
            {"client_id": "c", "anchor_cert_id": "root-old", "present": False},
            {"client_id": "c", "anchor_cert_id": "root-new", "present": False},
        ],
        "chain_observations": [
            {"endpoint_id": "svc", "chain": ["leaf-old", "root-old"]}
        ],
    })
    assert r.status_code == 409
    body = r.json()
    assert body["reason"] == "observation_conflict"
    (first,) = body["conflicts"]
    assert first["kind"] == "anchor"
    assert first["client_id"] == "c"
    assert first["anchor_cert_id"] == "root-old"
    assert first["present"] is False
    assert first["reason"] == "anchor_absent_mismatch"
    # The chain observation never participates once candidates are empty.
    assert all(c["kind"] != "endpoint_chain" for c in body["conflicts"])


def test_no_safe_reachable_state_when_all_plan_states_broken():
    # Nothing the plan does can create a trust path: the client never trusts
    # either root, so both the initial state and every post-action state are
    # broken and no resumption point exists.
    payload = {
        **SCENARIO,
        "trust_anchors": [],
        "actions": [
            {"action_id": "a2-replace", "type": "replace_cert",
             "endpoint_id": "svc",
             "new_chain": ["leaf-new", "root-new"],
             "allowed_stages": [1]},
        ],
    }
    r = reconcile({**payload, "stages": [
        {"stage": 1, "action_ids": ["a2-replace"]},
    ]})
    assert r.status_code == 409
    body = r.json()
    assert body["status"] == "conflict"
    assert body["reason"] == "no_safe_reachable_state"
    assert body["conflicts"] == []


# ---------------------------------------------------------------------------
# No-op (empty) stages: same mask at different stage positions
# ---------------------------------------------------------------------------

# Same rotation, but the actions are only eligible at sparse absolute stage
# numbers, so the generated plans contain explicit no-op gaps.
SPARSE_SCENARIO = {
    **SCENARIO,
    "actions": [
        {"action_id": "a1-add", "type": "add_trust",
         "client_id": "c", "anchor_cert_id": "root-new",
         "allowed_stages": [2]},
        {"action_id": "a2-replace", "type": "replace_cert",
         "endpoint_id": "svc",
         "new_chain": ["leaf-new", "root-new"],
         "allowed_stages": [3]},
        {"action_id": "a3-remove", "type": "remove_trust",
         "client_id": "c", "anchor_cert_id": "root-old",
         "allowed_stages": [3]},
    ],
}

# Leading no-op stage: nothing may run at stage 1.
LEADING_GAP_PLAN = [
    {"stage": 1, "action_ids": []},
    {"stage": 2, "action_ids": ["a1-add"]},
    {"stage": 3, "action_ids": ["a2-replace", "a3-remove"]},
]


def test_leading_noop_stage_keeps_both_sides_of_the_gap():
    # The to-be-added anchor is observed absent, so only the empty mask
    # survives -- but at TWO positions: stage 1 (no-op) not yet crossed and
    # stage 1 crossed. Both must be listed; neither may be collapsed away.
    r = reconcile({
        **SPARSE_SCENARIO, "stages": LEADING_GAP_PLAN,
        "anchor_observations": [
            {"client_id": "c", "anchor_cert_id": "root-new", "present": False}
        ],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["possible_progress"] == [
        {"completed_stages": 0, "current_stage": 1,
         "completed_action_ids": []},
        {"completed_stages": 1, "current_stage": 2,
         "completed_action_ids": []},
    ]
    # In the earlier progress the current stage is the empty stage 1, so no
    # action is current-stage in every progress: nothing may be recommended
    # (a1-add only becomes executable once the gap is known to be crossed).
    assert body["safe_next_actions"] == []


def test_leading_noop_stage_without_observations_lists_all_positions():
    r = reconcile({**SPARSE_SCENARIO, "stages": LEADING_GAP_PLAN})
    assert r.status_code == 200, r.text
    assert r.json()["possible_progress"] == [
        {"completed_stages": 0, "current_stage": 1,
         "completed_action_ids": []},
        {"completed_stages": 1, "current_stage": 2,
         "completed_action_ids": []},
        {"completed_stages": 2, "current_stage": 3,
         "completed_action_ids": ["a1-add"]},
        {"completed_stages": 2, "current_stage": 3,
         "completed_action_ids": ["a1-add", "a2-replace"]},
        {"completed_stages": 3, "current_stage": None,
         "completed_action_ids": ["a1-add", "a2-replace", "a3-remove"]},
    ]


def test_consecutive_noop_stages_keep_every_position():
    # Two consecutive no-op gaps: the empty mask is reachable before stage 1,
    # between the gaps, and after both -- three distinct progresses.
    plan = [
        {"stage": 1, "action_ids": []},
        {"stage": 2, "action_ids": []},
        {"stage": 3, "action_ids": ["a1-add", "a2-replace", "a3-remove"]},
    ]
    scenario = {
        **SCENARIO,
        "actions": [
            {"action_id": "a1-add", "type": "add_trust",
             "client_id": "c", "anchor_cert_id": "root-new",
             "allowed_stages": [3]},
            {"action_id": "a2-replace", "type": "replace_cert",
             "endpoint_id": "svc",
             "new_chain": ["leaf-new", "root-new"],
             "allowed_stages": [3]},
            {"action_id": "a3-remove", "type": "remove_trust",
             "client_id": "c", "anchor_cert_id": "root-old",
             "allowed_stages": [3]},
        ],
    }
    r = reconcile({
        **scenario, "stages": plan,
        "anchor_observations": [
            {"client_id": "c", "anchor_cert_id": "root-new", "present": False}
        ],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["possible_progress"] == [
        {"completed_stages": 0, "current_stage": 1,
         "completed_action_ids": []},
        {"completed_stages": 1, "current_stage": 2,
         "completed_action_ids": []},
        {"completed_stages": 2, "current_stage": 3,
         "completed_action_ids": []},
    ]
    assert body["safe_next_actions"] == []


# Middle no-op stage: a1 at stage 1, a2/a3 at stage 3.
MIDDLE_GAP_PLAN = [
    {"stage": 1, "action_ids": ["a1-add"]},
    {"stage": 2, "action_ids": []},
    {"stage": 3, "action_ids": ["a2-replace", "a3-remove"]},
]

MIDDLE_GAP_SCENARIO = {
    **SCENARIO,
    "actions": [
        {"action_id": "a1-add", "type": "add_trust",
         "client_id": "c", "anchor_cert_id": "root-new",
         "allowed_stages": [1]},
        {"action_id": "a2-replace", "type": "replace_cert",
         "endpoint_id": "svc",
         "new_chain": ["leaf-new", "root-new"],
         "allowed_stages": [3]},
        {"action_id": "a3-remove", "type": "remove_trust",
         "client_id": "c", "anchor_cert_id": "root-old",
         "allowed_stages": [3]},
    ],
}


def test_middle_noop_stage_is_not_assumed_crossed():
    # New root trusted (a1 done) and old chain still served (a2 not done):
    # the mask is pinned to {a1}, but the no-op stage 2 may or may not have
    # been crossed. Both positions must survive, and because the earlier one
    # is still at the empty stage 2, a2-replace is NOT safe to run yet.
    r = reconcile({
        **MIDDLE_GAP_SCENARIO, "stages": MIDDLE_GAP_PLAN,
        "anchor_observations": [
            {"client_id": "c", "anchor_cert_id": "root-new", "present": True}
        ],
        "chain_observations": [
            {"endpoint_id": "svc", "chain": ["leaf-old", "root-old"]}
        ],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["possible_progress"] == [
        {"completed_stages": 1, "current_stage": 2,
         "completed_action_ids": ["a1-add"]},
        {"completed_stages": 2, "current_stage": 3,
         "completed_action_ids": ["a1-add"]},
    ]
    assert body["safe_next_actions"] == []


def test_middle_noop_stage_safe_actions_once_gap_known_crossed():
    # Observing the new chain proves stage 3 was reached (a2 ran), and the
    # old root is still trusted (a3 pending): the gap is known to be crossed,
    # so the stage-3 remove becomes the unique safe next action.
    r = reconcile({
        **MIDDLE_GAP_SCENARIO, "stages": MIDDLE_GAP_PLAN,
        "anchor_observations": [
            {"client_id": "c", "anchor_cert_id": "root-old", "present": True}
        ],
        "chain_observations": [
            {"endpoint_id": "svc", "chain": ["leaf-new", "root-new"]}
        ],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["possible_progress"] == [
        {"completed_stages": 2, "current_stage": 3,
         "completed_action_ids": ["a1-add", "a2-replace"]},
    ]
    assert body["safe_next_actions"] == ["a3-remove"]


def test_trailing_noop_stage_completion_uses_full_progress_identity():
    # Everything ran at stage 1; stage 2 is a trailing no-op. The finished
    # mask is reachable before and after the gap ends: only the latter is the
    # completed deployment (current_stage null).
    plan = [
        {"stage": 1, "action_ids": ["a1-add", "a2-replace", "a3-remove"]},
        {"stage": 2, "action_ids": []},
    ]
    scenario = {
        **SCENARIO,
        "actions": [
            {"action_id": "a1-add", "type": "add_trust",
             "client_id": "c", "anchor_cert_id": "root-new",
             "allowed_stages": [1]},
            {"action_id": "a2-replace", "type": "replace_cert",
             "endpoint_id": "svc",
             "new_chain": ["leaf-new", "root-new"],
             "allowed_stages": [1]},
            {"action_id": "a3-remove", "type": "remove_trust",
             "client_id": "c", "anchor_cert_id": "root-old",
             "allowed_stages": [1]},
        ],
    }
    r = reconcile({
        **scenario, "stages": plan,
        "anchor_observations": [
            {"client_id": "c", "anchor_cert_id": "root-old", "present": False}
        ],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["possible_progress"] == [
        {"completed_stages": 1, "current_stage": 2,
         "completed_action_ids": ["a1-add", "a2-replace", "a3-remove"]},
        {"completed_stages": 2, "current_stage": None,
         "completed_action_ids": ["a1-add", "a2-replace", "a3-remove"]},
    ]
    assert body["safe_next_actions"] == []


# ---------------------------------------------------------------------------
# Structural validation -> 422
# ---------------------------------------------------------------------------


def test_stages_must_be_consecutive():
    r = reconcile({**SCENARIO, "stages": [
        {"stage": 1, "action_ids": ["a1-add"]},
        {"stage": 3, "action_ids": ["a2-replace", "a3-remove"]},
    ]})
    assert r.status_code == 422
    assert "consecutively" in r.json()["detail"]


def test_every_action_scheduled_exactly_once():
    r = reconcile({**SCENARIO, "stages": [
        {"stage": 1, "action_ids": ["a1-add"]},
        {"stage": 2, "action_ids": ["a2-replace"]},
    ]})
    assert r.status_code == 422
    assert "exactly once" in r.json()["detail"]

    r = client.post("/plans/reconcile", json={**SCENARIO, "stages": [
        {"stage": 1, "action_ids": ["a1-add", "a1-add"]},
        {"stage": 2, "action_ids": ["a2-replace", "a3-remove"]},
    ]})
    assert r.status_code == 422


def test_action_outside_allowed_stage_rejected():
    r = reconcile({**SCENARIO, "stages": [
        {"stage": 1, "action_ids": ["a2-replace"]},
        {"stage": 2, "action_ids": ["a1-add", "a3-remove"]},
    ]})
    assert r.status_code == 422
    assert "allowed_stages" in r.json()["detail"]


def test_unknown_observation_targets_rejected():
    r = reconcile({
        **SCENARIO, "stages": PLAN,
        "anchor_observations": [
            {"client_id": "ghost", "anchor_cert_id": "root-old",
             "present": True}
        ],
    })
    assert r.status_code == 422
    assert "unknown client_id" in r.json()["detail"]

    r = reconcile({
        **SCENARIO, "stages": PLAN,
        "chain_observations": [
            {"endpoint_id": "ghost", "chain": ["leaf-old", "root-old"]}
        ],
    })
    assert r.status_code == 422
    assert "unknown endpoint_id" in r.json()["detail"]


def test_duplicate_observation_rejected():
    r = reconcile({
        **SCENARIO, "stages": PLAN,
        "anchor_observations": [
            {"client_id": "c", "anchor_cert_id": "root-old", "present": True},
            {"client_id": "c", "anchor_cert_id": "root-old", "present": False},
        ],
    })
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# No-op stages
# ---------------------------------------------------------------------------


def test_empty_stages_advance_completed_count():
    payload = {**SCENARIO, "actions": [
        dict(SCENARIO["actions"][0], allowed_stages=[1]),
        dict(SCENARIO["actions"][1], allowed_stages=[3]),
        dict(SCENARIO["actions"][2], allowed_stages=[3]),
    ]}
    stages = [
        {"stage": 1, "action_ids": ["a1-add"]},
        {"stage": 2, "action_ids": []},
        {"stage": 3, "action_ids": ["a2-replace", "a3-remove"]},
    ]
    r = reconcile({**payload, "stages": stages})
    assert r.status_code == 200, r.text
    progress = r.json()["possible_progress"]
    # {}, then after the ended stage-1 + no-op stage-2: {a1} at current stage
    # 3, its partials, and the finished state.
    assert progress[0] == {
        "completed_stages": 0, "current_stage": 1,
        "completed_action_ids": [],
    }
    assert {
        "completed_stages": 2, "current_stage": 3,
        "completed_action_ids": ["a1-add"],
    } in progress
    assert progress[-1]["completed_stages"] == 3


def test_zero_actions_finished_immediately():
    payload = {
        **SCENARIO,
        "actions": [],
        "endpoints": [{
            "endpoint_id": "svc",
            "current_chain": ["leaf-old", "root-old"],
            "target_chain": ["leaf-old", "root-old"],
        }],
    }
    r = reconcile({**payload, "stages": []})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["possible_progress"] == [
        {"completed_stages": 0, "current_stage": None,
         "completed_action_ids": []}
    ]
    assert body["safe_next_actions"] == []
