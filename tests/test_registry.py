"""Tests for auditable, transactional stage commits (/plans/registrations)."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import registry
from app.main import app


@pytest.fixture(autouse=True)
def _temp_db(tmp_path):
    """Point the registry at a fresh SQLite database for every test."""
    path = str(tmp_path / "registrations.db")
    registry.set_database_path(path)
    registry.init_db()
    yield
    registry.set_database_path(None)


client = TestClient(app)

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def cert(cid, subject, issuer, *, expired=False, not_before=None):
    if not_before is None:
        not_before = NOW - timedelta(days=730) if expired else NOW - timedelta(days=1)
    return {
        "cert_id": cid,
        "subject": subject,
        "issuer": issuer,
        "not_valid_before": not_before.isoformat(),
        "not_valid_after": (
            NOW - timedelta(days=1) if expired else NOW + timedelta(days=365)
        ).isoformat(),
    }


ROTATION = {
    "certificates": [
        cert("root-old", "CN=Old Root", "CN=Old Root"),
        cert("root-new", "CN=New Root", "CN=New Root"),
        cert("leaf-old", "CN=svc", "CN=Old Root"),
        cert("leaf-new", "CN=svc", "CN=New Root"),
    ],
    "trust_anchors": [{"client_id": "client-a", "cert_id": "root-old"}],
    "endpoints": [
        {
            "endpoint_id": "svc",
            "current_chain": ["leaf-old", "root-old"],
            "target_chain": ["leaf-new", "root-new"],
        }
    ],
    "relationships": [{"client_id": "client-a", "endpoint_id": "svc"}],
    "actions": [
        {"action_id": "a1-add-new", "type": "add_trust",
         "client_id": "client-a", "anchor_cert_id": "root-new",
         "allowed_stages": [1, 2, 3]},
        {"action_id": "a2-replace", "type": "replace_cert",
         "endpoint_id": "svc",
         "new_chain": ["leaf-new", "root-new"],
         "allowed_stages": [2, 3]},
        {"action_id": "a3-remove-old", "type": "remove_trust",
         "client_id": "client-a", "anchor_cert_id": "root-old",
         "allowed_stages": [1, 2, 3]},
    ],
    "plan_time": NOW.isoformat(),
}

PLAN = [
    {"stage": 1, "action_ids": ["a1-add-new"]},
    {"stage": 2, "action_ids": ["a2-replace", "a3-remove-old"]},
]

STAGE1_COMMIT = {
    "expected_version": 0,
    "action_ids": ["a1-add-new"],
    "anchor_observations": [
        {"client_id": "client-a", "anchor_cert_id": "root-new", "present": True},
        {"client_id": "client-a", "anchor_cert_id": "root-old", "present": True},
    ],
    "chain_observations": [
        {"endpoint_id": "svc", "chain": ["leaf-old", "root-old"]}
    ],
}

STAGE2_COMMIT = {
    "expected_version": 1,
    "action_ids": ["a2-replace", "a3-remove-old"],
    "anchor_observations": [
        {"client_id": "client-a", "anchor_cert_id": "root-old", "present": False},
        {"client_id": "client-a", "anchor_cert_id": "root-new", "present": True},
    ],
    "chain_observations": [
        {"endpoint_id": "svc", "chain": ["leaf-new", "root-new"]}
    ],
}


def _register(plan=PLAN, scenario=ROTATION):
    r = client.post(
        "/plans/registrations", json={"plan": plan, **scenario}
    )
    assert r.status_code == 201, r.text
    return r.json()


def _commit(rid, body):
    return client.post(f"/plans/registrations/{rid}/stages", json=body)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def test_register_creates_version_zero_with_fingerprint():
    body = _register()
    assert body["current_version"] == 0
    assert body["completed_stages"] == []
    assert body["next_stage"] == 1
    assert body["snapshots"] == []
    assert body["stage_count"] == 2
    assert len(body["registration_id"]) == 32
    assert len(body["plan_fingerprint"]) == 64
    assert all(c in "0123456789abcdef" for c in body["plan_fingerprint"])


def test_identical_payloads_share_fingerprint_but_get_distinct_ids():
    a = _register()
    b = _register()
    assert a["plan_fingerprint"] == b["plan_fingerprint"]
    assert a["registration_id"] != b["registration_id"]


def test_register_rejects_plan_that_does_not_replay():
    bad_plan = [
        {"stage": 1, "action_ids": ["a3-remove-old"]},
        {"stage": 2, "action_ids": ["a1-add-new", "a2-replace"]},
    ]
    r = client.post("/plans/registrations", json={"plan": bad_plan, **ROTATION})
    assert r.status_code == 409
    body = r.json()
    assert body["status"] == "invalid"
    assert body["stage"] == 1
    assert body["blocking_action"] == "a3-remove-old"
    assert body["reason"] == "untrusted_root"


def test_register_rejects_structurally_bad_plan():
    bad_plan = [{"stage": 1, "action_ids": ["a1-add-new"]}]  # actions missing
    r = client.post("/plans/registrations", json={"plan": bad_plan, **ROTATION})
    assert r.status_code == 422
    assert "exactly once" in r.json()["detail"]


def test_register_unknown_registration_is_404():
    r = client.get("/plans/registrations/deadbeef")
    assert r.status_code == 404
    assert r.json()["detail"]["error"] == "registration_not_found"


# ---------------------------------------------------------------------------
# Happy-path commits and snapshots
# ---------------------------------------------------------------------------


def test_commit_stage_one_advances_version_and_saves_snapshot():
    rid = _register()["registration_id"]
    r = _commit(rid, STAGE1_COMMIT)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["idempotent_replay"] is False
    assert body["current_version"] == 1
    assert body["completed_stages"] == [1]
    assert body["next_stage"] == 2
    snap = body["snapshots"][0]
    assert snap["stage"] == 1
    assert snap["version"] == 1
    assert snap["committed_action_ids"] == ["a1-add-new"]
    assert snap["committed_at"]
    # Complete deterministic post-stage trust state: both anchors present.
    assert snap["anchors"] == [
        {"client_id": "client-a", "anchor_cert_id": "root-new", "present": True},
        {"client_id": "client-a", "anchor_cert_id": "root-old", "present": True},
    ]
    assert snap["endpoint_chains"] == [
        {"endpoint_id": "svc", "chain": ["leaf-old", "root-old"]}
    ]
    assert snap["relationships"] == [
        {
            "client_id": "client-a",
            "endpoint_id": "svc",
            "valid": True,
            "chain": ["leaf-old", "root-old"],
            "trusted_anchors": ["root-new", "root-old"],
        }
    ]
    # Submitted observations are recorded verbatim (sorted) for the audit.
    assert snap["anchor_observations"] == STAGE1_COMMIT_SORTED_ANCHORS
    assert snap["chain_observations"] == STAGE1_COMMIT["chain_observations"]


STAGE1_COMMIT_SORTED_ANCHORS = [
    {"client_id": "client-a", "anchor_cert_id": "root-new", "present": True},
    {"client_id": "client-a", "anchor_cert_id": "root-old", "present": True},
]


def test_full_rotation_commits_to_completion():
    rid = _register()["registration_id"]
    r1 = _commit(rid, STAGE1_COMMIT)
    assert r1.status_code == 200
    r2 = _commit(rid, STAGE2_COMMIT)
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["current_version"] == 2
    assert body["completed_stages"] == [1, 2]
    assert body["next_stage"] is None
    assert len(body["snapshots"]) == 2
    snap2 = body["snapshots"][1]
    assert snap2["committed_action_ids"] == ["a2-replace", "a3-remove-old"]
    assert snap2["anchors"] == [
        {"client_id": "client-a", "anchor_cert_id": "root-new", "present": True},
    ]
    assert snap2["endpoint_chains"] == [
        {"endpoint_id": "svc", "chain": ["leaf-new", "root-new"]}
    ]
    assert snap2["relationships"][0]["valid"] is True
    assert snap2["relationships"][0]["trusted_anchors"] == ["root-new"]

    # GET returns the same complete state.
    g = client.get(f"/plans/registrations/{rid}")
    assert g.status_code == 200
    assert g.json()["current_version"] == 2
    assert g.json()["next_stage"] is None


def test_commit_after_plan_finished_is_unexpected_stage():
    rid = _register()["registration_id"]
    _commit(rid, STAGE1_COMMIT)
    _commit(rid, STAGE2_COMMIT)
    r = _commit(rid, {**STAGE2_COMMIT, "expected_version": 2})
    assert r.status_code == 409
    assert r.json()["reason"] == "unexpected_stage"


# ---------------------------------------------------------------------------
# Concurrency / idempotency
# ---------------------------------------------------------------------------


def test_stale_expected_version_is_409_without_partial_progress():
    rid = _register()["registration_id"]
    assert _commit(rid, STAGE1_COMMIT).status_code == 200
    # expected_version 0 with a DIFFERENT observation set is a stale conflict,
    # not an idempotent replay.
    stale = {
        **STAGE1_COMMIT,
        "anchor_observations": [
            {"client_id": "client-a", "anchor_cert_id": "root-new",
             "present": False},
        ],
    }
    r = _commit(rid, stale)
    assert r.status_code == 409
    body = r.json()
    assert body["reason"] == "version_conflict"
    assert body["current_version"] == 1
    assert body["next_stage"] == 2
    assert body["expected_version"] == 0
    # nothing advanced
    assert client.get(f"/plans/registrations/{rid}").json()["current_version"] == 1


def test_duplicate_commit_returns_same_snapshot_without_advancing():
    rid = _register()["registration_id"]
    first = _commit(rid, STAGE1_COMMIT).json()
    again = _commit(rid, STAGE1_COMMIT).json()
    assert again["idempotent_replay"] is True
    assert again["current_version"] == 1
    assert again["completed_stages"] == [1]
    assert len(again["snapshots"]) == 1
    assert (
        again["snapshots"][0]["committed_at"]
        == first["snapshots"][0]["committed_at"]
    )
    assert again["snapshots"] == first["snapshots"]


def test_duplicate_commit_of_last_completed_stage_is_idempotent():
    rid = _register()["registration_id"]
    _commit(rid, STAGE1_COMMIT)
    done = _commit(rid, STAGE2_COMMIT).json()
    again = _commit(rid, STAGE2_COMMIT).json()
    assert again["idempotent_replay"] is True
    assert again["current_version"] == 2
    assert again["next_stage"] is None
    assert again["snapshots"] == done["snapshots"]


def test_future_expected_version_is_conflict_when_plan_finished():
    rid = _register()["registration_id"]
    _commit(rid, STAGE1_COMMIT)
    _commit(rid, STAGE2_COMMIT)
    r = _commit(rid, {**STAGE2_COMMIT, "expected_version": 5})
    assert r.status_code == 409
    assert r.json()["reason"] == "unexpected_stage"


# ---------------------------------------------------------------------------
# Atomic validation of action set, observations and relationships
# ---------------------------------------------------------------------------


def test_racing_commits_leave_exactly_one_advancing_version():
    rid = _register()["registration_id"]
    barrier = threading.Barrier(4)

    def _race(kind):
        barrier.wait()  # maximize the chance the commits interleave
        if kind == 0:
            # The legitimate stage-1 commit.
            return _commit(rid, STAGE1_COMMIT)
        # A distinct, invalid stage-1 request: it asserts the new anchor is
        # absent right after the add_trust. At v0 this fails observation
        # validation; once stage 1 landed, it also fails the version check —
        # either way 409, never a mutation.
        bad = {
            **STAGE1_COMMIT,
            "anchor_observations": [
                {"client_id": "client-a", "anchor_cert_id": "root-new",
                 "present": False},
            ],
        }
        return _commit(rid, bad)

    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(_race, [0, 1, 2, 3]))
    results = [(r.status_code, r.json()) for r in responses]

    successes = [body for code, body in results if code == 200]
    conflicts = [body for code, body in results if code == 409]

    # Exactly one commit wins and persists one snapshot; every racing loser is
    # a 409 (version conflict or observation mismatch), never a partial write.
    assert len(successes) == 1
    assert successes[0]["current_version"] == 1
    assert len(successes[0]["snapshots"]) == 1
    assert len(conflicts) == 3
    for c in conflicts:
        # A loser that ran before the winner sees version 0; one running
        # after it sees version 1 — both are valid non-mutating outcomes.
        assert c["current_version"] in (0, 1)
        assert c["reason"] in (
            "version_conflict", "anchor_observation_mismatch"
        )

    state = client.get(f"/plans/registrations/{rid}").json()
    assert state["current_version"] == 1
    assert len(state["snapshots"]) == 1
    # The loser can (and must be able to) read the new state and continue.
    nxt = _commit(rid, STAGE2_COMMIT)
    assert nxt.status_code == 200
    assert nxt.json()["current_version"] == 2


def test_wrong_action_set_is_409_and_leaves_no_progress():
    rid = _register()["registration_id"]
    r = _commit(rid, {**STAGE1_COMMIT, "action_ids": ["a2-replace"]})
    assert r.status_code == 409
    body = r.json()
    assert body["reason"] == "action_set_mismatch"
    assert body["submitted_stage"] == 1
    mm = body["mismatches"][0]
    assert mm["kind"] == "action_set"
    assert mm["expected_action_ids"] == ["a1-add-new"]
    assert mm["submitted_action_ids"] == ["a2-replace"]
    # rollback: still at version 0, and the correct commit then succeeds
    state = client.get(f"/plans/registrations/{rid}").json()
    assert state["current_version"] == 0
    assert state["snapshots"] == []
    assert _commit(rid, STAGE1_COMMIT).status_code == 200


def test_anchor_observation_mismatch_is_409():
    rid = _register()["registration_id"]
    bad = {
        **STAGE1_COMMIT,
        "anchor_observations": [
            {"client_id": "client-a", "anchor_cert_id": "root-new",
             "present": False},  # new root IS trusted after a1
        ],
    }
    r = _commit(rid, bad)
    assert r.status_code == 409
    body = r.json()
    assert body["reason"] == "anchor_observation_mismatch"
    mm = [m for m in body["mismatches"] if m["kind"] == "anchor_observation"]
    assert len(mm) == 1
    assert mm[0]["client_id"] == "client-a"
    assert mm[0]["anchor_cert_id"] == "root-new"
    assert mm[0]["observed_present"] is False
    assert mm[0]["expected_present"] is True


def test_chain_observation_mismatch_is_409():
    rid = _register()["registration_id"]
    bad = {
        **STAGE1_COMMIT,
        "chain_observations": [
            {"endpoint_id": "svc", "chain": ["leaf-new", "root-new"]},
        ],
    }
    r = _commit(rid, bad)
    assert r.status_code == 409
    body = r.json()
    assert body["reason"] == "chain_observation_mismatch"
    mm = body["mismatches"][0]
    assert mm["endpoint_id"] == "svc"
    assert mm["observed_chain"] == ["leaf-new", "root-new"]
    assert mm["expected_chain"] == ["leaf-old", "root-old"]


def test_unsafe_wrong_action_set_reports_broken_relationship_too():
    rid = _register()["registration_id"]
    bad = {
        **STAGE1_COMMIT,
        "action_ids": ["a3-remove-old"],
        "anchor_observations": [
            {"client_id": "client-a", "anchor_cert_id": "root-old",
             "present": False},
        ],
        "chain_observations": [
            {"endpoint_id": "svc", "chain": ["leaf-old", "root-old"]},
        ],
    }
    r = _commit(rid, bad)
    assert r.status_code == 409
    kinds = {m["kind"] for m in r.json()["mismatches"]}
    assert "action_set" in kinds
    rel = [m for m in r.json()["mismatches"] if m["kind"] == "relationship"]
    assert len(rel) == 1
    assert rel[0]["client_id"] == "client-a"
    assert rel[0]["endpoint_id"] == "svc"
    assert rel[0]["reason"] == "untrusted_root"
    assert rel[0]["chain"] == ["leaf-old", "root-old"]
    assert client.get(f"/plans/registrations/{rid}").json()["current_version"] == 0


def test_action_set_order_independent():
    rid = _register()["registration_id"]
    body = {
        **STAGE2_COMMIT,
        "action_ids": ["a3-remove-old", "a2-replace"],  # reversed
    }
    assert _commit(rid, STAGE1_COMMIT).status_code == 200
    r = _commit(rid, body)
    assert r.status_code == 200, r.text
    assert r.json()["snapshots"][1]["committed_action_ids"] == [
        "a2-replace", "a3-remove-old"
    ]


def test_unknown_ids_are_422_not_409():
    rid = _register()["registration_id"]
    r = _commit(rid, {**STAGE1_COMMIT, "action_ids": ["nope"]})
    assert r.status_code == 422
    r = _commit(
        rid,
        {
            **STAGE1_COMMIT,
            "anchor_observations": [
                {"client_id": "ghost", "anchor_cert_id": "root-old",
                 "present": True}
            ],
        },
    )
    assert r.status_code == 422
    r = _commit(
        rid,
        {
            **STAGE1_COMMIT,
            "chain_observations": [{"endpoint_id": "ghost", "chain": ["r"]}],
        },
    )
    assert r.status_code == 422


def test_duplicate_action_ids_in_commit_are_422():
    rid = _register()["registration_id"]
    r = _commit(
        rid,
        {
            **STAGE1_COMMIT,
            "action_ids": ["a1-add-new", "a1-add-new"],
        },
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# No-op (empty) stages
# ---------------------------------------------------------------------------


def test_noop_empty_stage_commits_with_empty_action_set():
    scenario = {
        **ROTATION,
        "actions": [
            dict(ROTATION["actions"][0], allowed_stages=[2]),
            dict(ROTATION["actions"][1], allowed_stages=[2]),
            dict(ROTATION["actions"][2], allowed_stages=[2]),
        ],
    }
    plan = [
        {"stage": 1, "action_ids": []},
        {"stage": 2,
         "action_ids": ["a1-add-new", "a2-replace", "a3-remove-old"]},
    ]
    rid = _register(plan=plan, scenario=scenario)["registration_id"]
    r = _commit(
        rid,
        {
            "expected_version": 0,
            "action_ids": [],
            "anchor_observations": [
                {"client_id": "client-a", "anchor_cert_id": "root-old",
                 "present": True}
            ],
            "chain_observations": [
                {"endpoint_id": "svc", "chain": ["leaf-old", "root-old"]}
            ],
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["current_version"] == 1
    assert body["next_stage"] == 2
    snap = body["snapshots"][0]
    assert snap["committed_action_ids"] == []
    # state carried unchanged across the no-op
    assert snap["anchors"] == [
        {"client_id": "client-a", "anchor_cert_id": "root-old", "present": True}
    ]
    assert snap["relationships"][0]["valid"] is True


def test_submitting_actions_for_a_noop_stage_fails():
    scenario = {
        **ROTATION,
        "actions": [
            dict(ROTATION["actions"][0], allowed_stages=[2]),
            dict(ROTATION["actions"][1], allowed_stages=[2]),
            dict(ROTATION["actions"][2], allowed_stages=[2]),
        ],
    }
    plan = [
        {"stage": 1, "action_ids": []},
        {"stage": 2,
         "action_ids": ["a1-add-new", "a2-replace", "a3-remove-old"]},
    ]
    rid = _register(plan=plan, scenario=scenario)["registration_id"]
    r = _commit(
        rid,
        {
            "expected_version": 0,
            "action_ids": ["a1-add-new"],
            "anchor_observations": [],
            "chain_observations": [],
        },
    )
    assert r.status_code == 409
    assert r.json()["reason"] == "action_set_mismatch"
    assert r.json()["mismatches"][0]["expected_action_ids"] == []


# ---------------------------------------------------------------------------
# Zero-action plan
# ---------------------------------------------------------------------------


def test_zero_action_plan_registers_already_finished():
    scenario = {
        "certificates": [cert("r0", "CN=r0", "CN=r0")],
        "trust_anchors": [{"client_id": "c", "cert_id": "r0"}],
        "endpoints": [{
            "endpoint_id": "svc",
            "current_chain": ["r0"],
            "target_chain": ["r0"],
        }],
        "relationships": [{"client_id": "c", "endpoint_id": "svc"}],
        "actions": [],
        "plan_time": NOW.isoformat(),
    }
    r = client.post(
        "/plans/registrations", json={"plan": [], **scenario}
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["stage_count"] == 0
    assert body["current_version"] == 0
    assert body["next_stage"] is None


# ---------------------------------------------------------------------------
# Persistence: committed state survives a new connection to the same file
# ---------------------------------------------------------------------------


def test_commits_persist_in_sqlite_file(tmp_path):
    path = str(tmp_path / "registrations.db")
    registry.set_database_path(path)
    registry.init_db()
    rid = _register()["registration_id"]
    assert _commit(rid, STAGE1_COMMIT).status_code == 200
    # Reopen the database through fresh connections (same process, same file):
    # the version and snapshot must come back from disk.
    state = registry.get_state(rid)
    assert state.current_version == 1
    assert state.snapshots[0].committed_action_ids == ["a1-add-new"]
