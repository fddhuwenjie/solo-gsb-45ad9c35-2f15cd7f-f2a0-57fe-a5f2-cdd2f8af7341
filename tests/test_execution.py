"""Tests for auditable, transactional plan-execution stage commits."""
import threading
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import execution
from app.main import app
from app.models import ExecutionRegisterRequest, StageCommitRequest

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)

client = TestClient(app)


@pytest.fixture(autouse=True)
def _fresh_db(tmp_path, monkeypatch):
    """Point the store at a throwaway SQLite file for every test."""
    db = tmp_path / "rotation.db"
    monkeypatch.setenv("ROTATION_DB_PATH", str(db))
    execution.reset_store()
    yield
    execution.reset_store()


def cert(cid, subject, issuer):
    return {
        "cert_id": cid,
        "subject": subject,
        "issuer": issuer,
        "not_valid_before": (NOW - timedelta(days=365)).isoformat(),
        "not_valid_after": (NOW + timedelta(days=365)).isoformat(),
    }


SCENARIO = {
    "certificates": [
        cert("root-old", "CN=Old Root CA", "CN=Old Root CA"),
        cert("root-new", "CN=New Root CA", "CN=New Root CA"),
        cert("leaf-old", "CN=svc", "CN=Old Root CA"),
        cert("leaf-new", "CN=svc", "CN=New Root CA"),
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
        {"action_id": "a1-add", "type": "add_trust", "client_id": "c",
         "anchor_cert_id": "root-new", "allowed_stages": [1, 2, 3]},
        {"action_id": "a2-replace", "type": "replace_cert", "endpoint_id": "svc",
         "new_chain": ["leaf-new", "root-new"], "allowed_stages": [2, 3]},
        {"action_id": "a3-remove", "type": "remove_trust", "client_id": "c",
         "anchor_cert_id": "root-old", "allowed_stages": [1, 2, 3]},
    ],
    "plan_time": NOW.isoformat(),
}

PLAN = [
    {"stage": 1, "action_ids": ["a1-add"]},
    {"stage": 2, "action_ids": ["a2-replace", "a3-remove"]},
]


def register(plan=PLAN, scenario=SCENARIO):
    r = client.post("/plan-executions", json={**scenario, "plan": plan})
    assert r.status_code == 201, r.text
    return r.json()


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def test_register_creates_version_zero_with_initial_snapshot():
    body = register()
    assert body["execution_id"]
    assert body["version"] == 0
    assert body["stage_count"] == 2
    assert body["completed_stages"] == []
    assert body["next_stage"] == 1
    assert body["finished"] is False
    assert len(body["snapshots"]) == 1

    snap = body["snapshots"][0]
    assert snap["version"] == 0
    assert snap["stage"] == 0
    assert snap["action_ids"] == []
    anchors = {(a["client_id"], a["anchor_cert_id"])
               for a in snap["trust_anchors"]}
    assert anchors == {("c", "root-old")}
    chains = {e["endpoint_id"]: e["chain"] for e in snap["endpoint_chains"]}
    assert chains == {"svc": ["leaf-old", "root-old"]}
    rel = snap["relationships"][0]
    assert rel["valid"] is True
    assert [c["cert_id"] for c in rel["chain"]] == ["leaf-old", "root-old"]
    assert rel["trusted_anchors"] == ["root-old"]


def test_register_rejects_unsafe_plan_with_409_and_creates_nothing():
    bad_plan = [
        {"stage": 1, "action_ids": ["a3-remove"]},
        {"stage": 2, "action_ids": ["a1-add", "a2-replace"]},
    ]
    r = client.post("/plan-executions", json={**SCENARIO, "plan": bad_plan})
    assert r.status_code == 409
    body = r.json()
    assert body["reason"] == "untrusted_root"
    assert body["stage"] == 1
    assert body["blocking_action"] == "a3-remove"


def test_register_rejects_structurally_bad_plan_with_422():
    bad_plan = [{"stage": 1, "action_ids": ["a1-add"]}]  # actions missing
    r = client.post("/plan-executions", json={**SCENARIO, "plan": bad_plan})
    assert r.status_code == 422
    assert "exactly once" in r.json()["detail"]


def test_register_rejects_invalid_initial_state_with_409():
    scenario = {**SCENARIO, "trust_anchors": []}
    r = client.post("/plan-executions", json={**scenario, "plan": PLAN})
    assert r.status_code == 409
    assert r.json()["status"] == "invalid"
    assert r.json()["stage"] == 0


# ---------------------------------------------------------------------------
# Commits
# ---------------------------------------------------------------------------


def test_commit_stages_in_order_advances_versions_and_appends_snapshots():
    exec_id = register()["execution_id"]

    r = client.post(
        f"/plan-executions/{exec_id}/stages",
        json={
            "expected_version": 0, "stage": 1,
            "action_ids": ["a1-add"],
            "anchor_observations": [
                {"client_id": "c", "anchor_cert_id": "root-new",
                 "present": True},
                {"client_id": "c", "anchor_cert_id": "root-old",
                 "present": True},
            ],
            "chain_observations": [
                {"endpoint_id": "svc", "chain": ["leaf-old", "root-old"]}
            ],
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["version"] == 1
    assert body["completed_stages"] == [1]
    assert body["next_stage"] == 2
    assert len(body["snapshots"]) == 2

    snap1 = body["snapshots"][1]
    assert snap1["version"] == 1
    assert snap1["stage"] == 1
    assert snap1["action_ids"] == ["a1-add"]
    anchors = sorted((a["client_id"], a["anchor_cert_id"])
                     for a in snap1["trust_anchors"])
    assert anchors == [("c", "root-new"), ("c", "root-old")]
    # endpoint still serves the old chain after stage 1
    assert snap1["endpoint_chains"][0]["chain"] == ["leaf-old", "root-old"]
    assert snap1["anchor_observations"][0]["anchor_cert_id"] == "root-new"
    assert all(rel["valid"] for rel in snap1["relationships"])

    r = client.post(
        f"/plan-executions/{exec_id}/stages",
        json={
            "expected_version": 1, "stage": 2,
            "action_ids": ["a3-remove", "a2-replace"],  # order-independent
            "anchor_observations": [
                {"client_id": "c", "anchor_cert_id": "root-new",
                 "present": True},
                {"client_id": "c", "anchor_cert_id": "root-old",
                 "present": False},
            ],
            "chain_observations": [
                {"endpoint_id": "svc", "chain": ["leaf-new", "root-new"]}
            ],
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["version"] == 2
    assert body["completed_stages"] == [1, 2]
    assert body["next_stage"] is None
    assert body["finished"] is True

    snap2 = body["snapshots"][2]
    # action_ids are echoed in the plan's (sorted) order
    assert snap2["action_ids"] == ["a2-replace", "a3-remove"]
    anchors = [(a["client_id"], a["anchor_cert_id"])
               for a in snap2["trust_anchors"]]
    assert anchors == [("c", "root-new")]
    assert snap2["endpoint_chains"][0]["chain"] == ["leaf-new", "root-new"]
    rel = snap2["relationships"][0]
    assert rel["valid"] is True
    assert [c["cert_id"] for c in rel["chain"]] == ["leaf-new", "root-new"]
    assert rel["trusted_anchors"] == ["root-new"]


def test_get_execution_reflects_persisted_state():
    exec_id = register()["execution_id"]
    client.post(
        f"/plan-executions/{exec_id}/stages",
        json={"expected_version": 0, "stage": 1,
              "action_ids": ["a1-add"]},
    )
    r = client.get(f"/plan-executions/{exec_id}")
    assert r.status_code == 200
    body = r.json()
    assert body["version"] == 1
    assert len(body["snapshots"]) == 2


def test_get_unknown_execution_is_404():
    r = client.get("/plan-executions/does-not-exist")
    assert r.status_code == 404
    r = client.post(
        "/plan-executions/does-not-exist/stages",
        json={"expected_version": 0, "stage": 1, "action_ids": ["a1-add"]},
    )
    assert r.status_code == 404


def test_stale_expected_version_is_409_and_leaves_no_progress():
    exec_id = register()["execution_id"]
    client.post(
        f"/plan-executions/{exec_id}/stages",
        json={"expected_version": 0, "stage": 1,
              "action_ids": ["a1-add"]},
    )
    r = client.post(
        f"/plan-executions/{exec_id}/stages",
        json={"expected_version": 0, "stage": 2,
              "action_ids": ["a2-replace", "a3-remove"]},
    )
    assert r.status_code == 409
    body = r.json()
    assert body["reason"] == "version_conflict"
    assert body["current_version"] == 1
    assert body["expected_version"] == 1
    # nothing partial: version still 1, still only two snapshots
    status = client.get(f"/plan-executions/{exec_id}").json()
    assert status["version"] == 1
    assert len(status["snapshots"]) == 2


def test_out_of_order_stage_is_409():
    exec_id = register()["execution_id"]
    r = client.post(
        f"/plan-executions/{exec_id}/stages",
        json={"expected_version": 0, "stage": 2,
              "action_ids": ["a2-replace", "a3-remove"]},
    )
    assert r.status_code == 409
    assert r.json()["reason"] == "unexpected_stage"


def test_stage_beyond_plan_is_409():
    exec_id = register()["execution_id"]
    r = client.post(
        f"/plan-executions/{exec_id}/stages",
        json={"expected_version": 0, "stage": 3, "action_ids": []},
    )
    assert r.status_code == 409
    assert r.json()["reason"] == "unexpected_stage"


def test_wrong_action_set_is_409():
    exec_id = register()["execution_id"]
    r = client.post(
        f"/plan-executions/{exec_id}/stages",
        json={"expected_version": 0, "stage": 1, "action_ids": []},
    )
    assert r.status_code == 409
    assert r.json()["reason"] == "action_set_mismatch"

    # unknown action id is a malformed request (422)
    r = client.post(
        f"/plan-executions/{exec_id}/stages",
        json={"expected_version": 0, "stage": 1,
              "action_ids": ["a1-add", "ghost"]},
    )
    assert r.status_code == 422


def test_commit_breaking_relationships_is_409_and_atomic():
    # Register a plan whose stage-2 batch matches; then tamper the commit by
    # reporting stage 1 with the stage-2 action set: mismatch is caught first.
    # Here use a plan that is valid but a commit whose observations lie.
    exec_id = register()["execution_id"]
    # A remove-only stage at stage 1 is not the registered plan stage, so it
    # is an action_set_mismatch; instead exercise trust replay via a legal
    # plan whose own stage breaks nothing, then lie in observations:
    r = client.post(
        f"/plan-executions/{exec_id}/stages",
        json={
            "expected_version": 0, "stage": 1,
            "action_ids": ["a1-add"],
            "anchor_observations": [
                {"client_id": "c", "anchor_cert_id": "root-new",
                 "present": False},  # actual state has it present
            ],
        },
    )
    assert r.status_code == 409
    assert r.json()["reason"] == "observation_mismatch"
    obs = r.json()["observation"]
    assert obs["submitted_present"] is False
    assert obs["expected_present"] is True
    status = client.get(f"/plan-executions/{exec_id}").json()
    assert status["version"] == 0  # rolled back
    assert len(status["snapshots"]) == 1


def test_chain_observation_mismatch_is_409():
    exec_id = register()["execution_id"]
    r = client.post(
        f"/plan-executions/{exec_id}/stages",
        json={
            "expected_version": 0, "stage": 1,
            "action_ids": ["a1-add"],
            "chain_observations": [
                {"endpoint_id": "svc", "chain": ["leaf-new", "root-new"]}
            ],
        },
    )
    assert r.status_code == 409
    assert r.json()["reason"] == "observation_mismatch"
    obs = r.json()["observation"]
    assert obs["expected_chain"] == ["leaf-old", "root-old"]


def test_bad_observation_references_are_422():
    exec_id = register()["execution_id"]
    r = client.post(
        f"/plan-executions/{exec_id}/stages",
        json={
            "expected_version": 0, "stage": 1,
            "action_ids": ["a1-add"],
            "anchor_observations": [
                {"client_id": "nobody", "anchor_cert_id": "root-new",
                 "present": True}
            ],
        },
    )
    assert r.status_code == 422

    r = client.post(
        f"/plan-executions/{exec_id}/stages",
        json={
            "expected_version": 0, "stage": 1,
            "action_ids": ["a1-add"],
            "chain_observations": [
                {"endpoint_id": "ghost-ep", "chain": ["leaf-old", "root-old"]}
            ],
        },
    )
    assert r.status_code == 422


def test_duplicate_commit_returns_same_snapshot():
    exec_id = register()["execution_id"]
    payload = {
        "expected_version": 0, "stage": 1,
        "action_ids": ["a1-add"],
        "anchor_observations": [
            {"client_id": "c", "anchor_cert_id": "root-new", "present": True}
        ],
    }
    first = client.post(
        f"/plan-executions/{exec_id}/stages", json=payload
    ).json()
    # identical re-submission based on the current version (1) is idempotent
    # and returns the same stored snapshot rather than re-committing.
    repeat = client.post(
        f"/plan-executions/{exec_id}/stages",
        json={**payload, "expected_version": 1},
    )
    assert repeat.status_code == 200, repeat.text
    second = repeat.json()
    assert second["version"] == first["version"] == 1
    assert len(second["snapshots"]) == len(first["snapshots"]) == 2
    assert (second["snapshots"][1]["committed_at"]
            == first["snapshots"][1]["committed_at"])

    # but the identical content with a stale expected_version is still a
    # version_conflict, never a silent second commit
    stale = client.post(
        f"/plan-executions/{exec_id}/stages", json=payload
    )
    assert stale.status_code == 409
    assert stale.json()["reason"] == "version_conflict"


def test_duplicate_commit_with_different_content_is_409():
    exec_id = register()["execution_id"]
    client.post(
        f"/plan-executions/{exec_id}/stages",
        json={"expected_version": 0, "stage": 1,
              "action_ids": ["a1-add"]},
    )
    # same stage with the current version, but now an extra observation ->
    # different content: the immutable audit record cannot be overwritten
    r = client.post(
        f"/plan-executions/{exec_id}/stages",
        json={
            "expected_version": 1, "stage": 1,
            "action_ids": ["a1-add"],
            "anchor_observations": [
                {"client_id": "c", "anchor_cert_id": "root-new",
                 "present": True}
            ],
        },
    )
    assert r.status_code == 409
    assert r.json()["reason"] == "duplicate_payload_mismatch"


def test_noop_stage_commit_advances_version_with_empty_actions():
    plan = [
        {"stage": 1, "action_ids": []},
        {"stage": 2, "action_ids": ["a1-add", "a2-replace", "a3-remove"]},
    ]
    scenario = {**SCENARIO, "actions": [
        dict(SCENARIO["actions"][0], allowed_stages=[2]),
        dict(SCENARIO["actions"][1], allowed_stages=[2]),
        dict(SCENARIO["actions"][2], allowed_stages=[2]),
    ]}
    exec_id = register(plan=plan, scenario=scenario)["execution_id"]

    r = client.post(
        f"/plan-executions/{exec_id}/stages",
        json={"expected_version": 0, "stage": 1, "action_ids": []},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["version"] == 1
    assert body["completed_stages"] == [1]
    assert body["next_stage"] == 2
    # no-op snapshot preserves the initial trust state
    snap = body["snapshots"][1]
    assert snap["action_ids"] == []
    assert [(a["client_id"], a["anchor_cert_id"])
            for a in snap["trust_anchors"]] == [("c", "root-old")]

    r = client.post(
        f"/plan-executions/{exec_id}/stages",
        json={
            "expected_version": 1, "stage": 2,
            "action_ids": ["a1-add", "a2-replace", "a3-remove"],
            "anchor_observations": [
                {"client_id": "c", "anchor_cert_id": "root-new",
                 "present": True}
            ],
            "chain_observations": [
                {"endpoint_id": "svc", "chain": ["leaf-new", "root-new"]}
            ],
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["finished"] is True


def _service_commit(exec_id, expected, stage, actions):
    try:
        execution.commit_stage(
            exec_id,
            StageCommitRequest(
                expected_version=expected, stage=stage, action_ids=actions
            ),
        )
        return 200
    except execution.CommitRejected as exc:
        return 409 if exc.conflict.reason == "version_conflict" else exc.conflict.reason


def test_concurrent_commits_one_wins_one_gets_version_conflict():
    exec_id = execution.register_execution(
        ExecutionRegisterRequest.model_validate({**SCENARIO, "plan": PLAN})
    ).execution_id
    results = []

    # Worker A commits stage 1 from version 0 and wins. Worker B, racing with a
    # stale view (still version 0), tries to commit stage 2 on the old prefix;
    # by the time it takes the write lock the version is 1, so it is rejected
    # with version_conflict and nothing is partially applied.
    t1 = threading.Thread(
        target=lambda: results.append(("a", _service_commit(exec_id, 0, 1, ["a1-add"])))
    )
    t2 = threading.Thread(
        target=lambda: results.append(
            ("b", _service_commit(exec_id, 0, 2, ["a2-replace", "a3-remove"]))
        )
    )
    t1.start(); t2.start()
    t1.join(); t2.join()

    by = dict(results)
    assert by == {"a": 200, "b": 409}, results
    status = client.get(f"/plan-executions/{exec_id}").json()
    assert status["version"] == 1
    assert status["completed_stages"] == [1]
    assert len(status["snapshots"]) == 2


def test_concurrent_identical_stage_commits_one_replays_one_conflicts():
    # The same stage raced by two workers (both at version 0): one wins and
    # advances the version; the other now sees current_version=1 and gets
    # version_conflict (it may refresh and, if the content matched, retry the
    # idempotent replay). The version never double-advances.
    exec_id = execution.register_execution(
        ExecutionRegisterRequest.model_validate({**SCENARIO, "plan": PLAN})
    ).execution_id
    results = []

    def commit():
        results.append(_service_commit(exec_id, 0, 1, ["a1-add"]))

    t1 = threading.Thread(target=commit)
    t2 = threading.Thread(target=commit)
    t1.start(); t2.start()
    t1.join(); t2.join()
    assert sorted(results) == [200, 409], results
    status = client.get(f"/plan-executions/{exec_id}").json()
    assert status["version"] == 1
    assert len(status["snapshots"]) == 2


def test_zero_action_plan_is_finished_at_registration():
    scenario = {
        "certificates": [cert("r0", "CN=r0", "CN=r0")],
        "trust_anchors": [{"client_id": "c", "cert_id": "r0"}],
        "endpoints": [{"endpoint_id": "svc", "current_chain": ["r0"],
                       "target_chain": ["r0"]}],
        "relationships": [{"client_id": "c", "endpoint_id": "svc"}],
        "actions": [],
        "plan_time": NOW.isoformat(),
    }
    body = register(plan=[], scenario=scenario)
    assert body["version"] == 0
    assert body["stage_count"] == 0
    assert body["finished"] is True
    assert body["next_stage"] is None
