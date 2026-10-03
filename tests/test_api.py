"""Pytest test suite for the rotation planning API."""
import itertools
import random
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.engine import build_scenario
from app.models import PlanRequest
from app.engine import Solver

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)

client = TestClient(app)


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


# ---------------------------------------------------------------------------
# /plans happy path
# ---------------------------------------------------------------------------


def test_plan_minimum_two_stages():
    r = client.post("/plans", json=ROTATION)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert body["stage_count"] == 2
    stages = body["stages"]
    assert stages[0]["action_ids"] == ["a1-add-new"]
    assert stages[1]["action_ids"] == ["a2-replace", "a3-remove-old"]


def test_plan_single_stage_when_replaces_not_constrained():
    payload = {**ROTATION, "actions": [
        dict(ROTATION["actions"][0], allowed_stages=[1]),
        dict(ROTATION["actions"][1], allowed_stages=[1]),
        dict(ROTATION["actions"][2], allowed_stages=[1]),
    ]}
    r = client.post("/plans", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body["stage_count"] == 1
    assert body["stages"][0]["action_ids"] == [
        "a1-add-new", "a2-replace", "a3-remove-old"
    ]


def test_plan_infeasible_reports_relationship_and_blocker():
    # The remove is forced into stage 1 while the add/replace can only happen
    # in stage 2; the leading empty stage cannot rescue the instance.
    payload = {**ROTATION, "actions": [
        dict(ROTATION["actions"][0], allowed_stages=[2]),
        dict(ROTATION["actions"][1], allowed_stages=[2]),
        dict(ROTATION["actions"][2], allowed_stages=[1]),
    ]}
    r = client.post("/plans", json=payload)
    assert r.status_code == 409
    body = r.json()
    assert body["status"] == "infeasible"
    assert body["relationship"] == {"client_id": "client-a", "endpoint_id": "svc"}
    assert body["blocking_action"] == "a3-remove-old"
    assert [c["cert_id"] for c in body["chain"]] == ["leaf-old", "root-old"]
    assert body["stage"] == 1
    assert body["reason"] == "untrusted_root"


def test_plan_sparse_leading_empty_stages():
    # Every action is only eligible at the absolute stage 2: the planner must
    # carry the intact trust state across an explicit no-op stage 1 instead of
    # declaring the instance infeasible.
    payload = {**ROTATION, "actions": [
        dict(ROTATION["actions"][0], allowed_stages=[2]),
        dict(ROTATION["actions"][1], allowed_stages=[2]),
        dict(ROTATION["actions"][2], allowed_stages=[2]),
    ]}
    r = client.post("/plans", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert body["stage_count"] == 2
    assert body["stages"] == [
        {"stage": 1, "action_ids": []},
        {"stage": 2,
         "action_ids": ["a1-add-new", "a2-replace", "a3-remove-old"]},
    ]


def test_plan_sparse_middle_empty_stage():
    # add at stage 1; replace/remove only at stage 3. Stage 2 is a no-op gap
    # across which the trust state is carried unchanged.
    payload = {**ROTATION, "actions": [
        dict(ROTATION["actions"][0], allowed_stages=[1]),
        dict(ROTATION["actions"][1], allowed_stages=[3]),
        dict(ROTATION["actions"][2], allowed_stages=[3]),
    ]}
    r = client.post("/plans", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["stage_count"] == 3
    assert body["stages"] == [
        {"stage": 1, "action_ids": ["a1-add-new"]},
        {"stage": 2, "action_ids": []},
        {"stage": 3, "action_ids": ["a2-replace", "a3-remove-old"]},
    ]


def test_plan_infeasible_diagnostic_skips_legal_gap():
    # Nothing is eligible at stages 1-2; at stage 3 the forced remove breaks
    # the path (add/replace only arrive at stage 4). The diagnostic must skip
    # the legal empty gap and report the real failure stage 3.
    payload = {**ROTATION, "actions": [
        dict(ROTATION["actions"][0], allowed_stages=[4]),
        dict(ROTATION["actions"][1], allowed_stages=[4]),
        dict(ROTATION["actions"][2], allowed_stages=[3]),
    ]}
    r = client.post("/plans", json=payload)
    assert r.status_code == 409
    body = r.json()
    assert body["status"] == "infeasible"
    assert body["stage"] == 3
    assert body["blocking_action"] == "a3-remove-old"
    assert body["reason"] == "untrusted_root"


def test_initial_state_invalid():
    payload = {
        **ROTATION,
        "trust_anchors": [],
    }
    r = client.post("/plans", json=payload)
    assert r.status_code == 409
    body = r.json()
    assert body["status"] == "invalid"
    assert body["stage"] == 0
    assert body["blocking_action"] is None
    assert body["relationship"] == {"client_id": "client-a", "endpoint_id": "svc"}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_expired_certificate_rejected():
    certs = [
        cert("root-old", "CN=Old Root", "CN=Old Root", expired=True),
        cert("leaf-old", "CN=svc", "CN=Old Root"),
    ]
    payload = {**ROTATION, "certificates": certs,
              "actions": [], "endpoints": [
                  {"endpoint_id": "svc",
                   "current_chain": ["leaf-old", "root-old"],
                   "target_chain": ["leaf-old", "root-old"]}]}
    r = client.post("/plans", json=payload)
    assert r.status_code == 422
    assert "not valid at plan_time" in r.json()["detail"]


def test_not_yet_valid_certificate_rejected():
    future = cert("future-root", "CN=Future", "CN=Future",
                  not_before=NOW + timedelta(days=10))
    payload = {
        **ROTATION,
        "certificates": ROTATION["certificates"] + [future],
        "trust_anchors": [{"client_id": "client-a", "cert_id": "future-root"}],
    }
    r = client.post("/plans", json=payload)
    assert r.status_code == 422


def test_cyclic_chain_rejected():
    # self-referential root in the middle: duplicate id is the cyclic shape
    payload = {
        **ROTATION,
        "endpoints": [{
            "endpoint_id": "svc",
            "current_chain": ["leaf-old", "root-old", "leaf-old"],
            "target_chain": ["leaf-new", "root-new"],
        }],
    }
    r = client.post("/plans", json=payload)
    assert r.status_code == 422
    assert "cycle" in r.json()["detail"] or "more than once" in r.json()["detail"]


def test_chain_ending_in_non_root_rejected():
    extra = cert("inter", "CN=Old Root", "CN=somewhere-else")
    payload = {
        **ROTATION,
        "certificates": ROTATION["certificates"] + [extra],
        "endpoints": [{
            "endpoint_id": "svc",
            "current_chain": ["leaf-old", "inter"],
            "target_chain": ["leaf-new", "root-new"],
        }],
    }
    r = client.post("/plans", json=payload)
    assert r.status_code == 422
    assert "self-signed root" in r.json()["detail"]


def test_issuer_mismatch_rejected():
    extra = cert("other", "CN=Other", "CN=Other")
    payload = {
        **ROTATION,
        "certificates": ROTATION["certificates"] + [extra],
        "endpoints": [{
            "endpoint_id": "svc",
            "current_chain": ["leaf-old", "other"],
            "target_chain": ["leaf-new", "root-new"],
        }],
    }
    r = client.post("/plans", json=payload)
    assert r.status_code == 422
    assert "issuer mismatch" in r.json()["detail"]


def test_more_than_12_actions_rejected():
    acts = [
        {"action_id": f"a{i:02d}", "type": "add_trust",
         "client_id": "client-a", "anchor_cert_id": "root-new",
         "allowed_stages": [1]}
        for i in range(13)
    ]
    # duplicates on the same trust edge are allowed as a set of distinct
    # action ids; the >12 rule fires first at schema level
    payload = {**ROTATION, "actions": acts}
    r = client.post("/plans", json=payload)
    assert r.status_code == 422
    assert "at most 12" in r.text


def test_bad_allowed_stages_rejected():
    acts = [dict(ROTATION["actions"][0], allowed_stages=[0])]
    payload = {**ROTATION, "actions": acts}
    r = client.post("/plans", json=payload)
    assert r.status_code == 422


def test_replace_chain_must_equal_target():
    acts = [
        dict(ROTATION["actions"][0]),
        dict(ROTATION["actions"][1],
             new_chain=["leaf-old", "root-old"]),
        dict(ROTATION["actions"][2]),
    ]
    payload = {**ROTATION, "actions": acts}
    r = client.post("/plans", json=payload)
    assert r.status_code == 422
    assert "target_chain" in r.json()["detail"]


# ---------------------------------------------------------------------------
# /plans/verify
# ---------------------------------------------------------------------------


def test_verify_accepts_good_plan():
    plan = {
        "plan": [
            {"stage": 1, "action_ids": ["a1-add-new"]},
            {"stage": 2, "action_ids": ["a2-replace", "a3-remove-old"]},
        ],
        **ROTATION,
    }
    r = client.post("/plans/verify", json=plan)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "valid"
    assert body["stage_count"] == 2


def test_verify_rejects_remove_before_replace():
    plan = {
        "plan": [
            {"stage": 1, "action_ids": ["a1-add-new", "a3-remove-old"]},
            {"stage": 2, "action_ids": ["a2-replace"]},
        ],
        **ROTATION,
    }
    r = client.post("/plans/verify", json=plan)
    assert r.status_code == 409
    body = r.json()
    assert body["status"] == "invalid"
    assert body["stage"] == 1
    assert body["blocking_action"] == "a3-remove-old"
    assert body["relationship"] == {"client_id": "client-a", "endpoint_id": "svc"}
    # disconnected chain shown leaf-first
    assert [c["cert_id"] for c in body["chain"]] == ["leaf-old", "root-old"]
    assert body["trusted_anchors"] == ["root-new"]


def test_verify_rejects_replace_before_add():
    payload = {**ROTATION, "actions": [
        dict(ROTATION["actions"][0], allowed_stages=[1, 2]),
        dict(ROTATION["actions"][1], allowed_stages=[1, 2]),
        dict(ROTATION["actions"][2], allowed_stages=[1, 2]),
    ]}
    plan = {
        "plan": [
            {"stage": 1, "action_ids": ["a2-replace"]},
            {"stage": 2, "action_ids": ["a1-add-new"]},
            {"stage": 3, "action_ids": ["a3-remove-old"]},
        ],
        **payload,
    }
    r = client.post("/plans/verify", json=plan)
    assert r.status_code == 409
    body = r.json()
    assert body["stage"] == 1
    assert body["blocking_action"] == "a2-replace"
    assert [c["cert_id"] for c in body["chain"]] == ["leaf-new", "root-new"]


def test_verify_rejects_action_outside_allowed_stage():
    # a2 is only allowed from stage 2, but the plan schedules it at stage 1
    # while every trust path is still intact -> the failure is the
    # allowed_stages violation, not a broken chain.
    plan = {
        "plan": [
            {"stage": 1, "action_ids": ["a1-add-new", "a2-replace"]},
            {"stage": 2, "action_ids": ["a3-remove-old"]},
        ],
        **ROTATION,
    }
    r = client.post("/plans/verify", json=plan)
    assert r.status_code == 409
    body = r.json()
    assert body["blocking_action"] == "a2-replace"
    assert body["reason"] == "action_not_allowed_at_stage"
    assert body["stage"] == 1


def test_verify_rejects_contradictory_add_and_remove_same_stage():
    # add and remove the SAME anchor in one stage has no defined result.
    extra_add = {
        "action_id": "a0-add-old", "type": "add_trust",
        "client_id": "client-a", "anchor_cert_id": "root-old",
        "allowed_stages": [1, 2],
    }
    payload = {**ROTATION, "actions": [
        extra_add,
        dict(ROTATION["actions"][0], allowed_stages=[1, 2]),
        dict(ROTATION["actions"][1], allowed_stages=[1, 2]),
        dict(ROTATION["actions"][2], allowed_stages=[1, 2]),
    ]}
    plan = {
        "plan": [
            {"stage": 1, "action_ids": ["a0-add-old", "a3-remove-old"]},
            {"stage": 2, "action_ids": [
                "a1-add-new", "a2-replace"]},
        ],
        **payload,
    }
    r = client.post("/plans/verify", json=plan)
    assert r.status_code == 409
    body = r.json()
    assert body["reason"] == "contradictory_actions_same_stage"
    assert body["stage"] == 1
    assert body["blocking_action"] == "a3-remove-old"


def test_verify_accepts_leading_empty_stage():
    # Every action is only allowed at absolute stage 2; stage 1 is an explicit
    # no-op across which every relationship is re-checked and still valid.
    payload = {**ROTATION, "actions": [
        dict(ROTATION["actions"][0], allowed_stages=[2]),
        dict(ROTATION["actions"][1], allowed_stages=[2]),
        dict(ROTATION["actions"][2], allowed_stages=[2]),
    ]}
    plan = {
        "plan": [
            {"stage": 1, "action_ids": []},
            {"stage": 2, "action_ids": [
                "a1-add-new", "a2-replace", "a3-remove-old"]},
        ],
        **payload,
    }
    r = client.post("/plans/verify", json=plan)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "valid"
    assert body["stage_count"] == 2
    assert body["stages"] == [
        {"stage": 1, "action_ids": []},
        {"stage": 2, "action_ids": [
            "a1-add-new", "a2-replace", "a3-remove-old"]},
    ]


def test_verify_replays_middle_empty_stage():
    # Stage 2 is a legal no-op gap; the add at stage 1 keeps both roots
    # trusted, and stage 3 finishes the rotation.
    payload = {**ROTATION, "actions": [
        dict(ROTATION["actions"][0], allowed_stages=[1]),
        dict(ROTATION["actions"][1], allowed_stages=[3]),
        dict(ROTATION["actions"][2], allowed_stages=[3]),
    ]}
    plan = {
        "plan": [
            {"stage": 1, "action_ids": ["a1-add-new"]},
            {"stage": 2, "action_ids": []},
            {"stage": 3, "action_ids": ["a2-replace", "a3-remove-old"]},
        ],
        **payload,
    }
    r = client.post("/plans/verify", json=plan)
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "valid"


def test_verify_empty_stage_still_checks_trust():
    # A no-op stage cannot repair (and therefore must not mask) a broken
    # relationship: the early remove at stage 1 breaks the path, and the
    # following empty stage cannot skip past that failure.
    plan = {
        "plan": [
            {"stage": 1, "action_ids": ["a3-remove-old"]},
            {"stage": 2, "action_ids": []},
            {"stage": 3, "action_ids": ["a1-add-new", "a2-replace"]},
        ],
        **ROTATION,
    }
    r = client.post("/plans/verify", json=plan)
    assert r.status_code == 409
    body = r.json()
    assert body["stage"] == 1
    assert body["blocking_action"] == "a3-remove-old"
    assert body["reason"] == "untrusted_root"


def test_verify_accepts_trailing_empty_stage():
    plan = {
        "plan": [
            {"stage": 1, "action_ids": ["a1-add-new"]},
            {"stage": 2, "action_ids": ["a2-replace", "a3-remove-old"]},
            {"stage": 3, "action_ids": []},
        ],
        **ROTATION,
    }
    r = client.post("/plans/verify", json=plan)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "valid"
    assert body["stage_count"] == 3


def test_verify_rejects_action_outside_allowed_stage_after_empty_gap():
    # a2 is only allowed from stage 2; scheduling it at stage 3 after a no-op
    # stage 2 is an out-of-range ("越界") action and must be rejected.
    payload = {**ROTATION, "actions": [
        dict(ROTATION["actions"][0], allowed_stages=[1, 2, 3]),
        dict(ROTATION["actions"][1], allowed_stages=[2]),
        dict(ROTATION["actions"][2], allowed_stages=[1, 2, 3]),
    ]}
    plan = {
        "plan": [
            {"stage": 1, "action_ids": ["a1-add-new"]},
            {"stage": 2, "action_ids": []},
            {"stage": 3, "action_ids": ["a2-replace", "a3-remove-old"]},
        ],
        **payload,
    }
    r = client.post("/plans/verify", json=plan)
    assert r.status_code == 409
    body = r.json()
    assert body["reason"] == "action_not_allowed_at_stage"
    assert body["stage"] == 3
    assert body["blocking_action"] == "a2-replace"


def test_verify_rejects_duplicate_and_missing_action():
    plan = {
        "plan": [
            {"stage": 1, "action_ids": ["a1-add-new"]},
            {"stage": 2, "action_ids": ["a2-replace", "a2-replace"]},
        ],
        **ROTATION,
    }
    r = client.post("/plans/verify", json=plan)
    assert r.status_code == 422

    plan2 = {
        "plan": [
            {"stage": 1, "action_ids": ["a1-add-new"]},
        ],
        **ROTATION,
    }
    r = client.post("/plans/verify", json=plan2)
    assert r.status_code == 422
    assert "exactly once" in r.json()["detail"]


# ---------------------------------------------------------------------------
# Differential tests: solver vs exhaustive enumeration
# ---------------------------------------------------------------------------


def _build_random_scenario(rng):
    """Random single-endpoint rotation with up to 4 actions."""
    certs = [
        cert("r0", "CN=r0", "CN=r0"),
        cert("r1", "CN=r1", "CN=r1"),
        cert("l0", "CN=s", "CN=r0"),
        cert("l1", "CN=s", "CN=r1"),
    ]
    actions_def = [
        ("add", "add_trust", "r1"),
        ("rem", "remove_trust", "r0"),
        ("rep", "replace_cert", None),
    ]
    n = rng.randint(1, 3)
    names = rng.sample([a[0] for a in actions_def], n)
    max_stage = rng.randint(1, 4)
    actions = []
    for name in names:
        kind = next(a for a in actions_def if a[0] == name)
        k = rng.randint(1, max_stage)
        allowed = sorted(rng.sample(range(1, max_stage + 1), k))
        if kind[1] == "add_trust":
            actions.append({"action_id": f"z-{name}", "type": "add_trust",
                            "client_id": "c", "anchor_cert_id": kind[2],
                            "allowed_stages": allowed})
        elif kind[1] == "remove_trust":
            actions.append({"action_id": f"z-{name}", "type": "remove_trust",
                            "client_id": "c", "anchor_cert_id": kind[2],
                            "allowed_stages": allowed})
        else:
            actions.append({"action_id": f"z-{name}", "type": "replace_cert",
                            "endpoint_id": "svc",
                            "new_chain": ["l1", "r1"],
                            "allowed_stages": allowed})
    return {
        "certificates": certs,
        "trust_anchors": [{"client_id": "c", "cert_id": "r0"}],
        "endpoints": [{
            "endpoint_id": "svc",
            "current_chain": ["l0", "r0"],
            "target_chain": ["l1", "r1"],
        }],
        "relationships": [{"client_id": "c", "endpoint_id": "svc"}],
        "actions": actions,
        "plan_time": NOW.isoformat(),
    }


def _brute_force(payload):
    """Return (min_stages, canonical key) or (INF, None).

    Canonical ordering: the minimum plan is the one whose per-action stage
    vector (actions taken in action_id order) is lexicographically smallest.
    """
    req = PlanRequest.model_validate(payload)
    sc = build_scenario(req)
    solver = Solver(sc)
    if not solver.good[0]:
        return None  # invalid instance
    n = sc.n
    choices = [sorted(s) for s in sc.allowed]
    best = None
    best_key = None
    for assignment in itertools.product(*choices):
        # Absolute stage numbers may be sparse: unused stage numbers are legal
        # no-op gaps; the canonical stage is the largest used stage number.
        m = max(assignment)
        mask = 0
        ok = True
        for st in range(1, m + 1):
            bits = 0
            for i, t in enumerate(assignment):
                if t == st:
                    bits |= 1 << i
            from app.engine import batch_conflict
            if batch_conflict(sc, bits) is not None:
                ok = False
                break
            mask |= bits
            if not solver.good[mask]:
                ok = False
                break
        if not ok:
            continue
        key = tuple(assignment)  # action_ids are already sorted in sc
        if best is None or m < best or (m == best and key < best_key):
            best = m
            best_key = key
    return best, best_key


@pytest.mark.parametrize("seed", range(120))
def test_solver_matches_brute_force(seed):
    rng = random.Random(seed)
    payload = _build_random_scenario(rng)
    expected = _brute_force(payload)
    req = PlanRequest.model_validate(payload)
    sc = build_scenario(req)
    solver = Solver(sc)
    if expected is None:
        pytest.skip("invalid initial state")
    best, best_key = expected
    got = solver.finish(0, 1)
    if best is None:
        assert got >= 10 ** 9
        return
    assert got == best
    batches = solver.solve()
    # rebuild the per-action stage vector from the solver's batches
    stage_of = [0] * sc.n
    for num, batch in enumerate(batches, start=1):
        for i in batch:
            stage_of[i] = num
    assert tuple(stage_of) == best_key


def test_solver_stable_sorting_within_stage():
    # action_ids chosen to prove lex ordering, not request order
    payload = {
        "certificates": [
            cert("r0", "CN=r0", "CN=r0"),
            cert("r1", "CN=r1", "CN=r1"),
            cert("l0", "CN=s", "CN=r0"),
            cert("l1", "CN=s", "CN=r1"),
        ],
        "trust_anchors": [{"client_id": "c", "cert_id": "r0"}],
        "endpoints": [{
            "endpoint_id": "svc",
            "current_chain": ["l0", "r0"],
            "target_chain": ["l1", "r1"],
        }],
        "relationships": [{"client_id": "c", "endpoint_id": "svc"}],
        "actions": [
            {"action_id": "z-rep", "type": "replace_cert", "endpoint_id": "svc",
             "new_chain": ["l1", "r1"], "allowed_stages": [1]},
            {"action_id": "a-add", "type": "add_trust", "client_id": "c",
             "anchor_cert_id": "r1", "allowed_stages": [1]},
            {"action_id": "m-rem", "type": "remove_trust", "client_id": "c",
             "anchor_cert_id": "r0", "allowed_stages": [1]},
        ],
        "plan_time": NOW.isoformat(),
    }
    r = client.post("/plans", json=payload)
    assert r.status_code == 200
    ids = r.json()["stages"][0]["action_ids"]
    assert ids == ["a-add", "m-rem", "z-rep"]


def test_solver_stable_sorting_with_sparse_stages():
    # Like the dense case, but all actions are eligible only at absolute stage
    # 2: the plan must keep the explicit no-op stage 1 and still emit the
    # stage-2 actions sorted by action_id regardless of request order.
    payload = {
        "certificates": [
            cert("r0", "CN=r0", "CN=r0"),
            cert("r1", "CN=r1", "CN=r1"),
            cert("l0", "CN=s", "CN=r0"),
            cert("l1", "CN=s", "CN=r1"),
        ],
        "trust_anchors": [{"client_id": "c", "cert_id": "r0"}],
        "endpoints": [{
            "endpoint_id": "svc",
            "current_chain": ["l0", "r0"],
            "target_chain": ["l1", "r1"],
        }],
        "relationships": [{"client_id": "c", "endpoint_id": "svc"}],
        "actions": [
            {"action_id": "z-rep", "type": "replace_cert", "endpoint_id": "svc",
             "new_chain": ["l1", "r1"], "allowed_stages": [2]},
            {"action_id": "a-add", "type": "add_trust", "client_id": "c",
             "anchor_cert_id": "r1", "allowed_stages": [2]},
            {"action_id": "m-rem", "type": "remove_trust", "client_id": "c",
             "anchor_cert_id": "r0", "allowed_stages": [2]},
        ],
        "plan_time": NOW.isoformat(),
    }
    r = client.post("/plans", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["stage_count"] == 2
    assert body["stages"][0] == {"stage": 1, "action_ids": []}
    assert body["stages"][1] == {
        "stage": 2, "action_ids": ["a-add", "m-rem", "z-rep"]
    }


def test_plan_action_only_eligible_beyond_reach_is_infeasible():
    # The remove is the only thing allowed early (stage 1) and it breaks the
    # path before the add/replace that could restore it (stage 3): the empty
    # stage 2 cannot help, so the instance is genuinely infeasible.
    payload = {**ROTATION, "actions": [
        dict(ROTATION["actions"][0], allowed_stages=[3]),
        dict(ROTATION["actions"][1], allowed_stages=[3]),
        dict(ROTATION["actions"][2], allowed_stages=[1]),
    ]}
    r = client.post("/plans", json=payload)
    assert r.status_code == 409
    body = r.json()
    assert body["status"] == "infeasible"
    assert body["stage"] == 1
    assert body["blocking_action"] == "a3-remove-old"


def test_multi_client_scenario():
    # Two clients rotate at their own pace; one can't have its old anchor
    # removed until that client is also on the new chain.
    payload = {
        "certificates": [
            cert("r0", "CN=r0", "CN=r0"),
            cert("r1", "CN=r1", "CN=r1"),
            cert("l0", "CN=s", "CN=r0"),
            cert("l1", "CN=s", "CN=r1"),
        ],
        "trust_anchors": [
            {"client_id": "c1", "cert_id": "r0"},
            {"client_id": "c2", "cert_id": "r0"},
        ],
        "endpoints": [{
            "endpoint_id": "svc",
            "current_chain": ["l0", "r0"],
            "target_chain": ["l1", "r1"],
        }],
        "relationships": [
            {"client_id": "c1", "endpoint_id": "svc"},
            {"client_id": "c2", "endpoint_id": "svc"},
        ],
        "actions": [
            {"action_id": "add1", "type": "add_trust", "client_id": "c1",
             "anchor_cert_id": "r1", "allowed_stages": [1, 2, 3]},
            {"action_id": "add2", "type": "add_trust", "client_id": "c2",
             "anchor_cert_id": "r1", "allowed_stages": [1, 2, 3]},
            {"action_id": "remove0", "type": "remove_trust",
             "client_id": "c1", "anchor_cert_id": "r0",
             "allowed_stages": [1, 2, 3]},
            {"action_id": "remove1", "type": "remove_trust",
             "client_id": "c2", "anchor_cert_id": "r0",
             "allowed_stages": [1, 2, 3]},
            {"action_id": "replace", "type": "replace_cert",
             "endpoint_id": "svc", "new_chain": ["l1", "r1"],
             "allowed_stages": [2]},
        ],
        "plan_time": NOW.isoformat(),
    }
    r = client.post("/plans", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    # stage1 must include both adds; remove0/remove1 before stage 2 break the
    # clients; stage2 = replace; stage3 removes can follow (or stage2 together
    # with replace since new chain trusts r1). Minimum: 2.
    assert body["stage_count"] == 2
    s1 = set(body["stages"][0]["action_ids"])
    assert s1 == {"add1", "add2"}
    s2 = set(body["stages"][1]["action_ids"])
    assert s2 == {"remove0", "remove1", "replace"}


def test_zero_actions_scenario():
    # Nothing to rotate: /plans yields 0 stages; /plans/verify accepts [].
    payload = {
        "certificates": [
            cert("r0", "CN=r0", "CN=r0"),
        ],
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
    r = client.post("/plans", json=payload)
    assert r.status_code == 200
    assert r.json()["stage_count"] == 0
    assert r.json()["stages"] == []

    r = client.post("/plans/verify", json={**payload, "plan": []})
    assert r.status_code == 200
    assert r.json()["status"] == "valid"

    r = client.post("/plans/verify", json={**ROTATION, "plan": []})
    assert r.status_code == 422
    assert "exactly once" in r.json()["detail"]


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
