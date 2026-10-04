"""Auditable, transactional stage commits for registered rotation plans.

Caller flow:

1. ``POST /plan-executions`` registers an **immutable** plan (normally the
   output of ``/plans``) together with its scenario. The service replays the
   whole plan once, stores the scenario/plan verbatim and saves the **version
   0** (initial-state) snapshot. The current version starts at 0.
2. ``POST /plan-executions/{id}/stages`` commits one stage's executed actions
   plus the field observations (client trust anchors and endpoint chains)
   attesting them. The commit is validated **inside one SQLite transaction**:
   the action set must equal exactly the plan stage, every observation must
   match the state the stage deterministically produces, and every required
   communication relationship must still have a valid trust path. Only when
   all checks pass does the version advance and the stage snapshot get saved.
   Nothing is ever left half-applied.

Optimistic concurrency: every commit carries ``expected_version``. A stale or
concurrent commit (its ``expected_version`` differs from the stored version) is
rejected with ``409 version_conflict`` without touching stored state. Re-
submitting an already-committed stage with the content-identical commit *and*
the version it was based on is idempotent: it returns the same stored snapshot
instead of failing; different content for the same stage always returns 409.

The plan and every snapshot are immutable; the only mutable fields of an
execution are its current version and the strictly appended snapshots.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from .engine import (
    Scenario,
    ScenarioValidationError,
    TrustEdge,
    TrustState,
    build_scenario,
    check_batch,
    evaluate_path,
    first_broken_relationship,
    initial_state,
    state_for_mask_applied,
)
from .models import (
    ChainCert,
    CommitAnchorObservation,
    CommitChainObservation,
    CommitConflict,
    ExecutionRegisterRequest,
    ExecutionStage,
    ExecutionStatus,
    Failure,
    PlannedStage,
    PlanRequest,
    RelationshipRef,
    StageCommitRequest,
    StageSnapshot,
    SnapshotEndpointChain,
    SnapshotRelationship,
    SnapshotTrustAnchor,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS plan_executions (
    execution_id    TEXT PRIMARY KEY,
    scenario_json   TEXT NOT NULL,
    plan_json       TEXT NOT NULL,
    stage_count     INTEGER NOT NULL,
    current_version INTEGER NOT NULL,
    created_at      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS stage_commits (
    execution_id  TEXT NOT NULL,
    version       INTEGER NOT NULL,
    stage         INTEGER NOT NULL,
    payload_json  TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    committed_at  TEXT NOT NULL,
    PRIMARY KEY (execution_id, version),
    UNIQUE (execution_id, stage),
    FOREIGN KEY (execution_id) REFERENCES plan_executions(execution_id)
);
"""


class ExecutionReplayError(Exception):
    """The registered/committed plan replay breaks a relationship (HTTP 409)."""

    def __init__(self, failure: Failure) -> None:
        super().__init__(failure.message)
        self.failure = failure


class CommitRejected(Exception):
    """A stage commit failed its transactional validation (HTTP 409)."""

    def __init__(self, conflict: CommitConflict) -> None:
        super().__init__(conflict.message)
        self.conflict = conflict


class UnknownExecution(Exception):
    """No registered execution with that id (HTTP 404)."""

    def __init__(self, execution_id: str) -> None:
        super().__init__(f"unknown execution_id '{execution_id}'")
        self.execution_id = execution_id


# ---------------------------------------------------------------------------
# SQLite plumbing
# ---------------------------------------------------------------------------


def db_path() -> str:
    return os.environ.get("ROTATION_DB_PATH", "/data/rotation.db")


_initialized: set[str] = set()
_init_lock = threading.Lock()


def _connect() -> sqlite3.Connection:
    path = db_path()
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    # Writers take the write lock up front so concurrent commits serialize;
    # busy_timeout makes lock contention wait instead of erroring immediately.
    conn.execute(f"PRAGMA busy_timeout = {10_000}")
    conn.execute("PRAGMA foreign_keys = ON")
    if path not in _initialized:
        with _init_lock:
            if path not in _initialized:
                conn.execute("PRAGMA journal_mode = WAL")
                conn.executescript(SCHEMA)
                _initialized.add(path)
    return conn


def reset_store() -> None:
    """Forget cached schema state (tests point ROTATION_DB_PATH at a fresh dir)."""

    _initialized.clear()


# ---------------------------------------------------------------------------
# Plan structural validation + full replay (shared registration semantics)
# ---------------------------------------------------------------------------


def _structural_batches(
    sc: Scenario, stages: list[ExecutionStage]
) -> list[list[int]]:
    """Translate plan stages to action-index batches exactly like /plans/verify."""

    index = {aid: i for i, aid in enumerate(sc.action_ids)}
    seen: set[str] = set()
    expected_stage = 1
    batches: list[list[int]] = []
    for st in stages:
        if st.stage != expected_stage:
            raise ScenarioValidationError(
                f"plan: stages must be numbered consecutively from 1; "
                f"expected stage {expected_stage}, got {st.stage}"
            )
        expected_stage += 1
        batch: list[int] = []
        for aid in st.action_ids:
            if aid not in index:
                raise ScenarioValidationError(
                    f"plan: unknown action_id '{aid}'"
                )
            if aid in seen:
                raise ScenarioValidationError(
                    f"plan: action '{aid}' appears more than once"
                )
            seen.add(aid)
            batch.append(index[aid])
        batches.append(batch)
    missing = sorted(set(sc.action_ids) - seen)
    if missing:
        raise ScenarioValidationError(
            "plan: every action must be scheduled exactly once; missing: "
            + ", ".join(missing)
        )
    return batches


def _replay_message(sc: Scenario, rf: Any) -> str:
    rel = sc.relationships[rf.relationship_index]
    who = f"relationship {rel.client_id} -> {rel.endpoint_id}"
    prefix = "initial state already invalid" if rf.stage == 0 else f"stage {rf.stage}"
    if rf.reason == "untrusted_root":
        broken = rf.chain[rf.failure_index]
        return (
            f"{prefix}: {who} loses its trust path; chain terminates at "
            f"'{broken}', which is not among the client's trust anchors "
            f"({', '.join(rf.trusted_anchors) or 'none'})"
        )
    if rf.reason == "issuer_mismatch":
        broken = rf.chain[rf.failure_index]
        nxt = rf.chain[rf.failure_index + 1]
        return (
            f"{prefix}: {who} chain breaks at '{broken}' -> '{nxt}': "
            f"issuer/subject mismatch"
        )
    if rf.reason == "action_not_allowed_at_stage":
        return (
            f"{prefix}: action is scheduled outside its allowed_stages; "
            f"{who} cannot be verified"
        )
    if rf.reason == "contradictory_actions_same_stage":
        return (
            f"{prefix}: an add_trust and a remove_trust on the same anchor "
            f"are scheduled together; {who} cannot be verified"
        )
    return f"{prefix}: {who} invalid ({rf.reason})"


def _replay_failure_dto(sc: Scenario, rf: Any, *, status: str) -> Failure:
    rel = sc.relationships[rf.relationship_index]
    return Failure(
        status=status,  # type: ignore[arg-type]
        stage=rf.stage,
        relationship=RelationshipRef(
            client_id=rel.client_id, endpoint_id=rel.endpoint_id
        ),
        blocking_action=(
            sc.action_ids[rf.blocking_action_index]
            if rf.blocking_action_index is not None
            else None
        ),
        reason=rf.reason,
        chain=[
            ChainCert(
                cert_id=cid,
                subject=sc.certs[cid].subject,
                issuer=sc.certs[cid].issuer,
            )
            for cid in rf.chain
        ],
        trusted_anchors=rf.trusted_anchors,
        message=_replay_message(sc, rf),
    )


def replay_plan(sc: Scenario, batches: list[list[int]]) -> None:
    """Replay the whole plan; raise ExecutionReplayError at the first break."""

    state = initial_state(sc)
    broken = first_broken_relationship(sc, state)
    if broken is not None:
        from .engine import ReplayFailure

        ridx, pf = broken
        rf = ReplayFailure(
            stage=0,
            relationship_index=ridx,
            blocking_action_index=None,
            reason=pf.reason,
            chain=pf.chain,
            failure_index=pf.failure_index,
            trusted_anchors=pf.trusted_anchors,
        )
        raise ExecutionReplayError(_replay_failure_dto(sc, rf, status="invalid"))

    for num, batch in enumerate(batches, start=1):
        bits = 0
        for i in batch:
            bits |= 1 << i
        rf = check_batch(sc, state, bits, num)
        if rf is not None:
            raise ExecutionReplayError(
                _replay_failure_dto(sc, rf, status="invalid")
            )
        state = state_for_mask_applied(sc, state, bits)


# ---------------------------------------------------------------------------
# Snapshot construction
# ---------------------------------------------------------------------------


def _build_snapshot(
    sc: Scenario,
    state: TrustState,
    *,
    version: int,
    stage: int,
    action_ids: list[str],
    anchor_observations: list[CommitAnchorObservation],
    chain_observations: list[CommitChainObservation],
    committed_at: datetime,
) -> StageSnapshot:
    anchor_snap = sorted(
        (
            SnapshotTrustAnchor(client_id=edge.client_id, anchor_cert_id=edge.cert_id)
            for edge in state.anchors
        ),
        key=lambda a: (a.client_id, a.anchor_cert_id),
    )
    chain_snap = [
        SnapshotEndpointChain(endpoint_id=ep, chain=list(state.chains[ep]))
        for ep in sorted(state.chains)
    ]
    rel_snaps: list[SnapshotRelationship] = []
    for rel in sc.relationships:
        failure = evaluate_path(sc, state, rel.client_id, rel.endpoint_id)
        chain_ids = list(state.chains[rel.endpoint_id])
        rel_snaps.append(
            SnapshotRelationship(
                client_id=rel.client_id,
                endpoint_id=rel.endpoint_id,
                valid=failure is None,
                chain=[
                    ChainCert(
                        cert_id=cid,
                        subject=sc.certs[cid].subject,
                        issuer=sc.certs[cid].issuer,
                    )
                    for cid in chain_ids
                ],
                trusted_anchors=sorted(
                    edge.cert_id
                    for edge in state.anchors
                    if edge.client_id == rel.client_id
                ),
            )
        )
    return StageSnapshot(
        version=version,
        stage=stage,
        action_ids=list(action_ids),
        anchor_observations=sorted(
            anchor_observations,
            key=lambda o: (o.client_id, o.anchor_cert_id),
        ),
        chain_observations=sorted(
            chain_observations, key=lambda o: o.endpoint_id
        ),
        trust_anchors=anchor_snap,
        endpoint_chains=chain_snap,
        relationships=rel_snaps,
        committed_at=committed_at,
    )


# ---------------------------------------------------------------------------
# Status assembly
# ---------------------------------------------------------------------------


def _status_from_row(conn: sqlite3.Connection, row: sqlite3.Row) -> ExecutionStatus:
    cur = conn.execute(
        "SELECT snapshot_json FROM stage_commits WHERE execution_id = ? "
        "ORDER BY version ASC",
        (row["execution_id"],),
    )
    snapshots = [
        StageSnapshot.model_validate_json(blob) for (blob,) in cur.fetchall()
    ]
    version = row["current_version"]
    stage_count = row["stage_count"]
    completed = [s.stage for s in snapshots if s.stage >= 1]
    finished = version >= stage_count
    return ExecutionStatus(
        execution_id=row["execution_id"],
        version=version,
        stage_count=stage_count,
        completed_stages=completed,
        next_stage=None if finished else version + 1,
        finished=finished,
        snapshots=snapshots,
    )


def get_execution(execution_id: str) -> ExecutionStatus:
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT * FROM plan_executions WHERE execution_id = ?",
            (execution_id,),
        ).fetchone()
        if row is None:
            raise UnknownExecution(execution_id)
        return _status_from_row(conn, row)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_execution(req: ExecutionRegisterRequest) -> ExecutionStatus:
    sc = build_scenario(req)
    batches = _structural_batches(sc, req.plan)
    # A registered plan must be executable: replay it fully before storing
    # anything, so an invalid/unsafe plan is never made an immutable record.
    replay_plan(sc, batches)

    execution_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc)
    stages_dto = [
        PlannedStage(
            stage=num, action_ids=[sc.action_ids[i] for i in batch]
        )
        for num, batch in enumerate(batches, start=1)
    ]
    plan_blob = json.dumps(
        [s.model_dump() for s in stages_dto], separators=(",", ":")
    )

    initial_snapshot = _build_snapshot(
        sc,
        initial_state(sc),
        version=0,
        stage=0,
        action_ids=[],
        anchor_observations=[],
        chain_observations=[],
        committed_at=now,
    )

    # Store the scenario verbatim (datetimes as ISO-8601 via mode="json");
    # the plan is stored separately and never changes after registration.
    scenario_blob = json.dumps(
        req.model_dump(mode="json", exclude={"plan"}),
        separators=(",", ":"),
    )

    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO plan_executions "
            "(execution_id, scenario_json, plan_json, stage_count, "
            "current_version, created_at) VALUES (?, ?, ?, ?, 0, ?)",
            (
                execution_id,
                scenario_blob,
                plan_blob,
                len(batches),
                now.isoformat(),
            ),
        )
        conn.execute(
            "INSERT INTO stage_commits "
            "(execution_id, version, stage, payload_json, snapshot_json, "
            "committed_at) VALUES (?, 0, 0, ?, ?, ?)",
            (
                execution_id,
                json.dumps({"kind": "initial"}, separators=(",", ":")),
                initial_snapshot.model_dump_json(),
                now.isoformat(),
            ),
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()

    return get_execution(execution_id)


# ---------------------------------------------------------------------------
# Stage commit
# ---------------------------------------------------------------------------


def _known_clients(sc: Scenario) -> set[str]:
    clients = {rel.client_id for rel in sc.relationships}
    clients.update(edge.client_id for edge in sc.initial_anchors)
    for edge in sc.add_edges.values():
        clients.add(edge.client_id)
    for edge in sc.remove_edges.values():
        clients.add(edge.client_id)
    return clients


def _load_execution(
    conn: sqlite3.Connection, execution_id: str
) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM plan_executions WHERE execution_id = ?",
        (execution_id,),
    ).fetchone()
    if row is None:
        raise UnknownExecution(execution_id)
    return row


def _canonical_payload(req: StageCommitRequest) -> str:
    """Order-independent content identity of a commit, for idempotent replay."""

    payload = {
        "action_ids": sorted(req.action_ids),
        "anchor_observations": sorted(
            (
                [o.client_id, o.anchor_cert_id, o.present]
                for o in req.anchor_observations
            ),
            key=lambda t: (t[0], t[1]),
        ),
        "chain_observations": sorted(
            ([o.endpoint_id, list(o.chain)] for o in req.chain_observations),
            key=lambda t: t[0],
        ),
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def _conflict(
    reason: str,
    message: str,
    *,
    expected_version: Optional[int] = None,
    current_version: Optional[int] = None,
    stage: Optional[int] = None,
) -> CommitConflict:
    return CommitConflict(
        reason=reason,
        message=message,
        expected_version=expected_version,
        current_version=current_version,
        stage=stage,
    )


def commit_stage(
    execution_id: str, req: StageCommitRequest
) -> ExecutionStatus:
    # ---- load + scenario-level reference validation (outside the txn) ------
    read_conn = _connect()
    try:
        row = _load_execution(read_conn, execution_id)
        scenario_blob = row["scenario_json"]
        plan_blob = row["plan_json"]
    finally:
        read_conn.close()

    scenario_req = PlanRequest.model_validate(json.loads(scenario_blob))
    sc = build_scenario(scenario_req)

    plan_stages = [PlannedStage.model_validate(d) for d in json.loads(plan_blob)]
    batches = _structural_batches(sc, plan_stages)

    # Malformed references are client errors (422), not optimistic conflicts.
    index = {aid: i for i, aid in enumerate(sc.action_ids)}
    for aid in req.action_ids:
        if aid not in index:
            raise ScenarioValidationError(
                f"action_ids: unknown action_id '{aid}'"
            )
    clients = _known_clients(sc)
    for obs in req.anchor_observations:
        if obs.client_id not in clients:
            raise ScenarioValidationError(
                f"anchor_observations: unknown client_id '{obs.client_id}'"
            )
        if obs.anchor_cert_id not in sc.certs:
            raise ScenarioValidationError(
                f"anchor_observations: unknown certificate "
                f"'{obs.anchor_cert_id}'"
            )
    for obs in req.chain_observations:
        if obs.endpoint_id not in sc.endpoint_chains:
            raise ScenarioValidationError(
                f"chain_observations: unknown endpoint_id '{obs.endpoint_id}'"
            )
        for cid in obs.chain:
            if cid not in sc.certs:
                raise ScenarioValidationError(
                    f"chain_observations: unknown certificate '{cid}' in "
                    f"observed chain of endpoint '{obs.endpoint_id}'"
                )

    payload = _canonical_payload(req)

    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = _load_execution(conn, execution_id)
        current_version = row["current_version"]
        stage_count = row["stage_count"]
        stage = req.stage

        # -- optimistic lock first: stale or concurrent commits lose --------
        # This precedes idempotent replay: a duplicate is recognized only when
        # the caller still bases it on the version the stage advanced from.
        if req.expected_version != current_version:
            raise CommitRejected(
                _conflict(
                    "version_conflict",
                    f"expected_version {req.expected_version} does not match "
                    f"the current version {current_version}; a concurrent or "
                    f"stale commit must be retried with "
                    f"expected_version={current_version} against the latest "
                    f"state.",
                    expected_version=current_version,
                    current_version=current_version,
                    stage=stage,
                )
            )

        # -- already committed? idempotent replay or content conflict -------
        committed_row = conn.execute(
            "SELECT payload_json, snapshot_json FROM stage_commits "
            "WHERE execution_id = ? AND stage = ?",
            (execution_id, stage),
        ).fetchone()
        if committed_row is not None:
            if committed_row["payload_json"] == payload:
                conn.execute("ROLLBACK")
                return get_execution(execution_id)
            raise CommitRejected(
                _conflict(
                    "duplicate_payload_mismatch",
                    f"stage {stage} is already committed; re-submitting it "
                    f"with different content is forbidden (the audit record "
                    f"is immutable). Re-send the identical commit to receive "
                    f"the same snapshot.",
                    expected_version=current_version,
                    current_version=current_version,
                    stage=stage,
                )
            )

        # -- plan ordering: the next consecutive stage only -----------------
        if stage != current_version + 1 or stage > stage_count:
            raise CommitRejected(
                _conflict(
                    "unexpected_stage",
                    f"stage {stage} cannot be committed next: expected "
                    f"stage {current_version + 1} of {stage_count}.",
                    expected_version=current_version,
                    current_version=current_version,
                    stage=stage,
                )
            )

        # -- action set must be exactly this plan stage ---------------------
        planned_actions = [sc.action_ids[i] for i in batches[stage - 1]]
        if sorted(req.action_ids) != sorted(planned_actions):
            raise CommitRejected(
                _conflict(
                    "action_set_mismatch",
                    f"stage {stage} plan actions "
                    f"[{', '.join(sorted(planned_actions)) or 'none'}] do not "
                    f"match the committed action set "
                    f"[{', '.join(sorted(req.action_ids)) or 'none'}].",
                    expected_version=current_version,
                    current_version=current_version,
                    stage=stage,
                )
            )

        # -- replay the prefix to obtain the exact pre-stage state ----------
        # The immutable plan fixes prior stages; rebuild the state they
        # produced so the new stage is validated against the true prefix.
        pre_state = initial_state(sc)
        for num in range(1, stage):
            prior_bits = 0
            for i in batches[num - 1]:
                prior_bits |= 1 << i
            pre_state = state_for_mask_applied(sc, pre_state, prior_bits)

        bits = 0
        for aid in req.action_ids:
            bits |= 1 << index[aid]

        # -- batch validation: allowed_stages, contradictions, trust paths --
        rf = check_batch(sc, pre_state, bits, stage)
        if rf is not None:
            failure = _replay_failure_dto(sc, rf, status="invalid")
            raise CommitRejected(
                CommitConflict(
                    reason=rf.reason,
                    message=failure.message,
                    expected_version=current_version,
                    current_version=current_version,
                    stage=stage,
                    relationship=failure.relationship,
                    blocking_action=failure.blocking_action,
                    chain=failure.chain,
                    trusted_anchors=failure.trusted_anchors,
                )
            )

        end_state = state_for_mask_applied(sc, pre_state, bits)

        # -- observations must attest the computed field state --------------
        for obs in req.anchor_observations:
            edge = TrustEdge(obs.client_id, obs.anchor_cert_id)
            if (edge in end_state.anchors) != obs.present:
                expected_present = edge in end_state.anchors
                raise CommitRejected(
                    CommitConflict(
                        reason="observation_mismatch",
                        message=(
                            f"anchor observation ({obs.client_id}, "
                            f"{obs.anchor_cert_id}) present="
                            f"{str(obs.present).lower()} does not match the "
                            f"post-stage state (present="
                            f"{str(expected_present).lower()})."
                        ),
                        expected_version=current_version,
                        current_version=current_version,
                        stage=stage,
                        observation={
                            "kind": "anchor",
                            "client_id": obs.client_id,
                            "anchor_cert_id": obs.anchor_cert_id,
                            "submitted_present": obs.present,
                            "expected_present": expected_present,
                        },
                    )
                )
        for obs in req.chain_observations:
            expected_chain = list(end_state.chains[obs.endpoint_id])
            if list(obs.chain) != expected_chain:
                raise CommitRejected(
                    CommitConflict(
                        reason="observation_mismatch",
                        message=(
                            f"chain observation for endpoint "
                            f"'{obs.endpoint_id}' ['"
                            + "' -> '".join(obs.chain)
                            + "'] does not match the post-stage chain ['"
                            + "' -> '".join(expected_chain)
                            + "']."
                        ),
                        expected_version=current_version,
                        current_version=current_version,
                        stage=stage,
                        observation={
                            "kind": "endpoint_chain",
                            "endpoint_id": obs.endpoint_id,
                            "submitted_chain": list(obs.chain),
                            "expected_chain": expected_chain,
                        },
                    )
                )

        # Defense in depth: the registered plan was fully replayed at
        # registration, but every relationship is re-checked here inside the
        # transaction before any version advance.
        broken = first_broken_relationship(sc, end_state)
        if broken is not None:
            ridx, pf = broken
            rel = sc.relationships[ridx]
            raise CommitRejected(
                CommitConflict(
                    reason=pf.reason,
                    message=(
                        f"stage {stage}: relationship {rel.client_id} -> "
                        f"{rel.endpoint_id} has no valid trust path after "
                        f"the committed actions."
                    ),
                    expected_version=current_version,
                    current_version=current_version,
                    stage=stage,
                    relationship=RelationshipRef(
                        client_id=rel.client_id, endpoint_id=rel.endpoint_id
                    ),
                    chain=[
                        ChainCert(
                            cert_id=cid,
                            subject=sc.certs[cid].subject,
                            issuer=sc.certs[cid].issuer,
                        )
                        for cid in pf.chain
                    ],
                    trusted_anchors=pf.trusted_anchors,
                )
            )

        now = datetime.now(timezone.utc)
        snapshot = _build_snapshot(
            sc,
            end_state,
            version=stage,
            stage=stage,
            action_ids=[sc.action_ids[i] for i in batches[stage - 1]],
            anchor_observations=list(req.anchor_observations),
            chain_observations=list(req.chain_observations),
            committed_at=now,
        )

        conn.execute(
            "INSERT INTO stage_commits "
            "(execution_id, version, stage, payload_json, snapshot_json, "
            "committed_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                execution_id,
                stage,
                stage,
                payload,
                snapshot.model_dump_json(),
                now.isoformat(),
            ),
        )
        cur = conn.execute(
            "UPDATE plan_executions SET current_version = ? "
            "WHERE execution_id = ? AND current_version = ?",
            (stage, execution_id, current_version),
        )
        # The conditional UPDATE is the final optimistic-lock guarantee: under
        # the write lock the row must still be at the version we validated.
        if cur.rowcount != 1:
            raise CommitRejected(
                _conflict(
                    "version_conflict",
                    f"execution '{execution_id}' advanced concurrently while "
                    f"stage {stage} was being committed; no progress was "
                    f"applied.",
                    expected_version=None,
                    current_version=None,
                    stage=stage,
                )
            )
        conn.execute("COMMIT")
    except CommitRejected:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    finally:
        conn.close()

    return get_execution(execution_id)
