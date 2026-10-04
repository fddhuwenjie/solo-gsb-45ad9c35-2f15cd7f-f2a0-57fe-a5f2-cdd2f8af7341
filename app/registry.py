"""SQLite-backed, auditable stage commits of registered rotation plans.

A caller first *registers* an immutable plan (the scenario payload plus the
stages, exactly as ``/plans/verify`` accepts them). Registration replays the
whole plan once; only a plan that keeps every communication relationship valid
after every stage can be registered. The registration starts at version 0.

Each subsequent stage commit:

* carries ``expected_version`` for optimistic concurrency control;
* names the exact action set of the next plan stage;
* carries the caller's on-site trust-anchor and endpoint-chain observations;

and, **inside one SQLite transaction**, verifies in plan order:

1. the submitted action set equals the next stage's action set;
2. every observation equals the deterministic post-stage state
   (the complete trust state and endpoint chains implied by the plan);
3. every required communication relationship still has a valid trust path.

Only when every check passes does the transaction advance the version by one
and append an immutable stage snapshot. A failure rolls back: no partial
progress is ever persisted. Re-submitting an already committed stage with the
same action set and observations is an idempotent replay: the exact same
snapshot is returned and the version is not advanced. Any other stale/racing
commit is rejected with 409.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Optional

from .engine import (
    Scenario,
    ScenarioValidationError,
    TrustEdge,
    TrustState,
    build_scenario,
    evaluate_path,
    failure_message,
    first_broken_relationship,
    initial_state,
    replay_batches,
    state_for_mask_applied,
    structure_plan_batches,
)
from .models import (
    PlanRegistrationState,
    PlanReplayConflict,
    RegisterRequest,
    RelationshipRef,
    StageCommitConflict,
    StageCommitMismatch,
    StageCommitRequest,
    StageCommitResponse,
    StageSnapshot,
    SnapshotAnchorObservation,
    SnapshotChainObservation,
    SnapshotRelationship,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS registrations (
    registration_id   TEXT PRIMARY KEY,
    plan_fingerprint  TEXT NOT NULL,
    payload_json      TEXT NOT NULL,
    plan_json         TEXT NOT NULL,
    stage_count       INTEGER NOT NULL,
    current_version   INTEGER NOT NULL,
    created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots (
    registration_id   TEXT NOT NULL,
    stage             INTEGER NOT NULL,
    version           INTEGER NOT NULL,
    snapshot_json     TEXT NOT NULL,
    committed_at      TEXT NOT NULL,
    PRIMARY KEY (registration_id, stage),
    FOREIGN KEY (registration_id) REFERENCES registrations(registration_id)
);
"""


class RegistrationNotFound(Exception):
    """No registration exists for the given id (mapped to HTTP 404)."""


_lock = threading.RLock()
_db_path: Optional[str] = None
_initialized = False


def set_database_path(path: Optional[str]) -> None:
    """Override the SQLite file location (tests use a temporary database)."""
    global _db_path, _initialized
    with _lock:
        _db_path = path
        _initialized = False


def database_path() -> str:
    if _db_path is not None:
        return _db_path
    env = os.environ.get("ROTATION_REGISTRY_DB")
    if env:
        return env
    return os.path.join("data", "rotations.db")


def _connect() -> sqlite3.Connection:
    global _initialized
    path = database_path()
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    # WAL lets a concurrent reader not block the single writer; BEGIN
    # IMMEDIATE below serializes writers across processes/workers, and the
    # busy timeout makes a contended writer wait instead of erroring.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    if not _initialized:
        conn.executescript(_SCHEMA)
        conn.commit()
        _initialized = True
    return conn


def init_db() -> None:
    """Create the schema eagerly (also used by tests)."""
    with _lock:
        conn = _connect()
        conn.close()


def _canonical_payload_json(req: RegisterRequest) -> str:
    return json.dumps(
        req.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _plan_fingerprint(canonical: str) -> str:
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _known_clients(sc: Scenario) -> set[str]:
    clients = {rel.client_id for rel in sc.relationships}
    clients.update(edge.client_id for edge in sc.initial_anchors)
    for edge in sc.add_edges.values():
        clients.add(edge.client_id)
    for edge in sc.remove_edges.values():
        clients.add(edge.client_id)
    return clients


def _validate_observation_refs(sc: Scenario, req: StageCommitRequest) -> None:
    """422-level checks: observations may only reference known objects."""
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


def _chain_dto_dicts(sc: Scenario, cert_ids: list[str]) -> list[dict]:
    return [
        {
            "cert_id": cid,
            "subject": sc.certs[cid].subject,
            "issuer": sc.certs[cid].issuer,
        }
        for cid in cert_ids
    ]


def _replay_conflict_dto(sc, rf) -> PlanReplayConflict:
    rel = sc.relationships[rf.relationship_index]
    return PlanReplayConflict(
        status="invalid",
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
        chain=_chain_dto_dicts(sc, rf.chain),
        trusted_anchors=rf.trusted_anchors,
        message=failure_message(sc, rf),
    )


# ---------------------------------------------------------------------------
# Snapshot construction
# ---------------------------------------------------------------------------


def _build_snapshot(
    sc: Scenario,
    stage: int,
    post_state: TrustState,
    committed_action_ids: list[str],
    req: StageCommitRequest,
    committed_at: datetime,
) -> StageSnapshot:
    anchors = [
        SnapshotAnchorObservation(
            client_id=edge.client_id, anchor_cert_id=edge.cert_id, present=True
        )
        for edge in sorted(post_state.anchors, key=lambda e: (e.client_id, e.cert_id))
    ]
    endpoint_chains = [
        SnapshotChainObservation(endpoint_id=ep, chain=list(post_state.chains[ep]))
        for ep in sorted(post_state.chains)
    ]
    relationships: list[SnapshotRelationship] = []
    for rel in sorted(sc.relationships, key=lambda r: (r.client_id, r.endpoint_id)):
        failure = evaluate_path(sc, post_state, rel.client_id, rel.endpoint_id)
        relationships.append(
            SnapshotRelationship(
                client_id=rel.client_id,
                endpoint_id=rel.endpoint_id,
                valid=failure is None,
                chain=list(post_state.chains[rel.endpoint_id]),
                trusted_anchors=sorted(
                    edge.cert_id
                    for edge in post_state.anchors
                    if edge.client_id == rel.client_id
                ),
            )
        )
    anchor_observations = [
        SnapshotAnchorObservation(
            client_id=o.client_id,
            anchor_cert_id=o.anchor_cert_id,
            present=o.present,
        )
        for o in sorted(
            req.anchor_observations,
            key=lambda o: (o.client_id, o.anchor_cert_id),
        )
    ]
    chain_observations = [
        SnapshotChainObservation(endpoint_id=o.endpoint_id, chain=list(o.chain))
        for o in sorted(req.chain_observations, key=lambda o: o.endpoint_id)
    ]
    return StageSnapshot(
        stage=stage,
        version=stage,
        committed_action_ids=sorted(committed_action_ids),
        committed_at=committed_at,
        anchors=anchors,
        endpoint_chains=endpoint_chains,
        relationships=relationships,
        anchor_observations=anchor_observations,
        chain_observations=chain_observations,
    )


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register(
    req: RegisterRequest,
) -> tuple[Optional[PlanRegistrationState], Optional[PlanReplayConflict]]:
    """Validate and store an immutable plan at version 0.

    Returns (state, None) on success or (None, conflict) when the registered
    plan itself does not replay cleanly (mapped to 409 by the route).
    """
    sc = build_scenario(req)
    batches = structure_plan_batches(sc, req.plan)
    rf, _states = replay_batches(sc, batches)
    if rf is not None:
        return None, _replay_conflict_dto(sc, rf)

    canonical = _canonical_payload_json(req)
    fingerprint = _plan_fingerprint(canonical)
    plan_json = json.dumps(
        [st.model_dump(mode="json") for st in req.plan],
        separators=(",", ":"),
        ensure_ascii=False,
    )
    registration_id = uuid.uuid4().hex
    created_at = datetime.now(timezone.utc)

    with _lock:
        conn = _connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO registrations "
                "(registration_id, plan_fingerprint, payload_json, plan_json, "
                " stage_count, current_version, created_at) "
                "VALUES (?, ?, ?, ?, ?, 0, ?)",
                (
                    registration_id,
                    fingerprint,
                    canonical,
                    plan_json,
                    len(req.plan),
                    created_at.isoformat(),
                ),
            )
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    state = PlanRegistrationState(
        registration_id=registration_id,
        plan_fingerprint=fingerprint,
        stage_count=len(req.plan),
        current_version=0,
        completed_stages=[],
        next_stage=1 if req.plan else None,
        snapshots=[],
    )
    return state, None


# ---------------------------------------------------------------------------
# State reconstruction
# ---------------------------------------------------------------------------


def _load_row(conn: sqlite3.Connection, registration_id: str) -> sqlite3.Row:
    row = conn.execute(
        "SELECT * FROM registrations WHERE registration_id = ?",
        (registration_id,),
    ).fetchone()
    if row is None:
        raise RegistrationNotFound(registration_id)
    return row


def _load_snapshots(
    conn: sqlite3.Connection, registration_id: str
) -> list[StageSnapshot]:
    rows = conn.execute(
        "SELECT snapshot_json FROM snapshots "
        "WHERE registration_id = ? ORDER BY stage",
        (registration_id,),
    ).fetchall()
    return [StageSnapshot.model_validate(json.loads(r["snapshot_json"])) for r in rows]


def _state_from_snapshot(snap: StageSnapshot) -> TrustState:
    return TrustState(
        anchors=frozenset(
            TrustEdge(a.client_id, a.anchor_cert_id) for a in snap.anchors
        ),
        chains={ec.endpoint_id: list(ec.chain) for ec in snap.endpoint_chains},
    )


def _state_response(row: sqlite3.Row, snapshots: list[StageSnapshot]) -> dict:
    version = row["current_version"]
    stage_count = row["stage_count"]
    return {
        "registration_id": row["registration_id"],
        "plan_fingerprint": row["plan_fingerprint"],
        "stage_count": stage_count,
        "current_version": version,
        "completed_stages": list(range(1, version + 1)),
        "next_stage": version + 1 if version < stage_count else None,
        "snapshots": [s.model_dump(mode="json") for s in snapshots],
    }


def get_state(registration_id: str) -> PlanRegistrationState:
    with _lock:
        conn = _connect()
        try:
            row = _load_row(conn, registration_id)
            snapshots = _load_snapshots(conn, registration_id)
        finally:
            conn.close()
    return PlanRegistrationState.model_validate(_state_response(row, snapshots))


# ---------------------------------------------------------------------------
# Stage commit
# ---------------------------------------------------------------------------


def _observations_equal_snapshot(
    snap: StageSnapshot, req: StageCommitRequest
) -> bool:
    submitted_anchors = sorted(
        (o.client_id, o.anchor_cert_id, o.present)
        for o in req.anchor_observations
    )
    saved_anchors = sorted(
        (o.client_id, o.anchor_cert_id, o.present)
        for o in snap.anchor_observations
    )
    if submitted_anchors != saved_anchors:
        return False
    submitted_chains = sorted(
        (o.endpoint_id, tuple(o.chain)) for o in req.chain_observations
    )
    saved_chains = sorted(
        (o.endpoint_id, tuple(o.chain)) for o in snap.chain_observations
    )
    return submitted_chains == saved_chains


def _conflict(
    row: sqlite3.Row,
    snapshots: list[StageSnapshot],
    reason: str,
    message: str,
    req: StageCommitRequest,
    *,
    submitted_stage: Optional[int],
    mismatches: Optional[list[StageCommitMismatch]] = None,
) -> StageCommitConflict:
    version = row["current_version"]
    stage_count = row["stage_count"]
    return StageCommitConflict(
        reason=reason,
        message=message,
        registration_id=row["registration_id"],
        current_version=version,
        next_stage=version + 1 if version < stage_count else None,
        expected_version=req.expected_version,
        submitted_stage=submitted_stage,
        mismatches=mismatches or [],
    )


def commit_stage(
    registration_id: str, req: StageCommitRequest
) -> StageCommitResponse:
    """Atomically validate and commit one stage; see module docstring."""
    with _lock:
        conn = _connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = _load_row(conn, registration_id)
            snapshots = _load_snapshots(conn, registration_id)

            payload = json.loads(row["payload_json"])
            register_req = RegisterRequest.model_validate(payload)
            sc = build_scenario(register_req)
            plan_stages = register_req.plan
            version = row["current_version"]
            stage_count = row["stage_count"]

            # --- stale / racing versions, including idempotent replay ------
            if req.expected_version != version:
                # Re-submitting an already completed stage with the identical
                # action set and observations returns the same snapshot.
                replay_stage = req.expected_version + 1
                if 1 <= replay_stage <= len(snapshots):
                    snap = snapshots[replay_stage - 1]
                    if (
                        snap.committed_action_ids == sorted(req.action_ids)
                        and _observations_equal_snapshot(snap, req)
                    ):
                        body = _state_response(row, snapshots)
                        body["idempotent_replay"] = True
                        conn.rollback()
                        return StageCommitResponse.model_validate(body)
                conn.rollback()
                if version >= stage_count and req.expected_version > version:
                    raise _ConflictRaised(
                        _conflict(
                            row,
                            snapshots,
                            "unexpected_stage",
                            f"plan already finished at version {version}; "
                            f"commit expected_version={req.expected_version} "
                            f"addresses a stage past the end of the plan",
                            req,
                            submitted_stage=req.expected_version + 1,
                        )
                    )
                raise _ConflictRaised(
                    _conflict(
                        row,
                        snapshots,
                        "version_conflict",
                        f"expected_version {req.expected_version} does not "
                        f"match current version {version}; reload the "
                        f"registration state and retry",
                        req,
                        submitted_stage=req.expected_version + 1,
                    )
                )

            if version >= stage_count:
                conn.rollback()
                raise _ConflictRaised(
                    _conflict(
                        row,
                        snapshots,
                        "unexpected_stage",
                        f"all {stage_count} stage(s) are already committed; "
                        f"nothing left to commit",
                        req,
                        submitted_stage=None,
                    )
                )

            target_stage = version + 1
            expected_stage_obj = plan_stages[target_stage - 1]
            expected_action_ids = sorted(expected_stage_obj.action_ids)
            submitted_action_ids = sorted(req.action_ids)

            # Reference validation (422) happens before any 409 mismatch.
            for aid in req.action_ids:
                if aid not in set(sc.action_ids):
                    raise ScenarioValidationError(
                        f"action_ids: unknown action_id '{aid}'"
                    )
            _validate_observation_refs(sc, req)

            mismatches: list[StageCommitMismatch] = []

            # 1. Action set must equal the next stage's action set.
            if submitted_action_ids != expected_action_ids:
                mismatches.append(
                    StageCommitMismatch(
                        kind="action_set",
                        expected_action_ids=expected_action_ids,
                        submitted_action_ids=submitted_action_ids,
                        client_id=None,
                        anchor_cert_id=None,
                        observed_present=None,
                        expected_present=None,
                        endpoint_id=None,
                        observed_chain=None,
                        expected_chain=None,
                        chain=None,
                        trusted_anchors=None,
                        reason="action_set_mismatch",
                        message=(
                            f"stage {target_stage} requires the action set "
                            f"{expected_action_ids}, but "
                            f"{submitted_action_ids} was submitted"
                        ),
                    )
                )

            # Pre-state: deterministic state after all previously committed
            # stages (initial state at version 0).
            pre_state = (
                _state_from_snapshot(snapshots[-1])
                if snapshots
                else initial_state(sc)
            )

            index = {aid: i for i, aid in enumerate(sc.action_ids)}
            batch_bits = 0
            for aid in set(req.action_ids):
                batch_bits |= 1 << index[aid]
            post_state = state_for_mask_applied(sc, pre_state, batch_bits)

            # 2. Every observation must equal the deterministic post-stage state.
            for obs in sorted(
                req.anchor_observations,
                key=lambda o: (o.client_id, o.anchor_cert_id),
            ):
                expected_present = TrustEdge(
                    obs.client_id, obs.anchor_cert_id
                ) in post_state.anchors
                if obs.present != expected_present:
                    mismatches.append(
                        StageCommitMismatch(
                            kind="anchor_observation",
                            expected_action_ids=None,
                            client_id=obs.client_id,
                            anchor_cert_id=obs.anchor_cert_id,
                            observed_present=obs.present,
                            expected_present=expected_present,
                            reason="anchor_present_mismatch",
                            message=(
                                f"observed anchor ({obs.client_id}, "
                                f"{obs.anchor_cert_id}) present="
                                f"{obs.present}, but the deterministic state "
                                f"after stage {target_stage} requires "
                                f"present={expected_present}"
                            ),
                        )
                    )
            for obs in sorted(req.chain_observations, key=lambda o: o.endpoint_id):
                expected_chain = list(post_state.chains[obs.endpoint_id])
                if list(obs.chain) != expected_chain:
                    mismatches.append(
                        StageCommitMismatch(
                            kind="chain_observation",
                            expected_action_ids=None,
                            endpoint_id=obs.endpoint_id,
                            observed_chain=list(obs.chain),
                            expected_chain=expected_chain,
                            reason="endpoint_chain_mismatch",
                            message=(
                                f"observed chain of endpoint "
                                f"'{obs.endpoint_id}' {list(obs.chain)} does "
                                f"not match the deterministic chain "
                                f"{expected_chain} after stage {target_stage}"
                            ),
                        )
                    )

            # 3. Every required communication relationship must stay valid.
            broken: list[tuple[int, object]] = []
            for ridx, rel in enumerate(sc.relationships):
                failure = evaluate_path(
                    sc, post_state, rel.client_id, rel.endpoint_id
                )
                if failure is not None:
                    broken.append((ridx, failure))
            for ridx, failure in sorted(
                broken,
                key=lambda item: (
                    sc.relationships[item[0]].client_id,
                    sc.relationships[item[0]].endpoint_id,
                ),
            ):
                rel = sc.relationships[ridx]
                mismatches.append(
                    StageCommitMismatch(
                        kind="relationship",
                        expected_action_ids=None,
                        client_id=rel.client_id,
                        endpoint_id=rel.endpoint_id,
                        chain=list(failure.chain),
                        trusted_anchors=list(failure.trusted_anchors),
                        reason=failure.reason,
                        message=(
                            f"stage {target_stage}: relationship "
                            f"{rel.client_id} -> {rel.endpoint_id} loses its "
                            f"trust path ({failure.reason})"
                        ),
                    )
                )

            if mismatches:
                conn.rollback()
                anchor_bad = [m for m in mismatches if m.kind == "anchor_observation"]
                chain_bad = [m for m in mismatches if m.kind == "chain_observation"]
                rel_bad = [m for m in mismatches if m.kind == "relationship"]
                action_bad = [m for m in mismatches if m.kind == "action_set"]
                if action_bad:
                    reason = "action_set_mismatch"
                    message = (
                        f"the submitted action set does not equal stage "
                        f"{target_stage}'s planned action set"
                    )
                elif anchor_bad:
                    reason = "anchor_observation_mismatch"
                    message = (
                        f"on-site anchor observations do not match the state "
                        f"planned after stage {target_stage}"
                    )
                elif chain_bad:
                    reason = "chain_observation_mismatch"
                    message = (
                        f"on-site endpoint chains do not match the chains "
                        f"planned after stage {target_stage}"
                    )
                else:
                    reason = "relationship_broken"
                    message = (
                        f"stage {target_stage} leaves one or more required "
                        f"communication relationships without a valid trust "
                        f"path"
                    )
                raise _ConflictRaised(
                    _conflict(
                        row,
                        snapshots,
                        reason,
                        message,
                        req,
                        submitted_stage=target_stage,
                        mismatches=mismatches,
                    )
                )

            # All checks passed: persist the snapshot and advance the version.
            committed_at = datetime.now(timezone.utc)
            snapshot = _build_snapshot(
                sc,
                target_stage,
                post_state,
                req.action_ids,
                req,
                committed_at,
            )
            snapshot_json = json.dumps(
                snapshot.model_dump(mode="json"),
                separators=(",", ":"),
                ensure_ascii=False,
            )
            conn.execute(
                "INSERT INTO snapshots "
                "(registration_id, stage, version, snapshot_json, committed_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    registration_id,
                    target_stage,
                    target_stage,
                    snapshot_json,
                    committed_at.isoformat(),
                ),
            )
            conn.execute(
                "UPDATE registrations SET current_version = ? "
                "WHERE registration_id = ?",
                (target_stage, registration_id),
            )
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    return get_state_response(registration_id, idempotent_replay=False)


def get_state_response(
    registration_id: str, *, idempotent_replay: bool
) -> StageCommitResponse:
    state = get_state(registration_id)
    body = state.model_dump(mode="json")
    body["idempotent_replay"] = idempotent_replay
    return StageCommitResponse.model_validate(body)


class _ConflictRaised(Exception):
    """Internal control-flow carrying the staged 409 response."""

    def __init__(self, conflict: StageCommitConflict):
        self.conflict = conflict
        super().__init__(conflict.message)
