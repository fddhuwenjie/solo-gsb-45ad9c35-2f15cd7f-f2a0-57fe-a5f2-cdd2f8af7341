"""Recovery-point reconciliation after an interrupted deployment.

``POST /plans/reconcile`` answers: given the original scenario, the plan that
was generated, and a *partial* view of what actually happened (some client
trust edges and some endpoint chains), at which points is it safe to resume?

The reachable progress states are enumerated from the plan order without
guessing anything unobserved:

* **Ended stages are complete.** Every action of every stage up to stage ``p``
  has executed (their effects are mandatory in the state).
* **The current stage is partial.** At stage ``p + 1`` any subset of that
  stage's actions may have executed — including none of them.
* **Later stages never start early.** No action scheduled at a later stage has
  executed.
* Explicit no-op stages (empty action lists, as /plans emits) are real ended
  stages: they advance the completed-stage counter but change no state.

A progress state is identified by the *pair* ``(executed-action mask,
completed-stage count)``, never by the mask alone: a no-op stage carries the
trust state over unchanged, so the same mask is reachable on both sides of the
gap at different stage positions. Each such pair is a distinct reachable
progress and is kept separately — collapsing them onto the largest
completed-stage count would invent certainty the observations cannot provide
(e.g. it would make a later-stage action look executable while the
deployment may still sit before the gap, where only crossing the no-op stage
remains). Health checks, observation matching, the completion flag and the
safe-next test all operate on the full pair identity. The one canonical
collapse that remains is observational equivalence: a *non-empty* current
stage whose actions have all executed is the same bookkeeping point as
"that stage ended, next stage not started", so it is reported at the ended
position.

Two extra filters remove states that cannot describe a recoverable system:

* the state must keep a valid trust path for *every* required relationship
  (a state in which communication is already broken is never offered as a
  resumption point);
* the state must match every reported observation.

Observed (client, anchor) pairs and observed endpoint chains constrain the
state; anything not reported stays **unknown**, never "did not execute" /
"absent". When the observations jointly rule out every healthy plan-ordered
state, a 409 lists the first-incompatible observations in stable order.

``safe_next_actions`` is strictly conservative: an action is suggested only
when, in *every* surviving possible state, it belongs to that state's current
stage, has not executed there yet, is allowed at that absolute stage number,
and applying it alone keeps every relationship intact.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .engine import (
    Scenario,
    ScenarioValidationError,
    TrustEdge,
    TrustState,
    batch_conflict,
    build_scenario,
    first_broken_relationship,
    state_for_mask,
)
from .models import (
    ReconcileAnchorObservation,
    ReconcileChainObservation,
    ReconcileConflict,
    ReconcileConflictObservation,
    ReconcileProgress,
    ReconcileRequest,
    ReconcileResult,
)


# ---------------------------------------------------------------------------
# Structural validation of the submitted plan and observations
# ---------------------------------------------------------------------------


def _plan_batches(sc: Scenario, req: ReconcileRequest) -> list[list[int]]:
    """Translate the submitted stages to action-bit batches.

    Mirrors the structural checks of /plans/verify: consecutive numbering
    from 1, every scenario action scheduled exactly once.
    """
    known = set(range(sc.n))
    index = {aid: i for i, aid in enumerate(sc.action_ids)}
    seen: set[int] = set()
    expected_stage = 1
    batches: list[list[int]] = []
    for st in req.stages:
        if st.stage != expected_stage:
            raise ScenarioValidationError(
                f"stages: must be numbered consecutively from 1; expected "
                f"stage {expected_stage}, got {st.stage}"
            )
        expected_stage += 1
        batch: list[int] = []
        for aid in st.action_ids:
            if aid not in index:
                raise ScenarioValidationError(
                    f"stages: unknown action_id '{aid}'"
                )
            i = index[aid]
            if i in seen:
                raise ScenarioValidationError(
                    f"stages: action '{aid}' appears more than once"
                )
            seen.add(i)
            batch.append(i)
        batches.append(batch)
    missing = sorted(known - seen)
    if missing:
        raise ScenarioValidationError(
            "stages: every action must be scheduled exactly once; missing: "
            + ", ".join(sc.action_ids[i] for i in missing)
        )

    # Each ended stage must itself be a legally executable batch. A plan
    # returned by /plans always is; an arbitrary plan that schedules an
    # action outside its allowed_stages (or a contradictory add/remove pair)
    # has no meaningful interruption semantics and is rejected.
    for num, batch in enumerate(batches, start=1):
        bits = 0
        for i in batch:
            bits |= 1 << i
            if num not in sc.allowed[i]:
                raise ScenarioValidationError(
                    f"stages: action '{sc.action_ids[i]}' is scheduled at "
                    f"stage {num} which is outside its allowed_stages"
                )
        if batch_conflict(sc, bits) is not None:
            raise ScenarioValidationError(
                f"stages: stage {num} schedules an add_trust and a "
                f"remove_trust on the same anchor together"
            )
    return batches


def _known_clients(req: ReconcileRequest) -> set[str]:
    clients = {r.client_id for r in req.relationships}
    clients.update(a.client_id for a in req.trust_anchors)
    for act in req.actions:
        if act.type in ("add_trust", "remove_trust"):
            clients.add(act.client_id)
    return clients


def _validate_observations(sc: Scenario, req: ReconcileRequest) -> None:
    clients = _known_clients(req)
    for obs in req.anchor_observations:
        if obs.client_id not in clients:
            raise ScenarioValidationError(
                f"anchor_observations: unknown client_id "
                f"'{obs.client_id}'"
            )
        if obs.anchor_cert_id not in sc.certs:
            raise ScenarioValidationError(
                f"anchor_observations: unknown certificate "
                f"'{obs.anchor_cert_id}'"
            )
    for obs in req.chain_observations:
        if obs.endpoint_id not in sc.endpoint_chains:
            raise ScenarioValidationError(
                f"chain_observations: unknown endpoint_id "
                f"'{obs.endpoint_id}'"
            )
        for cid in obs.chain:
            if cid not in sc.certs:
                raise ScenarioValidationError(
                    f"chain_observations: unknown certificate '{cid}' in "
                    f"observed chain of endpoint '{obs.endpoint_id}'"
                )


# ---------------------------------------------------------------------------
# Plan-ordered reachable states
# ---------------------------------------------------------------------------


def _subsets(bits: int) -> list[int]:
    """All submasks of ``bits`` (including 0), numeric (thus stable) order."""
    out: list[int] = []
    sub = bits
    while True:
        out.append(sub)
        if sub == 0:
            break
        sub = (sub - 1) & bits
    return list(reversed(out))


def _legal_partial_masks(
    sc: Scenario, batch_bits: int, stage: int
) -> list[int]:
    """Subsets of one stage's actions that could really have partially run.

    Every action must be authorized at this absolute stage number and the
    partial batch must not contain a contradictory add/remove pair on one
    trust edge. Plans returned by /plans satisfy both for the full batch, so
    this only trims states that could never occur under a malformed plan.
    """
    eligible = 0
    for i in range(sc.n):
        if (batch_bits >> i & 1) and stage in sc.allowed[i]:
            eligible |= 1 << i
    return [
        sub
        for sub in _subsets(eligible)
        if batch_conflict(sc, sub) is None
    ]


def _reachable_progress(
    sc: Scenario, batches: list[list[int]]
) -> list[tuple[int, int]]:
    """Every reachable ``(executed-action mask, completed-stage count)`` pair.

    The pair — not the mask alone — is the progress identity: ended empty
    stages advance the completed-stage count without adding bits, so one
    physical mask can be reached at several stage positions (before a no-op
    gap, after it, between consecutive gaps). Each position across a no-op
    stage is a distinct progress and is kept separately; collapsing it onto
    the larger count would assert that the empty stage was crossed even
    though no observation can ever show that.

    A non-empty current stage whose actions have *all* executed, by
    contrast, is the same bookkeeping point as "that stage ended while the
    next one has not started" — that pair is enumerated at ``p + 1`` with
    the empty partial subset (or as the final pair). The crossed boundary
    leaves no unexecuted action behind, so the canonical position advances
    and the duplicate full-subset pair is omitted.
    """
    batch_bits = [0] * len(batches)
    for num, batch in enumerate(batches):
        for i in batch:
            batch_bits[num] |= 1 << i

    ended = [0] * (len(batches) + 1)
    for p in range(1, len(batches) + 1):
        ended[p] = ended[p - 1] | batch_bits[p - 1]

    reachable: list[tuple[int, int]] = []
    for p in range(len(batches) + 1):
        prefix = ended[p]
        if p < len(batches):
            # Current stage p+1: any legal subset of its actions may have run.
            full_batch = batch_bits[p]
            for sub in _legal_partial_masks(sc, full_batch, p + 1):
                # A fully executed NON-EMPTY current stage is canonicalized
                # to the ended position, which is enumerated at p + 1 (empty
                # partial subset there, or the final pair when p + 1 is the
                # last stage). An empty current stage (full_batch == 0) keeps
                # both sides of the no-op gap.
                if full_batch and sub == full_batch:
                    continue
                reachable.append((prefix | sub, p))
        else:
            # All stages have ended; the full mask is the only state left.
            reachable.append((prefix, p))
    return reachable


# ---------------------------------------------------------------------------
# Observation matching
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Observation:
    kind: str  # "anchor" | "endpoint_chain"
    sort_key: tuple
    anchor: Optional[ReconcileAnchorObservation] = None
    chain: Optional[ReconcileChainObservation] = None

    def matches(self, state: TrustState) -> bool:
        if self.kind == "anchor":
            assert self.anchor is not None
            edge = TrustEdge(
                self.anchor.client_id, self.anchor.anchor_cert_id
            )
            return (edge in state.anchors) == self.anchor.present
        assert self.chain is not None
        return state.chains[self.chain.endpoint_id] == list(self.chain.chain)


def _ordered_observations(
    req: ReconcileRequest,
) -> list[_Observation]:
    """Deterministic scan order: anchors first, then endpoint chains."""
    obs: list[_Observation] = []
    for a in sorted(
        req.anchor_observations,
        key=lambda o: (o.client_id, o.anchor_cert_id),
    ):
        obs.append(
            _Observation(
                kind="anchor",
                sort_key=(0, a.client_id, a.anchor_cert_id, ""),
                anchor=a,
            )
        )
    for c in sorted(req.chain_observations, key=lambda o: o.endpoint_id):
        obs.append(
            _Observation(
                kind="endpoint_chain",
                sort_key=(1, "", "", c.endpoint_id),
                chain=c,
            )
        )
    return obs


def _conflict_dto(obs: _Observation) -> ReconcileConflictObservation:
    if obs.kind == "anchor":
        a = obs.anchor
        assert a is not None
        reason = (
            "anchor_present_mismatch" if a.present
            else "anchor_absent_mismatch"
        )
        relation = "trusted" if a.present else "not trusted"
        message = (
            f"observed trust edge ({a.client_id}, {a.anchor_cert_id}) with "
            f"present={'true' if a.present else 'false'}: no plan-ordered "
            f"healthy state consistent with the preceding observations has "
            f"that anchor {relation}"
        )
        return ReconcileConflictObservation(
            kind="anchor",
            client_id=a.client_id,
            anchor_cert_id=a.anchor_cert_id,
            present=a.present,
            reason=reason,
            message=message,
        )
    c = obs.chain
    assert c is not None
    message = (
        f"observed chain on endpoint '{c.endpoint_id}' "
        f"[{' -> '.join(c.chain)}] is not served in any plan-ordered healthy "
        f"state consistent with the preceding observations"
    )
    return ReconcileConflictObservation(
        kind="endpoint_chain",
        endpoint_id=c.endpoint_id,
        chain=list(c.chain),
        reason="endpoint_chain_mismatch",
        message=message,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def reconcile(req: ReconcileRequest) -> ReconcileResult | ReconcileConflict:
    sc = build_scenario(req)
    batches = _plan_batches(sc, req)
    _validate_observations(sc, req)

    reachable = _reachable_progress(sc, batches)

    state_cache: dict[int, TrustState] = {}

    def state_for(mask: int) -> TrustState:
        st = state_cache.get(mask)
        if st is None:
            st = state_for_mask(sc, mask)
            state_cache[mask] = st
        return st

    # A deployment may only resume from a state in which no communication
    # relationship has already been destroyed. Candidates keep the full
    # (mask, completed-stage count) identity: two progresses that share a
    # mask across a no-op gap are filtered independently.
    candidates = {
        (mask, completed)
        for mask, completed in reachable
        if first_broken_relationship(sc, state_for(mask)) is None
    }
    if not candidates:
        return ReconcileConflict(
            reason="no_safe_reachable_state",
            message=(
                "every plan-ordered state (including the initial one) breaks "
                "a communication relationship; there is no safe point to "
                "resume from"
            ),
            conflicts=[],
        )

    # Greedy first-incompatible cut over a fixed observation order: each
    # observation that contradicts *all* states surviving the preceding ones
    # is reported; unknown (unreported) objects never participate.
    conflicts: list[_Observation] = []
    for obs in _ordered_observations(req):
        surviving = {
            (mask, completed)
            for mask, completed in candidates
            if obs.matches(state_for(mask))
        }
        if surviving:
            candidates = surviving
        else:
            conflicts.append(obs)

    if conflicts:
        dtos = [_conflict_dto(o) for o in conflicts]
        return ReconcileConflict(
            reason="observation_conflict",
            message=(
                "the observations rule out every plan-ordered healthy "
                "state; listed observations are the first-incompatible cut "
                "in stable order"
            ),
            conflicts=dtos,
        )

    progress: list[ReconcileProgress] = []
    keys: list[tuple[int, tuple[int, ...]]] = []
    for mask, completed in candidates:
        done = tuple(i for i in range(sc.n) if mask >> i & 1)
        keys.append((completed, done))
    for completed, done in sorted(keys):
        current_stage: Optional[int]
        if completed >= len(batches):
            # Completion is a property of the full progress identity: every
            # stage (including trailing no-op gaps) has ended. A finished
            # action set with stages still open is not complete yet.
            current_stage = None
        else:
            current_stage = completed + 1
        progress.append(
            ReconcileProgress(
                completed_stages=completed,
                current_stage=current_stage,
                completed_action_ids=[sc.action_ids[i] for i in done],
            )
        )

    # Conservative safe-next test: the action must be current-stage, pending
    # and singleton-safe in EVERY surviving possible progress — including
    # same-mask progresses sitting on either side of a no-op gap.
    safe: list[str] = []
    batch_sets = [set(b) for b in batches]
    for i in range(sc.n):
        bit = 1 << i
        keep = True
        for mask, completed in candidates:
            if completed >= len(batches):
                keep = False  # nothing left to do in a finished deployment
                break
            if i not in batch_sets[completed]:
                keep = False  # belongs to a later (or no) stage here
                break
            if mask & bit:
                keep = False  # may already have executed in this state
                break
            if completed + 1 not in sc.allowed[i]:
                keep = False  # not authorized at this absolute stage
                break
            if first_broken_relationship(
                sc, state_for(mask | bit)
            ) is not None:
                keep = False  # applying it alone breaks communication
                break
        if keep:
            safe.append(sc.action_ids[i])

    return ReconcileResult(
        safe_next_actions=safe,
        possible_progress=progress,
    )
