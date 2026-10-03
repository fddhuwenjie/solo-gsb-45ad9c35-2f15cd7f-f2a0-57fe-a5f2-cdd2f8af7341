"""Core planning engine: validation, trust-path evaluation and stage search."""
from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Optional

from .models import (
    AddTrustAction,
    PlanRequest,
    RemoveTrustAction,
    ReplaceCertAction,
)


class ScenarioValidationError(ValueError):
    """Semantic validation failure (mapped to HTTP 422)."""


# ---------------------------------------------------------------------------
# Validated scenario
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CertInfo:
    cert_id: str
    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime


@dataclass(frozen=True)
class Rel:
    client_id: str
    endpoint_id: str


@dataclass(frozen=True)
class TrustEdge:
    client_id: str
    cert_id: str


@dataclass
class Scenario:
    plan_time: datetime
    certs: dict[str, CertInfo]
    initial_anchors: frozenset[TrustEdge]
    endpoint_chains: dict[str, list[str]]          # endpoint -> current chain
    target_chains: dict[str, list[str]]
    relationships: list[Rel]
    # actions sorted lexicographically by action_id (bit index = list index)
    action_ids: list[str]
    add_edges: dict[int, TrustEdge]
    remove_edges: dict[int, TrustEdge]
    replace_endpoint: dict[int, str]
    allowed: list[frozenset[int]]
    allowed_sorted: list[list[int]]
    n: int
    # largest absolute stage number any action is eligible for (0 when the
    # scenario defines no actions); nothing useful can happen past this stage
    max_stage: int

    # derived
    conflict_pairs: list[tuple[int, int]] = field(default_factory=list)


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _validate_chain(
    chain: Iterable[str],
    certs: dict[str, CertInfo],
    where: str,
    plan_time: datetime,
) -> None:
    ids = list(chain)
    if len(set(ids)) != len(ids):
        raise ScenarioValidationError(
            f"{where}: certificate chain must not contain a certificate more "
            f"than once (chains with cycles are rejected)"
        )
    for cid in ids:
        cert = certs.get(cid)
        if cert is None:
            raise ScenarioValidationError(f"{where}: unknown certificate '{cid}'")
    for idx, cid in enumerate(ids):
        cert = certs[cid]
        if not (cert.not_before <= plan_time <= cert.not_after):
            raise ScenarioValidationError(
                f"{where}: certificate '{cid}' is not valid at plan_time "
                f"{plan_time.isoformat()} (valid "
                f"{cert.not_before.isoformat()}..{cert.not_after.isoformat()})"
            )
        if idx == len(ids) - 1:
            if cert.issuer != cert.subject:
                raise ScenarioValidationError(
                    f"{where}: chain must end at a self-signed root, but "
                    f"'{cid}' is not self-signed (subject='{cert.subject}', "
                    f"issuer='{cert.issuer}')"
                )
        else:
            nxt = certs[ids[idx + 1]]
            if cert.issuer != nxt.subject:
                raise ScenarioValidationError(
                    f"{where}: issuer mismatch at '{cid}' -> '{ids[idx + 1]}' "
                    f"(issuer '{cert.issuer}' != subject '{nxt.subject}')"
                )
            if nxt.issuer == nxt.subject and idx + 1 != len(ids) - 1:
                # defensive: unreachable because links below would still be
                # checked, but keeps the intent explicit
                raise ScenarioValidationError(
                    f"{where}: self-signed certificate '{nxt.cert_id}' cannot "
                    f"be an intermediate certificate"
                )


def build_scenario(req: PlanRequest) -> Scenario:
    plan_time = _as_utc(req.plan_time) if req.plan_time else datetime.now(timezone.utc)

    # --- certificates -------------------------------------------------------
    if len({c.cert_id for c in req.certificates}) != len(req.certificates):
        raise ScenarioValidationError("certificates: cert_id values must be unique")
    certs: dict[str, CertInfo] = {}
    for c in req.certificates:
        if c.not_valid_after <= c.not_valid_before:
            raise ScenarioValidationError(
                f"certificates: '{c.cert_id}' has an empty validity interval "
                f"(not_valid_after must be after not_valid_before)"
            )
        certs[c.cert_id] = CertInfo(
            cert_id=c.cert_id,
            subject=c.subject,
            issuer=c.issuer,
            not_before=_as_utc(c.not_valid_before),
            not_after=_as_utc(c.not_valid_after),
        )
    # Every declared certificate must be live at the planning instant —
    # including ones referenced only as trust anchors or target chains.
    for c in certs.values():
        if not (c.not_before <= plan_time <= c.not_after):
            raise ScenarioValidationError(
                f"certificates: '{c.cert_id}' is not valid at plan_time "
                f"{plan_time.isoformat()} (valid "
                f"{c.not_before.isoformat()}..{c.not_after.isoformat()})"
            )

    # --- endpoints ----------------------------------------------------------
    if len({e.endpoint_id for e in req.endpoints}) != len(req.endpoints):
        raise ScenarioValidationError("endpoints: endpoint_id values must be unique")
    endpoint_chains: dict[str, list[str]] = {}
    target_chains: dict[str, list[str]] = {}
    for e in req.endpoints:
        _validate_chain(e.current_chain, certs,
                        f"endpoints['{e.endpoint_id}'].current_chain", plan_time)
        _validate_chain(e.target_chain, certs,
                        f"endpoints['{e.endpoint_id}'].target_chain", plan_time)
        endpoint_chains[e.endpoint_id] = list(e.current_chain)
        target_chains[e.endpoint_id] = list(e.target_chain)

    # --- relationships ------------------------------------------------------
    rels: list[Rel] = []
    seen_rel: set[Rel] = set()
    for r in req.relationships:
        if r.endpoint_id not in endpoint_chains:
            raise ScenarioValidationError(
                f"relationships: unknown endpoint_id '{r.endpoint_id}'"
            )
        rel = Rel(r.client_id, r.endpoint_id)
        if rel in seen_rel:
            raise ScenarioValidationError(
                f"relationships: duplicate relationship "
                f"({r.client_id} -> {r.endpoint_id})"
            )
        seen_rel.add(rel)
        rels.append(rel)

    # --- initial anchors ----------------------------------------------------
    initial_anchors: set[TrustEdge] = set()
    for a in req.trust_anchors:
        if a.cert_id not in certs:
            raise ScenarioValidationError(
                f"trust_anchors: unknown certificate '{a.cert_id}'"
            )
        edge = TrustEdge(a.client_id, a.cert_id)
        if edge in initial_anchors:
            raise ScenarioValidationError(
                f"trust_anchors: duplicate anchor "
                f"({a.client_id}, {a.cert_id})"
            )
        initial_anchors.add(edge)

    # --- actions ------------------------------------------------------------
    if len({a.action_id for a in req.actions}) != len(req.actions):
        raise ScenarioValidationError("actions: action_id values must be unique")
    ordered = sorted(req.actions, key=lambda a: a.action_id)

    add_edges: dict[int, TrustEdge] = {}
    remove_edges: dict[int, TrustEdge] = {}
    replace_endpoint: dict[int, str] = {}

    replaces_by_endpoint: dict[str, int] = {}
    for idx, act in enumerate(ordered):
        if isinstance(act, AddTrustAction):
            if act.anchor_cert_id not in certs:
                raise ScenarioValidationError(
                    f"actions['{act.action_id}']: unknown anchor certificate "
                    f"'{act.anchor_cert_id}'"
                )
            add_edges[idx] = TrustEdge(act.client_id, act.anchor_cert_id)
        elif isinstance(act, RemoveTrustAction):
            if act.anchor_cert_id not in certs:
                raise ScenarioValidationError(
                    f"actions['{act.action_id}']: unknown anchor certificate "
                    f"'{act.anchor_cert_id}'"
                )
            remove_edges[idx] = TrustEdge(act.client_id, act.anchor_cert_id)
        elif isinstance(act, ReplaceCertAction):
            if act.endpoint_id not in endpoint_chains:
                raise ScenarioValidationError(
                    f"actions['{act.action_id}']: unknown endpoint "
                    f"'{act.endpoint_id}'"
                )
            _validate_chain(act.new_chain, certs,
                            f"actions['{act.action_id}'].new_chain", plan_time)
            if list(act.new_chain) != target_chains[act.endpoint_id]:
                raise ScenarioValidationError(
                    f"actions['{act.action_id}']: new_chain must equal the "
                    f"target_chain of endpoint '{act.endpoint_id}'"
                )
            if act.endpoint_id in replaces_by_endpoint:
                raise ScenarioValidationError(
                    f"actions['{act.action_id}']: endpoint "
                    f"'{act.endpoint_id}' already has a replace_cert action "
                    f"'{ordered[replaces_by_endpoint[act.endpoint_id]].action_id}'"
                )
            replaces_by_endpoint[act.endpoint_id] = idx
            replace_endpoint[idx] = act.endpoint_id

    allowed = [frozenset(a.allowed_stages) for a in ordered]
    allowed_sorted = [list(a.allowed_stages) for a in ordered]
    max_stage = max(
        (a.allowed_stages[-1] for a in ordered), default=0
    )

    # An add_trust and a remove_trust on the same trust edge scheduled in the
    # same stage have no order-independent result; such batches are forbidden.
    edge_to_adds: dict[TrustEdge, list[int]] = {}
    edge_to_removes: dict[TrustEdge, list[int]] = {}
    for i, e in add_edges.items():
        edge_to_adds.setdefault(e, []).append(i)
    for i, e in remove_edges.items():
        edge_to_removes.setdefault(e, []).append(i)
    conflict_pairs: list[tuple[int, int]] = []
    for e, adds in edge_to_adds.items():
        for ai in adds:
            for ri in edge_to_removes.get(e, []):
                conflict_pairs.append((min(ai, ri), max(ai, ri)))

    return Scenario(
        plan_time=plan_time,
        certs=certs,
        initial_anchors=frozenset(initial_anchors),
        endpoint_chains=endpoint_chains,
        target_chains=target_chains,
        relationships=rels,
        action_ids=[a.action_id for a in ordered],
        add_edges=add_edges,
        remove_edges=remove_edges,
        replace_endpoint=replace_endpoint,
        allowed=allowed,
        allowed_sorted=allowed_sorted,
        n=len(ordered),
        max_stage=max_stage,
        conflict_pairs=conflict_pairs,
    )


# ---------------------------------------------------------------------------
# Trust path evaluation
# ---------------------------------------------------------------------------


@dataclass
class TrustState:
    anchors: frozenset[TrustEdge]
    chains: dict[str, list[str]]


def initial_state(sc: Scenario) -> TrustState:
    return TrustState(
        anchors=sc.initial_anchors,
        chains={ep: list(ch) for ep, ch in sc.endpoint_chains.items()},
    )


def state_for_mask(sc: Scenario, mask: int) -> TrustState:
    anchors = set(sc.initial_anchors)
    chains = {ep: list(ch) for ep, ch in sc.endpoint_chains.items()}
    for i, edge in sc.add_edges.items():
        if mask >> i & 1:
            anchors.add(edge)
    for i, edge in sc.remove_edges.items():
        if mask >> i & 1:
            anchors.discard(edge)
    for i, ep in sc.replace_endpoint.items():
        if mask >> i & 1:
            chains[ep] = list(sc.target_chains[ep])
    return TrustState(anchors=frozenset(anchors), chains=chains)


@dataclass
class PathFailure:
    reason: str          # untrusted_root | issuer_mismatch
    chain: list[str]     # endpoint-presented chain (leaf-first)
    failure_index: int   # index of the cert where the walk broke
    trusted_anchors: list[str]


def evaluate_path(
    sc: Scenario, state: TrustState, client_id: str, endpoint_id: str
) -> Optional[PathFailure]:
    chain = state.chains[endpoint_id]
    trusted = {
        edge.cert_id for edge in state.anchors if edge.client_id == client_id
    }
    for idx, cid in enumerate(chain):
        cert = sc.certs[cid]
        if cid in trusted:
            return None  # reached a configured trust anchor
        if cert.issuer == cert.subject:
            # self-signed cert that the client does not trust
            return PathFailure("untrusted_root", list(chain), idx, sorted(trusted))
        if idx + 1 >= len(chain):
            return PathFailure("untrusted_root", list(chain), idx, sorted(trusted))
        nxt = sc.certs[chain[idx + 1]]
        if cert.issuer != nxt.subject:
            return PathFailure(
                "issuer_mismatch", list(chain), idx, sorted(trusted)
            )
    return PathFailure("untrusted_root", list(chain), 0, sorted(trusted))


def first_broken_relationship(
    sc: Scenario, state: TrustState
) -> Optional[tuple[int, PathFailure]]:
    """Return (relationship index, failure) for the first broken relationship."""
    for ridx, rel in enumerate(sc.relationships):
        failure = evaluate_path(sc, state, rel.client_id, rel.endpoint_id)
        if failure is not None:
            return ridx, failure
    return None


# ---------------------------------------------------------------------------
# Batch validation
# ---------------------------------------------------------------------------


def batch_conflict(sc: Scenario, batch: int) -> Optional[tuple[int, int]]:
    """Return an (i, j) add/remove pair on one edge inside one batch."""
    for i, j in sc.conflict_pairs:
        if (batch >> i & 1) and (batch >> j & 1):
            return i, j
    return None


# ---------------------------------------------------------------------------
# Solver: minimum-stage schedule, lexicographically smallest tie-break
#
# Stage numbers are absolute: an action may only be eligible at sparse, late
# stage numbers (e.g. its only allowed stage is 2). Such gaps are filled with
# explicit no-op stages at which the trust state is carried over unchanged,
# so every relationship stays valid after every real *and* empty stage.
# ---------------------------------------------------------------------------

INF = 10 ** 9


def _next_allowed_stage(
    allowed_sorted: list[list[int]], remaining: int, after: int
) -> Optional[int]:
    """Smallest stage > ``after`` allowed for any bit set in ``remaining``."""
    best: Optional[int] = None
    for i, stages in enumerate(allowed_sorted):
        if not (remaining >> i & 1):
            continue
        pos = bisect_right(stages, after)
        if pos < len(stages) and (best is None or stages[pos] < best):
            best = stages[pos]
    return best


@dataclass
class Solver:
    sc: Scenario
    good: list[bool] = field(default_factory=list)
    memo: dict[tuple[int, int], int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        size = 1 << self.sc.n
        self.good = [False] * size
        for mask in range(size):
            state = state_for_mask(self.sc, mask)
            self.good[mask] = first_broken_relationship(self.sc, state) is None

    # -- sparse stage helpers ------------------------------------------------

    def next_growth_stage(self, mask: int, stage: int) -> Optional[int]:
        """Earliest stage > ``stage`` at which an action that is *not*
        currently eligible becomes eligible.

        An empty (no-op) stage only helps when the set of actions that can
        run strictly grows: if it stays the same, anything executable later
        is executable now, so the gap can be deleted and the plan shortened.
        When nothing at all is eligible (a genuine sparse gap), this is
        simply the earliest stage any remaining action allows.
        """
        full = (1 << self.sc.n) - 1
        current = 0
        remaining = full ^ mask
        for i in range(self.sc.n):
            if remaining >> i & 1 and stage in self.sc.allowed[i]:
                current |= 1 << i
        new_only = remaining & ~current
        return _next_allowed_stage(self.sc.allowed_sorted, new_only, stage)

    # -- shortest completion -------------------------------------------------

    def finish(self, mask: int, stage: int) -> int:
        """Minimum absolute ending stage for completing from ``mask``.

        ``stage`` is the absolute 1-based number of the next stage to fill.
        The return value is the absolute stage number at which the final
        action executes (it is ``stage - 1`` when ``mask`` is already
        complete); INF means no completion exists. Empty stages (no action
        eligible at that stage number) are no-ops that carry the trust state
        unchanged; they are jumped over in one step instead of enumerated.
        """
        full = (1 << self.sc.n) - 1
        if mask == full:
            return stage - 1
        if stage > self.sc.max_stage:
            return INF
        key = (mask, stage)
        if key in self.memo:
            return self.memo[key]

        sc = self.sc
        remaining = full ^ mask
        available = 0
        for i in range(sc.n):
            if (remaining >> i & 1) and stage in sc.allowed[i]:
                available |= 1 << i

        best = INF
        sub = available
        while sub:
            if batch_conflict(sc, sub) is None and self.good[mask | sub]:
                best = min(best, self.finish(mask | sub, stage + 1))
                # stage is the earliest possible ending stage; once reached,
                # no other batch (or a no-op gap) can improve the result.
                if best == stage:
                    self.memo[key] = best
                    return best
            sub = (sub - 1) & available

        # No-op option: carry the state unchanged over empty stages. It is
        # worth taking only up to the next stage at which the eligible-action
        # set grows — either a genuine sparse gap (nothing eligible here) or a
        # currently-ineligible action that, once it joins, makes a safe joint
        # batch possible. Landing anywhere earlier sees an identical eligible
        # set and is dominated, which also bounds the search to O(n) change
        # points per mask even when allowed_stages span huge numbers.
        nxt = self.next_growth_stage(mask, stage)
        if nxt is not None and (best == INF or nxt < best) and self.good[mask]:
            best = min(best, self.finish(mask, nxt))

        self.memo[key] = best
        return best

    # -- lexicographically smallest minimum schedule -------------------------

    def solve(self) -> list[list[int]]:
        full = (1 << self.sc.n) - 1
        k = self.finish(0, 1)
        if k >= INF:
            return []
        stages: list[list[int]] = []
        mask = 0
        stage = 1
        while mask != full and stage <= self.sc.max_stage:
            remaining = full ^ mask
            available = 0
            for i in range(self.sc.n):
                if (remaining >> i & 1) and stage in self.sc.allowed[i]:
                    available |= 1 << i

            chosen = 0
            decided = 0
            for i in range(self.sc.n):
                bit = 1 << i
                if not (available & bit) or (decided & bit):
                    continue
                decided |= bit
                must_include = chosen | bit
                optional = available & ~(mask | decided | chosen)
                exists = False
                t = optional
                while True:
                    cand = must_include | t
                    nxt_mask = mask | cand
                    if (
                        batch_conflict(self.sc, cand) is None
                        and self.good[nxt_mask]
                    ):
                        # finish() returns an absolute ending stage; k is the
                        # globally optimal one, so compare directly.
                        if self.finish(nxt_mask, stage + 1) <= k:
                            exists = True
                            break
                    if t == 0:
                        break
                    t = (t - 1) & optional
                if exists:
                    chosen = must_include
            if chosen == 0:
                # No eligible action can belong to an optimal completion at
                # this stage: either nothing is eligible (a sparse gap) or
                # every eligible batch would break a relationship and the
                # safe joint batch only forms once more actions become
                # eligible. Emit explicit no-op stages up to that growth point
                # while it still fits the minimum-stage budget.
                nxt = self.next_growth_stage(mask, stage)
                if nxt is None or self.finish(mask, nxt) > k:
                    return []  # should be unreachable when finish() found k
                while stage < nxt:
                    stages.append([])
                    stage += 1
                continue
            stages.append([i for i in range(self.sc.n) if chosen >> i & 1])
            mask |= chosen
            stage += 1
        if mask != full:
            return []
        return stages


# ---------------------------------------------------------------------------
# Replay / diagnostics shared by /plans infeasibility and /plans/verify
# ---------------------------------------------------------------------------


@dataclass
class ReplayFailure:
    stage: int
    relationship_index: int
    blocking_action_index: Optional[int]
    reason: str
    chain: list[str]
    failure_index: int
    trusted_anchors: list[str]


def _blocking_action_for_bad_batch(
    sc: Scenario,
    state: TrustState,
    batch: list[int],
    target_ridx: int,
) -> Optional[int]:
    """First action (lex order) after which relationship target_ridx is bad."""
    cur = TrustState(anchors=state.anchors, chains=dict(state.chains))
    rel = sc.relationships[target_ridx]
    for i in batch:
        if i in sc.add_edges:
            cur = TrustState(cur.anchors | {sc.add_edges[i]}, cur.chains)
        elif i in sc.remove_edges:
            cur = TrustState(cur.anchors - {sc.remove_edges[i]}, cur.chains)
        else:
            ep = sc.replace_endpoint[i]
            chains = dict(cur.chains)
            chains[ep] = list(sc.target_chains[ep])
            cur = TrustState(cur.anchors, chains)
        failure = evaluate_path(sc, cur, rel.client_id, rel.endpoint_id)
        if failure is not None:
            return i
    return None


def state_for_mask_applied(
    sc: Scenario, state: TrustState, batch_bits: int
) -> TrustState:
    anchors = set(state.anchors)
    chains = dict(state.chains)
    for i, edge in sc.add_edges.items():
        if batch_bits >> i & 1:
            anchors.add(edge)
    for i, edge in sc.remove_edges.items():
        if batch_bits >> i & 1:
            anchors.discard(edge)
    for i, ep in sc.replace_endpoint.items():
        if batch_bits >> i & 1:
            chains[ep] = list(sc.target_chains[ep])
    return TrustState(anchors=frozenset(anchors), chains=chains)


def check_batch(
    sc: Scenario,
    state: TrustState,
    batch_bits: int,
    stage: int,
) -> Optional[ReplayFailure]:
    """Validate one replayed stage; return the first failure or None."""
    # 1. allowed_stages
    ordered_actions = [
        i for i in range(sc.n) if batch_bits >> i & 1
    ]
    for i in ordered_actions:
        if stage not in sc.allowed[i]:
            # no relationship-specific chain; attach the first relationship
            ridx = 0
            rel = sc.relationships[ridx]
            failure = evaluate_path(sc, state, rel.client_id, rel.endpoint_id)
            chain = failure.chain if failure else list(state.chains[rel.endpoint_id])
            fidx = failure.failure_index if failure else 0
            anchors = (
                failure.trusted_anchors
                if failure
                else sorted(e.cert_id for e in state.anchors if e.client_id == rel.client_id)
            )
            return ReplayFailure(
                stage=stage,
                relationship_index=ridx,
                blocking_action_index=i,
                reason="action_not_allowed_at_stage",
                chain=chain,
                failure_index=fidx,
                trusted_anchors=anchors,
            )

    # 2. contradictory add/remove in one stage
    conflict = batch_conflict(sc, batch_bits)
    if conflict is not None:
        i, j = conflict
        blocker = max(i, j)  # the later (lex) action completes the contradiction
        ridx = 0
        rel = sc.relationships[ridx]
        failure = evaluate_path(sc, state, rel.client_id, rel.endpoint_id)
        chain = failure.chain if failure else list(state.chains[rel.endpoint_id])
        fidx = failure.failure_index if failure else 0
        anchors = (
            failure.trusted_anchors
            if failure
            else sorted(e.cert_id for e in state.anchors if e.client_id == rel.client_id)
        )
        return ReplayFailure(
            stage=stage,
            relationship_index=ridx,
            blocking_action_index=blocker,
            reason="contradictory_actions_same_stage",
            chain=chain,
            failure_index=fidx,
            trusted_anchors=anchors,
        )

    # 3. end-of-state trust paths
    end_state = state_for_mask_applied(sc, state, batch_bits)
    broken = first_broken_relationship(sc, end_state)
    if broken is not None:
        ridx, failure = broken
        blocker = _blocking_action_for_bad_batch(
            sc, state, ordered_actions, ridx
        )
        return ReplayFailure(
            stage=stage,
            relationship_index=ridx,
            blocking_action_index=blocker,
            reason=failure.reason,
            chain=failure.chain,
            failure_index=failure.failure_index,
            trusted_anchors=failure.trusted_anchors,
        )
    return None


def _no_eligible_failure(
    sc: Scenario, state: TrustState, stage: int
) -> ReplayFailure:
    """Diagnostic for a stage at which no remaining action can execute."""
    ridx = 0
    rel = sc.relationships[ridx]
    failure = evaluate_path(sc, state, rel.client_id, rel.endpoint_id)
    chain = failure.chain if failure else list(state.chains[rel.endpoint_id])
    fidx = failure.failure_index if failure else 0
    anchors = (
        failure.trusted_anchors
        if failure
        else sorted(e.cert_id for e in state.anchors if e.client_id == rel.client_id)
    )
    return ReplayFailure(
        stage=stage,
        relationship_index=ridx,
        blocking_action_index=None,
        reason="no_eligible_actions_at_stage",
        chain=chain,
        failure_index=fidx,
        trusted_anchors=anchors,
    )


def eager_failure(sc: Scenario) -> ReplayFailure:
    """Replay the canonical eager schedule and return its first failure.

    Every action is placed in the smallest stage number it allows. Stages at
    which no remaining action is eligible are legal no-op gaps (the trust
    state simply carries over unchanged) and are skipped; the replay only
    stops when actions remain but none is eligible at *any* later stage, or
    when an eager batch breaks a relationship. This replay is a concrete valid
    schedule whenever the instance is feasible, so on an infeasible instance it
    deterministically locates the first relationship that cannot be maintained
    and the blocking action.
    """
    state = initial_state(sc)
    broken = first_broken_relationship(sc, state)
    if broken is not None:
        ridx, failure = broken
        return ReplayFailure(
            stage=0,
            relationship_index=ridx,
            blocking_action_index=None,
            reason=failure.reason,
            chain=failure.chain,
            failure_index=failure.failure_index,
            trusted_anchors=failure.trusted_anchors,
        )

    placed = 0
    full = (1 << sc.n) - 1
    stage = 1
    while placed != full:
        batch = 0
        for i in range(sc.n):
            if not (placed >> i & 1) and stage in sc.allowed[i]:
                batch |= 1 << i
        if batch == 0:
            # No action is eligible at this absolute stage: skip the legal
            # no-op gap and continue at the earliest stage some remaining
            # action allows. Only give up when no such stage exists at all.
            nxt = _next_allowed_stage(
                sc.allowed_sorted, full ^ placed, stage
            )
            if nxt is None:
                return _no_eligible_failure(sc, state, stage)
            stage = nxt
            continue
        failure = check_batch(sc, state, batch, stage)
        if failure is not None:
            return failure
        state = state_for_mask_applied(sc, state, batch)
        placed |= batch
        stage += 1
    # Unreachable for an infeasible instance; defensive guard.
    raise RuntimeError("eager replay unexpectedly succeeded")
