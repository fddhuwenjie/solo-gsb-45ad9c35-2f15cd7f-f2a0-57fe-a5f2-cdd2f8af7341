"""Safe continuation planning after a mid-rotation certificate revocation.

``POST /plans/replan`` answers: the rotation plan computed by ``/plans`` is
partially executed when offline revocation evidence (fresh ``revoked``
verdicts, or an unresolved fresh good/revoked conflict) taints the chain an
endpoint currently serves or the chain it was supposed to rotate to. Given
the original ``PlanRequest``, the actions that have definitely completed, the
chains the endpoints serve right now, up to twelve candidate replacement
chains per endpoint and the corresponding offline revocation evidence,
compute a minimum-stage continuation that finishes the remaining actions
without ever breaking a communication relationship.

The completed prefix is **non-revertible**: its trust-anchor effects (and the
chain switch of every completed ``replace_cert``) are applied to the
resumption state and never planned around. Chains containing a certificate
with fresh revoked evidence — or with a fresh good/revoked conflict — are
filtered out: a tainted *current* chain must be rotated away from, and
tainted *target/candidate* chains are never deployed. Each pending
``replace_cert`` action is re-targeted to one of the endpoint's clean chains
(the declared ``target_chain`` plus the candidates); every other remaining
action keeps its declaration. Continuation stages are numbered from 1 and
each remaining action's ``allowed_stages`` apply to that numbering, exactly
as if the continuation were a fresh ``/plans`` request (sparse stage numbers
produce explicit no-op stages).

Ties are broken stably: fewest stages first, then the per-action stage vector
in ``action_id`` order (the ``/plans`` rule), then the chosen chains'
complete fingerprints ordered by endpoint. When no continuation exists, the
response names the first relationship that cannot be maintained, the blocking
certificate and a machine-readable reason.
"""
from __future__ import annotations

from itertools import product
from typing import Optional

from .engine import (
    INF,
    ReplayFailure,
    Scenario,
    ScenarioValidationError,
    Solver,
    TrustEdge,
    TrustState,
    _validate_chain,
    build_scenario,
    eager_failure,
    first_broken_relationship,
)
from .models import (
    ChainCert,
    PlannedStage,
    RelationshipRef,
    ReplanChainSelection,
    ReplanExcludedChain,
    ReplanFailure,
    ReplanRequest,
    ReplanSuccess,
)

# Chain-level exclusion reasons.
_REVOKED = "certificate_revoked"
_CONFLICT = "conflicting_evidence"

# Path-level failure reasons for which the certificate at the break point is
# the meaningful blocking certificate (action-level reasons carry none).
_PATH_REASONS = {"untrusted_root", "issuer_mismatch"}


# ---------------------------------------------------------------------------
# DTO helpers
# ---------------------------------------------------------------------------


def _chain_dto(sc: Scenario, chain: list[str]) -> list[ChainCert]:
    return [
        ChainCert(
            cert_id=cid,
            subject=sc.certs[cid].subject,
            issuer=sc.certs[cid].issuer,
        )
        for cid in chain
    ]


def _path_message(prefix: str, sc: Scenario, ridx: int, reason: str,
                  chain: list[str], failure_index: int,
                  trusted_anchors: list[str]) -> str:
    rel = sc.relationships[ridx]
    who = f"relationship {rel.client_id} -> {rel.endpoint_id}"
    if reason == "untrusted_root":
        broken = chain[failure_index]
        return (
            f"{prefix}: {who} loses its trust path; chain terminates at "
            f"'{broken}', which is not among the client's trust anchors "
            f"({', '.join(trusted_anchors) or 'none'})"
        )
    if reason == "issuer_mismatch":
        broken = chain[failure_index]
        nxt = chain[failure_index + 1]
        return (
            f"{prefix}: {who} chain breaks at '{broken}' -> '{nxt}': "
            f"issuer/subject mismatch"
        )
    return f"{prefix}: {who} invalid ({reason})"


def _replay_message(sc: Scenario, rf: ReplayFailure) -> str:
    prefix = (
        "resumption state already invalid"
        if rf.stage == 0
        else f"continuation stage {rf.stage}"
    )
    if rf.reason in _PATH_REASONS:
        return _path_message(
            prefix, sc, rf.relationship_index, rf.reason, rf.chain,
            rf.failure_index, rf.trusted_anchors,
        )
    rel = sc.relationships[rf.relationship_index]
    who = f"relationship {rel.client_id} -> {rel.endpoint_id}"
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
    if rf.reason == "no_eligible_actions_at_stage":
        return (
            f"{prefix}: remaining actions are not allowed at this stage; "
            f"{who} cannot be maintained"
        )
    return f"{prefix}: {who} invalid ({rf.reason})"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def replan(req: ReplanRequest) -> ReplanSuccess | ReplanFailure:
    sc = build_scenario(req)

    # -- completed prefix: non-revertible, applied to the resumption state ---
    index = {aid: i for i, aid in enumerate(sc.action_ids)}
    completed = 0
    for aid in req.completed_action_ids:
        i = index.get(aid)
        if i is None:
            raise ScenarioValidationError(
                f"completed_action_ids: unknown action_id '{aid}'"
            )
        completed |= 1 << i

    anchors: set[TrustEdge] = set(sc.initial_anchors)
    for i, edge in sc.add_edges.items():
        if completed >> i & 1:
            anchors.add(edge)
    for i, edge in sc.remove_edges.items():
        if completed >> i & 1:
            anchors.discard(edge)

    # -- live chains ----------------------------------------------------------
    live: dict[str, list[str]] = {}
    for obs in req.live_chains:
        if obs.endpoint_id not in sc.endpoint_chains:
            raise ScenarioValidationError(
                f"live_chains: unknown endpoint_id '{obs.endpoint_id}'"
            )
        _validate_chain(obs.chain, sc.certs,
                        f"live_chains['{obs.endpoint_id}']", sc.plan_time)
        live[obs.endpoint_id] = list(obs.chain)

    replace_by_ep = {ep: i for i, ep in sc.replace_endpoint.items()}
    served: dict[str, list[str]] = {}
    for ep in sc.endpoint_chains:
        ridx = replace_by_ep.get(ep)
        if ridx is not None and completed >> ridx & 1:
            chain = list(sc.target_chains[ep])
            if ep in live and live[ep] != chain:
                raise ScenarioValidationError(
                    f"live_chains['{ep}']: the observed chain contradicts the "
                    f"completed replace_cert action '{sc.action_ids[ridx]}'; "
                    f"a completed replace_cert means the endpoint serves its "
                    f"target_chain"
                )
        elif ep in live:
            chain = live[ep]
        else:
            chain = list(sc.endpoint_chains[ep])
        served[ep] = chain

    # -- candidate replacement chains -----------------------------------------
    candidates: dict[str, set[tuple[str, ...]]] = {}
    for group in req.candidates:
        ep = group.endpoint_id
        if ep not in sc.endpoint_chains:
            raise ScenarioValidationError(
                f"candidates: unknown endpoint_id '{ep}'"
            )
        chains: set[tuple[str, ...]] = set()
        for pos, chain in enumerate(group.candidate_chains):
            where = f"candidates['{ep}'].candidate_chains[{pos}]"
            if not chain:
                raise ScenarioValidationError(
                    f"{where}: chain must not be empty"
                )
            _validate_chain(chain, sc.certs, where, sc.plan_time)
            chains.add(tuple(chain))
        candidates[ep] = chains

    # -- offline revocation evidence ------------------------------------------
    fresh_good: set[str] = set()
    fresh_revoked: set[str] = set()
    for item in req.revocation_evidence:
        if item.cert_id not in sc.certs:
            raise ScenarioValidationError(
                f"revocation_evidence: unknown certificate '{item.cert_id}'"
            )
        if not item.fresh:
            continue
        if item.status == "good":
            fresh_good.add(item.cert_id)
        elif item.status == "revoked":
            fresh_revoked.add(item.cert_id)
    # A certificate is tainted by fresh revoked evidence; a simultaneous fresh
    # good verdict makes the taint an unresolved conflict. Stale and unknown
    # items never taint.
    taint: dict[str, str] = {
        cid: (_CONFLICT if cid in fresh_good else _REVOKED)
        for cid in fresh_revoked
    }

    def chain_taint(chain) -> Optional[tuple[str, str]]:
        """(first tainted cert, its reason) for a chain, or None."""
        for cid in chain:
            reason = taint.get(cid)
            if reason is not None:
                return cid, reason
        return None

    # -- audit: every tainted current/target/candidate chain ------------------
    excluded: dict[tuple[str, tuple[str, ...]], ReplanExcludedChain] = {}

    def note_excluded(ep: str, chain, role: str) -> None:
        hit = chain_taint(chain)
        if hit is None:
            return
        key = (ep, tuple(chain))
        if key in excluded:
            return  # same chain already reported under an earlier role
        excluded[key] = ReplanExcludedChain(
            endpoint_id=ep,
            role=role,  # type: ignore[arg-type]
            chain=list(chain),
            blocking_certificate=hit[0],
            reason=hit[1],  # type: ignore[arg-type]
        )

    for ep in sc.endpoint_chains:
        note_excluded(ep, served[ep], "current")
        note_excluded(ep, sc.target_chains[ep], "target")
        for chain in sorted(candidates.get(ep, set())):
            note_excluded(ep, list(chain), "candidate")

    # -- remaining actions and clean replacement options ----------------------
    remaining = [i for i in range(sc.n) if not (completed >> i & 1)]
    pending_replace = {
        ep: i for ep, i in replace_by_ep.items()
        if not (completed >> i & 1)
    }
    clean_options: dict[str, list[tuple[str, ...]]] = {}
    for ep in pending_replace:
        raw = {tuple(sc.target_chains[ep])} | candidates.get(ep, set())
        clean_options[ep] = sorted(o for o in raw if chain_taint(o) is None)

    # -- the resumption state itself must keep every relationship -------------
    state0 = TrustState(
        anchors=frozenset(anchors),
        chains={ep: list(ch) for ep, ch in served.items()},
    )
    broken = first_broken_relationship(sc, state0)
    if broken is not None:
        ridx, pf = broken
        rel = sc.relationships[ridx]
        return ReplanFailure(
            status="invalid",
            stage=0,
            relationship=RelationshipRef(
                client_id=rel.client_id, endpoint_id=rel.endpoint_id
            ),
            blocking_action=None,
            blocking_certificate=pf.chain[pf.failure_index],
            reason=pf.reason,
            chain=_chain_dto(sc, pf.chain),
            trusted_anchors=pf.trusted_anchors,
            message=_path_message(
                "resumption state already invalid", sc, ridx, pf.reason,
                pf.chain, pf.failure_index, pf.trusted_anchors,
            ),
        )

    # -- revocation blocks: tainted chains no continuation can escape ---------
    def endpoint_block(ep: str):
        """(kind, chain, cert_id, reason, blocking_action) or None."""
        served_hit = chain_taint(served[ep])
        ridx = pending_replace.get(ep)
        options = clean_options.get(ep, [])
        if served_hit is not None and (ridx is None or not options):
            # The endpoint serves a tainted chain and no clean replacement
            # can ever be deployed (no pending replace_cert, or no clean
            # target/candidate chain left for it).
            return (
                "current", list(served[ep]), served_hit[0], served_hit[1],
                sc.action_ids[ridx] if ridx is not None else None,
            )
        if ridx is not None and not options:
            # The declared target and every candidate are tainted: the
            # pending replace_cert has no clean chain to deploy.
            hit = chain_taint(sc.target_chains[ep])
            assert hit is not None  # empty options imply a tainted target
            return (
                "target", list(sc.target_chains[ep]), hit[0], hit[1],
                sc.action_ids[ridx],
            )
        return None

    def block_failure(rel, ep: str, block) -> ReplanFailure:
        kind, chain, cid, reason, action_id = block
        verdict = (
            "has conflicting fresh good/revoked evidence"
            if reason == _CONFLICT
            else "is revoked by fresh evidence"
        )
        if kind == "current":
            message = (
                f"endpoint '{ep}' currently serves a chain in which '{cid}' "
                f"{verdict}; the continuation must rotate away from this "
                f"chain, but no clean replacement chain is available"
            )
        else:
            message = (
                f"every deployable chain for endpoint '{ep}' is tainted: the "
                f"declared target_chain and all candidate chains contain "
                f"certificates with fresh revoked or conflicting evidence "
                f"(first: '{cid}'); the pending replace_cert action "
                f"'{action_id}' has no clean chain to deploy"
            )
        return ReplanFailure(
            status="infeasible",
            stage=0,
            relationship=RelationshipRef(
                client_id=rel.client_id, endpoint_id=rel.endpoint_id
            ),
            blocking_action=action_id,
            blocking_certificate=cid,
            reason=reason,
            chain=_chain_dto(sc, chain),
            trusted_anchors=sorted(
                e.cert_id for e in anchors if e.client_id == rel.client_id
            ),
            message=message,
        )

    seen_eps: set[str] = set()
    for rel in sc.relationships:
        ep = rel.endpoint_id
        if ep in seen_eps:
            continue
        seen_eps.add(ep)
        block = endpoint_block(ep)
        if block is not None:
            return block_failure(rel, ep, block)
    # Endpoints no relationship references can still block plan completion;
    # report them against the first declared relationship.
    for ep in sc.endpoint_chains:
        if ep in seen_eps:
            continue
        block = endpoint_block(ep)
        if block is not None:
            return block_failure(sc.relationships[0], ep, block)

    # -- continuation solver over the remaining actions -----------------------
    # Anchors a client may trust at some point of the continuation: the
    # resumption anchors plus every remaining add_trust edge (removals only
    # shrink the set).
    possible: dict[str, set[str]] = {}
    for rel in sc.relationships:
        possible.setdefault(
            rel.client_id,
            {e.cert_id for e in anchors if e.client_id == rel.client_id},
        )
    for i in remaining:
        edge = sc.add_edges.get(i)
        if edge is not None:
            possible.setdefault(edge.client_id, set()).add(edge.cert_id)

    def signature(ep: str, chain: tuple[str, ...]) -> tuple:
        """Trust behaviour of a served chain in every reachable state.

        Two chains with the same signature hit exactly the same potential
        anchors of every related client, so they are interchangeable for
        scheduling; only the lexicographically smallest chain of a class can
        win the fingerprint tie-break.
        """
        certs_in_chain = set(chain)
        return tuple(
            (rel.client_id,
             frozenset(certs_in_chain & possible[rel.client_id]))
            for rel in sc.relationships
            if rel.endpoint_id == ep
        )

    pending_eps = sorted(pending_replace)
    class_options: dict[str, list[tuple[str, ...]]] = {}
    for ep in pending_eps:
        groups: dict[tuple, list[tuple[str, ...]]] = {}
        for chain in clean_options[ep]:
            groups.setdefault(signature(ep, chain), []).append(chain)
        class_options[ep] = sorted(
            min(members) for members in groups.values()
        )

    def continuation_scenario(override: dict[str, tuple[str, ...]]) -> Scenario:
        add_edges: dict[int, TrustEdge] = {}
        remove_edges: dict[int, TrustEdge] = {}
        replace_endpoint: dict[int, str] = {}
        for new_i, old_i in enumerate(remaining):
            if old_i in sc.add_edges:
                add_edges[new_i] = sc.add_edges[old_i]
            elif old_i in sc.remove_edges:
                remove_edges[new_i] = sc.remove_edges[old_i]
            elif old_i in sc.replace_endpoint:
                replace_endpoint[new_i] = sc.replace_endpoint[old_i]
        target_chains = {ep: list(ch) for ep, ch in sc.target_chains.items()}
        for ep, chain in override.items():
            target_chains[ep] = list(chain)
        edge_adds: dict[TrustEdge, list[int]] = {}
        edge_removes: dict[TrustEdge, list[int]] = {}
        for i, e in add_edges.items():
            edge_adds.setdefault(e, []).append(i)
        for i, e in remove_edges.items():
            edge_removes.setdefault(e, []).append(i)
        conflict_pairs: list[tuple[int, int]] = []
        for e, adds in edge_adds.items():
            for ai in adds:
                for ri in edge_removes.get(e, []):
                    conflict_pairs.append((min(ai, ri), max(ai, ri)))
        allowed = [sc.allowed[i] for i in remaining]
        allowed_sorted = [sc.allowed_sorted[i] for i in remaining]
        return Scenario(
            plan_time=sc.plan_time,
            certs=sc.certs,
            initial_anchors=frozenset(anchors),
            endpoint_chains={ep: list(ch) for ep, ch in served.items()},
            target_chains=target_chains,
            relationships=sc.relationships,
            action_ids=[sc.action_ids[i] for i in remaining],
            add_edges=add_edges,
            remove_edges=remove_edges,
            replace_endpoint=replace_endpoint,
            allowed=allowed,
            allowed_sorted=allowed_sorted,
            n=len(remaining),
            max_stage=max((s[-1] for s in allowed_sorted), default=0),
            conflict_pairs=conflict_pairs,
        )

    best_key: Optional[tuple] = None
    best: Optional[tuple[Scenario, list[list[int]], tuple]] = None
    first_sc2: Optional[Scenario] = None
    for combo in product(*(class_options[ep] for ep in pending_eps)):
        override = dict(zip(pending_eps, combo))
        sc2 = continuation_scenario(override)
        if first_sc2 is None:
            first_sc2 = sc2
        solver = Solver(sc2)
        if not solver.good[0]:
            continue  # unreachable: the resumption state was validated above
        k = solver.finish(0, 1)
        if k >= INF:
            continue
        batches = solver.solve()
        stage_of = [0] * sc2.n
        for num, batch in enumerate(batches, start=1):
            for i in batch:
                stage_of[i] = num
        # Stable adjudication: fewest stages, then the per-action stage
        # vector in action_id order, then the complete chain fingerprints
        # ordered by endpoint.
        key = (len(batches), tuple(stage_of), combo)
        if best_key is None or key < best_key:
            best_key = key
            best = (sc2, batches, combo)

    if best is not None:
        sc2, batches, combo = best
        stages = [
            PlannedStage(
                stage=num,
                action_ids=[sc2.action_ids[i] for i in batch],
            )
            for num, batch in enumerate(batches, start=1)
        ]
        chosen = dict(zip(pending_eps, combo))
        selections = [
            ReplanChainSelection(
                endpoint_id=ep,
                action_id=sc.action_ids[pending_replace[ep]],
                chain=list(chosen[ep]),
            )
            for ep in sorted(chosen)
        ]
        return ReplanSuccess(
            stage_count=len(batches),
            stages=stages,
            chain_selections=selections,
            excluded_chains=sorted(
                excluded.values(),
                key=lambda e: (e.endpoint_id, tuple(e.chain), e.role),
            ),
        )

    # -- no continuation exists: replay the canonical (lexicographically -----
    # smallest) chain choice for a deterministic first-failure diagnostic.
    assert first_sc2 is not None
    rf = eager_failure(first_sc2)
    rel = first_sc2.relationships[rf.relationship_index]
    blocking_certificate = (
        rf.chain[rf.failure_index]
        if rf.reason in _PATH_REASONS and rf.chain
        else None
    )
    return ReplanFailure(
        status="infeasible" if rf.stage > 0 else "invalid",
        stage=rf.stage,
        relationship=RelationshipRef(
            client_id=rel.client_id, endpoint_id=rel.endpoint_id
        ),
        blocking_action=(
            first_sc2.action_ids[rf.blocking_action_index]
            if rf.blocking_action_index is not None
            else None
        ),
        blocking_certificate=blocking_certificate,
        reason=rf.reason,
        chain=_chain_dto(sc, rf.chain),
        trusted_anchors=rf.trusted_anchors,
        message=_replay_message(first_sc2, rf),
    )
