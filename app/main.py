"""FastAPI application exposing the rotation planning endpoints."""
from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from .engine import (
    ReplayFailure,
    ScenarioValidationError,
    build_scenario,
    check_batch,
    eager_failure,
    initial_state,
    state_for_mask_applied,
)
from .models import (
    ChainCert,
    Failure,
    NormalizeErrorDetail,
    NormalizeRequest,
    NormalizeResult,
    OcspPrecheckRequest,
    OcspPrecheckResult,
    PlannedStage,
    PlanRequest,
    PlanSuccess,
    PolicyReviewErrorDetail,
    PolicyReviewRequest,
    PolicyReviewResult,
    PrecheckErrorDetail,
    PrecheckRequest,
    PrecheckResult,
    ReconcileConflict,
    ReconcileRequest,
    ReconcileResult,
    RelationshipRef,
    ReplanFailure,
    ReplanRequest,
    ReplanSuccess,
    RevocationReviewRequest,
    RevocationReviewResult,
    VariantSelectionErrorDetail,
    VariantSelectionConflict,
    VariantSelectionRequest,
    VariantSelectionResult,
)
from .normalize import NormalizeError, normalize_scenario
from .ocsp import ocsp_precheck
from .policy import policy_review
from .precheck import precheck_identities
from .reconcile import reconcile
from .replan import replan
from .revocation import revocation_review
from .variants import VariantSelectionError, select_variants


class _NormalizeErrorResponse(BaseModel):
    detail: NormalizeErrorDetail


class _PrecheckErrorResponse(BaseModel):
    detail: PrecheckErrorDetail


class _PolicyReviewErrorResponse(BaseModel):
    detail: PolicyReviewErrorDetail


class _VariantSelectionErrorResponse(BaseModel):
    detail: VariantSelectionErrorDetail

app = FastAPI(
    title="TLS Certificate Zero-Downtime Rotation Planner",
    version="1.0.0",
    description=(
        "Plan and verify zero-downtime TLS certificate rotations. After every "
        "stage, every required client→endpoint relationship must still have a "
        "valid trust path (a chain from the endpoint leaf to one of the "
        "client's trust anchors)."
    ),
)


@app.exception_handler(ScenarioValidationError)
async def _scenario_validation_handler(_request, exc: ScenarioValidationError):
    return JSONResponse(status_code=422, content={"detail": str(exc)})


@app.exception_handler(NormalizeError)
async def _normalize_error_handler(request, exc: NormalizeError):    # Both /scenarios/normalize and /deployments/precheck raise NormalizeError
    # (shared PEM/fingerprint/chain diagnostics); only the pre-check carries
    # identity_issues, so shape the detail per route.
    if request.url.path.startswith("/deployments/precheck"):
        detail = PrecheckErrorDetail(
            error=exc.error,
            message=exc.message,
            pem_issues=exc.pem_issues,
            fingerprint_issues=exc.fingerprint_issues,
            chain_issues=exc.chain_issues,
            identity_issues=getattr(exc, "identity_issues", []),
        )
    elif request.url.path.startswith("/deployments/policy-review"):
        detail = PolicyReviewErrorDetail(
            error=exc.error,
            message=exc.message,
            pem_issues=exc.pem_issues,
            fingerprint_issues=exc.fingerprint_issues,
            chain_issues=exc.chain_issues,
            eku_issues=getattr(exc, "eku_issues", []),
        )
    else:
        detail = NormalizeErrorDetail(
            error=exc.error,
            message=exc.message,
            pem_issues=exc.pem_issues,
            fingerprint_issues=exc.fingerprint_issues,
            chain_issues=exc.chain_issues,
        )
    return JSONResponse(status_code=422, content={"detail": detail.model_dump()})


@app.exception_handler(VariantSelectionError)
async def _variant_selection_error_handler(_request, exc: VariantSelectionError):
    return JSONResponse(
        status_code=422, content={"detail": exc.detail().model_dump()}
    )


# ---------------------------------------------------------------------------
# /plans/verify request: a plan plus the same scenario payload
# ---------------------------------------------------------------------------


class VerifyStage(BaseModel):
    stage: int = Field(..., ge=1)
    action_ids: list[str] = Field(
        ...,
        description="Actions that execute at this absolute stage number. An "
        "empty list is a no-op stage: the trust state is carried over "
        "unchanged and still re-validated.",
    )

    @field_validator("action_ids")
    @classmethod
    def _unique(cls, v: list[str]) -> list[str]:
        if len(set(v)) != len(v):
            raise ValueError("action_ids within a stage must be unique")
        return v


class VerifyRequest(PlanRequest):
    plan: list[VerifyStage] = Field(
        default_factory=list,
        description="Stages numbered consecutively from 1. Empty action_ids "
        "mark a no-op stage (a legal gap when no action is eligible at that "
        "absolute stage); the whole plan may be empty only when the scenario "
        "defines no actions.",
    )


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


def _chain_dto(sc, cert_ids: list[str]) -> list[ChainCert]:
    return [
        ChainCert(
            cert_id=cid,
            subject=sc.certs[cid].subject,
            issuer=sc.certs[cid].issuer,
        )
        for cid in cert_ids
    ]


def _stages_dto(sc, batches: list[list[int]]) -> list[PlannedStage]:
    return [
        PlannedStage(
            stage=num,
            action_ids=[sc.action_ids[i] for i in batch],
        )
        for num, batch in enumerate(batches, start=1)
    ]


def _failure_dto(sc, rf: ReplayFailure, *, status: str) -> Failure:
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
        chain=_chain_dto(sc, rf.chain),
        trusted_anchors=rf.trusted_anchors,
        message=_failure_message(sc, rf),
    )


def _failure_message(sc, rf: ReplayFailure) -> str:
    rel = sc.relationships[rf.relationship_index]
    who = f"relationship {rel.client_id} -> {rel.endpoint_id}"
    if rf.stage == 0:
        prefix = "initial state already invalid"
    else:
        prefix = f"stage {rf.stage}"
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
            f"{prefix}: an add_trust and a remove_trust on the same anchor are "
            f"scheduled together; {who} cannot be verified"
        )
    if rf.reason == "no_eligible_actions_at_stage":
        return (
            f"{prefix}: remaining actions are not allowed at this stage; "
            f"{who} cannot be maintained"
        )
    return f"{prefix}: {who} invalid ({rf.reason})"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.post(
    "/scenarios/normalize",
    response_model=NormalizeResult,
    responses={422: {"model": _NormalizeErrorResponse}},
    summary="Normalize a shuffled PEM bundle into leaf-first verified chains",
)
def normalize_pem_bundle(req: NormalizeRequest) -> Any:
    """Parse a PEM bag, dedupe by DER fingerprint, establish issuance edges by
    real signature verification and reconstruct each endpoint's current/target
    leaf-first chain to a declared self-signed trust root.

    Returns 422 when a leaf has no verified path to a trust root or when
    cross-signing makes more than one such path possible; the detail lists the
    leaf, its cryptographic candidate issuers and the candidate paths.
    """
    return normalize_scenario(req)


@app.post(
    "/deployments/precheck",
    response_model=PrecheckResult,
    responses={422: {"model": _PrecheckErrorResponse}},
    summary="Pre-check target leaves' DNS/IP identities before planning",
)
def precheck_deployment(req: PrecheckRequest) -> Any:
    """Reconstruct each endpoint's target-leaf chain with the same signature
    verification as /scenarios/normalize, then certify the endpoint's claimed
    DNS/IP identities against the leaf's SANs (SAN-only; DNS normalized for
    case, trailing dot and IDNA A-labels; leftmost-label-only wildcards; IP
    exact) and against the name constraints accumulated along the
    intermediate CAs (excluded wins; permitted intersected).

    Results are sorted by endpoint_id with stable, machine-readable
    violations. Only ``eligible: true`` endpoints are safe to hand to
    ``/plans``; an ineligible endpoint's chain is still returned so the
    failure can be diagnosed without a second round trip.
    """
    return precheck_identities(req)


@app.post(
    "/deployments/ocsp-precheck",
    response_model=OcspPrecheckResult,
    responses={422: {"model": _NormalizeErrorResponse}},
    summary="Offline pre-check of a stapled OCSP response for one leaf",
)
def ocsp_precheck_deployment(req: OcspPrecheckRequest) -> Any:
    """Validate a stapled OCSP response offline against the PEM bundle.

    The leaf's issuer is established by signature verification inside the
    bundle (same machinery as /scenarios/normalize; no trust roots needed).
    The response CertID is checked against the leaf's serial number and the
    issuer's name/key hashes; the signer is selected by
    responderName/responderKeyHash and must be the issuer itself or a
    delegated responder certificate (directly issued by the issuer, valid at
    ``check_time``, carrying id-kp-OCSPSigning) whose signature is verified.
    The response must be successful with certificate status good, producedAt
    no later than ``check_time`` plus the skew allowance (at most 300s), and
    ``check_time`` must fall inside the thisUpdate/nextUpdate window widened
    by that skew; nextUpdate is required. Every failure returns 200 with
    ``eligible: false`` and a stable machine-readable reason (revoked
    verdicts also carry the revocation time and reason); malformed requests
    (bad fingerprint, unknown leaf, unparseable PEM) return 422.
    """
    return ocsp_precheck(req)


@app.post(
    "/deployments/revocation-review",
    response_model=RevocationReviewResult,
    responses={422: {"model": _NormalizeErrorResponse}},
    summary="Offline chain-wide OCSP/CRL revocation evidence review",
)
def revocation_review_deployment(req: RevocationReviewRequest) -> Any:
    """Review offline revocation evidence for every certificate of each
    endpoint's reconstructed target chain.

    Each target leaf's unique signature-verified chain is rebuilt with the
    same machinery as /scenarios/normalize. OCSP responses are bound by
    CertID to a certificate and its verified on-chain issuer; each response's
    responder (the issuer or an authorized delegate), signature and
    thisUpdate/nextUpdate freshness are checked exactly as in
    /deployments/ocsp-precheck. Each CRL is parsed (DER or PEM), bound to the
    unique bundle certificate whose subject matches its issuer DN and whose
    key verifies its signature, checked for CA/cRLSign authority and the
    thisUpdate(lastUpdate)/nextUpdate window, and scanned for the chain
    certificates' serials. Indirect CRLs (issuingDistributionPoint
    indirectCRL) and delta CRLs (deltaCRLIndicator), and CRLs whose signer
    cannot be bound uniquely, are reported as unsupported/unusable rather
    than guessed at.

    Only fresh, authentic evidence valid at the exact check_time counts: a
    certificate is eligible only when it has good evidence and no revoked
    evidence; fresh revoked always wins, simultaneous fresh good and revoked
    is an unresolved conflict, and missing/stale evidence fails closed. The
    trust anchor terminating a chain is not reviewed. Results are sorted by
    endpoint_id, per-certificate entries are in chain order and each carries
    its full evidence list with stable source indices; evidence that binds
    to no reviewed certificate is returned under unattributed_evidence.
    Eligible endpoints' ``chain`` is ready to hand to /plans.
    """
    return revocation_review(req)


@app.post(
    "/deployments/policy-review",
    response_model=PolicyReviewResult,
    responses={422: {"model": _PolicyReviewErrorResponse}},
    summary="Review certificate purpose and path policy for current/target chains",
)
def policy_review_deployment(req: PolicyReviewRequest) -> Any:
    """Audit both the currently served and the target chain of every endpoint
    against RFC 5280 path policy before planning a rotation.

    Both chains are reconstructed from the PEM bundle with the same
    signature-verification machinery as /scenarios/normalize (issuance edges
    by real signature verification; a leaf must have exactly one path to a
    declared trust root or the request fails with the structured 422 used by
    every /deployments route). At ``check_time`` every certificate of each
    chain — including the trust anchor — must be within its validity period;
    every CA-position certificate must carry basicConstraints with cA=TRUE
    and a pathLenConstraint large enough for the non-self-issued
    intermediates below it, and a KeyUsage extension (when present) must
    assert keyCertSign; the leaf must not be marked a CA, its KeyUsage must
    fit the TLS role and it must assert the role EKU
    (id-kp-serverAuth/id-kp-clientAuth) plus every caller-supplied required
    EKU (intermediate EKUs chain-restrict the leaf; anyExtendedKeyUsage
    satisfies all purposes); every unrecognized critical extension fails
    closed.

    Results are sorted by endpoint_id; each entry lists every participating
    certificate (chain order, with BasicConstraints/pathLen/KeyUsage/EKU and
    critical-extension metadata), the full stably ordered conflict list and
    the first conflicting rule. An endpoint is eligible only when BOTH its
    current and its target chain comply — an endpoint whose current chain is
    already non-compliant at check_time is not passed through — and only the
    eligible target chain (its ``chain`` list) should be handed to /plans.
    """
    return policy_review(req)


@app.post(
    "/deployments/variants",
    response_model=VariantSelectionResult,
    responses={
        409: {"model": VariantSelectionConflict},
        422: {"model": _VariantSelectionErrorResponse},
    },
    summary="Select the minimum set of certificate variants covering every "
            "heterogeneous client",
)
def select_deployment_variants(req: VariantSelectionRequest) -> Any:
    """For each endpoint, pick the smallest set of candidate leaf-first
    fingerprint chains that covers every required client relationship.

    A chain covers a (client, endpoint) relationship only when every hop
    cryptographically verifies (reusing the normalizer's PEM dedup and
    signature verification), it terminates at one of the client's trust
    roots, the leaf public key type is one the client accepts, and every
    certificate except the trust root is signed with an accepted signature
    algorithm OID.

    The minimum set cover per endpoint is solved **exactly** by exhaustive
    subset search (there are at most 12 candidates per endpoint); a
    per-client greedy is never substituted for the global optimum. Ties are
    broken by sorting each set's complete fingerprint chains and taking the
    lexicographically smallest set, and each relationship is mapped to the
    first compatible variant in that order. If any relationship is
    uncoverable, 409 lists, stably by client and endpoint, every reason each
    candidate chain fails for.
    """
    result = select_variants(req)
    if isinstance(result, VariantSelectionConflict):
        return JSONResponse(status_code=409, content=result.model_dump())
    return result


@app.post(
    "/plans",
    response_model=PlanSuccess,
    responses={409: {"model": Failure}},
    summary="Compute a minimum-stage zero-downtime rotation plan",
)
def create_plan(req: PlanRequest) -> Any:
    sc = build_scenario(req)
    from .engine import Solver

    solver = Solver(sc)

    if not solver.good[0]:
        rf = eager_failure(sc)
        response = _failure_dto(sc, rf, status="invalid")
        return JSONResponse(status_code=409, content=response.model_dump())

    min_stages = solver.finish(0, 1)
    if min_stages >= 10 ** 9:
        rf = eager_failure(sc)
        response = _failure_dto(sc, rf, status="infeasible")
        return JSONResponse(status_code=409, content=response.model_dump())

    batches = solver.solve()

    return PlanSuccess(stage_count=len(batches), stages=_stages_dto(sc, batches))


@app.post(
    "/plans/verify",
    summary="Replay an arbitrary plan stage by stage",
)
def verify_plan(req: VerifyRequest) -> Any:
    sc = build_scenario(req)

    # Structural validation of the submitted plan itself.
    known = set(sc.action_ids)
    seen: set[str] = set()
    expected_stage = 1
    for st in req.plan:
        if st.stage != expected_stage:
            raise ScenarioValidationError(
                f"plan: stages must be numbered consecutively from 1; "
                f"expected stage {expected_stage}, got {st.stage}"
            )
        expected_stage += 1
        for aid in st.action_ids:
            if aid not in known:
                raise ScenarioValidationError(
                    f"plan: unknown action_id '{aid}'"
                )
            if aid in seen:
                raise ScenarioValidationError(
                    f"plan: action '{aid}' appears more than once"
                )
            seen.add(aid)
    missing = sorted(known - seen)
    if missing:
        raise ScenarioValidationError(
            f"plan: every action must be scheduled exactly once; missing: "
            f"{', '.join(missing)}"
        )

    index = {aid: i for i, aid in enumerate(sc.action_ids)}
    state = initial_state(sc)

    # Stage 0: initial state must already hold.
    from .engine import first_broken_relationship

    broken = first_broken_relationship(sc, state)
    if broken is not None:
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
        response = _failure_dto(sc, rf, status="invalid")
        return JSONResponse(status_code=409, content=response.model_dump())

    batches: list[list[int]] = []
    for st in req.plan:
        batch_bits = 0
        batch_list: list[int] = []
        for aid in st.action_ids:
            i = index[aid]
            batch_bits |= 1 << i
            batch_list.append(i)
        # Empty batches are no-op stages: check_batch still re-validates every
        # relationship against the carried-over trust state afterwards, so a
        # legal gap is accepted and any breakage at it is still reported.
        rf = check_batch(sc, state, batch_bits, st.stage)
        if rf is not None:
            response = _failure_dto(sc, rf, status="invalid")
            return JSONResponse(status_code=409, content=response.model_dump())
        state = state_for_mask_applied(sc, state, batch_bits)
        batches.append(batch_list)

    return {
        "status": "valid",
        "stage_count": len(batches),
        "stages": _stages_dto(sc, batches),
    }


@app.post(
    "/plans/reconcile",
    response_model=ReconcileResult,
    responses={409: {"model": ReconcileConflict}},
    summary="Infer safe resumption points after an interrupted deployment",
)
def reconcile_plan(req: ReconcileRequest) -> Any:
    """Enumerate every plan-ordered progress state consistent with partial
    post-outage observations.

    Ended stages must have executed completely, the current stage may have
    executed any subset of its actions, later stages cannot have started, and
    states that already break a communication relationship or contradict an
    observation are discarded. Unobserved clients/anchors/endpoints stay
    unknown (never assumed absent). Returns all compatible progresses plus
    the actions safe to execute next in *every* one of them, or 409 with a
    stable conflict cut when no such state exists.
    """
    result = reconcile(req)
    if result.status == "conflict":
        return JSONResponse(status_code=409, content=result.model_dump())
    return result


@app.post(
    "/plans/replan",
    response_model=ReplanSuccess,
    responses={409: {"model": ReplanFailure}},
    summary="Re-plan a safe continuation after a mid-rotation revocation",
)
def replan_plan(req: ReplanRequest) -> Any:
    """Recompute a minimum-stage safe continuation when revocation evidence
    surfaces while the rotation plan is being executed.

    The completed action prefix is non-revertible: its trust effects are
    applied to the resumption state (a completed replace_cert means the
    endpoint serves its target_chain). Chains containing a certificate with
    fresh revoked evidence — or with an unresolved fresh good/revoked
    conflict — are filtered out: a tainted current chain must be rotated
    away from, and tainted target/candidate chains are never deployed. Each
    pending replace_cert is re-targeted to one of the endpoint's clean
    chains (the declared target_chain plus up to 12 candidates); every other
    remaining action keeps its declaration. Continuation stages are numbered
    from 1 and allowed_stages apply to that numbering, with explicit no-op
    stages for sparse eligibility exactly as in /plans.

    Ties are adjudicated stably: fewest stages, then the per-action stage
    vector in action_id order, then the chosen chains' complete fingerprints
    ordered by endpoint. When no continuation exists, 409 names the first
    relationship that cannot be maintained, the blocking certificate and a
    machine-readable reason (the resumption state being already broken
    yields status invalid at stage 0).
    """
    result = replan(req)
    if isinstance(result, ReplanFailure):
        return JSONResponse(status_code=409, content=result.model_dump())
    return result


@app.get("/health", summary="Liveness probe")
def health() -> dict[str, str]:
    return {"status": "ok"}
