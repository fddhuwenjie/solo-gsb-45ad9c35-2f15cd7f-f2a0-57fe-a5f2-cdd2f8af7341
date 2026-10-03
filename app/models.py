"""Pydantic models for the certificate rotation planning API."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Literal, Optional, Union

from pydantic import BaseModel, Field, field_validator, model_validator

MAX_ACTIONS = 12
MAX_VARIANT_CANDIDATES = 12


class Certificate(BaseModel):
    """A certificate participating in the rotation scenario.

    ``subject`` / ``issuer`` are distinguished names; a self-signed root has
    issuer == subject. Validity instants are ISO-8601 (timezone recommended,
    naive datetimes are treated as UTC).
    """

    cert_id: str = Field(..., min_length=1, examples=["root-old"])
    subject: str = Field(..., min_length=1)
    issuer: str = Field(..., min_length=1)
    not_valid_before: datetime
    not_valid_after: datetime


class TrustAnchor(BaseModel):
    """A certificate that a client trusts *before* the plan starts."""

    client_id: str = Field(..., min_length=1)
    cert_id: str = Field(..., min_length=1)


class Endpoint(BaseModel):
    """A TLS endpoint with its current and target certificate chains.

    Chains are ordered leaf-first and must finish at a self-signed root.
    """

    endpoint_id: str = Field(..., min_length=1)
    current_chain: list[str] = Field(..., min_length=1)
    target_chain: list[str] = Field(..., min_length=1)


class Relationship(BaseModel):
    """A communication relationship that must keep a valid trust path."""

    client_id: str = Field(..., min_length=1)
    endpoint_id: str = Field(..., min_length=1)


class _BaseAction(BaseModel):
    action_id: str = Field(..., min_length=1)
    allowed_stages: list[int] = Field(..., min_length=1)

    @model_validator(mode="after")
    def _check_stages(self) -> "_BaseAction":
        for stage in self.allowed_stages:
            if stage < 1:
                raise ValueError("allowed_stages entries must be positive integers")
        if len(set(self.allowed_stages)) != len(self.allowed_stages):
            raise ValueError("allowed_stages must not contain duplicates")
        self.allowed_stages = sorted(self.allowed_stages)
        return self


class AddTrustAction(_BaseAction):
    """增信: a client starts trusting a certificate as an anchor."""

    type: Literal["add_trust"]
    client_id: str
    anchor_cert_id: str


class RemoveTrustAction(_BaseAction):
    """撤信: a client stops trusting a certificate anchor."""

    type: Literal["remove_trust"]
    client_id: str
    anchor_cert_id: str


class ReplaceCertAction(_BaseAction):
    """换证: an endpoint switches to a new leaf-first certificate chain."""

    type: Literal["replace_cert"]
    endpoint_id: str
    new_chain: list[str] = Field(..., min_length=1)


Action = Annotated[
    Union[AddTrustAction, RemoveTrustAction, ReplaceCertAction],
    Field(discriminator="type"),
]


class PlanRequest(BaseModel):
    certificates: list[Certificate] = Field(..., min_length=1)
    trust_anchors: list[TrustAnchor] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(..., min_length=1)
    relationships: list[Relationship] = Field(..., min_length=1)
    actions: list[Action] = Field(default_factory=list)
    plan_time: Optional[datetime] = Field(
        default=None,
        description="Planning instant; defaults to current UTC. Certificates "
        "expired (or not yet valid) at this instant are rejected.",
    )

    @model_validator(mode="after")
    def _check_action_limit(self) -> "PlanRequest":
        if len(self.actions) > MAX_ACTIONS:
            raise ValueError(
                f"at most {MAX_ACTIONS} actions are supported "
                f"(got {len(self.actions)})"
            )
        return self


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class PlannedStage(BaseModel):
    stage: int
    action_ids: list[str]


class PlanSuccess(BaseModel):
    status: Literal["ok"] = "ok"
    stage_count: int
    stages: list[PlannedStage]


class RelationshipRef(BaseModel):
    client_id: str
    endpoint_id: str


class ChainCert(BaseModel):
    cert_id: str
    subject: str
    issuer: str


class Failure(BaseModel):
    status: Literal["infeasible", "invalid"]
    stage: int = Field(..., description="Stage that first breaks a relationship; 0 = initial state")
    relationship: RelationshipRef
    blocking_action: Optional[str] = Field(
        ..., description="Action that first breaks the relationship, or null at stage 0"
    )
    reason: str
    chain: list[ChainCert]
    trusted_anchors: list[str]
    message: str


class VerifyResult(BaseModel):
    status: Literal["valid"] = "valid"
    stage_count: int
    stages: list[PlannedStage]


# ---------------------------------------------------------------------------
# /scenarios/normalize: PEM bundle -> planner-ready scenario data
# ---------------------------------------------------------------------------


class NormalizeEndpointRef(BaseModel):
    """An endpoint whose current/target leaves are identified by fingerprint."""

    endpoint_id: str = Field(..., min_length=1)
    current_leaf_fingerprint: str = Field(
        ...,
        min_length=64,
        description="Lower-case (case-insensitive) SHA-256 fingerprint of the "
                    "leaf currently served, hex-encoded.",
    )
    target_leaf_fingerprint: str = Field(
        ...,
        min_length=64,
        description="SHA-256 fingerprint of the leaf that will be served after "
                    "the rotation.",
    )


class NormalizeRequest(BaseModel):
    pem_certificates: list[str] = Field(
        ...,
        min_length=1,
        description="Unordered PEM bag; each element may contain one or more "
                    "concatenated PEM CERTIFICATE blocks. Duplicates are "
                    "deduplicated by DER fingerprint.",
    )
    endpoints: list[NormalizeEndpointRef] = Field(..., min_length=1)
    trust_roots: list[str] = Field(
        ...,
        min_length=1,
        description="SHA-256 fingerprints of self-signed roots that are "
                    "allowed to terminate a reconstructed chain.",
    )


class NormalizedCertificate(Certificate):
    """Certificate metadata; ``cert_id`` is the lower-case SHA-256 fingerprint."""


class NormalizedEndpoint(BaseModel):
    endpoint_id: str
    current_chain: list[str] = Field(
        ...,
        description="Reconstructed leaf-first fingerprint chain currently "
                    "served; the final element is a trust root.",
    )
    target_chain: list[str]


class NormalizeResult(BaseModel):
    certificates: list[NormalizedCertificate]
    endpoints: list[NormalizedEndpoint]


# -- 422 detail payloads -----------------------------------------------------


class NormalizePemIssue(BaseModel):
    index: int = Field(..., description="Index of the bad element in pem_certificates.")
    message: str


class NormalizeFingerprintIssue(BaseModel):
    fingerprint: str
    referred_by: str = Field(
        ...,
        description="Request location that referenced this fingerprint.",
    )


class NormalizeChainIssue(BaseModel):
    endpoint_id: str
    leaf_role: Literal["current", "target"]
    leaf: str = Field(..., description="Fingerprint of the leaf that could not be resolved.")
    candidate_issuers: list[str] = Field(
        ...,
        description="Fingerprints whose public key cryptographically verifies "
                    "the leaf's signature (the real issuance candidates; "
                    "empty when nothing signed it).",
    )
    candidate_paths: list[list[str]] = Field(
        ...,
        description="Bounded diagnostic sample (at most 64) of leaf-first "
                    "simple paths over verified issuance edges found while "
                    "resolving this leaf, including paths that do not end at "
                    "a trust root. The sample may be truncated in heavily "
                    "cross-signed bundles; the no_trust_path / ambiguous_chain "
                    "verdict itself is always exact.",
    )
    reason: Literal["no_trust_path", "ambiguous_chain"]


class NormalizeErrorDetail(BaseModel):
    error: str = Field(
        ...,
        description="Machine-readable error code, e.g. no_trust_path or "
                    "ambiguous_chain.",
    )
    message: str
    pem_issues: list[NormalizePemIssue] = Field(default_factory=list)
    fingerprint_issues: list[NormalizeFingerprintIssue] = Field(default_factory=list)
    chain_issues: list[NormalizeChainIssue] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# /deployments/precheck: target-leaf identity (SAN + name constraints) checks
# ---------------------------------------------------------------------------


class PrecheckIdentity(BaseModel):
    """An identity the endpoint claims to speak for.

    Only subjectAltName is consulted (CN is never a fallback). DNS identities
    are case-folded, IDNA A-label encoded and have a single trailing dot
    stripped; IP identities must be literal IPv4/IPv6 addresses and are
    matched exactly (no DNS syntax, no subnetting).
    """

    type: Literal["dns", "ip"]
    value: str = Field(..., min_length=1)


class PrecheckEndpoint(BaseModel):
    endpoint_id: str = Field(..., min_length=1)
    target_leaf_fingerprint: str = Field(
        ...,
        min_length=64,
        description="SHA-256 fingerprint (hex, case-insensitive) of the "
                    "target leaf certificate in the PEM bundle.",
    )
    identities: list[PrecheckIdentity] = Field(
        ...,
        min_length=1,
        description="DNS/IP identities claimed for this endpoint. Each is "
                    "checked against the target leaf's SANs and the "
                    "accumulated name constraints of the intermediate CAs "
                    "above it.",
    )


class PrecheckRequest(BaseModel):
    pem_certificates: list[str] = Field(
        ...,
        min_length=1,
        description="Unordered PEM bag; same parsing/deduplication rules as "
                    "/scenarios/normalize.",
    )
    trust_roots: list[str] = Field(
        ...,
        min_length=1,
        description="Self-signed root fingerprints allowed to terminate the "
                    "target chain.",
    )
    endpoints: list[PrecheckEndpoint] = Field(..., min_length=1)


class PrecheckUnsupportedConstraint(BaseModel):
    ca_fingerprint: str = Field(
        ...,
        description="Fingerprint of the intermediate CA carrying the "
                    "constraint that cannot be evaluated for DNS/IP "
                    "identities (e.g. rfc822Name/URI/directoryName/otherName, "
                    "or a malformed iPAddress constraint).",
    )
    section: Literal["permitted", "excluded"]
    general_name_type: str = Field(
        ...,
        description="GeneralName type tag, one of dns_name, ip_address, "
                    "rfc822_name, directory_name, edi_party_name, uri, "
                    "x400_address, registered_id, other_name, or "
                    "malformed_ip_address when an iPAddress constraint is "
                    "not a valid 8/32-byte address+mask.",
    )


class PrecheckViolation(BaseModel):
    """One machine-readable reason an endpoint fails the identity pre-check.

    Sorted stably in every response: first by reason in the precedence order
    unsupported_constraint_type -> excluded_by_name_constraint ->
    not_within_permitted_subtree -> identity_not_covered, then by identity
    type/value and the remaining fields.
    """

    reason: Literal[
        "identity_not_covered",
        "excluded_by_name_constraint",
        "not_within_permitted_subtree",
        "unsupported_constraint_type",
    ]
    identity_type: Optional[Literal["dns", "ip"]] = Field(
        ...,
        description="Claimed identity the violation pertains to; null when "
                    "an unsupported constraint disqualifies the endpoint "
                    "independently of any specific identity.",
    )
    identity_value: Optional[str] = Field(
        ...,
        description="Normalized declared identity value, or null.",
    )
    san: Optional[str] = Field(
        ...,
        description="The offending same-type SAN entry (normalized), or "
                    "null for a claimed identity that no SAN covers / for an "
                    "unsupported constraint.",
    )
    constraint: Optional[str] = Field(
        ...,
        description="The name constraint responsible (DNS subtree string, "
                    "or an IP network in CIDR notation), or null.",
    )
    ca_fingerprint: Optional[str] = Field(
        ...,
        description="Intermediate CA whose constraint triggered this "
                    "violation, or null.",
    )


class PrecheckIdentityResult(BaseModel):
    type: Literal["dns", "ip"]
    value: str = Field(..., description="Normalized identity value.")
    covered: bool = Field(
        ...,
        description="True iff at least one same-type SAN of the target leaf "
                    "covers this identity.",
    )


class PrecheckEndpointResult(BaseModel):
    endpoint_id: str
    target_leaf_fingerprint: str
    eligible: bool = Field(
        ...,
        description="True only when every declared identity is covered by a "
                    "SAN that survives the accumulated name constraints; "
                    "only eligible endpoints may be handed to /plans.",
    )
    reason: Literal["ok",
                    "identity_not_covered",
                    "excluded_by_name_constraint",
                    "not_within_permitted_subtree",
                    "unsupported_constraint_type"]
    chain: list[str] = Field(
        ...,
        description="Cryptographically verified leaf-first fingerprint chain "
        "from the target leaf to a declared trust root (the target_chain to "
        "hand to the planning API); present for every endpoint.",
    )
    dns_sans: list[str] = Field(
        ...,
        description="Target leaf's dNSName SAN entries, normalized "
                    "(lower-case, trailing dot stripped, A-label encoded).",
    )
    ip_sans: list[str] = Field(
        ..., description="Target leaf's iPAddress SAN entries (normalized)."
    )
    identities: list[PrecheckIdentityResult]
    violations: list[PrecheckViolation]


class PrecheckResult(BaseModel):
    results: list[PrecheckEndpointResult] = Field(
        ...,
        description="Per-endpoint verdicts, sorted by endpoint_id.",
    )


class PrecheckIdentityIssue(BaseModel):
    endpoint_id: str
    index: int = Field(
        ..., description="Index of the bad identity in the endpoint's list.",
    )
    message: str


class PrecheckErrorDetail(NormalizeErrorDetail):
    identity_issues: list[PrecheckIdentityIssue] = Field(default_factory=list)


class PolicyReviewErrorDetail(NormalizeErrorDetail):
    eku_issues: list[PolicyEkuIssue] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# /deployments/ocsp-precheck: offline check of a stapled OCSP response
# ---------------------------------------------------------------------------

MAX_OCSP_SKEW_SECONDS = 300


class OcspPrecheckRequest(BaseModel):
    """One stapled OCSP response, checked offline against the PEM bundle.

    The bundle must contain the leaf and the certificate that issued it; the
    issuer is established by signature verification (never by DN matching),
    exactly as in /scenarios/normalize. No trust roots are required: a
    stapled response is validated against the leaf's direct issuer alone.
    """

    pem_certificates: list[str] = Field(
        ...,
        min_length=1,
        description="Unordered PEM bag; same parsing/deduplication rules as "
                    "/scenarios/normalize. Must contain the leaf and its "
                    "issuer.",
    )
    leaf_fingerprint: str = Field(
        ...,
        min_length=64,
        description="SHA-256 fingerprint (hex, case-insensitive) of the leaf "
                    "certificate the stapled response speaks for.",
    )
    ocsp_response: str = Field(
        ...,
        min_length=1,
        description="Base64-encoded DER OCSP response, exactly as stapled "
                    "(ASCII whitespace inside the blob is ignored).",
    )
    check_time: datetime = Field(
        ...,
        description="Validation instant (ISO-8601; naive datetimes are "
                    "treated as UTC).",
    )
    max_skew_seconds: int = Field(
        default=0,
        ge=0,
        le=MAX_OCSP_SKEW_SECONDS,
        description="Clock skew tolerance in seconds applied to producedAt "
                    "and the thisUpdate/nextUpdate window; at most 300.",
    )

    @field_validator("check_time")
    @classmethod
    def _check_time_utc(cls, v: datetime) -> datetime:
        # Same convention as Certificate: naive instants are UTC.
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)


OcspPrecheckReason = Literal[
    "ok",
    "invalid_ocsp_response",
    "response_not_successful",
    "issuer_not_found",
    "cert_id_mismatch",
    "responder_not_found",
    "unauthorized_responder",
    "signature_invalid",
    "certificate_revoked",
    "certificate_unknown",
    "produced_at_in_future",
    "next_update_missing",
    "response_not_yet_valid",
    "response_stale",
]


class OcspPrecheckResult(BaseModel):
    """Verdict for one stapled OCSP response.

    Every check failure is reported as ``eligible: false`` with a stable,
    machine-readable ``reason`` (the reasons are listed in precedence
    order); only a fully authentic, timely, good-status response yields
    ``eligible: true``.
    """

    leaf_fingerprint: str
    issuer_fingerprint: Optional[str] = Field(
        ...,
        description="Fingerprint of the bundle certificate that verifiably "
                    "signed the leaf and matches the response CertID; null "
                    "when no issuer matched.",
    )
    eligible: bool
    reason: OcspPrecheckReason
    message: str
    response_status: Optional[str] = Field(
        ...,
        description="OCSP response status (successful, malformed_request, "
                    "internal_error, try_later, sig_required, unauthorized); "
                    "null when the response could not be parsed at all.",
    )
    certificate_status: Optional[str] = Field(
        ...,
        description="good / revoked / unknown; null unless the response was "
                    "successful.",
    )
    responder_id_type: Optional[Literal["name", "key_hash"]] = Field(
        ...,
        description="Which responderID form the response carries.",
    )
    signer_type: Optional[Literal["issuer", "responder_certificate"]] = Field(
        ...,
        description="Who was selected to sign: the issuer itself, or a "
                    "delegated responder certificate embedded in the "
                    "response.",
    )
    signer_fingerprint: Optional[str] = Field(
        ...,
        description="SHA-256 fingerprint of the selected signer certificate.",
    )
    produced_at: Optional[datetime] = Field(
        ..., description="Response producedAt (UTC); null when unparseable."
    )
    this_update: Optional[datetime] = Field(
        ..., description="Single-response thisUpdate (UTC)."
    )
    next_update: Optional[datetime] = Field(
        ..., description="Single-response nextUpdate (UTC); null when the "
                    "response omits it (which is itself a failure).",
    )
    revocation_time: Optional[datetime] = Field(
        ..., description="Revocation instant (UTC) when the status is "
                    "revoked and the response carries it; null otherwise.",
    )
    revocation_reason: Optional[str] = Field(
        ..., description="CRL reason flag name (e.g. key_compromise) when "
                    "revoked and present; null otherwise.",
    )


# ---------------------------------------------------------------------------
# /plans/reconcile: infer a safe resumption point after a deployment outage
# ---------------------------------------------------------------------------


class ReconcileStage(BaseModel):
    """One stage of the plan that was generated before the interruption."""

    stage: int = Field(..., ge=1)
    action_ids: list[str] = Field(
        ...,
        description="Actions scheduled at this absolute stage number; may be "
                    "empty for an explicit no-op gap, exactly as /plans emits.",
    )

    @field_validator("action_ids")
    @classmethod
    def _unique(cls, v: list[str]) -> list[str]:
        if len(set(v)) != len(v):
            raise ValueError("action_ids within a stage must be unique")
        return v


class ReconcileAnchorObservation(BaseModel):
    """Partial observation of one client's trust anchor set.

    Only observed (client, anchor) pairs are reported; anything unobserved
    stays unknown and must never be treated as absent.
    """

    client_id: str = Field(..., min_length=1)
    anchor_cert_id: str = Field(..., min_length=1)
    present: bool = Field(
        ...,
        description="Observed state of this exact trust edge: true = the "
                    "client currently trusts this anchor; false = it "
                    "currently does not. Absence of the observation means "
                    "unknown, never false.",
    )


class ReconcileChainObservation(BaseModel):
    """Partial observation of one endpoint's currently served chain."""

    endpoint_id: str = Field(..., min_length=1)
    chain: list[str] = Field(
        ...,
        min_length=1,
        description="The leaf-first chain observed on the endpoint right now. "
                    "Endpoints not listed stay unknown.",
    )


class ReconcileRequest(PlanRequest):
    stages: list[ReconcileStage] = Field(
        ...,
        description="The generated plan (as /plans returned): stages numbered "
                    "consecutively from 1, every scenario action scheduled "
                    "exactly once.",
    )
    anchor_observations: list[ReconcileAnchorObservation] = Field(
        default_factory=list,
        description="Observed client/anchor trust edges. Unreported edges are "
                    "unknown rather than absent.",
    )
    chain_observations: list[ReconcileChainObservation] = Field(
        default_factory=list,
        description="Observed current endpoint chains. Unreported endpoints "
                    "are unknown.",
    )

    @model_validator(mode="after")
    def _unique_observations(self) -> "ReconcileRequest":
        anchors = [
            (o.client_id, o.anchor_cert_id) for o in self.anchor_observations
        ]
        if len(set(anchors)) != len(anchors):
            raise ValueError(
                "anchor_observations: each (client_id, anchor_cert_id) pair "
                "may be observed at most once"
            )
        endpoints = [o.endpoint_id for o in self.chain_observations]
        if len(set(endpoints)) != len(endpoints):
            raise ValueError(
                "chain_observations: each endpoint_id may be observed at "
                "most once"
            )
        return self


class ReconcileProgress(BaseModel):
    completed_stages: int = Field(
        ...,
        description="Stages whose actions have all executed. null current "
                    "stage means the whole plan is finished.",
    )
    current_stage: Optional[int] = Field(
        ...,
        description="The stage the deployment may be resuming at: the first "
                    "stage with unexecuted actions; null once every action "
                    "has executed.",
    )
    completed_action_ids: list[str] = Field(
        ...,
        description="Every action that has definitely executed in this "
                    "possible progress (all ended-stage actions plus any "
                    "subset of the current stage), sorted by action_id.",
    )


class ReconcileResult(BaseModel):
    status: Literal["ok"] = "ok"
    safe_next_actions: list[str] = Field(
        ...,
        description="Actions that, in every possible progress, belong to the "
                    "current stage, are not yet completed, and still keep "
                    "every relationship valid when applied alone. Sorted by "
                    "action_id; empty once the plan is finished.",
    )
    possible_progress: list[ReconcileProgress] = Field(
        ...,
        description="All plan-ordered states consistent with the observations "
                    "in which every relationship still has a trust path; "
                    "sorted by (completed_stages, completed_action_ids).",
    )


class ReconcileConflictObservation(BaseModel):
    """An observation that contradicts every compatible reachable state.

    For an anchor observation ``anchor_cert_id`` / ``present`` are set and
    ``chain`` is null; for a chain observation ``endpoint_id`` / ``chain``
    are set and ``anchor_cert_id`` / ``present`` are null.
    """

    kind: Literal["anchor", "endpoint_chain"]
    client_id: Optional[str] = None
    anchor_cert_id: Optional[str] = None
    present: Optional[bool] = None
    endpoint_id: Optional[str] = None
    chain: Optional[list[str]] = None
    reason: str = Field(
        ...,
        description="Machine-readable code: anchor_present_mismatch, "
                    "anchor_absent_mismatch, endpoint_chain_mismatch, or "
                    "no_safe_reachable_state.",
    )
    message: str


class ReconcileConflict(BaseModel):
    status: Literal["conflict"] = "conflict"
    reason: Literal[
        "observation_conflict", "no_safe_reachable_state"
    ] = Field(
        ...,
        description="observation_conflict: the observations rule out every "
                    "plan-ordered healthy state; no_safe_reachable_state: "
                    "every plan-ordered state already breaks a relationship "
                    "(including before any observation).",
    )
    message: str
    conflicts: list[ReconcileConflictObservation] = Field(
        ...,
        description="Stably sorted observations responsible for the "
                    "contradiction (greedy first-incompatible cut).",
    )


# ---------------------------------------------------------------------------
# /plans/replan: safe continuation after a mid-plan certificate revocation
# ---------------------------------------------------------------------------

MAX_REPLAN_CANDIDATES = 12


class ReplanLiveChain(BaseModel):
    """The chain one endpoint is observed to serve right now."""

    endpoint_id: str = Field(..., min_length=1)
    chain: list[str] = Field(
        ...,
        min_length=1,
        description="Leaf-first chain currently served by this endpoint.",
    )


class ReplanEndpointCandidates(BaseModel):
    """Replacement chains one endpoint may rotate to."""

    endpoint_id: str = Field(..., min_length=1)
    candidate_chains: list[list[str]] = Field(
        ...,
        min_length=1,
        max_length=MAX_REPLAN_CANDIDATES,
        description=f"At most {MAX_REPLAN_CANDIDATES} leaf-first candidate "
                    "chains, each ending at a self-signed root; exact "
                    "duplicates collapse to one option.",
    )


class ReplanEvidenceItem(BaseModel):
    """One offline revocation verdict for one certificate.

    Mirrors the per-certificate conclusions of
    ``/deployments/revocation-review``: ``fresh`` marks evidence that is
    authentic and inside its validity window at the caller's check instant.
    Stale, not-yet-valid or unverifiable items must be submitted with
    ``fresh: false`` (or omitted entirely) and never taint a chain; an
    ``unknown`` status carries no conclusion either way.
    """

    cert_id: str = Field(..., min_length=1)
    status: Literal["good", "revoked", "unknown"]
    fresh: bool


class ReplanRequest(PlanRequest):
    """The original scenario plus the mid-execution revocation situation."""

    completed_action_ids: list[str] = Field(
        default_factory=list,
        description="Actions that have definitely executed. Their effects "
                    "are non-revertible and are applied to the resumption "
                    "state before the continuation is planned.",
    )
    live_chains: list[ReplanLiveChain] = Field(
        default_factory=list,
        description="Currently served chain per endpoint. Endpoints not "
                    "listed serve the chain implied by the completed prefix "
                    "(target_chain after a completed replace_cert, otherwise "
                    "current_chain).",
    )
    candidates: list[ReplanEndpointCandidates] = Field(
        default_factory=list,
        description="Replacement chains each endpoint may rotate to when "
                    "its declared target_chain is tainted by revocation "
                    "evidence.",
    )
    revocation_evidence: list[ReplanEvidenceItem] = Field(
        default_factory=list,
        description="Offline revocation verdicts per certificate. A "
                    "certificate is tainted when it has fresh revoked "
                    "evidence; simultaneous fresh good and fresh revoked "
                    "evidence is a conflict (and still taints).",
    )

    @model_validator(mode="after")
    def _check_unique_entries(self) -> "ReplanRequest":
        if len(set(self.completed_action_ids)) != len(self.completed_action_ids):
            raise ValueError(
                "completed_action_ids must not contain duplicates"
            )
        live_eps = [c.endpoint_id for c in self.live_chains]
        if len(set(live_eps)) != len(live_eps):
            raise ValueError(
                "live_chains: each endpoint_id may be reported at most once"
            )
        cand_eps = [c.endpoint_id for c in self.candidates]
        if len(set(cand_eps)) != len(cand_eps):
            raise ValueError(
                "candidates: each endpoint_id may appear at most once"
            )
        return self


class ReplanChainSelection(BaseModel):
    """The clean chain a pending replace_cert action is re-targeted to."""

    endpoint_id: str
    action_id: str = Field(
        ..., description="The replace_cert action this selection fulfills."
    )
    chain: list[str] = Field(
        ..., description="Leaf-first chain the endpoint will serve."
    )


class ReplanExcludedChain(BaseModel):
    """A current/target/candidate chain filtered out by revocation evidence."""

    endpoint_id: str
    role: Literal["current", "target", "candidate"]
    chain: list[str]
    blocking_certificate: str = Field(
        ...,
        description="First certificate of the chain (leaf-first) carrying "
                    "fresh revoked or conflicting evidence.",
    )
    reason: Literal["certificate_revoked", "conflicting_evidence"]


class ReplanSuccess(BaseModel):
    status: Literal["ok"] = "ok"
    stage_count: int
    stages: list[PlannedStage]
    chain_selections: list[ReplanChainSelection] = Field(
        ...,
        description="Chosen clean chain for every pending replace_cert "
                    "action, sorted by endpoint_id.",
    )
    excluded_chains: list[ReplanExcludedChain] = Field(
        ...,
        description="Every current/target/candidate chain tainted by fresh "
                    "revocation evidence, sorted by (endpoint_id, chain).",
    )


class ReplanFailure(BaseModel):
    status: Literal["infeasible", "invalid"]
    stage: int = Field(
        ...,
        description="Continuation stage at which the first relationship is "
                    "lost; 0 when the resumption state itself is broken or "
                    "revocation evidence already blocks every continuation.",
    )
    relationship: RelationshipRef
    blocking_action: Optional[str] = Field(
        ...,
        description="Action that cannot be placed safely, or null when the "
                    "block is not attributable to one action.",
    )
    blocking_certificate: Optional[str] = Field(
        ...,
        description="Certificate responsible for the block: the revoked or "
                    "conflicting certificate, or the chain certificate at "
                    "which the trust walk breaks; null for action-level "
                    "scheduling failures.",
    )
    reason: str
    chain: list[ChainCert]
    trusted_anchors: list[str]
    message: str


# ---------------------------------------------------------------------------
# /deployments/variants: minimum heterogeneous-client variant selection
# ---------------------------------------------------------------------------


LeafKeyType = Literal["rsa", "ec", "dsa", "ed25519", "ed448"]

# Precedence order for the reasons one candidate chain fails to cover a
# relationship; also used as the stable sort order inside one entry.
VARIANT_REASON_ORDER = {
    "chain_signature_invalid": 0,
    "root_untrusted": 1,
    "leaf_key_type_incompatible": 2,
    "signature_algorithm_incompatible": 3,
}

VariantIncompatibilityReason = Literal[
    "chain_signature_invalid",
    "root_untrusted",
    "leaf_key_type_incompatible",
    "signature_algorithm_incompatible",
]


class VariantClient(BaseModel):
    """A heterogeneous client with its own trust roots and crypto policy.

    Every client carries its own constraints: two clients behind different TLS
    stacks may trust different roots, accept different leaf public key types
    and accept different certificate signature algorithm OIDs.
    """

    client_id: str = Field(..., min_length=1)
    trust_roots: list[str] = Field(
        ...,
        min_length=1,
        description="SHA-256 fingerprints (hex, case-insensitive) of the "
                    "self-signed roots this client trusts. A candidate chain "
                    "covers a relationship only when its final certificate is "
                    "one of these fingerprints.",
    )
    acceptable_leaf_key_types: list[LeafKeyType] = Field(
        ...,
        min_length=1,
        description="Leaf public key types this client accepts: rsa, ec, dsa, "
                    "ed25519 or ed448.",
    )
    acceptable_signature_oid: list[str] = Field(
        ...,
        min_length=1,
        description="Dotted OIDs of certificate signature algorithms this "
                    "client accepts, e.g. 1.2.840.113549.1.1.12 "
                    "(SHA-256 RSA PKCS#1 v1.5) or 1.2.840.10045.4.3.2 "
                    "(ECDSA-with-SHA-256). Every certificate of a candidate "
                    "chain except the terminal trust root must be signed with "
                    "one of these OIDs.",
    )


class VariantEndpoint(BaseModel):
    """An endpoint and the deployable leaf-first fingerprint-chain variants."""

    endpoint_id: str = Field(..., min_length=1)
    candidate_chains: list[list[str]] = Field(
        ...,
        min_length=1,
        max_length=MAX_VARIANT_CANDIDATES,
        description=f"At most {MAX_VARIANT_CANDIDATES} candidate chains, each "
                    "ordered leaf-first and ending at a self-signed root. "
                    "Duplicate chains are collapsed to one variant.",
    )


class VariantRelationship(BaseModel):
    """A client -> endpoint relationship that must stay connected."""

    client_id: str = Field(..., min_length=1)
    endpoint_id: str = Field(..., min_length=1)


class VariantSelectionRequest(BaseModel):
    pem_certificates: list[str] = Field(
        ...,
        min_length=1,
        description="Unordered PEM bag; same parsing/deduplication rules as "
                    "/scenarios/normalize.",
    )
    clients: list[VariantClient] = Field(..., min_length=1)
    endpoints: list[VariantEndpoint] = Field(..., min_length=1)
    relationships: list[VariantRelationship] = Field(..., min_length=1)


class VariantSelection(BaseModel):
    """The minimum variant set chosen for one endpoint."""

    endpoint_id: str
    variant_index: int = Field(
        ...,
        description="0-based index of the variant within this endpoint's "
                    "sorted ``variants`` list.",
    )
    chain: list[str] = Field(
        ...,
        description="Leaf-first fingerprint chain that must be deployed for "
                    "this variant.",
    )


class VariantAssignment(BaseModel):
    """Which selected variant one required relationship is served by."""

    client_id: str
    endpoint_id: str
    variant_index: int = Field(
        ...,
        description="Index into the endpoint's sorted ``variants`` list of "
                    "the lexicographically first variant compatible with this "
                    "relationship.",
    )
    chain: list[str]


class VariantSelectionResult(BaseModel):
    status: Literal["ok"] = "ok"
    selections: list[VariantSelection] = Field(
        ...,
        description="Per-endpoint minimum variant sets, sorted by "
                    "endpoint_id; variants inside one set are sorted "
                    "lexicographically by their complete fingerprint chain.",
    )
    assignments: list[VariantAssignment] = Field(
        ...,
        description="Every required relationship mapped to the first "
                    "compatible variant of its endpoint's selected set, "
                    "sorted by (client_id, endpoint_id).",
    )


class VariantChainIssue(BaseModel):
    endpoint_id: str
    index: int = Field(
        ...,
        description="Index of the bad chain in the endpoint's "
                    "candidate_chains list.",
    )
    reason: Literal["empty_chain", "chain_cycle"]
    message: str


class VariantOidIssue(BaseModel):
    client_id: str
    index: int = Field(
        ..., description="Index of the bad OID in the client's "
                         "acceptable_signature_oid list.",
    )
    oid: str


class VariantIncompatibility(BaseModel):
    """Why one relationship cannot be served by any candidate chain.

    One entry per (relationship, candidate chain) that fails; a chain carries
    every reason it fails for (signature, root, leaf key type and signature
    algorithm checks are evaluated independently).
    """

    client_id: str
    endpoint_id: str
    chain: list[str]
    reasons: list[VariantIncompatibilityReason] = Field(
        ...,
        description="All reasons this chain fails for this client, in "
                    "precedence order chain_signature_invalid -> "
                    "root_untrusted -> leaf_key_type_incompatible -> "
                    "signature_algorithm_incompatible.",
    )
    leaf_key_type: Optional[str] = Field(
        ...,
        description="The leaf's actual public key type (rsa/ec/dsa/ed25519/"
                    "ed448; null only when the leaf certificate cannot be "
                    "classified).",
    )
    signature_oids: list[str] = Field(
        ...,
        description="Signature algorithm OID of every certificate in the "
                    "chain except the terminal trust root, leaf-first.",
    )
    trusted_roots: list[str] = Field(
        ...,
        description="The client's trust root fingerprints (sorted).",
    )


class VariantSelectionConflict(BaseModel):
    status: Literal["conflict"] = "conflict"
    reason: Literal["uncoverable_relationship"]
    message: str
    incompatibilities: list[VariantIncompatibility] = Field(
        ...,
        description="Stably sorted by (client_id, endpoint_id, chain, "
                    "reasons).",
    )


class VariantSelectionErrorDetail(BaseModel):
    error: str
    message: str
    pem_issues: list[NormalizePemIssue] = Field(default_factory=list)
    fingerprint_issues: list[NormalizeFingerprintIssue] = Field(
        default_factory=list
    )
    oid_issues: list[VariantOidIssue] = Field(default_factory=list)
    chain_issues: list[VariantChainIssue] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# /deployments/revocation-review: chain-wide offline revocation evidence
# ---------------------------------------------------------------------------

MAX_REVOCATION_SKEW_SECONDS = 300


class RevocationReviewEndpoint(BaseModel):
    """An endpoint whose target leaf needs a chain-wide revocation review."""

    endpoint_id: str = Field(..., min_length=1)
    target_leaf_fingerprint: str = Field(
        ...,
        min_length=64,
        description="SHA-256 fingerprint (hex, case-insensitive) of the "
                    "target leaf certificate in the PEM bundle. Its unique "
                    "signature-verified chain to a declared trust root is "
                    "reconstructed as in /deployments/precheck.",
    )


class RevocationReviewRequest(BaseModel):
    """Offline OCSP + CRL evidence review for every non-anchor chain cert.

    OCSP responses are applied globally by CertID and CRLs globally by
    (unique) signer/issuer binding; evidence is attached to every endpoint
    certificate it cryptographically pertains to, regardless of the order in
    which it was submitted.
    """

    pem_certificates: list[str] = Field(
        ...,
        min_length=1,
        description="Unordered PEM bag; same parsing/deduplication rules as "
                    "/scenarios/normalize. Must contain every endpoint's "
                    "target leaf, its intermediates and the trust roots.",
    )
    trust_roots: list[str] = Field(
        ...,
        min_length=1,
        description="Self-signed root fingerprints allowed to terminate the "
                    "reconstructed chains.",
    )
    endpoints: list[RevocationReviewEndpoint] = Field(..., min_length=1)
    ocsp_responses: list[str] = Field(
        default_factory=list,
        description="Offline (stapled) OCSP responses, each Base64-encoded "
                    "DER exactly as stapled (ASCII whitespace inside a blob "
                    "is ignored). Responses are matched to certificates by "
                    "CertID against the bundle's signature-verified issuance "
                    "edges; they need not be ordered.",
    )
    crls: list[str] = Field(
        default_factory=list,
        description="Certificate Revocation Lists, each either PEM-encoded "
                    "(one CRL block per element) or Base64-encoded DER. A CRL "
                    "is usable only when exactly one bundle certificate's "
                    "key verifies its signature; delta CRLs and indirect CRLs "
                    "(id-ce-deltaCRLIndicator present or "
                    "issuingDistributionPoint.indirectCRL set) are reported as "
                    "unsupported.",
    )
    check_time: datetime = Field(
        ...,
        description="Review instant (ISO-8601; naive datetimes are treated "
                    "as UTC). All evidence must be valid at this exact "
                    "instant; good and revoked evidence are comparable only "
                    "when both are fresh at it.",
    )
    max_skew_seconds: int = Field(
        default=0,
        ge=0,
        le=MAX_REVOCATION_SKEW_SECONDS,
        description="Clock skew tolerance in seconds applied to OCSP "
                    "producedAt / thisUpdate / nextUpdate and CRL "
                    "thisUpdate(lastUpdate) / nextUpdate; at most 300.",
    )

    @field_validator("check_time")
    @classmethod
    def _check_time_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)


# Verdict of one piece of evidence independently of its binding:
# good / revoked -> usable status evidence, fresh at check_time
# stale / not_yet_valid -> parsed and authentic, but outside the window
# every other reason -> unusable for any status conclusion
OcspEvidenceReason = Literal[
    "good",
    "revoked",
    "invalid_ocsp_response",
    "response_not_successful",
    "cert_id_mismatch",
    "responder_not_found",
    "unauthorized_responder",
    "signature_invalid",
    "certificate_unknown",
    "produced_at_in_future",
    "next_update_missing",
    "not_yet_valid",
    "stale",
]

CrlEvidenceReason = Literal[
    "good",
    "revoked",
    "invalid_crl",
    "indirect_or_delta_crl",
    "signer_not_found",
    "signer_not_ca",
    "issuer_mismatch",
    "signature_invalid",
    "next_update_missing",
    "not_yet_valid",
    "stale",
]


class _EvidenceBase(BaseModel):
    source_index: int = Field(
        ...,
        description="0-based index of this blob in the request list it came "
                    "from (ocsp_responses or crls).",
    )
    message: str
    fresh: bool = Field(
        ...,
        description="True only when the evidence is authentic and check_time "
                    "falls inside its validity window (widened by the skew "
                    "allowance). Only fresh evidence participates in the "
                    "good/revoked conclusion.",
    )
    this_update: Optional[datetime] = Field(
        ..., description="thisUpdate (OCSP) / lastUpdate (CRL), UTC; null when unavailable."
    )
    next_update: Optional[datetime] = Field(
        ..., description="nextUpdate (UTC); null when absent."
    )


class OcspEvidence(_EvidenceBase):
    """One evaluated offline OCSP response (stable ordering by source_index)."""

    kind: Literal["ocsp"] = "ocsp"
    reason: OcspEvidenceReason
    certificate_fingerprint: Optional[str] = Field(
        ...,
        description="Bundle certificate the response CertID speaks for (a "
                    "chain leaf or intermediate), or null when no verified "
                    "issuer in the bundle matches the CertID "
                    "(cert_id_mismatch).",
    )
    issuer_fingerprint: Optional[str] = Field(
        ...,
        description="Bundle certificate that cryptographically signed the "
                    "named certificate and matches the CertID hashes; null "
                    "when none does.",
    )
    response_status: Optional[str] = Field(
        ..., description="successful / malformed_request / ...; null when unparseable."
    )
    certificate_status: Optional[str] = Field(
        ..., description="good / revoked / unknown; null unless successful."
    )
    responder_id_type: Optional[Literal["name", "key_hash"]] = None
    signer_type: Optional[Literal["issuer", "responder_certificate"]] = None
    signer_fingerprint: Optional[str] = None
    produced_at: Optional[datetime] = None
    revocation_time: Optional[datetime] = None
    revocation_reason: Optional[str] = None


class CrlEvidence(_EvidenceBase):
    """One evaluated CRL (stable ordering by source_index)."""

    kind: Literal["crl"] = "crl"
    reason: CrlEvidenceReason
    issuer_fingerprint: Optional[str] = Field(
        ...,
        description="The unique bundle certificate whose key verifies this "
                    "CRL and whose subject equals its issuer DN; null when "
                    "the signer cannot be uniquely bound (signer_not_found / "
                    "signer_ambiguous) or the CRL is unusable.",
    )
    crl_number: Optional[int] = Field(
        ..., description="id-ce-cRLNumber when present.",
    )
    is_delta: bool = Field(
        ..., description="True when id-ce-deltaCRLIndicator is present.",
    )
    is_indirect: bool = Field(
        ...,
        description="True when issuingDistributionPoint has indirectCRL set.",
    )
    revoked_serial_numbers: list[str] = Field(
        ...,
        description="Upper-case hex serial numbers listed as revoked on this "
                    "CRL (e.g. 01A2FF), sorted. Empty for a non-revoking CRL.",
    )
    covered_serial_numbers: list[str] = Field(
        ...,
        description="Revoked serial numbers that belong to a chain "
                    "certificate the CRL's issuer signed (the entries this "
                    "review actually consumes), sorted.",
    )
    revocation_time: Optional[datetime] = Field(
        ...,
        description="When this CRL revokes exactly one chain certificate, "
                    "that entry's revocation date; otherwise null.",
    )
    revocation_reason: Optional[str] = Field(
        ...,
        description="When this CRL revokes exactly one chain certificate and "
                    "the entry carries a CRL reason, that reason flag name.",
    )


RevocationEvidence = Annotated[
    Union[OcspEvidence, CrlEvidence],
    Field(discriminator="kind"),
]

# Per-certificate aggregate verdict:
# ok                       every evidence item is good and fresh
# certificate_revoked      at least one fresh authentic item says revoked
#                          (revocation always wins; revocation_time reported)
# conflicting_evidence     fresh authentic good and revoked items both exist
# evidence_missing         no fresh authentic status evidence at all
# evidence_stale           only stale/not-yet-valid authentic items exist
# trust_root               the chain terminator is not reviewed
CertReviewReason = Literal[
    "ok",
    "certificate_revoked",
    "conflicting_evidence",
    "evidence_missing",
    "evidence_stale",
    "trust_root",
]


class CertificateReview(BaseModel):
    """Review result for one certificate of one endpoint's chain."""

    certificate_fingerprint: str
    issuer_fingerprint: Optional[str] = Field(
        ...,
        description="Next certificate up the chain; null for the trust root."
    )
    role: Literal["leaf", "intermediate", "trust_root"]
    serial_number: str = Field(..., description="Upper-case hex serial number.")
    eligible: bool = Field(
        ...,
        description="True only for non-anchor certs with consistently fresh "
                    "good evidence; always true for the trust root, whose "
                    "revocation status is never established from within its "
                    "own chain.",
    )
    reason: CertReviewReason
    message: str
    revocation_time: Optional[datetime] = Field(
        ...,
        description="Revocation instant from the first (by a stable order) "
                    "fresh revoked evidence item, when any.",
    )
    revocation_reason: Optional[str] = None
    evidence: list[RevocationEvidence] = Field(
        ...,
        description="Every OCSP response whose CertID names this "
                    "certificate and every CRL uniquely signed by the "
                    "certificate directly above it in this chain, sorted by "
                    "(kind, source_index). Includes unusable and stale items "
                    "so the audit trail is complete.",
    )


class EndpointRevocationResult(BaseModel):
    endpoint_id: str
    target_leaf_fingerprint: str
    eligible: bool = Field(
        ...,
        description="True only when every non-trust-root certificate of the "
                    "reconstructed chain has fresh, mutually consistent good "
                    "evidence at check_time. Fresh revoked evidence, a "
                    "good/revoked conflict, missing evidence and stale "
                    "evidence all make the endpoint ineligible for /plans.",
    )
    reason: CertReviewReason = Field(
        ...,
        description="Endpoint-level rollup, precedence "
                    "certificate_revoked -> conflicting_evidence -> "
                    "evidence_stale -> evidence_missing -> ok over the "
                    "non-anchor certificates.",
    )
    chain: list[str] = Field(
        ...,
        description="Cryptographically verified leaf-first fingerprint chain "
                    "from the target leaf to a declared trust root (the "
                    "target_chain to hand to the planning API when eligible).",
    )
    certificates: list[CertificateReview] = Field(
        ...,
        description="Per-certificate results in chain order (leaf first).",
    )


class UnattributedEvidence(BaseModel):
    """An evidence blob that could not be attached to any chain certificate.

    It is still fully evaluated and reported (malformed blobs included) so
    that nothing submitted disappears silently from the audit.
    """

    kind: Literal["ocsp", "crl"]
    source_index: int
    reason: str
    message: str
    fresh: bool
    this_update: Optional[datetime] = None
    next_update: Optional[datetime] = None
    issuer_fingerprint: Optional[str] = None
    is_delta: Optional[bool] = None
    is_indirect: Optional[bool] = None
    revoked_serial_numbers: list[str] = Field(default_factory=list)


class RevocationReviewResult(BaseModel):
    check_time: datetime
    max_skew_seconds: int
    results: list[EndpointRevocationResult] = Field(
        ...,
        description="Per-endpoint verdicts, sorted by endpoint_id.",
    )
    unattributed_evidence: list[UnattributedEvidence] = Field(
        ...,
        description="Submitted evidence that pertains to no reviewed "
                    "certificate (CertID/issuer unknown to the chains, CRL "
                    "signer not uniquely bindable, indirect/delta CRL, or "
                    "unparseable blob), sorted by (kind, source_index).",
    )


# ---------------------------------------------------------------------------
# /deployments/policy-review: certificate purpose & path-policy review
# ---------------------------------------------------------------------------

TlsRole = Literal["server", "client"]

# Precedence order of the machine-readable policy reasons; also the stable
# sort key inside one chain's conflict list. Validity is verified before any
# structural/extension rule; leaf purpose (KeyUsage/EKU) is checked after the
# chain that certifies it.
POLICY_REASON_ORDER = {
    "certificate_expired": 0,
    "certificate_not_yet_valid": 1,
    "missing_basic_constraints": 2,
    "not_ca": 3,
    "path_len_violation": 4,
    "missing_key_cert_sign": 5,
    "leaf_marked_ca": 6,
    "leaf_key_usage_mismatch": 7,
    "required_eku_missing": 8,
    "unknown_critical_extension": 9,
}

PolicyReason = Literal[
    "certificate_expired",
    "certificate_not_yet_valid",
    "missing_basic_constraints",
    "not_ca",
    "path_len_violation",
    "missing_key_cert_sign",
    "leaf_marked_ca",
    "leaf_key_usage_mismatch",
    "required_eku_missing",
    "unknown_critical_extension",
]


class PolicyReviewEndpoint(BaseModel):
    """An endpoint whose current and target chains are policy-reviewed."""

    endpoint_id: str = Field(..., min_length=1)
    current_leaf_fingerprint: str = Field(
        ...,
        min_length=64,
        description="SHA-256 fingerprint (hex, case-insensitive) of the leaf "
                    "currently served by this endpoint.",
    )
    target_leaf_fingerprint: str = Field(
        ...,
        min_length=64,
        description="SHA-256 fingerprint (hex, case-insensitive) of the leaf "
                    "that will be served after the rotation.",
    )
    role: TlsRole = Field(
        ...,
        description="TLS role the endpoint plays: 'server' (presents an "
                    "id-kp-serverAuth leaf) or 'client' (presents an "
                    "id-kp-clientAuth leaf).",
    )
    required_ekus: list[str] = Field(
        default_factory=list,
        description="Additional EKU OIDs (dotted notation) that every serving "
                    "leaf must carry; the role EKU (id-kp-serverAuth "
                    "1.3.6.1.5.5.7.3.1 / id-kp-clientAuth 1.3.6.1.5.5.7.3.2) "
                    "is always required implicitly. Duplicates collapse.",
    )


class PolicyReviewRequest(BaseModel):
    pem_certificates: list[str] = Field(
        ...,
        min_length=1,
        description="Unordered PEM bag; same parsing/deduplication rules as "
                    "/scenarios/normalize. Must contain every endpoint's "
                    "current and target leaves, intermediates and roots.",
    )
    trust_roots: list[str] = Field(
        ...,
        min_length=1,
        description="Self-signed root fingerprints allowed to terminate the "
                    "reconstructed chains.",
    )
    endpoints: list[PolicyReviewEndpoint] = Field(..., min_length=1)
    check_time: datetime = Field(
        ...,
        description="Verification instant (ISO-8601; naive datetimes are "
                    "treated as UTC). Every certificate of both the current "
                    "and the target chain must be within its validity period "
                    "at this exact instant.",
    )

    @field_validator("check_time")
    @classmethod
    def _check_time_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)


class PolicyConflict(BaseModel):
    """One machine-readable policy conflict found on one certificate.

    All locator fields apart from ``reason`` / ``certificate_fingerprint`` /
    ``chain_position`` / ``message`` are null when they do not pertain to the
    reason.
    """

    reason: PolicyReason
    certificate_fingerprint: str = Field(
        ...,
        description="Fingerprint of the certificate that violates the rule "
                    "(leaf-first chain position given by chain_position).",
    )
    chain_position: int = Field(
        ...,
        description="0-based position of the offending certificate in the "
                    "leaf-first chain (0 = leaf).",
    )
    message: str
    not_valid_before: Optional[datetime] = Field(
        ...,
        description="Present for certificate_not_yet_valid.",
    )
    not_valid_after: Optional[datetime] = Field(
        ...,
        description="Present for certificate_expired.",
    )
    path_length_constraint: Optional[int] = Field(
        ...,
        description="Offending CA's pathLenConstraint for "
                    "path_len_violation.",
    )
    subordinate_ca_count: Optional[int] = Field(
        ...,
        description="Number of non-self-issued intermediate CAs below the "
                    "offending CA in the reviewed chain, for "
                    "path_len_violation.",
    )
    required_eku: Optional[str] = Field(
        ...,
        description="The role/caller-required EKU OID the certificate does "
                    "not assert, for required_eku_missing.",
    )
    present_ekus: Optional[list[str]] = Field(
        ...,
        description="EKUs the certificate actually asserts (empty when it "
                    "carries no EKU extension), for required_eku_missing.",
    )
    required_key_usages: Optional[list[str]] = Field(
        ...,
        description="KeyUsage bits the role requires on a leaf "
                    "(digital_signature / key_encipherment), for "
                    "leaf_key_usage_mismatch.",
    )
    present_key_usages: Optional[list[str]] = Field(
        ...,
        description="KeyUsage bits the leaf actually asserts, for "
                    "leaf_key_usage_mismatch.",
    )
    extension_oid: Optional[str] = Field(
        ...,
        description="OID of the unrecognized critical extension, for "
                    "unknown_critical_extension.",
    )


class PolicyReviewCertificate(BaseModel):
    """One certificate participating in a reviewed chain (chain order)."""

    cert_id: str = Field(
        ..., description="Lower-case SHA-256 fingerprint of the certificate.",
    )
    subject: str
    issuer: str
    chain_position: int = Field(
        ..., description="0-based position in the leaf-first chain (0 = leaf).",
    )
    role: Literal["leaf", "intermediate", "trust_root"]
    not_valid_before: datetime
    not_valid_after: datetime
    is_ca: bool = Field(
        ...,
        description="basicConstraints cA value; false when the extension is "
                    "absent.",
    )
    path_length_constraint: Optional[int] = Field(
        ...,
        description="basicConstraints pathLenConstraint when present.",
    )
    key_usages: list[str] = Field(
        ...,
        description="Asserted KeyUsage bit names (digital_signature, "
                    "key_cert_sign, ...); empty when the extension is absent.",
    )
    extended_key_usages: list[str] = Field(
        ...,
        description="Asserted EKU dotted OIDs; empty when absent.",
    )
    critical_extension_oids: list[str] = Field(
        ...,
        description="OIDs of every extension marked critical on this "
                    "certificate, sorted.",
    )


class PolicyChainReview(BaseModel):
    """Policy verdict for one leaf-first chain of one endpoint."""

    chain_role: Literal["current", "target"]
    chain: list[str] = Field(
        ...,
        description="Cryptographically verified leaf-first fingerprint chain "
                    "to a declared trust root.",
    )
    eligible: bool = Field(
        ...,
        description="True only when no certificate of this chain violates a "
                    "policy rule at check_time.",
    )
    reason: str = Field(
        ...,
        description="'ok' or the machine-readable code of the first "
                    "conflicting rule (the first entry of conflicts).",
    )
    certificates: list[PolicyReviewCertificate] = Field(
        ...,
        description="Every certificate participating in this chain, in "
                    "leaf-first chain order.",
    )
    conflicts: list[PolicyConflict] = Field(
        ...,
        description="Every violated rule, stably sorted by reason precedence "
                    "then chain position; empty when eligible.",
    )


class PolicyReviewEndpointResult(BaseModel):
    endpoint_id: str
    role: TlsRole
    current_leaf_fingerprint: str
    target_leaf_fingerprint: str
    eligible: bool = Field(
        ...,
        description="True only when BOTH the current and the target chain "
                    "comply. An endpoint whose currently served chain is "
                    "already non-compliant must not be passed through.",
    )
    reason: str = Field(
        ...,
        description="First conflicting rule over both chains (current chain "
                    "first, then target, each in reason precedence order), or "
                    "'ok'.",
    )
    current_chain: PolicyChainReview
    target_chain: PolicyChainReview


class PolicyReviewResult(BaseModel):
    check_time: datetime
    results: list[PolicyReviewEndpointResult] = Field(
        ...,
        description="Per-endpoint verdicts, sorted by endpoint_id. Only an "
                    "endpoint whose target_chain is eligible may be handed to "
                    "/plans (its chain list is the target_chain).",
    )


class PolicyEkuIssue(BaseModel):
    endpoint_id: str
    index: int = Field(
        ..., description="Index of the bad OID in the endpoint's required_ekus list.",
    )
    oid: str
