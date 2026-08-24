"""Evaluation profiles and Process Assurance Level.

Two separate results, and keeping them separate is the whole point.

**A profile** is one context's opinion about which dimensions matter. A research
group cares about origination and reproducibility; a regulated enterprise cares
about authorised tools and human approval; a teacher may forbid delegated
execution outright. Core publishes the contribution vector and leaves the
weighting to explicit, versioned profiles, so two profiles can legitimately reach
opposite decisions from the same record and neither is wrong.

A profile's output is called ``meets_review_requirements``. It is never renamed to
anything about human authorship, because "this satisfies our review policy" and
"a human wrote this" are different statements and only the first is knowable.

**Process Assurance Level** measures how well supported a record is — evidence
strength and governance — and says nothing about creativity, originality, or
token share. A two-sentence insight that reshaped a project can be `PAL-1` if it
is merely self-declared. A routine implementation can be `PAL-4` because its
process was independently audited. A higher PAL means better supported, not more
human and not better work.

Neither result is a score for a person. Neither collapses the vector.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING, Literal

from pydantic import Field

from trueai.core.attestation import (
    AiAutonomy,
    ClaimType,
    ContributionClaim,
    ContributionDimension,
    ContributionLevel,
    EvidenceStatus,
    ProcessAttestation,
)
from trueai.core.models import FrozenModel

if TYPE_CHECKING:
    from trueai.core.attestation import AttestationVerification

EVALUATION_SCHEMA_VERSION: Literal["0.1"] = "0.1"


class ProcessAssuranceLevel(StrEnum):
    """How well supported a record is, never how human or how good the work is."""

    #: Missing, invalid, or not bound to the delivered artifact.
    UNSUBSTANTIATED = "PAL-0"
    #: An identified claimant signed a structured declaration bound to the artifact.
    DECLARED = "PAL-1"
    #: Material claims reference artifact-correlated evidence and disclose AI roles.
    EVIDENCED = "PAL-2"
    #: Decisions and validation are evidenced and countersigned by an identified reviewer.
    REVIEWED = "PAL-3"
    #: An independent assessor applied a named profile, with organization identity,
    #: finite validity, and a trusted timestamp or equivalent transparency proof.
    INDEPENDENTLY_ASSURED = "PAL-4"


_PAL_ORDER: tuple[ProcessAssuranceLevel, ...] = (
    ProcessAssuranceLevel.UNSUBSTANTIATED,
    ProcessAssuranceLevel.DECLARED,
    ProcessAssuranceLevel.EVIDENCED,
    ProcessAssuranceLevel.REVIEWED,
    ProcessAssuranceLevel.INDEPENDENTLY_ASSURED,
)

_LEVEL_ORDER: dict[ContributionLevel, int] = {
    ContributionLevel.NOT_CLAIMED: 0,
    ContributionLevel.SUPPORTING: 1,
    ContributionLevel.SUBSTANTIAL: 2,
    ContributionLevel.PRIMARY: 3,
    ContributionLevel.ORIGINATING_OR_CONTROLLING: 4,
}

_EVIDENCE_ORDER: dict[EvidenceStatus, int] = {
    EvidenceStatus.SELF_DECLARED: 0,
    EvidenceStatus.ARTIFACT_CORRELATED: 1,
    EvidenceStatus.COUNTERSIGNED: 2,
    EvidenceStatus.INDEPENDENTLY_ASSESSED: 3,
    EvidenceStatus.CRYPTOGRAPHICALLY_VERIFIED: 4,
}

#: Dimensions whose claims a `PAL-2` record must actually back with evidence.
#: Origination is deliberately excluded: it is the dimension least amenable to
#: artifact correlation, and requiring evidence for it would push people to
#: fabricate a paper trail for a genuine idea.
_MATERIAL_DIMENSIONS = frozenset(
    {
        ContributionDimension.EXECUTION,
        ContributionDimension.VALIDATION,
        ContributionDimension.DECISION_CONTROL,
    }
)


class AssuranceAssessment(FrozenModel):
    """A record's assurance level, with why it stopped there."""

    schema_version: Literal["0.1"] = EVALUATION_SCHEMA_VERSION
    level: ProcessAssuranceLevel
    reasons: tuple[str, ...] = ()
    #: What would have to be true for the next level, so the result is actionable
    #: rather than a grade.
    next_level_requires: tuple[str, ...] = ()

    @property
    def meaning(self) -> str:
        """Return the level's meaning, phrased so it cannot be read as a quality score."""

        return {
            ProcessAssuranceLevel.UNSUBSTANTIATED: (
                "The record is missing, invalid, or not bound to the delivered artifact."
            ),
            ProcessAssuranceLevel.DECLARED: (
                "An identified claimant signed a structured declaration bound to the artifact."
            ),
            ProcessAssuranceLevel.EVIDENCED: (
                "Material claims reference artifact-correlated evidence and AI roles are disclosed."
            ),
            ProcessAssuranceLevel.REVIEWED: (
                "Consequential decisions and validation are evidenced and countersigned by an "
                "identified reviewer."
            ),
            ProcessAssuranceLevel.INDEPENDENTLY_ASSURED: (
                "An independent assessor applied a named profile against verified evidence, "
                "under organization identity, finite validity, and a trusted timestamp."
            ),
        }[self.level]


def assess_process_assurance(
    attestation: ProcessAttestation,
    verification: AttestationVerification,
) -> AssuranceAssessment:
    """Derive the assurance level from what verification established.

    Deliberately computed from the *verification result*, not from the levels the
    record claims for itself. A record that claims `originating_or_controlling`
    everywhere and proves nothing stays at `PAL-1`.
    """

    reasons: list[str] = []

    if not verification.content_id_valid or verification.subject_bound is False:
        return AssuranceAssessment(
            level=ProcessAssuranceLevel.UNSUBSTANTIATED,
            reasons=("The record is not validly bound to the artifact it describes.",),
            next_level_requires=("Re-issue the record against the current artifact bytes.",),
        )
    if not verification.authenticated_declaration:
        return AssuranceAssessment(
            level=ProcessAssuranceLevel.UNSUBSTANTIATED,
            reasons=(
                "No identified claimant signature was established, so nobody stands behind "
                "the record.",
            ),
            next_level_requires=(
                "Have the claimant sign the record, and supply their public key when verifying.",
            ),
        )

    level = ProcessAssuranceLevel.DECLARED
    reasons.append("An identified claimant signed a declaration bound to these exact bytes.")

    material = [claim for claim in attestation.claims if claim.dimension in _MATERIAL_DIMENSIONS]
    evidenced = bool(material) and all(
        _EVIDENCE_ORDER[claim.evidence_status]
        >= _EVIDENCE_ORDER[EvidenceStatus.ARTIFACT_CORRELATED]
        and claim.evidence_ids
        for claim in material
    )
    ai_disclosed = _ai_roles_disclosed(attestation)
    if evidenced and ai_disclosed and verification.evidence_binding_complete:
        level = ProcessAssuranceLevel.EVIDENCED
        reasons.append("Material claims are backed by evidence the record actually contains.")
        reasons.append("AI roles are disclosed per stage.")
    else:
        missing: list[str] = []
        if not material:
            missing.append("claim at least one execution, validation, or decision dimension")
        elif not evidenced:
            missing.append("raise material claims to artifact_correlated evidence and reference it")
        if not ai_disclosed:
            missing.append("name the AI systems that participated, or state that none did")
        if not verification.evidence_binding_complete:
            missing.append("include every referenced evidence item in the record")
        return AssuranceAssessment(
            level=level, reasons=tuple(reasons), next_level_requires=tuple(missing)
        )

    countersigned = verification.reviewer_signature == "valid"
    reviewed = countersigned and _decisions_and_validation_evidenced(attestation)
    if reviewed:
        level = ProcessAssuranceLevel.REVIEWED
        reasons.append(
            "An identified reviewer countersigned, and decisions and validation carry evidence."
        )
    else:
        missing = []
        if not countersigned:
            missing.append("have an identified reviewer countersign the record")
        if not _decisions_and_validation_evidenced(attestation):
            missing.append("record decisions and validation with supporting evidence")
        return AssuranceAssessment(
            level=level, reasons=tuple(reasons), next_level_requires=tuple(missing)
        )

    independent = (
        attestation.evaluation is not None
        and verification.assessor_signature == "valid"
        and verification.evaluation_profile_supported is not False
    )
    governed = (
        verification.organizationally_attributed
        and attestation.expires_at is not None
        and verification.trusted_timestamp is True
    )
    if independent and governed and verification.disclosed_evidence_consistent is not False:
        return AssuranceAssessment(
            level=ProcessAssuranceLevel.INDEPENDENTLY_ASSURED,
            reasons=(
                *reasons,
                "An independent assessor applied a named profile and countersigned it.",
                "The issuer is organizationally attributed, the record expires, and a separate "
                "authority attested the time.",
            ),
        )

    missing = []
    if not independent:
        missing.append("have an independent assessor apply a named profile and sign as assessor")
    if not verification.organizationally_attributed:
        missing.append("bind the signing key to an organization through a trust profile")
    if attestation.expires_at is None:
        missing.append("give the record a finite validity window")
    if verification.trusted_timestamp is not True:
        missing.append("attach a verified timestamp from a separate authority")
    return AssuranceAssessment(
        level=level, reasons=tuple(reasons), next_level_requires=tuple(missing)
    )


def _ai_roles_disclosed(attestation: ProcessAttestation) -> bool:
    """Whether the record says what any machine did, one way or the other.

    Silence is not disclosure. A record that names an AI actor but never says what
    it did, or that describes autonomous execution without naming a system, has
    left the reader to guess.
    """

    from trueai.core.attestation import ActorKind

    ai_actors = {actor.id for actor in attestation.actors if actor.kind == ActorKind.AI_SYSTEM}
    machine_claims = [claim for claim in attestation.claims if claim.ai_autonomy != AiAutonomy.NONE]
    machine_activities = [
        activity for activity in attestation.activities if activity.ai_autonomy != AiAutonomy.NONE
    ]
    if ai_actors:
        return bool(machine_claims or machine_activities)
    # No AI actor named: the record must not describe machine work either.
    return not machine_claims and not machine_activities


def _decisions_and_validation_evidenced(attestation: ProcessAttestation) -> bool:
    """Whether consequential choices and checks are backed rather than asserted."""

    if not attestation.decisions or not attestation.validations:
        return False
    decisions_backed = all(
        decision.evidence_ids or decision.rationale or decision.rationale_commitment
        for decision in attestation.decisions
    )
    validations_backed = all(
        validation.evidence_ids or validation.outcome_sha256
        for validation in attestation.validations
    )
    return decisions_backed and validations_backed


# -- evaluation profiles -----------------------------------------------------------


class DimensionRequirement(FrozenModel):
    """What one profile expects of one dimension."""

    dimension: ContributionDimension
    #: Relative importance in this context. Exposed, never hidden inside a score.
    weight: float = Field(ge=0.0, le=1.0)
    minimum_level: ContributionLevel = ContributionLevel.NOT_CLAIMED
    minimum_evidence: EvidenceStatus = EvidenceStatus.SELF_DECLARED
    #: Autonomy values this profile refuses for this dimension. An education
    #: profile can forbid delegated execution for an assignment.
    forbidden_autonomy: frozenset[AiAutonomy] = frozenset()
    required: bool = False


class DimensionOutcome(FrozenModel):
    """How one dimension fared against one profile."""

    dimension: ContributionDimension
    weight: float
    claimed: bool
    satisfied: bool
    level: ContributionLevel | None = None
    evidence_status: EvidenceStatus | None = None
    ai_autonomy: AiAutonomy | None = None
    explanation: str


class EvaluationProfile(FrozenModel):
    """One context's versioned, inspectable opinion about what matters.

    Weights and thresholds are fields, not constants buried in code, because a
    profile that will not show its weights is asking to be trusted rather than
    checked.
    """

    schema_version: Literal["0.1"] = EVALUATION_SCHEMA_VERSION
    profile_id: str = Field(min_length=1, max_length=120)
    version: str = Field(min_length=1, max_length=40)
    description: str = Field(min_length=1, max_length=1000)
    requirements: tuple[DimensionRequirement, ...]
    minimum_assurance: ProcessAssuranceLevel = ProcessAssuranceLevel.DECLARED

    def requirement_for(self, dimension: ContributionDimension) -> DimensionRequirement | None:
        """Return this profile's expectation for a dimension, if it has one."""

        for requirement in self.requirements:
            if requirement.dimension == dimension:
                return requirement
        return None


class ProfileResult(FrozenModel):
    """What one profile concluded, with everything it used to conclude it."""

    schema_version: Literal["0.1"] = EVALUATION_SCHEMA_VERSION
    profile_id: str
    profile_version: str
    #: A policy decision about review requirements. Never a statement about
    #: authorship, and deliberately not renameable to one.
    meets_review_requirements: bool
    assurance: AssuranceAssessment
    outcomes: tuple[DimensionOutcome, ...] = ()
    unmet_requirements: tuple[str, ...] = ()
    #: The weights that produced this result, so a reader can disagree with them.
    weights: dict[str, float] = Field(default_factory=dict)

    @property
    def statement(self) -> str:
        """Return the one sentence this result licenses, and no stronger one."""

        verdict = "meets" if self.meets_review_requirements else "does not meet"
        return (
            f"This record {verdict} the review requirements of profile "
            f"{self.profile_id} {self.profile_version}, at assurance "
            f"{self.assurance.level.value}. This is a policy result about process "
            f"evidence, not a determination of authorship or originality."
        )


def evaluate_with_profile(
    attestation: ProcessAttestation,
    verification: AttestationVerification,
    profile: EvaluationProfile,
) -> ProfileResult:
    """Apply one profile's expectations to a record."""

    assurance = assess_process_assurance(attestation, verification)
    outcomes: list[DimensionOutcome] = []
    unmet: list[str] = []

    for requirement in profile.requirements:
        claims = attestation.claims_for(requirement.dimension)
        best = _strongest_claim(claims)
        if best is None:
            satisfied = not requirement.required
            outcomes.append(
                DimensionOutcome(
                    dimension=requirement.dimension,
                    weight=requirement.weight,
                    claimed=False,
                    satisfied=satisfied,
                    explanation=(
                        "Not claimed, and this profile requires it."
                        if requirement.required
                        else "Not claimed; this profile does not require it."
                    ),
                )
            )
            if not satisfied:
                unmet.append(f"{requirement.dimension.value}: the profile requires a claim")
            continue

        problems: list[str] = []
        if _LEVEL_ORDER[best.level] < _LEVEL_ORDER[requirement.minimum_level]:
            problems.append(
                f"level {best.level.value} is below the required {requirement.minimum_level.value}"
            )
        if _EVIDENCE_ORDER[best.evidence_status] < _EVIDENCE_ORDER[requirement.minimum_evidence]:
            problems.append(
                f"evidence {best.evidence_status.value} is below the required "
                f"{requirement.minimum_evidence.value}"
            )
        if best.ai_autonomy in requirement.forbidden_autonomy:
            problems.append(
                f"this profile does not permit {best.ai_autonomy.value} for this dimension"
            )
        satisfied = not problems
        outcomes.append(
            DimensionOutcome(
                dimension=requirement.dimension,
                weight=requirement.weight,
                claimed=True,
                satisfied=satisfied,
                level=best.level,
                evidence_status=best.evidence_status,
                ai_autonomy=best.ai_autonomy,
                explanation="Meets this profile." if satisfied else "; ".join(problems),
            )
        )
        if not satisfied:
            unmet.append(f"{requirement.dimension.value}: " + "; ".join(problems))

    if _PAL_ORDER.index(assurance.level) < _PAL_ORDER.index(profile.minimum_assurance):
        unmet.append(
            f"assurance {assurance.level.value} is below the profile minimum "
            f"{profile.minimum_assurance.value}"
        )

    return ProfileResult(
        profile_id=profile.profile_id,
        profile_version=profile.version,
        meets_review_requirements=not unmet,
        assurance=assurance,
        outcomes=tuple(outcomes),
        unmet_requirements=tuple(unmet),
        weights={
            requirement.dimension.value: requirement.weight for requirement in profile.requirements
        },
    )


def _strongest_claim(claims: tuple[ContributionClaim, ...]) -> ContributionClaim | None:
    """Return the best-supported claim about a dimension.

    Competing claims are kept in the record; a profile has to pick one to judge
    against, and picking the strongest is the reading most favourable to the
    claimant, which is the right default when the alternative is silent rejection.
    """

    if not claims:
        return None
    return max(
        claims,
        key=lambda claim: (
            _EVIDENCE_ORDER[claim.evidence_status],
            _LEVEL_ORDER[claim.level],
            claim.claim_type == ClaimType.ASSESSMENT,
        ),
    )


# -- built-in profiles -------------------------------------------------------------


def _requirement(
    dimension: ContributionDimension,
    weight: float,
    *,
    minimum_level: ContributionLevel = ContributionLevel.NOT_CLAIMED,
    minimum_evidence: EvidenceStatus = EvidenceStatus.SELF_DECLARED,
    forbidden_autonomy: frozenset[AiAutonomy] = frozenset(),
    required: bool = False,
) -> DimensionRequirement:
    return DimensionRequirement(
        dimension=dimension,
        weight=weight,
        minimum_level=minimum_level,
        minimum_evidence=minimum_evidence,
        forbidden_autonomy=forbidden_autonomy,
        required=required,
    )


RESEARCH_PROFILE = EvaluationProfile(
    profile_id="research",
    version="0.1",
    description=(
        "Emphasises origination, prior-art discipline, experimental validation, and "
        "reproducibility. Execution may be delegated; the claim about the idea may not be "
        "unsupported."
    ),
    requirements=(
        _requirement(
            ContributionDimension.ORIGINATION,
            1.0,
            minimum_level=ContributionLevel.SUBSTANTIAL,
            required=True,
        ),
        _requirement(ContributionDimension.FRAMING, 0.7),
        _requirement(
            ContributionDimension.VALIDATION,
            0.9,
            minimum_level=ContributionLevel.PRIMARY,
            minimum_evidence=EvidenceStatus.ARTIFACT_CORRELATED,
            required=True,
        ),
        _requirement(ContributionDimension.EXECUTION, 0.3),
        _requirement(
            ContributionDimension.ACCOUNTABILITY,
            0.8,
            minimum_level=ContributionLevel.PRIMARY,
            required=True,
        ),
    ),
    minimum_assurance=ProcessAssuranceLevel.EVIDENCED,
)

SOFTWARE_DELIVERY_PROFILE = EvaluationProfile(
    profile_id="software-delivery",
    version="0.1",
    description=(
        "Emphasises framing, architecture decisions, review, testing, and accountable release. "
        "Delegated execution is expected and unremarkable; unreviewed delegated execution is not."
    ),
    requirements=(
        _requirement(
            ContributionDimension.FRAMING,
            0.8,
            minimum_level=ContributionLevel.SUBSTANTIAL,
            required=True,
        ),
        _requirement(
            ContributionDimension.DECISION_CONTROL,
            0.9,
            minimum_level=ContributionLevel.PRIMARY,
            minimum_evidence=EvidenceStatus.ARTIFACT_CORRELATED,
            required=True,
        ),
        _requirement(
            ContributionDimension.VALIDATION,
            1.0,
            minimum_level=ContributionLevel.PRIMARY,
            minimum_evidence=EvidenceStatus.ARTIFACT_CORRELATED,
            required=True,
        ),
        _requirement(ContributionDimension.EXECUTION, 0.4),
        _requirement(ContributionDimension.INTEGRATION, 0.6),
        _requirement(
            ContributionDimension.ACCOUNTABILITY,
            0.9,
            minimum_level=ContributionLevel.PRIMARY,
            required=True,
        ),
    ),
    minimum_assurance=ProcessAssuranceLevel.REVIEWED,
)

CREATIVE_WORK_PROFILE = EvaluationProfile(
    profile_id="creative-work",
    version="0.1",
    description=(
        "Emphasises concept, selection, composition, transformation, and rights. Execution "
        "autonomy is disclosed rather than penalised."
    ),
    requirements=(
        _requirement(
            ContributionDimension.ORIGINATION,
            1.0,
            minimum_level=ContributionLevel.SUBSTANTIAL,
            required=True,
        ),
        _requirement(
            ContributionDimension.DECISION_CONTROL,
            0.9,
            minimum_level=ContributionLevel.SUBSTANTIAL,
            required=True,
        ),
        _requirement(ContributionDimension.INTEGRATION, 0.7),
        _requirement(
            ContributionDimension.ACCOUNTABILITY,
            0.8,
            minimum_level=ContributionLevel.PRIMARY,
            required=True,
        ),
    ),
    minimum_assurance=ProcessAssuranceLevel.DECLARED,
)

EDUCATION_PROFILE = EvaluationProfile(
    profile_id="education",
    version="0.1",
    description=(
        "For assignments where the point is demonstrated understanding. Execution must be the "
        "learner's own, so delegated and autonomous execution are refused for that dimension. "
        "This profile is about one assignment's rules, not about whether a learner is honest."
    ),
    requirements=(
        _requirement(
            ContributionDimension.EXECUTION,
            1.0,
            minimum_level=ContributionLevel.PRIMARY,
            forbidden_autonomy=frozenset(
                {AiAutonomy.DELEGATED_EXECUTION, AiAutonomy.AUTONOMOUS_WITH_REVIEW}
            ),
            required=True,
        ),
        _requirement(
            ContributionDimension.VALIDATION,
            0.8,
            minimum_level=ContributionLevel.SUBSTANTIAL,
            required=True,
        ),
        _requirement(ContributionDimension.ORIGINATION, 0.6),
        _requirement(
            ContributionDimension.ACCOUNTABILITY,
            0.7,
            minimum_level=ContributionLevel.PRIMARY,
            required=True,
        ),
    ),
    minimum_assurance=ProcessAssuranceLevel.DECLARED,
)

REGULATED_ENTERPRISE_PROFILE = EvaluationProfile(
    profile_id="regulated-enterprise",
    version="0.1",
    description=(
        "Emphasises authorised tools, human approval, validation controls, and responsibility "
        "rather than stylistic authorship. Who signed off matters more than who typed."
    ),
    requirements=(
        _requirement(
            ContributionDimension.ACCOUNTABILITY,
            1.0,
            minimum_level=ContributionLevel.ORIGINATING_OR_CONTROLLING,
            minimum_evidence=EvidenceStatus.COUNTERSIGNED,
            required=True,
        ),
        _requirement(
            ContributionDimension.DECISION_CONTROL,
            0.9,
            minimum_level=ContributionLevel.PRIMARY,
            minimum_evidence=EvidenceStatus.ARTIFACT_CORRELATED,
            required=True,
        ),
        _requirement(
            ContributionDimension.VALIDATION,
            1.0,
            minimum_level=ContributionLevel.PRIMARY,
            minimum_evidence=EvidenceStatus.ARTIFACT_CORRELATED,
            required=True,
        ),
        _requirement(ContributionDimension.EXECUTION, 0.2),
        _requirement(ContributionDimension.EVIDENCE_QUALITY, 0.8),
    ),
    minimum_assurance=ProcessAssuranceLevel.REVIEWED,
)

BUILT_IN_PROFILES: dict[str, EvaluationProfile] = {
    profile.profile_id: profile
    for profile in (
        RESEARCH_PROFILE,
        SOFTWARE_DELIVERY_PROFILE,
        CREATIVE_WORK_PROFILE,
        EDUCATION_PROFILE,
        REGULATED_ENTERPRISE_PROFILE,
    )
}


def get_profile(profile_id: str) -> EvaluationProfile:
    """Return a built-in profile by name."""

    try:
        return BUILT_IN_PROFILES[profile_id]
    except KeyError as exc:
        available = ", ".join(sorted(BUILT_IN_PROFILES))
        raise KeyError(f"Unknown profile {profile_id!r}; available: {available}") from exc


# -- presentation ------------------------------------------------------------------


def stage_summary(attestation: ProcessAttestation) -> str:
    """Describe the stage split in words, precisely and without upgrading it.

    Produces phrases like "human-originated, AI-executed, human-validated". Each
    part names a stage and who carried it; none of them says "human-authored",
    because no combination of stage claims establishes that.
    """

    from trueai.core.attestation import ActorKind

    actors = {actor.id: actor for actor in attestation.actors}
    parts: list[str] = []
    labels = {
        ContributionDimension.ORIGINATION: "originated",
        ContributionDimension.FRAMING: "framed",
        ContributionDimension.DECISION_CONTROL: "directed",
        ContributionDimension.EXECUTION: "executed",
        ContributionDimension.VALIDATION: "validated",
        ContributionDimension.INTEGRATION: "integrated",
        ContributionDimension.ACCOUNTABILITY: "owned",
    }
    for dimension, label in labels.items():
        claim = _strongest_claim(attestation.claims_for(dimension))
        if claim is None or claim.level == ContributionLevel.NOT_CLAIMED:
            continue
        actor = actors.get(claim.actor_id)
        who = "AI" if actor and actor.kind == ActorKind.AI_SYSTEM else "human"
        parts.append(f"{who}-{label}")
    return ", ".join(parts) if parts else "no stage claims"


def portable_summary(
    attestation: ProcessAttestation,
    verification: AttestationVerification,
    profile: EvaluationProfile | None = None,
) -> str:
    """Render the compact summary a recipient can read without training.

    Every line is a separate fact. There is no headline verdict, and the
    limitations are part of the summary rather than a footnote someone can crop.
    """

    result = (
        evaluate_with_profile(attestation, verification, profile) if profile is not None else None
    )
    assurance = result.assurance if result else assess_process_assurance(attestation, verification)

    lines = [f"TrueAI Process Attestation: {attestation.attestation_id}"]
    binding = {True: "verified", False: "FAILED", None: "not checked"}[verification.subject_bound]
    lines.append(f"Artifact binding: {binding}")
    lines.append(f"Process summary: {stage_summary(attestation)}")

    for dimension in ContributionDimension:
        claim = _strongest_claim(attestation.claims_for(dimension))
        if claim is None:
            continue
        lines.append(
            f"{dimension.value.replace('_', ' ').title()}: "
            f"{claim.level.value} / {claim.evidence_status.value}"
            + (f" / ai={claim.ai_autonomy.value}" if claim.ai_autonomy != AiAutonomy.NONE else "")
        )

    lines.append(f"Process Assurance Level: {assurance.level.value} — {assurance.meaning}")
    if result is not None:
        lines.append(result.statement)
    identity = verification.claimant_identity
    if identity is not None and identity.names_an_organization:
        lines.append(f"Issuer: {identity.organization} ({identity.assurance.value})")
    else:
        lines.append("Issuer: a key, not an identified organization")
    if attestation.evaluation is None:
        lines.append("Originality: not independently assessed")

    lines.append("Limitations:")
    for limitation in attestation.limitations:
        lines.append(f"  - {limitation.statement}")
    return "\n".join(lines)


def sarif_properties(
    attestation: ProcessAttestation,
    verification: AttestationVerification,
) -> dict[str, object]:
    """Return attestation facts for a SARIF run's property bag.

    Flat, typed, and named so a CI dashboard cannot present them as an authorship
    verdict: the keys say what was established, not what it means.
    """

    assurance = assess_process_assurance(attestation, verification)
    return {
        "trueaiAttestationId": attestation.attestation_id,
        "trueaiAttestationSubjectBound": verification.subject_bound,
        "trueaiAttestationAuthenticatedDeclaration": verification.authenticated_declaration,
        "trueaiAttestationOrganizationallyAttributed": (verification.organizationally_attributed),
        "trueaiProcessAssuranceLevel": assurance.level.value,
        "trueaiProcessStageSummary": stage_summary(attestation),
        "trueaiAttestationLimitations": [
            limitation.statement for limitation in attestation.limitations
        ],
    }
