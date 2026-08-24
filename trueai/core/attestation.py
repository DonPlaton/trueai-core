"""Human Contribution Records: who did what, with which evidence, and how strongly.

A `TAI1-…` audit certificate says what a scanner observed in exact bytes. This
module is the other half: a `TAIP1-…` process attestation says who originated,
framed, decided, executed, validated, integrated, and took responsibility for the
work that produced those bytes — and how well each of those claims is supported.

The two must never be merged. Finding no AI residue cannot populate
``execution=human``; finding a provider marker cannot erase a documented human
origination claim. A scan is forensics about an artifact; an attestation is
accountable workflow provenance about a process.

Three design decisions carry most of the weight, and all three exist to stop the
record from claiming more than it knows.

**Contribution is a vector, never a percentage.** Eight independent dimensions
each carry their own level, evidence status, and limitations. A single "human
percentage" would hide which stages were human-controlled and manufacture false
precision, so this module has no function that produces one.

**Claim type is separate from claim content.** A machine-verifiable fact, a signed
declaration, and an evaluator's judgement are different kinds of statement even
when they concern the same dimension. Collapsing them lets a signature launder an
opinion into a fact, so :class:`ClaimType` travels with every claim.

**AI autonomy is a per-stage property, not the inverse of human value.** A record
can say that execution was delegated to a model while origination, framing,
selection, validation, and accountability stayed human. A linear human-versus-AI
slider cannot represent real collaborative work.

Verification returns independent results rather than one badge. A valid signature
over ``self_declared`` evidence is an *authenticated declaration*, which is a
materially weaker statement than a verified contribution, and the result model
keeps those apart.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import Field, model_validator

from trueai._version import PACKAGE_VERSION
from trueai.core.certificates import (
    CertificateSignature,
    canonical_json_bytes,
    sign_detached_payload,
    verify_detached_payload,
)
from trueai.core.errors import AttestationError
from trueai.core.models import FrozenModel

ATTESTATION_SCHEMA_VERSION: Literal["0.1"] = "0.1"
ATTESTATION_ID_PREFIX = "TAIP1-"
_MAX_ATTESTATION_FILE_BYTES = 8 * 1024 * 1024


class ActorKind(StrEnum):
    """What kind of participant a record names."""

    PERSON = "person"
    ORGANIZATION = "organization"
    AI_SYSTEM = "ai_system"
    AUTOMATION = "automation"


class ContributionDimension(StrEnum):
    """Independent aspects of contributing to a result.

    They are deliberately not comparable to each other. Averaging them would
    reintroduce the aggregate score this model exists to avoid.
    """

    #: Who introduced the central insight, hypothesis, direction, or invention.
    ORIGINATION = "origination"
    #: Who turned the idea into constraints, requirements, and success criteria.
    FRAMING = "framing"
    #: Who compared alternatives and made the consequential choices.
    DECISION_CONTROL = "decision_control"
    #: Who or what produced the concrete prose, code, design, data, or media.
    EXECUTION = "execution"
    #: Who tested claims against reality rather than accepting generation.
    VALIDATION = "validation"
    #: Who reconciled components and adapted the result to its real context.
    INTEGRATION = "integration"
    #: Which person or organization accepts responsibility for the delivery.
    ACCOUNTABILITY = "accountability"
    #: How strongly the preceding claims are supported.
    EVIDENCE_QUALITY = "evidence_quality"


class ContributionLevel(StrEnum):
    """Descriptive strength of one actor's contribution to one dimension."""

    NOT_CLAIMED = "not_claimed"
    SUPPORTING = "supporting"
    SUBSTANTIAL = "substantial"
    PRIMARY = "primary"
    ORIGINATING_OR_CONTROLLING = "originating_or_controlling"


class EvidenceStatus(StrEnum):
    """How well a claim is corroborated, independent of how strong the claim is."""

    SELF_DECLARED = "self_declared"
    ARTIFACT_CORRELATED = "artifact_correlated"
    COUNTERSIGNED = "countersigned"
    INDEPENDENTLY_ASSESSED = "independently_assessed"
    CRYPTOGRAPHICALLY_VERIFIED = "cryptographically_verified"


class AiAutonomy(StrEnum):
    """How much of a stage a machine carried out, as a per-stage property."""

    NONE = "none"
    ASSISTIVE = "assistive"
    PROPOSAL = "proposal"
    DELEGATED_EXECUTION = "delegated_execution"
    AUTONOMOUS_WITH_REVIEW = "autonomous_with_review"


class ClaimType(StrEnum):
    """What kind of statement a claim is.

    Keeping these apart is what stops a valid signature over a subjective
    novelty claim from reading as an established fact.
    """

    #: Derived from bound artifacts or receipts a verifier can recompute.
    MACHINE_FACT = "machine_fact"
    #: Asserted by an identified actor who signed it.
    DECLARATION = "declaration"
    #: A judgement issued by an assessor under a named rubric.
    ASSESSMENT = "assessment"


class EvidenceKind(StrEnum):
    """Typed local evidence a record may reference by hash."""

    GIT_COMMIT = "git_commit"
    REVIEWED_DIFF = "reviewed_diff"
    TEST_RUN = "test_run"
    BUILD_RECEIPT = "build_receipt"
    RESEARCH_NOTE = "research_note"
    SOURCE_CITATION = "source_citation"
    APPROVAL = "approval"
    EXTERNAL_RECEIPT = "external_receipt"
    TOOL_IDENTITY = "tool_identity"
    SCAN_REPORT = "scan_report"
    AUDIT_CERTIFICATE = "audit_certificate"
    OTHER = "other"


class DisclosureStatus(StrEnum):
    """Whether the referenced material travels with the record."""

    #: The reference and its locator are in the public record.
    PUBLIC = "public"
    #: The hash is public; the material stays local.
    PRIVATE = "private"
    #: A commitment is published so the material can be revealed and checked later.
    COMMITTED = "committed"
    #: Deliberately left out, with a stated reason.
    OMITTED = "omitted"


class BindingRole(StrEnum):
    """Where an artifact sits in the derivation."""

    INPUT = "input"
    INTERMEDIATE = "intermediate"
    OUTPUT = "output"
    REFERENCE = "reference"


class SignatureRole(StrEnum):
    """Which statement a signature attests to."""

    CLAIMANT = "claimant"
    REVIEWER = "reviewer"
    ORGANIZATION = "organization"
    ASSESSOR = "assessor"


class ReviewDecision(StrEnum):
    """What happened to an activity's output when someone looked at it."""

    NOT_REVIEWED = "not_reviewed"
    ACCEPTED = "accepted"
    ACCEPTED_WITH_CHANGES = "accepted_with_changes"
    REJECTED = "rejected"


#: Limitations that every record carries because they are true of every record.
#: They are not boilerplate to be trimmed: each one names something a reader
#: could otherwise wrongly infer from a valid signature.
STANDING_LIMITATIONS: tuple[tuple[str, str], ...] = (
    (
        "completeness_is_declared",
        "Process completeness is a declared scope. No technical system can prove that every "
        "offline human action was recorded.",
    ),
    (
        "no_exclusive_authorship",
        "This record does not prove exclusive human authorship, and it does not assert that AI "
        "was not used.",
    ),
    (
        "signature_is_not_truth",
        "A valid signature proves who signed which bytes. It does not make a subjective claim "
        "about originality or contribution objectively true.",
    ),
    (
        "no_aggregate_score",
        "Contribution is reported per dimension. This record contains no overall human "
        "percentage, and one must not be derived from it.",
    ),
)


class Actor(FrozenModel):
    """A participant: a person, an organization, a model, or an automation."""

    id: str = Field(min_length=1, max_length=120)
    kind: ActorKind
    display_name: str | None = Field(default=None, max_length=200)
    #: An organizational or directory identifier, when the actor is not pseudonymous.
    identifier: str | None = Field(default=None, max_length=300)
    #: Model or tool version, for AI systems and automation.
    version: str | None = Field(default=None, max_length=120)
    #: The public key that signatures from this actor should verify against.
    public_key: str | None = None
    pseudonymous: bool = False

    @model_validator(mode="after")
    def require_identity_for_named_actors(self) -> Self:
        """A pseudonymous actor must not also carry a directory identifier."""

        if self.pseudonymous and self.identifier:
            raise ValueError("A pseudonymous actor cannot also declare an identifier")
        return self


class ArtifactBinding(FrozenModel):
    """One artifact the record is bound to, by exact digest."""

    id: str = Field(min_length=1, max_length=120)
    role: BindingRole
    #: A stable label. For an output this is normally the delivered file name.
    name: str = Field(min_length=1, max_length=500)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    media_type: str | None = None
    size: int | None = Field(default=None, ge=0)
    #: How this artifact relates to others, for example "derived from input-1".
    relationship: str | None = Field(default=None, max_length=500)


class EvidenceReference(FrozenModel):
    """A pointer to supporting material, recorded by hash rather than by copy.

    Raw prompts, proprietary sources, credentials, and personal data stay local by
    default. What travels is the digest and, when the holder chooses, a
    commitment that lets them reveal the material later and prove it is the same.
    """

    id: str = Field(min_length=1, max_length=120)
    kind: EvidenceKind
    description: str = Field(min_length=1, max_length=1000)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    issuer: str | None = Field(default=None, max_length=300)
    collection_method: str | None = Field(default=None, max_length=300)
    disclosure: DisclosureStatus = DisclosureStatus.PRIVATE
    #: Present only for public evidence. A locator on private evidence would
    #: defeat the point of keeping it private.
    locator: str | None = Field(default=None, max_length=1000)
    #: A salted commitment for material intended for later selective disclosure.
    commitment: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    #: Why the material was left out, required when the disclosure is OMITTED.
    omission_reason: str | None = Field(default=None, max_length=500)

    @model_validator(mode="after")
    def enforce_disclosure_consistency(self) -> Self:
        """Keep each disclosure status meaning exactly what it says."""

        if self.disclosure != DisclosureStatus.PUBLIC and self.locator:
            raise ValueError(
                "Only public evidence may carry a locator; a locator on private or committed "
                "evidence discloses what the status says is withheld"
            )
        if self.disclosure == DisclosureStatus.COMMITTED and not self.commitment:
            raise ValueError("Committed evidence must carry a commitment digest")
        if self.disclosure == DisclosureStatus.OMITTED and not self.omission_reason:
            raise ValueError("Omitted evidence must state why it was omitted")
        if self.disclosure == DisclosureStatus.OMITTED and self.sha256:
            raise ValueError(
                "Omitted evidence must not carry a digest; record it as private instead"
            )
        return self


class Activity(FrozenModel):
    """One derivation event: an actor acted on inputs and produced outputs."""

    id: str = Field(min_length=1, max_length=120)
    action: str = Field(min_length=1, max_length=300)
    actor_ids: tuple[str, ...] = Field(min_length=1)
    started_at: datetime | None = None
    ended_at: datetime | None = None
    input_binding_ids: tuple[str, ...] = ()
    output_binding_ids: tuple[str, ...] = ()
    #: How much of this activity the machine carried out.
    ai_autonomy: AiAutonomy = AiAutonomy.NONE
    evidence_ids: tuple[str, ...] = ()
    review_decision: ReviewDecision = ReviewDecision.NOT_REVIEWED
    reviewer_actor_id: str | None = None
    description: str | None = Field(default=None, max_length=2000)
    #: Set when this activity was an attempt that was not carried forward. A
    #: record that hides rejected attempts describes a process that did not happen.
    superseded: bool = False


class Decision(FrozenModel):
    """A consequential choice, with what it was chosen over."""

    id: str = Field(min_length=1, max_length=120)
    question: str = Field(min_length=1, max_length=1000)
    alternatives: tuple[str, ...] = ()
    selected: str = Field(min_length=1, max_length=1000)
    #: A digest of the private rationale, so it can be revealed and checked later.
    rationale_commitment: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    rationale: str | None = Field(default=None, max_length=4000)
    approving_actor_id: str | None = None
    evidence_ids: tuple[str, ...] = ()


class ValidationRecord(FrozenModel):
    """Something that was checked against reality, and what came back."""

    id: str = Field(min_length=1, max_length=120)
    kind: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1, max_length=1000)
    outcome: str = Field(min_length=1, max_length=1000)
    outcome_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    performed_by_actor_id: str | None = None
    evidence_ids: tuple[str, ...] = ()


class ContributionClaim(FrozenModel):
    """One actor's contribution to one dimension, with its own support level."""

    dimension: ContributionDimension
    actor_id: str = Field(min_length=1, max_length=120)
    claim_type: ClaimType
    level: ContributionLevel
    evidence_status: EvidenceStatus
    ai_autonomy: AiAutonomy = AiAutonomy.NONE
    #: What part of the work this claim covers, when it is not the whole subject.
    scope: str | None = Field(default=None, max_length=500)
    explanation: str = Field(min_length=1, max_length=4000)
    evidence_ids: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def require_support_for_strong_claims(self) -> Self:
        """A machine fact must point at something a verifier can recompute."""

        if self.claim_type == ClaimType.MACHINE_FACT and not self.evidence_ids:
            raise ValueError(
                "A machine_fact claim must reference the evidence a verifier recomputes; "
                "without it the claim is a declaration"
            )
        if (
            self.claim_type == ClaimType.DECLARATION
            and self.evidence_status == EvidenceStatus.INDEPENDENTLY_ASSESSED
        ):
            raise ValueError(
                "A declaration cannot claim independent assessment; record the assessment as "
                "a separate claim with claim_type=assessment"
            )
        return self


class DimensionAssessment(FrozenModel):
    """An assessor's per-dimension result under a named rubric."""

    dimension: ContributionDimension
    level: ContributionLevel
    confidence: str = Field(min_length=1, max_length=120)
    rationale: str | None = Field(default=None, max_length=2000)
    dissent: str | None = Field(default=None, max_length=2000)


class Evaluation(FrozenModel):
    """An optional judgement produced under a versioned, domain-specific profile."""

    profile: str = Field(min_length=1, max_length=120)
    rubric_version: str = Field(min_length=1, max_length=40)
    assessor_actor_id: str = Field(min_length=1, max_length=120)
    assessed_at: datetime
    results: tuple[DimensionAssessment, ...] = ()
    evidence_confidence: str | None = Field(default=None, max_length=200)
    dissent: str | None = Field(default=None, max_length=2000)


class Limitation(FrozenModel):
    """Something the record does not establish, in both machine and human form."""

    code: str = Field(min_length=1, max_length=120)
    statement: str = Field(min_length=1, max_length=1000)


class AttestationSignature(FrozenModel):
    """One signed statement over the record."""

    role: SignatureRole
    actor_id: str = Field(min_length=1, max_length=120)
    signed_at: datetime
    signature: CertificateSignature


class ProcessAttestation(FrozenModel):
    """A signed, content-bound record of how an artifact came to exist."""

    attestation_id: str = Field(pattern=r"^TAIP1-[A-Z2-7]{32}$")
    schema_version: Literal["0.1"] = ATTESTATION_SCHEMA_VERSION
    producer: str = PACKAGE_VERSION
    created_at: datetime
    expires_at: datetime | None = None

    #: What the record is about: the exact bytes, or a repository inventory digest.
    subject_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    subject_name: str = Field(min_length=1, max_length=500)
    subject_is_inventory: bool = False

    project_title: str | None = Field(default=None, max_length=300)
    project_purpose: str | None = Field(default=None, max_length=2000)
    policy_context: str | None = Field(default=None, max_length=300)
    parent_attestation_id: str | None = Field(default=None, pattern=r"^TAIP1-[A-Z2-7]{32}$")

    actors: tuple[Actor, ...] = Field(min_length=1)
    artifact_bindings: tuple[ArtifactBinding, ...] = ()
    activities: tuple[Activity, ...] = ()
    decisions: tuple[Decision, ...] = ()
    validations: tuple[ValidationRecord, ...] = ()
    evidence: tuple[EvidenceReference, ...] = ()
    claims: tuple[ContributionClaim, ...] = ()
    evaluation: Evaluation | None = None
    limitations: tuple[Limitation, ...] = Field(min_length=1)
    signatures: tuple[AttestationSignature, ...] = ()

    @model_validator(mode="after")
    def enforce_referential_integrity(self) -> Self:
        """Every cross-reference must resolve, or the graph is decorative."""

        actor_ids = {actor.id for actor in self.actors}
        if len(actor_ids) != len(self.actors):
            raise ValueError("Actor identifiers must be unique")
        binding_ids = {binding.id for binding in self.artifact_bindings}
        if len(binding_ids) != len(self.artifact_bindings):
            raise ValueError("Artifact binding identifiers must be unique")
        evidence_ids = {item.id for item in self.evidence}
        if len(evidence_ids) != len(self.evidence):
            raise ValueError("Evidence identifiers must be unique")

        def require_actor(actor_id: str | None, where: str) -> None:
            if actor_id is not None and actor_id not in actor_ids:
                raise ValueError(f"{where} references unknown actor {actor_id!r}")

        def require_evidence(ids: tuple[str, ...], where: str) -> None:
            for evidence_id in ids:
                if evidence_id not in evidence_ids:
                    raise ValueError(f"{where} references unknown evidence {evidence_id!r}")

        for activity in self.activities:
            for actor_id in activity.actor_ids:
                require_actor(actor_id, f"Activity {activity.id}")
            require_actor(activity.reviewer_actor_id, f"Activity {activity.id}")
            require_evidence(activity.evidence_ids, f"Activity {activity.id}")
            for binding_id in (*activity.input_binding_ids, *activity.output_binding_ids):
                if binding_id not in binding_ids:
                    raise ValueError(
                        f"Activity {activity.id} references unknown binding {binding_id!r}"
                    )
            if (
                activity.started_at
                and activity.ended_at
                and activity.ended_at < activity.started_at
            ):
                raise ValueError(f"Activity {activity.id} ends before it starts")
        for decision in self.decisions:
            require_actor(decision.approving_actor_id, f"Decision {decision.id}")
            require_evidence(decision.evidence_ids, f"Decision {decision.id}")
        for validation in self.validations:
            require_actor(validation.performed_by_actor_id, f"Validation {validation.id}")
            require_evidence(validation.evidence_ids, f"Validation {validation.id}")
        for claim in self.claims:
            require_actor(claim.actor_id, f"Claim {claim.dimension.value}")
            require_evidence(claim.evidence_ids, f"Claim {claim.dimension.value}")
        if self.evaluation is not None:
            require_actor(self.evaluation.assessor_actor_id, "Evaluation")
        for signature in self.signatures:
            require_actor(signature.actor_id, f"Signature {signature.role.value}")

        declared = {limitation.code for limitation in self.limitations}
        missing = [code for code, _ in STANDING_LIMITATIONS if code not in declared]
        if missing:
            raise ValueError(
                "Every record must carry the standing limitations; missing: "
                + ", ".join(sorted(missing))
            )
        if self.expires_at is not None and self.expires_at <= self.created_at:
            raise ValueError("expires_at must be later than created_at")
        return self

    def is_expired(self, now: datetime | None = None) -> bool:
        """Return whether the record has passed its own validity window."""

        if self.expires_at is None:
            return False
        return (now or datetime.now(UTC)) >= self.expires_at

    def claims_for(self, dimension: ContributionDimension) -> tuple[ContributionClaim, ...]:
        """Return every claim about one dimension, including competing ones."""

        return tuple(claim for claim in self.claims if claim.dimension == dimension)


class AttestationVerification(FrozenModel):
    """Independent verification results, deliberately not collapsed into one badge.

    A caller that wants a single answer has to decide which of these matter for
    its own purpose. That decision belongs to the caller, because "good enough"
    differs between a newsroom, a university, and a procurement review.
    """

    attestation_id: str
    schema_valid: bool
    content_id_valid: bool
    subject_bound: bool | None = None
    evidence_binding_complete: bool = False
    claimant_signature: str = "absent"
    reviewer_signature: str = "absent"
    organization_signature: str = "absent"
    assessor_signature: str = "absent"
    expired: bool = False
    evaluation_profile_supported: bool | None = None
    disclosed_evidence_consistent: bool | None = None
    unresolved_dissent: bool = False
    limitations_acknowledged: bool = False
    strongest_evidence_status: EvidenceStatus | None = None
    problems: tuple[str, ...] = ()

    @property
    def authenticated_declaration(self) -> bool:
        """Whether an identified claimant signed this record over these bytes.

        This is the honest ceiling for a self-declared record: someone stood
        behind it. It is not a verified contribution claim, and the property is
        named so that a caller cannot accidentally present it as one.
        """

        return (
            self.schema_valid
            and self.content_id_valid
            and self.claimant_signature == "valid"
            and not self.expired
        )


# -- issuance ----------------------------------------------------------------------


def issue_attestation(
    *,
    subject_sha256: str,
    subject_name: str,
    actors: tuple[Actor, ...],
    claims: tuple[ContributionClaim, ...] = (),
    artifact_bindings: tuple[ArtifactBinding, ...] = (),
    activities: tuple[Activity, ...] = (),
    decisions: tuple[Decision, ...] = (),
    validations: tuple[ValidationRecord, ...] = (),
    evidence: tuple[EvidenceReference, ...] = (),
    evaluation: Evaluation | None = None,
    extra_limitations: tuple[Limitation, ...] = (),
    subject_is_inventory: bool = False,
    project_title: str | None = None,
    project_purpose: str | None = None,
    policy_context: str | None = None,
    parent_attestation_id: str | None = None,
    created_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> ProcessAttestation:
    """Build an unsigned, content-addressed process attestation."""

    limitations = (
        tuple(
            Limitation(code=code, statement=statement) for code, statement in STANDING_LIMITATIONS
        )
        + extra_limitations
    )
    draft = {
        "attestation_id": ATTESTATION_ID_PREFIX + "A" * 32,
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "producer": PACKAGE_VERSION,
        "created_at": created_at or datetime.now(UTC),
        "expires_at": expires_at,
        "subject_sha256": subject_sha256,
        "subject_name": subject_name,
        "subject_is_inventory": subject_is_inventory,
        "project_title": project_title,
        "project_purpose": project_purpose,
        "policy_context": policy_context,
        "parent_attestation_id": parent_attestation_id,
        "actors": actors,
        "artifact_bindings": artifact_bindings,
        "activities": activities,
        "decisions": decisions,
        "validations": validations,
        "evidence": evidence,
        "claims": claims,
        "evaluation": evaluation,
        "limitations": limitations,
        "signatures": (),
    }
    placeholder = ProcessAttestation.model_validate(draft)
    identifier = compute_attestation_id(placeholder)
    return placeholder.model_copy(update={"attestation_id": identifier})


def compute_attestation_id(attestation: ProcessAttestation) -> str:
    """Derive the content identifier from everything except identity and signatures."""

    return _attestation_id(_identity_claims(attestation))


def sign_attestation(
    attestation: ProcessAttestation,
    *,
    role: SignatureRole,
    actor_id: str,
    signing_key: str | Path,
    signed_at: datetime | None = None,
) -> ProcessAttestation:
    """Add one signed statement over the record's canonical bytes."""

    if actor_id not in {actor.id for actor in attestation.actors}:
        raise AttestationError(f"Unknown actor for signature: {actor_id}")
    if any(
        existing.role == role and existing.actor_id == actor_id
        for existing in attestation.signatures
    ):
        raise AttestationError(f"{actor_id} already signed as {role.value}")
    signature = AttestationSignature(
        role=role,
        actor_id=actor_id,
        signed_at=signed_at or datetime.now(UTC),
        signature=sign_detached_payload(signed_payload(attestation), signing_key),
    )
    return attestation.model_copy(update={"signatures": (*attestation.signatures, signature)})


def signed_payload(attestation: ProcessAttestation) -> bytes:
    """Return the canonical bytes every signature covers.

    Signatures are excluded so that a countersignature does not invalidate the
    claimant's signature. Everything else is included, so a changed claim
    invalidates every signature over it.
    """

    payload = attestation.model_dump(mode="json", exclude={"signatures"})
    return canonical_json_bytes(payload)


# -- verification ------------------------------------------------------------------


def verify_attestation(
    attestation: ProcessAttestation,
    *,
    artifact: str | Path | None = None,
    public_keys: dict[str, str | Path] | None = None,
    supported_profiles: frozenset[str] | None = None,
    disclosed_evidence: dict[str, bytes] | None = None,
    now: datetime | None = None,
) -> AttestationVerification:
    """Check every independent property and report them separately."""

    problems: list[str] = []
    content_id_valid = compute_attestation_id(attestation) == attestation.attestation_id
    if not content_id_valid:
        problems.append("The content identifier does not match the record's own claims")

    subject_bound: bool | None = None
    if artifact is not None:
        path = Path(artifact)
        try:
            subject_bound = _sha256_file(path) == attestation.subject_sha256
        except OSError as exc:
            subject_bound = False
            problems.append(f"The subject artifact could not be read: {exc}")
        if subject_bound is False and not problems:
            problems.append("The artifact does not match the bound subject digest")

    keys = public_keys or {}
    statuses = {role: "absent" for role in SignatureRole}
    payload = signed_payload(attestation)
    for signature in attestation.signatures:
        key = keys.get(signature.actor_id)
        if key is None:
            statuses[signature.role] = "unverified"
            continue
        try:
            valid = verify_detached_payload(signature.signature, payload, key)
        except Exception as exc:  # foreign key material is caller-supplied
            statuses[signature.role] = "error"
            problems.append(f"Signature for {signature.actor_id} could not be checked: {exc}")
            continue
        statuses[signature.role] = "valid" if valid else "invalid"
        if not valid:
            problems.append(f"Signature for {signature.actor_id} does not verify")

    evidence_ids = {item.id for item in attestation.evidence}
    referenced = {evidence_id for claim in attestation.claims for evidence_id in claim.evidence_ids}
    evidence_binding_complete = referenced <= evidence_ids
    if not evidence_binding_complete:
        problems.append("A claim references evidence the record does not contain")

    profile_supported: bool | None = None
    if attestation.evaluation is not None:
        profile_supported = (
            supported_profiles is None or attestation.evaluation.profile in supported_profiles
        )
        if not profile_supported:
            problems.append(
                f"Evaluation profile {attestation.evaluation.profile!r} is not supported here, "
                "so its levels cannot be interpreted"
            )

    disclosed_consistent: bool | None = None
    if disclosed_evidence:
        disclosed_consistent = True
        by_id = {item.id: item for item in attestation.evidence}
        for evidence_id, payload_bytes in disclosed_evidence.items():
            reference = by_id.get(evidence_id)
            if reference is None:
                disclosed_consistent = False
                problems.append(f"Disclosed evidence {evidence_id!r} is not in the record")
                continue
            expected = reference.commitment or reference.sha256
            if expected is None:
                disclosed_consistent = False
                problems.append(
                    f"Evidence {evidence_id!r} carries no digest to check the disclosure against"
                )
                continue
            if hashlib.sha256(payload_bytes).hexdigest() != expected:
                disclosed_consistent = False
                problems.append(
                    f"Disclosed evidence {evidence_id!r} does not match its published commitment"
                )

    dissent = bool(
        attestation.evaluation
        and (
            attestation.evaluation.dissent
            or any(result.dissent for result in attestation.evaluation.results)
        )
    )

    declared = {limitation.code for limitation in attestation.limitations}
    limitations_acknowledged = all(code in declared for code, _ in STANDING_LIMITATIONS)

    expired = attestation.is_expired(now)
    if expired:
        problems.append("The record has passed its stated validity window")

    return AttestationVerification(
        attestation_id=attestation.attestation_id,
        schema_valid=True,
        content_id_valid=content_id_valid,
        subject_bound=subject_bound,
        evidence_binding_complete=evidence_binding_complete,
        claimant_signature=statuses[SignatureRole.CLAIMANT],
        reviewer_signature=statuses[SignatureRole.REVIEWER],
        organization_signature=statuses[SignatureRole.ORGANIZATION],
        assessor_signature=statuses[SignatureRole.ASSESSOR],
        expired=expired,
        evaluation_profile_supported=profile_supported,
        disclosed_evidence_consistent=disclosed_consistent,
        unresolved_dissent=dissent,
        limitations_acknowledged=limitations_acknowledged,
        strongest_evidence_status=_strongest_evidence_status(attestation),
        problems=tuple(problems),
    )


# -- serialization -----------------------------------------------------------------


def attestation_json(attestation: ProcessAttestation) -> str:
    """Serialize a record deterministically."""

    return json.dumps(
        attestation.model_dump(mode="json"),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )


def load_attestation(path: str | Path) -> ProcessAttestation:
    """Read and validate a record from disk within a bounded read."""

    source = Path(path)
    size = source.stat().st_size
    if size > _MAX_ATTESTATION_FILE_BYTES:
        raise AttestationError(
            f"Attestation file is {size} bytes; limit is {_MAX_ATTESTATION_FILE_BYTES}"
        )
    try:
        raw: Any = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AttestationError(f"Unable to read attestation: {exc}") from exc
    try:
        return ProcessAttestation.model_validate(raw)
    except Exception as exc:
        raise AttestationError(f"Invalid attestation: {exc}") from exc


def attestation_schema() -> dict[str, Any]:
    """Return the JSON Schema of the public process-attestation contract."""

    return ProcessAttestation.model_json_schema(mode="serialization")


def attestation_schema_json() -> str:
    """Return the process-attestation schema as canonical JSON text."""

    return json.dumps(attestation_schema(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"


# -- internals ---------------------------------------------------------------------


_EVIDENCE_STRENGTH: dict[EvidenceStatus, int] = {
    EvidenceStatus.SELF_DECLARED: 0,
    EvidenceStatus.ARTIFACT_CORRELATED: 1,
    EvidenceStatus.COUNTERSIGNED: 2,
    EvidenceStatus.INDEPENDENTLY_ASSESSED: 3,
    EvidenceStatus.CRYPTOGRAPHICALLY_VERIFIED: 4,
}


def _strongest_evidence_status(attestation: ProcessAttestation) -> EvidenceStatus | None:
    """Return the best-supported claim's status, for presentation only.

    This is not a score. It answers "what is the strongest support anywhere in
    this record", which a reader needs in order to not over-read a weak record,
    and it deliberately says nothing about the other claims.
    """

    if not attestation.claims:
        return None
    return max(
        (claim.evidence_status for claim in attestation.claims),
        key=lambda status: _EVIDENCE_STRENGTH[status],
    )


def _identity_claims(attestation: ProcessAttestation) -> dict[str, Any]:
    payload = attestation.model_dump(
        mode="json", exclude={"attestation_id", "signatures", "producer"}
    )
    return payload


def _attestation_id(claims: dict[str, Any]) -> str:
    digest = hashlib.sha256(canonical_json_bytes(claims)).digest()
    token = base64.b32encode(digest[:20]).decode("ascii").rstrip("=")
    return f"{ATTESTATION_ID_PREFIX}{token}"


def _sha256_file(path: Path) -> str:
    reader = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            reader.update(chunk)
    return reader.hexdigest()
