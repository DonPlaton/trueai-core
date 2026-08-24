"""Process attestations: the claim model, its refusals, and its verification results."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trueai.core.attestation import (
    STANDING_LIMITATIONS,
    Activity,
    Actor,
    ActorKind,
    AiAutonomy,
    ArtifactBinding,
    AttestationVerification,
    BindingRole,
    ClaimType,
    ContributionClaim,
    ContributionDimension,
    ContributionLevel,
    Decision,
    DimensionAssessment,
    DisclosureStatus,
    Evaluation,
    EvidenceKind,
    EvidenceReference,
    EvidenceStatus,
    ProcessAttestation,
    ReviewDecision,
    SignatureRole,
    ValidationRecord,
    attestation_json,
    attestation_schema,
    compute_attestation_id,
    issue_attestation,
    load_attestation,
    sign_attestation,
    verify_attestation,
)
from trueai.core.certificates import generate_ed25519_keypair
from trueai.core.errors import AttestationError

pytest.importorskip("cryptography", reason="Signing needs the attestation extra")

RESEARCHER = Actor(id="alice", kind=ActorKind.PERSON, display_name="Alice")
MODEL = Actor(
    id="assistant", kind=ActorKind.AI_SYSTEM, display_name="Coding assistant", version="1.0"
)
REVIEWER = Actor(id="bob", kind=ActorKind.PERSON, display_name="Bob")


def subject(tmp_path: Path, body: str = "deliverable\n") -> tuple[Path, str]:
    """Write a subject artifact and return it with its digest."""

    path = tmp_path / "deliverable.md"
    path.write_text(body, encoding="utf-8")
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def minimal(digest: str, **overrides: object) -> ProcessAttestation:
    """Build a small valid record."""

    arguments: dict[str, object] = {
        "subject_sha256": digest,
        "subject_name": "deliverable.md",
        "actors": (RESEARCHER,),
        "claims": (
            ContributionClaim(
                dimension=ContributionDimension.ORIGINATION,
                actor_id="alice",
                claim_type=ClaimType.DECLARATION,
                level=ContributionLevel.ORIGINATING_OR_CONTROLLING,
                evidence_status=EvidenceStatus.SELF_DECLARED,
                explanation="Alice proposed the central mechanism.",
            ),
        ),
    }
    arguments.update(overrides)
    return issue_attestation(**arguments)  # type: ignore[arg-type]


# -- the model refuses to overstate --------------------------------------------------


def test_every_record_carries_the_standing_limitations(tmp_path: Path) -> None:
    _, digest = subject(tmp_path)

    record = minimal(digest)

    codes = {limitation.code for limitation in record.limitations}
    assert codes >= {code for code, _ in STANDING_LIMITATIONS}


def test_a_record_without_the_standing_limitations_is_rejected(tmp_path: Path) -> None:
    """The limitations are not boilerplate a producer may trim away."""

    _, digest = subject(tmp_path)
    payload = minimal(digest).model_dump(mode="json")
    payload["limitations"] = [{"code": "custom", "statement": "Only this one."}]

    with pytest.raises(ValueError, match="standing limitations"):
        ProcessAttestation.model_validate(payload)


def test_the_module_exposes_no_aggregate_contribution_score() -> None:
    """A universal human percentage is a permanent non-goal, not a missing feature."""

    import trueai.core.attestation as module

    names = [name.lower() for name in dir(module)]
    for forbidden in ("percentage", "human_score", "overall_score", "aggregate_score"):
        assert not any(forbidden in name for name in names), forbidden


def test_contribution_is_reported_per_dimension(tmp_path: Path) -> None:
    """The short-genius case: human origination with delegated execution."""

    _, digest = subject(tmp_path)
    record = issue_attestation(
        subject_sha256=digest,
        subject_name="deliverable.md",
        actors=(RESEARCHER, MODEL),
        claims=(
            ContributionClaim(
                dimension=ContributionDimension.ORIGINATION,
                actor_id="alice",
                claim_type=ClaimType.DECLARATION,
                level=ContributionLevel.ORIGINATING_OR_CONTROLLING,
                evidence_status=EvidenceStatus.SELF_DECLARED,
                explanation="Stated the mechanism in two sentences.",
            ),
            ContributionClaim(
                dimension=ContributionDimension.EXECUTION,
                actor_id="assistant",
                claim_type=ClaimType.DECLARATION,
                level=ContributionLevel.PRIMARY,
                evidence_status=EvidenceStatus.SELF_DECLARED,
                ai_autonomy=AiAutonomy.DELEGATED_EXECUTION,
                explanation="Produced the implementation from the stated mechanism.",
            ),
        ),
    )

    origination = record.claims_for(ContributionDimension.ORIGINATION)
    execution = record.claims_for(ContributionDimension.EXECUTION)

    assert origination[0].actor_id == "alice"
    assert execution[0].actor_id == "assistant"
    assert execution[0].ai_autonomy == AiAutonomy.DELEGATED_EXECUTION
    # High machine autonomy in one stage says nothing about the others.
    assert origination[0].ai_autonomy == AiAutonomy.NONE


def test_a_machine_fact_must_reference_recomputable_evidence() -> None:
    with pytest.raises(ValueError, match="machine_fact"):
        ContributionClaim(
            dimension=ContributionDimension.EXECUTION,
            actor_id="alice",
            claim_type=ClaimType.MACHINE_FACT,
            level=ContributionLevel.PRIMARY,
            evidence_status=EvidenceStatus.ARTIFACT_CORRELATED,
            explanation="Commits show the work.",
        )


def test_a_declaration_cannot_claim_independent_assessment() -> None:
    """A signature over one's own claim is not an independent assessment of it."""

    with pytest.raises(ValueError, match="independent assessment"):
        ContributionClaim(
            dimension=ContributionDimension.ORIGINATION,
            actor_id="alice",
            claim_type=ClaimType.DECLARATION,
            level=ContributionLevel.ORIGINATING_OR_CONTROLLING,
            evidence_status=EvidenceStatus.INDEPENDENTLY_ASSESSED,
            explanation="I assessed my own novelty.",
        )


# -- privacy and disclosure ----------------------------------------------------------


def test_private_evidence_may_not_carry_a_locator() -> None:
    with pytest.raises(ValueError, match="locator"):
        EvidenceReference(
            id="notes",
            kind=EvidenceKind.RESEARCH_NOTE,
            description="Lab notebook",
            disclosure=DisclosureStatus.PRIVATE,
            locator="/home/alice/private/notebook.md",
        )


def test_committed_evidence_requires_a_commitment() -> None:
    with pytest.raises(ValueError, match="commitment"):
        EvidenceReference(
            id="notes",
            kind=EvidenceKind.RESEARCH_NOTE,
            description="Lab notebook",
            disclosure=DisclosureStatus.COMMITTED,
        )


def test_omitted_evidence_requires_a_reason_and_carries_no_digest() -> None:
    with pytest.raises(ValueError, match="why it was omitted"):
        EvidenceReference(
            id="notes",
            kind=EvidenceKind.RESEARCH_NOTE,
            description="Client feedback",
            disclosure=DisclosureStatus.OMITTED,
        )
    with pytest.raises(ValueError, match="must not carry a digest"):
        EvidenceReference(
            id="notes",
            kind=EvidenceKind.RESEARCH_NOTE,
            description="Client feedback",
            disclosure=DisclosureStatus.OMITTED,
            omission_reason="Confidential",
            sha256="a" * 64,
        )


def test_a_pseudonymous_actor_cannot_also_be_identified() -> None:
    with pytest.raises(ValueError, match="pseudonymous"):
        Actor(
            id="anon",
            kind=ActorKind.PERSON,
            pseudonymous=True,
            identifier="alice@example.test",
        )


# -- graph integrity -----------------------------------------------------------------


def test_every_cross_reference_must_resolve(tmp_path: Path) -> None:
    _, digest = subject(tmp_path)

    with pytest.raises(ValueError, match="unknown actor"):
        issue_attestation(
            subject_sha256=digest,
            subject_name="deliverable.md",
            actors=(RESEARCHER,),
            activities=(Activity(id="a1", action="draft", actor_ids=("ghost",)),),
        )


def test_a_claim_cannot_reference_absent_evidence(tmp_path: Path) -> None:
    _, digest = subject(tmp_path)

    with pytest.raises(ValueError, match="unknown evidence"):
        issue_attestation(
            subject_sha256=digest,
            subject_name="deliverable.md",
            actors=(RESEARCHER,),
            claims=(
                ContributionClaim(
                    dimension=ContributionDimension.VALIDATION,
                    actor_id="alice",
                    claim_type=ClaimType.MACHINE_FACT,
                    level=ContributionLevel.PRIMARY,
                    evidence_status=EvidenceStatus.ARTIFACT_CORRELATED,
                    explanation="Tests passed.",
                    evidence_ids=("missing",),
                ),
            ),
        )


def test_rejected_attempts_are_representable(tmp_path: Path) -> None:
    """A record that can only describe the happy path describes a process that did not happen."""

    _, digest = subject(tmp_path)
    record = issue_attestation(
        subject_sha256=digest,
        subject_name="deliverable.md",
        actors=(RESEARCHER, MODEL, REVIEWER),
        artifact_bindings=(
            ArtifactBinding(
                id="out", role=BindingRole.OUTPUT, name="deliverable.md", sha256=digest
            ),
        ),
        activities=(
            Activity(
                id="attempt-1",
                action="first generation",
                actor_ids=("assistant",),
                ai_autonomy=AiAutonomy.DELEGATED_EXECUTION,
                review_decision=ReviewDecision.REJECTED,
                reviewer_actor_id="bob",
                superseded=True,
            ),
            Activity(
                id="attempt-2",
                action="second generation",
                actor_ids=("assistant",),
                output_binding_ids=("out",),
                ai_autonomy=AiAutonomy.DELEGATED_EXECUTION,
                review_decision=ReviewDecision.ACCEPTED_WITH_CHANGES,
                reviewer_actor_id="bob",
            ),
        ),
    )

    superseded = [item for item in record.activities if item.superseded]
    assert len(superseded) == 1
    assert superseded[0].review_decision == ReviewDecision.REJECTED


def test_an_activity_cannot_end_before_it_starts(tmp_path: Path) -> None:
    _, digest = subject(tmp_path)
    start = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)

    with pytest.raises(ValueError, match="ends before it starts"):
        issue_attestation(
            subject_sha256=digest,
            subject_name="deliverable.md",
            actors=(RESEARCHER,),
            activities=(
                Activity(
                    id="a1",
                    action="draft",
                    actor_ids=("alice",),
                    started_at=start,
                    ended_at=start - timedelta(hours=1),
                ),
            ),
        )


# -- identity and signatures ---------------------------------------------------------


def test_the_identifier_is_derived_from_the_claims(tmp_path: Path) -> None:
    _, digest = subject(tmp_path)
    record = minimal(digest)

    assert record.attestation_id.startswith("TAIP1-")
    assert compute_attestation_id(record) == record.attestation_id


def test_changing_a_claim_changes_the_identifier(tmp_path: Path) -> None:
    _, digest = subject(tmp_path)
    record = minimal(digest)
    tampered = record.model_copy(
        update={
            "claims": (record.claims[0].model_copy(update={"level": ContributionLevel.SUPPORTING}),)
        }
    )

    assert compute_attestation_id(tampered) != record.attestation_id


def test_signing_and_verifying_a_claimant_statement(tmp_path: Path) -> None:
    artifact, digest = subject(tmp_path)
    private = tmp_path / "alice.key"
    public = tmp_path / "alice.pub"
    generate_ed25519_keypair(private, public)
    record = sign_attestation(
        minimal(digest), role=SignatureRole.CLAIMANT, actor_id="alice", signing_key=private
    )

    result = verify_attestation(record, artifact=artifact, public_keys={"alice": public})

    assert result.content_id_valid
    assert result.subject_bound is True
    assert result.claimant_signature == "valid"
    assert result.authenticated_declaration
    assert not result.problems


def test_a_changed_artifact_breaks_the_binding(tmp_path: Path) -> None:
    artifact, digest = subject(tmp_path)
    record = minimal(digest)
    artifact.write_text("edited after the record was issued\n", encoding="utf-8")

    result = verify_attestation(record, artifact=artifact)

    assert result.subject_bound is False
    assert any("does not match the bound subject" in problem for problem in result.problems)


def test_a_changed_claim_invalidates_the_signature(tmp_path: Path) -> None:
    _, digest = subject(tmp_path)
    private = tmp_path / "alice.key"
    public = tmp_path / "alice.pub"
    generate_ed25519_keypair(private, public)
    record = sign_attestation(
        minimal(digest), role=SignatureRole.CLAIMANT, actor_id="alice", signing_key=private
    )
    tampered = record.model_copy(
        update={
            "claims": (
                record.claims[0].model_copy(
                    update={"explanation": "Alice did everything, actually."}
                ),
            )
        }
    )

    result = verify_attestation(tampered, public_keys={"alice": public})

    assert result.claimant_signature == "invalid"
    assert not result.authenticated_declaration


def test_a_countersignature_does_not_invalidate_the_claimant_signature(
    tmp_path: Path,
) -> None:
    _, digest = subject(tmp_path)
    alice_key, alice_public = tmp_path / "a.key", tmp_path / "a.pub"
    bob_key, bob_public = tmp_path / "b.key", tmp_path / "b.pub"
    generate_ed25519_keypair(alice_key, alice_public)
    generate_ed25519_keypair(bob_key, bob_public)
    record = issue_attestation(
        subject_sha256=digest,
        subject_name="deliverable.md",
        actors=(RESEARCHER, REVIEWER),
        claims=(
            ContributionClaim(
                dimension=ContributionDimension.ORIGINATION,
                actor_id="alice",
                claim_type=ClaimType.DECLARATION,
                level=ContributionLevel.PRIMARY,
                evidence_status=EvidenceStatus.SELF_DECLARED,
                explanation="Alice proposed the approach.",
            ),
        ),
    )
    signed = sign_attestation(
        record, role=SignatureRole.CLAIMANT, actor_id="alice", signing_key=alice_key
    )
    countersigned = sign_attestation(
        signed, role=SignatureRole.REVIEWER, actor_id="bob", signing_key=bob_key
    )

    result = verify_attestation(
        countersigned, public_keys={"alice": alice_public, "bob": bob_public}
    )

    assert result.claimant_signature == "valid"
    assert result.reviewer_signature == "valid"


def test_signing_twice_in_the_same_role_is_refused(tmp_path: Path) -> None:
    _, digest = subject(tmp_path)
    private, public = tmp_path / "a.key", tmp_path / "a.pub"
    generate_ed25519_keypair(private, public)
    record = sign_attestation(
        minimal(digest), role=SignatureRole.CLAIMANT, actor_id="alice", signing_key=private
    )

    with pytest.raises(AttestationError, match="already signed"):
        sign_attestation(record, role=SignatureRole.CLAIMANT, actor_id="alice", signing_key=private)


def test_signing_as_an_unknown_actor_is_refused(tmp_path: Path) -> None:
    _, digest = subject(tmp_path)
    private, public = tmp_path / "a.key", tmp_path / "a.pub"
    generate_ed25519_keypair(private, public)

    with pytest.raises(AttestationError, match="Unknown actor"):
        sign_attestation(
            minimal(digest), role=SignatureRole.CLAIMANT, actor_id="ghost", signing_key=private
        )


def test_an_unverifiable_signature_is_reported_as_unverified_not_valid(
    tmp_path: Path,
) -> None:
    """No key means no verdict, which is not the same as a failed check."""

    _, digest = subject(tmp_path)
    private, public = tmp_path / "a.key", tmp_path / "a.pub"
    generate_ed25519_keypair(private, public)
    record = sign_attestation(
        minimal(digest), role=SignatureRole.CLAIMANT, actor_id="alice", signing_key=private
    )

    result = verify_attestation(record)

    assert result.claimant_signature == "unverified"
    assert not result.authenticated_declaration


# -- verification semantics ----------------------------------------------------------


def test_verification_reports_independent_results_not_one_badge(tmp_path: Path) -> None:
    artifact, digest = subject(tmp_path)

    result = verify_attestation(minimal(digest), artifact=artifact)

    assert isinstance(result, AttestationVerification)
    # A record can be content-valid and artifact-bound while nobody has signed it.
    assert result.content_id_valid
    assert result.subject_bound is True
    assert result.claimant_signature == "absent"
    assert not result.authenticated_declaration


def test_a_valid_signature_over_a_self_declared_claim_is_only_a_declaration(
    tmp_path: Path,
) -> None:
    _, digest = subject(tmp_path)
    private, public = tmp_path / "a.key", tmp_path / "a.pub"
    generate_ed25519_keypair(private, public)
    record = sign_attestation(
        minimal(digest), role=SignatureRole.CLAIMANT, actor_id="alice", signing_key=private
    )

    result = verify_attestation(record, public_keys={"alice": public})

    assert result.authenticated_declaration
    assert result.strongest_evidence_status == EvidenceStatus.SELF_DECLARED


def test_an_expired_record_is_not_an_authenticated_declaration(tmp_path: Path) -> None:
    _, digest = subject(tmp_path)
    private, public = tmp_path / "a.key", tmp_path / "a.pub"
    generate_ed25519_keypair(private, public)
    created = datetime(2026, 1, 1, tzinfo=UTC)
    record = sign_attestation(
        minimal(digest, created_at=created, expires_at=created + timedelta(days=1)),
        role=SignatureRole.CLAIMANT,
        actor_id="alice",
        signing_key=private,
    )

    result = verify_attestation(
        record, public_keys={"alice": public}, now=created + timedelta(days=2)
    )

    assert result.expired
    assert result.claimant_signature == "valid"
    assert not result.authenticated_declaration


def test_an_unsupported_evaluation_profile_is_reported(tmp_path: Path) -> None:
    _, digest = subject(tmp_path)
    record = issue_attestation(
        subject_sha256=digest,
        subject_name="deliverable.md",
        actors=(RESEARCHER, REVIEWER),
        evaluation=Evaluation(
            profile="unknown-domain",
            rubric_version="1.0",
            assessor_actor_id="bob",
            assessed_at=datetime(2026, 8, 24, tzinfo=UTC),
            results=(
                DimensionAssessment(
                    dimension=ContributionDimension.ORIGINATION,
                    level=ContributionLevel.PRIMARY,
                    confidence="moderate",
                ),
            ),
        ),
    )

    result = verify_attestation(record, supported_profiles=frozenset({"research"}))

    assert result.evaluation_profile_supported is False
    assert any("not supported" in problem for problem in result.problems)


def test_dissent_is_surfaced_rather_than_averaged_away(tmp_path: Path) -> None:
    _, digest = subject(tmp_path)
    record = issue_attestation(
        subject_sha256=digest,
        subject_name="deliverable.md",
        actors=(RESEARCHER, REVIEWER),
        evaluation=Evaluation(
            profile="research",
            rubric_version="1.0",
            assessor_actor_id="bob",
            assessed_at=datetime(2026, 8, 24, tzinfo=UTC),
            results=(
                DimensionAssessment(
                    dimension=ContributionDimension.ORIGINATION,
                    level=ContributionLevel.SUPPORTING,
                    confidence="low",
                    dissent="The claimant rates this as originating.",
                ),
            ),
        ),
    )

    result = verify_attestation(record, supported_profiles=frozenset({"research"}))

    assert result.unresolved_dissent


def test_disclosed_evidence_must_match_its_published_commitment(tmp_path: Path) -> None:
    _, digest = subject(tmp_path)
    material = b"the private rationale that was committed to"
    commitment = hashlib.sha256(material).hexdigest()
    record = issue_attestation(
        subject_sha256=digest,
        subject_name="deliverable.md",
        actors=(RESEARCHER,),
        evidence=(
            EvidenceReference(
                id="rationale",
                kind=EvidenceKind.RESEARCH_NOTE,
                description="Design rationale",
                disclosure=DisclosureStatus.COMMITTED,
                commitment=commitment,
            ),
        ),
    )

    honest = verify_attestation(record, disclosed_evidence={"rationale": material})
    swapped = verify_attestation(record, disclosed_evidence={"rationale": b"a different rationale"})

    assert honest.disclosed_evidence_consistent is True
    assert swapped.disclosed_evidence_consistent is False
    assert any("does not match its published commitment" in p for p in swapped.problems)


# -- serialization -------------------------------------------------------------------


def test_a_record_round_trips_through_disk(tmp_path: Path) -> None:
    _, digest = subject(tmp_path)
    record = minimal(digest)
    path = tmp_path / "deliverable.process.json"
    path.write_text(attestation_json(record), encoding="utf-8")

    loaded = load_attestation(path)

    assert loaded == record
    assert compute_attestation_id(loaded) == record.attestation_id


def test_a_malformed_record_is_an_attestation_error(tmp_path: Path) -> None:
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(AttestationError):
        load_attestation(path)


def test_the_schema_declares_the_distinct_identifier_prefix() -> None:
    schema = attestation_schema()

    pattern = schema["properties"]["attestation_id"]["pattern"]
    assert pattern.startswith("^TAIP1-")
    assert schema["properties"]["schema_version"]["const"] == "0.1"


def test_the_schema_is_separate_from_the_audit_certificate_contract() -> None:
    """Process claims and scan observations must never share one contract."""

    from trueai.core.certificates import certificate_schema

    process = json.dumps(attestation_schema(), sort_keys=True)
    certificate = json.dumps(certificate_schema(), sort_keys=True)

    assert process != certificate
    assert "TAIP1-" in process
    assert "TAIP1-" not in certificate


def test_a_validation_record_can_bind_its_outcome_by_hash(tmp_path: Path) -> None:
    _, digest = subject(tmp_path)
    outcome = hashlib.sha256(b"312 passed").hexdigest()
    record = issue_attestation(
        subject_sha256=digest,
        subject_name="deliverable.md",
        actors=(RESEARCHER,),
        evidence=(
            EvidenceReference(
                id="tests",
                kind=EvidenceKind.TEST_RUN,
                description="Full suite",
                sha256=outcome,
            ),
        ),
        validations=(
            ValidationRecord(
                id="v1",
                kind="test_suite",
                description="pytest",
                outcome="passed",
                outcome_sha256=outcome,
                performed_by_actor_id="alice",
                evidence_ids=("tests",),
            ),
        ),
        decisions=(
            Decision(
                id="d1",
                question="Which parser?",
                alternatives=("defusedxml", "lxml"),
                selected="defusedxml",
                approving_actor_id="alice",
            ),
        ),
    )

    assert record.validations[0].outcome_sha256 == outcome
    assert record.decisions[0].alternatives == ("defusedxml", "lxml")
