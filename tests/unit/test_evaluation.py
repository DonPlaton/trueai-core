"""Evaluation profiles and Process Assurance Level."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from trueai.cli.app import app
from trueai.core.attestation import (
    Activity,
    Actor,
    ActorKind,
    AiAutonomy,
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
    SignatureRole,
    ValidationRecord,
    issue_attestation,
    sign_attestation,
    verify_attestation,
)
from trueai.core.certificates import generate_ed25519_keypair
from trueai.core.evaluation import (
    BUILT_IN_PROFILES,
    EDUCATION_PROFILE,
    REGULATED_ENTERPRISE_PROFILE,
    RESEARCH_PROFILE,
    SOFTWARE_DELIVERY_PROFILE,
    ProcessAssuranceLevel,
    assess_process_assurance,
    evaluate_with_profile,
    get_profile,
    portable_summary,
    sarif_properties,
    stage_summary,
)
from trueai.core.trust import (
    IssuerBinding,
    LocalKeySigningProvider,
    OfflineTimestampProvider,
    TrustProfile,
)

pytest.importorskip("cryptography", reason="Signing needs the attestation extra")

runner = CliRunner()

NOW = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
DIGEST = hashlib.sha256(b"deliverable").hexdigest()

ALICE = Actor(id="alice", kind=ActorKind.PERSON, display_name="Alice")
ASSISTANT = Actor(id="assistant", kind=ActorKind.AI_SYSTEM, display_name="Assistant", version="2")
BOB = Actor(id="bob", kind=ActorKind.PERSON, display_name="Bob")
CAROL = Actor(id="carol", kind=ActorKind.PERSON, display_name="Carol")

TEST_EVIDENCE = EvidenceReference(
    id="tests",
    kind=EvidenceKind.TEST_RUN,
    description="Suite run",
    sha256="a" * 64,
    disclosure=DisclosureStatus.PRIVATE,
)
DIFF_EVIDENCE = EvidenceReference(
    id="diff",
    kind=EvidenceKind.REVIEWED_DIFF,
    description="Reviewed change",
    sha256="b" * 64,
    disclosure=DisclosureStatus.PRIVATE,
)


def claim(
    dimension: ContributionDimension,
    actor: str,
    level: ContributionLevel,
    evidence_status: EvidenceStatus = EvidenceStatus.SELF_DECLARED,
    *,
    autonomy: AiAutonomy = AiAutonomy.NONE,
    evidence: tuple[str, ...] = (),
    claim_type: ClaimType = ClaimType.DECLARATION,
) -> ContributionClaim:
    return ContributionClaim(
        dimension=dimension,
        actor_id=actor,
        claim_type=claim_type,
        level=level,
        evidence_status=evidence_status,
        ai_autonomy=autonomy,
        explanation=f"{actor} contributed to {dimension.value}.",
        evidence_ids=evidence,
    )


def signed(
    record: ProcessAttestation,
    tmp_path: Path,
    *,
    reviewer: bool = False,
    assessor: bool = False,
) -> tuple[ProcessAttestation, dict[str, Path]]:
    """Sign a record as claimant, and optionally reviewer and assessor."""

    keys: dict[str, Path] = {}
    for actor_id in ["alice"] + (["bob"] if reviewer else []) + (["carol"] if assessor else []):
        private, public = tmp_path / f"{actor_id}.key", tmp_path / f"{actor_id}.pub"
        if not private.exists():
            generate_ed25519_keypair(private, public)
        keys[actor_id] = public
    record = sign_attestation(
        record, role=SignatureRole.CLAIMANT, actor_id="alice", signing_key=tmp_path / "alice.key"
    )
    if reviewer:
        record = sign_attestation(
            record, role=SignatureRole.REVIEWER, actor_id="bob", signing_key=tmp_path / "bob.key"
        )
    if assessor:
        record = sign_attestation(
            record,
            role=SignatureRole.ASSESSOR,
            actor_id="carol",
            signing_key=tmp_path / "carol.key",
        )
    return record, keys


def subject_artifact(tmp_path: Path) -> Path:
    """Write the exact bytes all records in this module bind to."""

    tmp_path.mkdir(parents=True, exist_ok=True)
    artifact = tmp_path / "deliverable"
    artifact.write_bytes(b"deliverable")
    return artifact


# -- Process Assurance Level ---------------------------------------------------------


def test_an_unsigned_record_is_unsubstantiated() -> None:
    record = issue_attestation(
        subject_sha256=DIGEST,
        subject_name="deliverable.md",
        actors=(ALICE,),
        claims=(claim(ContributionDimension.ORIGINATION, "alice", ContributionLevel.PRIMARY),),
    )

    assurance = assess_process_assurance(record, verify_attestation(record))

    assert assurance.level == ProcessAssuranceLevel.UNSUBSTANTIATED
    assert assurance.next_level_requires


def test_a_signed_self_declared_record_is_declared(tmp_path: Path) -> None:
    """Strong claims with no support do not raise the level."""

    record = issue_attestation(
        subject_sha256=DIGEST,
        subject_name="deliverable.md",
        actors=(ALICE,),
        claims=(
            claim(
                ContributionDimension.ORIGINATION,
                "alice",
                ContributionLevel.ORIGINATING_OR_CONTROLLING,
            ),
            claim(
                ContributionDimension.EXECUTION,
                "alice",
                ContributionLevel.ORIGINATING_OR_CONTROLLING,
            ),
        ),
    )
    record, keys = signed(record, tmp_path)

    assurance = assess_process_assurance(
        record,
        verify_attestation(record, artifact=subject_artifact(tmp_path), public_keys=keys),
    )

    assert assurance.level == ProcessAssuranceLevel.DECLARED
    assert any("artifact_correlated" in item for item in assurance.next_level_requires)


def evidenced_record(**extra: object) -> ProcessAttestation:
    """A record whose material claims are backed by evidence it contains."""

    return issue_attestation(
        subject_sha256=DIGEST,
        subject_name="deliverable.md",
        actors=extra.pop("actors", (ALICE, ASSISTANT, BOB)),  # type: ignore[arg-type]
        evidence=(TEST_EVIDENCE, DIFF_EVIDENCE),
        activities=(
            Activity(
                id="draft",
                action="Generated the draft",
                actor_ids=("assistant",),
                ai_autonomy=AiAutonomy.DELEGATED_EXECUTION,
            ),
        ),
        claims=(
            claim(
                ContributionDimension.ORIGINATION,
                "alice",
                ContributionLevel.ORIGINATING_OR_CONTROLLING,
            ),
            claim(
                ContributionDimension.FRAMING,
                "alice",
                ContributionLevel.PRIMARY,
                EvidenceStatus.ARTIFACT_CORRELATED,
                evidence=("diff",),
            ),
            claim(
                ContributionDimension.EXECUTION,
                "assistant",
                ContributionLevel.PRIMARY,
                EvidenceStatus.ARTIFACT_CORRELATED,
                autonomy=AiAutonomy.DELEGATED_EXECUTION,
                evidence=("diff",),
            ),
            claim(
                ContributionDimension.VALIDATION,
                "alice",
                ContributionLevel.PRIMARY,
                EvidenceStatus.ARTIFACT_CORRELATED,
                evidence=("tests",),
            ),
            claim(
                ContributionDimension.DECISION_CONTROL,
                "alice",
                ContributionLevel.PRIMARY,
                EvidenceStatus.ARTIFACT_CORRELATED,
                evidence=("diff",),
            ),
            claim(
                ContributionDimension.ACCOUNTABILITY,
                "alice",
                ContributionLevel.ORIGINATING_OR_CONTROLLING,
            ),
        ),
        **extra,  # type: ignore[arg-type]
    )


def test_evidence_and_disclosed_ai_roles_reach_evidenced(tmp_path: Path) -> None:
    record, keys = signed(evidenced_record(), tmp_path)

    assurance = assess_process_assurance(
        record,
        verify_attestation(record, artifact=subject_artifact(tmp_path), public_keys=keys),
    )

    assert assurance.level == ProcessAssuranceLevel.EVIDENCED


def test_undisclosed_machine_work_blocks_the_evidenced_level() -> None:
    """A record describing machine work with no AI actor has left the reader guessing."""

    record = issue_attestation(
        subject_sha256=DIGEST,
        subject_name="deliverable.md",
        actors=(ALICE,),
        evidence=(TEST_EVIDENCE,),
        claims=(
            claim(
                ContributionDimension.EXECUTION,
                "alice",
                ContributionLevel.PRIMARY,
                EvidenceStatus.ARTIFACT_CORRELATED,
                autonomy=AiAutonomy.DELEGATED_EXECUTION,
                evidence=("tests",),
            ),
        ),
    )

    from trueai.core.evaluation import _ai_roles_disclosed

    assert not _ai_roles_disclosed(record)


def reviewed_record(**extra: object) -> ProcessAttestation:
    """An evidenced record that also documents decisions and validation.

    Built through ``issue_attestation`` rather than ``model_copy`` so the record
    stays content-addressed: an attestation id computed over different content is
    exactly what verification is supposed to reject.
    """

    return evidenced_record(
        decisions=(
            Decision(
                id="d1",
                question="Which approach?",
                alternatives=("a", "b"),
                selected="b",
                approving_actor_id="alice",
                evidence_ids=("diff",),
            ),
        ),
        validations=(
            ValidationRecord(
                id="v1",
                kind="test_suite",
                description="Full suite",
                outcome="passed",
                outcome_sha256="c" * 64,
                performed_by_actor_id="alice",
                evidence_ids=("tests",),
            ),
        ),
        **extra,
    )


def test_a_countersigned_evidenced_record_reaches_reviewed(tmp_path: Path) -> None:
    record, keys = signed(reviewed_record(), tmp_path, reviewer=True)

    assurance = assess_process_assurance(
        record,
        verify_attestation(record, artifact=subject_artifact(tmp_path), public_keys=keys),
    )

    assert assurance.level == ProcessAssuranceLevel.REVIEWED


def test_independent_assurance_needs_identity_expiry_and_a_timestamp(tmp_path: Path) -> None:
    from trueai.core.trust import public_key_id

    base = reviewed_record(
        actors=(ALICE, ASSISTANT, BOB, CAROL),
        created_at=NOW,
        expires_at=NOW + timedelta(days=365),
        evaluation=Evaluation(
            profile="software-delivery",
            rubric_version="0.1",
            assessor_actor_id="carol",
            assessed_at=NOW,
            results=(
                DimensionAssessment(
                    dimension=ContributionDimension.VALIDATION,
                    level=ContributionLevel.PRIMARY,
                    confidence="high",
                ),
            ),
        ),
    )

    authority_key, authority_public = tmp_path / "tsa.key", tmp_path / "tsa.pub"
    generate_ed25519_keypair(authority_key, authority_public)
    alice_key, alice_public = tmp_path / "alice.key", tmp_path / "alice.pub"
    generate_ed25519_keypair(alice_key, alice_public)
    record = sign_attestation(
        base,
        role=SignatureRole.CLAIMANT,
        actor_id="alice",
        signing_key=alice_key,
        timestamp_provider=OfflineTimestampProvider(
            LocalKeySigningProvider(authority_key), authority="ACME TSA"
        ),
    )
    for actor_id in ("bob", "carol"):
        private, public = tmp_path / f"{actor_id}.key", tmp_path / f"{actor_id}.pub"
        generate_ed25519_keypair(private, public)
        record = sign_attestation(
            record,
            role=SignatureRole.REVIEWER if actor_id == "bob" else SignatureRole.ASSESSOR,
            actor_id=actor_id,
            signing_key=private,
        )
    profile = TrustProfile(
        profile_id="acme",
        issued_at=NOW,
        bindings=(
            IssuerBinding(
                key_id=public_key_id(alice_public),
                organization="ACME Research",
                not_before=NOW - timedelta(days=1),
            ),
        ),
    )

    verification = verify_attestation(
        record,
        artifact=subject_artifact(tmp_path),
        public_keys={
            "alice": alice_public,
            "bob": tmp_path / "bob.pub",
            "carol": tmp_path / "carol.pub",
        },
        trust_profile=profile,
        timestamp_authority_key=authority_public,
        supported_profiles=frozenset({"software-delivery"}),
        now=NOW,
    )
    assurance = assess_process_assurance(record, verification)

    assert assurance.level == ProcessAssuranceLevel.INDEPENDENTLY_ASSURED


def test_assurance_is_orthogonal_to_how_human_the_work_was(tmp_path: Path) -> None:
    """A delegated-execution record can outrank a purely human self-declared one."""

    human_only = issue_attestation(
        subject_sha256=DIGEST,
        subject_name="deliverable.md",
        actors=(ALICE,),
        claims=(
            claim(
                ContributionDimension.ORIGINATION,
                "alice",
                ContributionLevel.ORIGINATING_OR_CONTROLLING,
            ),
            claim(ContributionDimension.EXECUTION, "alice", ContributionLevel.PRIMARY),
        ),
    )
    human_only, human_keys = signed(human_only, tmp_path / "human")
    machine_assisted, machine_keys = signed(evidenced_record(), tmp_path / "machine")

    human = assess_process_assurance(
        human_only,
        verify_attestation(
            human_only, artifact=subject_artifact(tmp_path / "human"), public_keys=human_keys
        ),
    )
    machine = assess_process_assurance(
        machine_assisted,
        verify_attestation(
            machine_assisted,
            artifact=subject_artifact(tmp_path / "machine"),
            public_keys=machine_keys,
        ),
    )

    assert human.level == ProcessAssuranceLevel.DECLARED
    assert machine.level == ProcessAssuranceLevel.EVIDENCED


# -- profiles ------------------------------------------------------------------------


def test_every_built_in_profile_exposes_its_weights() -> None:
    """A profile that will not show its weights asks to be trusted rather than checked."""

    for profile in BUILT_IN_PROFILES.values():
        assert profile.requirements
        for requirement in profile.requirements:
            assert 0.0 <= requirement.weight <= 1.0
        assert profile.description
    assert (
        REGULATED_ENTERPRISE_PROFILE.minimum_assurance
        == ProcessAssuranceLevel.INDEPENDENTLY_ASSURED
    )


def test_two_profiles_can_disagree_about_the_same_record(tmp_path: Path) -> None:
    """Different contexts value different dimensions, and neither is wrong."""

    record, keys = signed(reviewed_record(), tmp_path, reviewer=True)
    verification = verify_attestation(record, artifact=subject_artifact(tmp_path), public_keys=keys)

    education = evaluate_with_profile(record, verification, EDUCATION_PROFILE)
    software = evaluate_with_profile(record, verification, SOFTWARE_DELIVERY_PROFILE)

    # The same delegated execution that a delivery team expects is exactly what an
    # assignment about demonstrated understanding forbids.
    assert not education.meets_review_requirements
    assert any("does not permit" in item for item in education.unmet_requirements)
    assert software.meets_review_requirements


def test_a_profile_result_never_claims_authorship(tmp_path: Path) -> None:
    record, keys = signed(reviewed_record(), tmp_path, reviewer=True)
    result = evaluate_with_profile(
        record,
        verify_attestation(record, artifact=subject_artifact(tmp_path), public_keys=keys),
        SOFTWARE_DELIVERY_PROFILE,
    )

    fields = set(result.model_dump().keys())

    assert "meets_review_requirements" in fields
    for forbidden in ("human_authored", "human_score", "authorship", "originality"):
        assert not any(forbidden in field for field in fields)
    assert "not a determination of authorship" in result.statement


def test_a_profile_reports_the_weights_it_used(tmp_path: Path) -> None:
    record, keys = signed(reviewed_record(), tmp_path, reviewer=True)

    result = evaluate_with_profile(
        record,
        verify_attestation(record, artifact=subject_artifact(tmp_path), public_keys=keys),
        RESEARCH_PROFILE,
    )

    assert result.weights
    assert set(result.weights) == {
        requirement.dimension.value for requirement in RESEARCH_PROFILE.requirements
    }


def test_an_unclaimed_optional_dimension_does_not_fail_a_profile(tmp_path: Path) -> None:
    record, keys = signed(reviewed_record(), tmp_path, reviewer=True)

    result = evaluate_with_profile(
        record,
        verify_attestation(record, artifact=subject_artifact(tmp_path), public_keys=keys),
        SOFTWARE_DELIVERY_PROFILE,
    )

    optional = [item for item in result.outcomes if not item.claimed]
    assert all(item.satisfied for item in optional)


def test_a_required_dimension_that_is_not_claimed_fails(tmp_path: Path) -> None:
    record = issue_attestation(
        subject_sha256=DIGEST,
        subject_name="deliverable.md",
        actors=(ALICE,),
        claims=(claim(ContributionDimension.EXECUTION, "alice", ContributionLevel.PRIMARY),),
    )
    record, keys = signed(record, tmp_path)

    result = evaluate_with_profile(
        record,
        verify_attestation(record, artifact=subject_artifact(tmp_path), public_keys=keys),
        RESEARCH_PROFILE,
    )

    assert not result.meets_review_requirements
    assert any("origination" in item for item in result.unmet_requirements)


def test_a_profile_minimum_assurance_is_enforced(tmp_path: Path) -> None:
    record, keys = signed(evidenced_record(), tmp_path)

    result = evaluate_with_profile(
        record,
        verify_attestation(record, artifact=subject_artifact(tmp_path), public_keys=keys),
        REGULATED_ENTERPRISE_PROFILE,
    )

    assert not result.meets_review_requirements
    assert any("assurance" in item for item in result.unmet_requirements)


def test_an_unknown_profile_names_the_available_ones() -> None:
    with pytest.raises(KeyError, match="available"):
        get_profile("astrology")


# -- presentation --------------------------------------------------------------------


def test_the_stage_summary_names_stages_not_authorship() -> None:
    summary = stage_summary(evidenced_record())

    assert "human-originated" in summary
    assert "AI-executed" in summary
    assert "human-validated" in summary
    assert "authored" not in summary


def test_the_portable_summary_carries_its_limitations(tmp_path: Path) -> None:
    record, keys = signed(reviewed_record(), tmp_path, reviewer=True)
    verification = verify_attestation(record, artifact=subject_artifact(tmp_path), public_keys=keys)

    summary = portable_summary(record, verification, SOFTWARE_DELIVERY_PROFILE)

    assert "Process Assurance Level: PAL-3" in summary
    assert "Limitations:" in summary
    for limitation in record.limitations:
        assert limitation.statement in summary
    assert "%" not in summary


def test_the_portable_summary_says_when_an_issuer_is_only_a_key(tmp_path: Path) -> None:
    record, keys = signed(reviewed_record(), tmp_path, reviewer=True)

    summary = portable_summary(
        record,
        verify_attestation(record, artifact=subject_artifact(tmp_path), public_keys=keys),
    )

    assert "a key, not an identified organization" in summary


def test_the_portable_summary_marks_unassessed_originality(tmp_path: Path) -> None:
    record, keys = signed(evidenced_record(), tmp_path)

    summary = portable_summary(
        record,
        verify_attestation(record, artifact=subject_artifact(tmp_path), public_keys=keys),
    )

    assert "Originality: not independently assessed" in summary


def test_sarif_properties_name_what_was_established(tmp_path: Path) -> None:
    record, keys = signed(reviewed_record(), tmp_path, reviewer=True)

    properties = sarif_properties(
        record,
        verify_attestation(record, artifact=subject_artifact(tmp_path), public_keys=keys),
    )

    assert properties["trueaiProcessAssuranceLevel"] == "PAL-3"
    assert properties["trueaiAttestationAuthenticatedDeclaration"] is True
    assert properties["trueaiAttestationOrganizationallyAttributed"] is False
    assert properties["trueaiAttestationLimitations"]
    for key in properties:
        assert "human" not in str(key).lower()


# -- CLI and CI presentation ---------------------------------------------------------


def written(record: ProcessAttestation, tmp_path: Path) -> Path:
    """Write a record where the CLI can read it."""

    from trueai.core.attestation import attestation_json

    destination = tmp_path / "record.process.json"
    destination.write_text(attestation_json(record) + "\n", encoding="utf-8")
    return destination


def test_the_cli_evaluates_a_record_against_a_named_profile(tmp_path: Path) -> None:
    record, keys = signed(reviewed_record(), tmp_path, reviewer=True)
    path = written(record, tmp_path)

    result = runner.invoke(
        app,
        [
            "attestations",
            "evaluate",
            str(path),
            "--artifact",
            str(subject_artifact(tmp_path)),
            "--profile",
            "software-delivery",
            "--public-key",
            f"alice={keys['alice']}",
            "--public-key",
            f"bob={keys['bob']}",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "software-delivery" in result.output
    assert "PAL-3" in result.output
    # The presentation names stages and stops there.
    assert "authored" not in result.output.lower()
    assert "%" not in result.output


def test_the_cli_exit_code_says_review_required_without_calling_it_dishonest(
    tmp_path: Path,
) -> None:
    """An unmet profile requirement is a review outcome, not an accusation."""

    record, keys = signed(reviewed_record(), tmp_path, reviewer=True)
    path = written(record, tmp_path)

    result = runner.invoke(
        app,
        [
            "attestations",
            "evaluate",
            str(path),
            "--artifact",
            str(subject_artifact(tmp_path)),
            "--profile",
            "education",
            "--public-key",
            f"alice={keys['alice']}",
        ],
    )

    assert result.exit_code == 1, result.output
    assert "does not meet the review requirements" in result.output
    for word in ("cheat", "fraud", "plagiar", "dishonest"):
        assert word not in result.output.lower()


def test_the_cli_rejects_an_unknown_profile_by_name(tmp_path: Path) -> None:
    path = written(evidenced_record(), tmp_path)

    result = runner.invoke(app, ["attestations", "evaluate", str(path), "--profile", "vibes"])

    assert result.exit_code == 3
    assert "vibes" in result.output
    assert "available" in result.output


def test_the_cli_emits_the_profile_result_as_json(tmp_path: Path) -> None:
    import json

    record, keys = signed(reviewed_record(), tmp_path, reviewer=True)
    path = written(record, tmp_path)

    result = runner.invoke(
        app,
        [
            "attestations",
            "evaluate",
            str(path),
            "--artifact",
            str(subject_artifact(tmp_path)),
            "--format",
            "json",
            "--public-key",
            f"alice={keys['alice']}",
            "--public-key",
            f"bob={keys['bob']}",
        ],
    )

    payload = json.loads(result.output)
    assert payload["meets_review_requirements"] is True
    assert payload["weights"]
    assert "authorship" not in json.dumps(payload).lower().replace(
        "not a determination of authorship", ""
    )


def test_the_cli_emits_sarif_properties_for_ci(tmp_path: Path) -> None:
    import json

    record, keys = signed(reviewed_record(), tmp_path, reviewer=True)
    path = written(record, tmp_path)

    result = runner.invoke(
        app,
        [
            "attestations",
            "evaluate",
            str(path),
            "--artifact",
            str(subject_artifact(tmp_path)),
            "--format",
            "sarif-properties",
            "--public-key",
            f"alice={keys['alice']}",
            "--public-key",
            f"bob={keys['bob']}",
        ],
    )

    payload = json.loads(result.output)
    assert payload["trueaiProcessAssuranceLevel"] == "PAL-3"
    assert payload["trueaiProcessStageSummary"]


def test_the_cli_summary_is_readable_without_training(tmp_path: Path) -> None:
    record, keys = signed(reviewed_record(), tmp_path, reviewer=True)
    path = written(record, tmp_path)

    result = runner.invoke(
        app,
        [
            "attestations",
            "evaluate",
            str(path),
            "--artifact",
            str(subject_artifact(tmp_path)),
            "--format",
            "summary",
            "--public-key",
            f"alice={keys['alice']}",
        ],
    )

    assert "Process summary:" in result.output
    assert "Limitations:" in result.output


def test_the_profiles_command_shows_its_weights(tmp_path: Path) -> None:
    """A profile that will not show its weights is asking to be trusted, not checked."""

    result = runner.invoke(app, ["attestations", "profiles"])

    assert result.exit_code == 0, result.output
    for profile_id in BUILT_IN_PROFILES:
        assert profile_id in result.output
    assert "weights:" in result.output


def test_a_scan_carries_attestation_facts_into_sarif_without_changing_findings(
    tmp_path: Path,
) -> None:
    """The record travels with the scan; it never becomes a finding or a severity."""

    import json

    artifact = tmp_path / "deliverable.md"
    artifact.write_text("# Report\n\nPlain text.\n", encoding="utf-8")
    record, _ = signed(reviewed_record(), tmp_path, reviewer=True)
    path = written(record, tmp_path)

    plain = runner.invoke(app, ["scan", str(artifact), "--format", "sarif"])
    with_record = runner.invoke(
        app, ["scan", str(artifact), "--format", "sarif", "--attestation", str(path)]
    )

    before, after = json.loads(plain.output), json.loads(with_record.output)
    assert before["runs"][0]["results"] == after["runs"][0]["results"]
    properties = after["runs"][0]["properties"]
    assert properties["trueaiProcessAssuranceLevel"]
    # No key was supplied to the scan, and the property bag says so rather than
    # implying the record was authenticated.
    assert properties["trueaiAttestationAuthenticatedDeclaration"] is False


def test_sarif_run_properties_are_unchanged_without_a_record(tmp_path: Path) -> None:
    import json

    from trueai.core.models import ScanReport
    from trueai.reporters import SARIFReporter

    artifact = tmp_path / "deliverable.md"
    artifact.write_text("plain\n", encoding="utf-8")
    scan = runner.invoke(app, ["scan", str(artifact), "--format", "json"])
    report = ScanReport.model_validate_json(scan.output)

    payload = json.loads(SARIFReporter().render(report))

    assert set(payload["runs"][0]["properties"]) == {
        "trueaiSchemaVersion",
        "trueaiIntegrityStatus",
    }
