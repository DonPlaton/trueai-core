"""Adversarial and usability tests for Human Contribution Records.

Each test names an attack or a misreading, and asserts what the system says
instead. The shared theme is that a record must never quietly become stronger
than the evidence behind it, and that failing a check must read as a fact about
the record rather than an accusation about a person.
"""

from __future__ import annotations

import hashlib
import json
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
    AttestationSignature,
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
    Limitation,
    ProcessAttestation,
    SignatureRole,
    ValidationRecord,
    attestation_json,
    compute_attestation_id,
    issue_attestation,
    load_attestation,
    sign_attestation,
    verify_attestation,
)
from trueai.core.attestation_manifest import private_material, redact_for_public
from trueai.core.certificates import generate_ed25519_keypair
from trueai.core.errors import AttestationError
from trueai.core.evaluation import (
    ProcessAssuranceLevel,
    assess_process_assurance,
    evaluate_with_profile,
    get_profile,
    portable_summary,
)
from trueai.core.evidence import commitment
from trueai.core.trust import (
    IssuerBinding,
    LocalKeySigningProvider,
    OfflineTimestampProvider,
    TrustProfile,
    public_key_id,
)

pytest.importorskip("cryptography", reason="Signing needs the attestation extra")

runner = CliRunner()

NOW = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
DIGEST = hashlib.sha256(b"deliverable").hexdigest()

ALICE = Actor(id="alice", kind=ActorKind.PERSON, display_name="Alice")
ASSISTANT = Actor(id="assistant", kind=ActorKind.AI_SYSTEM, display_name="Assistant", version="2")
BOB = Actor(id="bob", kind=ActorKind.PERSON, display_name="Bob")
MALLORY = Actor(id="mallory", kind=ActorKind.PERSON, display_name="Mallory")

TESTS = EvidenceReference(
    id="tests",
    kind=EvidenceKind.TEST_RUN,
    description="Suite run",
    sha256="a" * 64,
    disclosure=DisclosureStatus.PRIVATE,
)
DIFF = EvidenceReference(
    id="diff",
    kind=EvidenceKind.REVIEWED_DIFF,
    description="Reviewed change",
    sha256="b" * 64,
    disclosure=DisclosureStatus.PRIVATE,
)


def claim(
    dimension: ContributionDimension,
    actor: str,
    level: ContributionLevel = ContributionLevel.PRIMARY,
    evidence_status: EvidenceStatus = EvidenceStatus.ARTIFACT_CORRELATED,
    *,
    autonomy: AiAutonomy = AiAutonomy.NONE,
    evidence: tuple[str, ...] = (),
    explanation: str | None = None,
) -> ContributionClaim:
    return ContributionClaim(
        dimension=dimension,
        actor_id=actor,
        claim_type=ClaimType.DECLARATION,
        level=level,
        evidence_status=evidence_status,
        ai_autonomy=autonomy,
        explanation=explanation or f"{actor} contributed to {dimension.value}.",
        evidence_ids=evidence,
    )


def keypair(tmp_path: Path, actor_id: str) -> tuple[Path, Path]:
    private, public = tmp_path / f"{actor_id}.key", tmp_path / f"{actor_id}.pub"
    if not private.exists():
        generate_ed25519_keypair(private, public)
    return private, public


def solid_record(**extra: object) -> ProcessAttestation:
    """A record that reaches PAL-3 so a single defect is the only variable."""

    return issue_attestation(
        subject_sha256=DIGEST,
        subject_name="deliverable.md",
        actors=extra.pop("actors", (ALICE, ASSISTANT, BOB)),  # type: ignore[arg-type]
        evidence=extra.pop("evidence", (TESTS, DIFF)),  # type: ignore[arg-type]
        activities=(
            Activity(
                id="draft",
                action="Generated the draft",
                actor_ids=("assistant",),
                ai_autonomy=AiAutonomy.DELEGATED_EXECUTION,
            ),
        ),
        claims=(
            claim(ContributionDimension.ORIGINATION, "alice", evidence=("diff",)),
            claim(ContributionDimension.FRAMING, "alice", evidence=("diff",)),
            claim(
                ContributionDimension.EXECUTION,
                "assistant",
                autonomy=AiAutonomy.DELEGATED_EXECUTION,
                evidence=("diff",),
            ),
            claim(ContributionDimension.VALIDATION, "alice", evidence=("tests",)),
            claim(ContributionDimension.DECISION_CONTROL, "alice", evidence=("diff",)),
            claim(
                ContributionDimension.ACCOUNTABILITY,
                "alice",
                ContributionLevel.ORIGINATING_OR_CONTROLLING,
                EvidenceStatus.SELF_DECLARED,
            ),
        ),
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
        **extra,  # type: ignore[arg-type]
    )


def countersigned(record: ProcessAttestation, tmp_path: Path) -> tuple[ProcessAttestation, dict]:
    alice_key, alice_public = keypair(tmp_path, "alice")
    bob_key, bob_public = keypair(tmp_path, "bob")
    record = sign_attestation(
        record, role=SignatureRole.CLAIMANT, actor_id="alice", signing_key=alice_key
    )
    record = sign_attestation(
        record, role=SignatureRole.REVIEWER, actor_id="bob", signing_key=bob_key
    )
    return record, {"alice": alice_public, "bob": bob_public}


def test_the_baseline_record_reaches_reviewed(tmp_path: Path) -> None:
    """Every test below removes one thing from this record. It must start clean."""

    record, keys = countersigned(solid_record(), tmp_path)

    assurance = assess_process_assurance(record, verify_attestation(record, public_keys=keys))

    assert assurance.level == ProcessAssuranceLevel.REVIEWED


# -- forged evidence -----------------------------------------------------------------


def test_disclosed_bytes_that_miss_their_commitment_block_the_evidenced_level(
    tmp_path: Path,
) -> None:
    """Offering bytes that do not hash to the commitment falsifies the claim."""

    digest, salt = commitment(b"the real test log")
    evidence = EvidenceReference(
        id="tests",
        kind=EvidenceKind.TEST_RUN,
        description="Suite run",
        commitment=digest,
        disclosure=DisclosureStatus.COMMITTED,
    )
    record, keys = countersigned(solid_record(evidence=(evidence, DIFF)), tmp_path)

    verification = verify_attestation(
        record,
        public_keys=keys,
        disclosed_evidence={"tests": salt + b"a log that was never produced"},
    )
    assurance = assess_process_assurance(record, verification)

    assert verification.disclosed_evidence_consistent is False
    assert assurance.level == ProcessAssuranceLevel.DECLARED
    assert any("commitment" in item for item in assurance.next_level_requires)


def test_honest_disclosure_of_the_committed_bytes_still_verifies(tmp_path: Path) -> None:
    """The check must not be a blanket failure for anyone who discloses anything."""

    digest, salt = commitment(b"the real test log")
    evidence = EvidenceReference(
        id="tests",
        kind=EvidenceKind.TEST_RUN,
        description="Suite run",
        commitment=digest,
        disclosure=DisclosureStatus.COMMITTED,
    )
    record, keys = countersigned(solid_record(evidence=(evidence, DIFF)), tmp_path)

    verification = verify_attestation(
        record, public_keys=keys, disclosed_evidence={"tests": salt + b"the real test log"}
    )

    assert verification.disclosed_evidence_consistent is True


def test_construction_refuses_a_claim_referencing_evidence_the_record_lacks() -> None:
    """The first line of defence is that such a record cannot be built here."""

    with pytest.raises(ValueError, match="unknown evidence"):
        issue_attestation(
            subject_sha256=DIGEST,
            subject_name="deliverable.md",
            actors=(ALICE,),
            claims=(claim(ContributionDimension.VALIDATION, "alice", evidence=("ghost",)),),
        )


def test_a_dangling_evidence_reference_from_elsewhere_is_reported(tmp_path: Path) -> None:
    """Records arrive from other tools. Verification cannot assume ours built them."""

    record, keys = countersigned(solid_record(), tmp_path)
    stripped = record.model_copy(
        update={"evidence": tuple(item for item in record.evidence if item.id != "tests")}
    )

    verification = verify_attestation(stripped, public_keys=keys)

    assert verification.evidence_binding_complete is False
    assert any("does not contain" in problem for problem in verification.problems)
    assert assess_process_assurance(stripped, verification).level == (
        ProcessAssuranceLevel.UNSUBSTANTIATED
    ), "editing the record after signing breaks its identifier as well"


# -- backdated claims ----------------------------------------------------------------


def test_a_backdated_signature_is_only_caught_by_a_separate_authority(tmp_path: Path) -> None:
    """``signed_at`` is the signer's own claim, and a backdater simply writes it."""

    alice_key, alice_public = keypair(tmp_path, "alice")
    record = sign_attestation(
        solid_record(),
        role=SignatureRole.CLAIMANT,
        actor_id="alice",
        signing_key=alice_key,
        signed_at=datetime(2019, 1, 1, tzinfo=UTC),
    )

    verification = verify_attestation(record, public_keys={"alice": alice_public})

    # The signature is valid: nothing in it constrains the date the signer wrote.
    assert verification.claimant_signature == "valid"
    assert verification.trusted_timestamp is None
    # And the assurance ceiling reflects that no authority attested the time.
    assurance = assess_process_assurance(record, verification)
    assert assurance.level != ProcessAssuranceLevel.INDEPENDENTLY_ASSURED


def test_a_timestamp_token_over_different_bytes_does_not_establish_the_time(
    tmp_path: Path,
) -> None:
    """A token is evidence about the bytes it covers, and no others."""

    authority_key, authority_public = keypair(tmp_path, "tsa")
    alice_key, alice_public = keypair(tmp_path, "alice")
    provider = OfflineTimestampProvider(
        LocalKeySigningProvider(authority_key), authority="ACME TSA"
    )
    stolen = provider.timestamp(hashlib.sha256(b"some other document").hexdigest())

    record = sign_attestation(
        solid_record(), role=SignatureRole.CLAIMANT, actor_id="alice", signing_key=alice_key
    )
    signature = record.signatures[0]
    forged = record.model_copy(
        update={
            "signatures": (
                AttestationSignature(
                    role=signature.role,
                    actor_id=signature.actor_id,
                    signed_at=signature.signed_at,
                    signature=signature.signature,
                    timestamp=stolen,
                ),
            )
        }
    )

    verification = verify_attestation(
        forged, public_keys={"alice": alice_public}, timestamp_authority_key=authority_public
    )

    assert verification.trusted_timestamp is False
    assert any("Timestamp not established" in problem for problem in verification.problems)


# -- prompt spam and hostile text ----------------------------------------------------


def test_record_prose_reaches_the_terminal_as_text_not_as_formatting(tmp_path: Path) -> None:
    """A record's own strings are data. Rich must never interpret them as markup."""

    injected = "[red]CERTIFIED HUMAN[/red] [bold]100% original[/bold]"
    record = solid_record(extra_limitations=(Limitation(code="vendor_note", statement=injected),))
    record, keys = countersigned(record, tmp_path)
    destination = tmp_path / "record.process.json"
    destination.write_text(attestation_json(record) + "\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "attestations",
            "verify",
            str(destination),
            "--public-key",
            f"alice={keys['alice']}",
        ],
    )

    # The brackets survive as literal characters. If Rich had parsed them, the
    # tags would have been consumed and only the words would remain.
    assert "[red]CERTIFIED HUMAN[/red]" in result.output
    assert "\x1b[31m" not in result.output


def test_a_claim_explanation_cannot_style_the_profile_view(tmp_path: Path) -> None:
    injected = "[bold green]VERIFIED HUMAN AUTHOR[/bold green]"
    record = solid_record(extra_limitations=(Limitation(code="vendor_note", statement=injected),))
    record, keys = countersigned(record, tmp_path)
    destination = tmp_path / "record.process.json"
    destination.write_text(attestation_json(record) + "\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "attestations",
            "evaluate",
            str(destination),
            "--public-key",
            f"alice={keys['alice']}",
            "--public-key",
            f"bob={keys['bob']}",
        ],
    )

    assert "[bold green]VERIFIED HUMAN AUTHOR[/bold green]" in result.output


def test_a_flood_of_claims_is_refused_at_the_model_boundary() -> None:
    """String caps alone do not bound a record. Collections need their own."""

    flood = tuple(
        claim(
            ContributionDimension.ORIGINATION,
            "alice",
            evidence_status=EvidenceStatus.SELF_DECLARED,
            explanation=f"Filler claim {index}.",
        )
        for index in range(1001)
    )

    with pytest.raises(ValueError):
        issue_attestation(
            subject_sha256=DIGEST,
            subject_name="deliverable.md",
            actors=(ALICE,),
            claims=flood,
        )


def test_a_realistic_number_of_claims_is_accepted() -> None:
    """The bound exists to refuse a flood, not to constrain a real project."""

    record = issue_attestation(
        subject_sha256=DIGEST,
        subject_name="deliverable.md",
        actors=(ALICE,),
        claims=tuple(
            claim(
                dimension,
                "alice",
                evidence_status=EvidenceStatus.SELF_DECLARED,
            )
            for dimension in ContributionDimension
        ),
    )

    assert len(record.claims) == len(ContributionDimension)


def test_a_flood_of_signatures_is_refused() -> None:
    with pytest.raises(ValueError):
        ProcessAttestation.model_validate(
            {
                **solid_record().model_dump(mode="python"),
                "signatures": tuple({} for _ in range(51)),
            }
        )


def test_oversized_prose_is_refused_at_the_model_boundary() -> None:
    """Field limits exist so a record cannot become a delivery vehicle for a blob."""

    with pytest.raises(ValueError):
        claim(
            ContributionDimension.ORIGINATION,
            "alice",
            explanation="x" * 100_000,
        )


def test_a_record_with_control_characters_survives_a_round_trip(tmp_path: Path) -> None:
    """Hostile input must not corrupt canonical serialization."""

    record = issue_attestation(
        subject_sha256=DIGEST,
        subject_name="deliverable‮.md",
        actors=(ALICE,),
        claims=(
            claim(
                ContributionDimension.ORIGINATION,
                "alice",
                evidence_status=EvidenceStatus.SELF_DECLARED,
            ),
        ),
    )
    path = tmp_path / "record.process.json"
    path.write_text(attestation_json(record) + "\n", encoding="utf-8")

    reloaded = load_attestation(path)

    assert reloaded == record
    assert compute_attestation_id(reloaded) == reloaded.attestation_id


# -- actor impersonation -------------------------------------------------------------


def test_signing_under_another_actors_id_does_not_verify_with_their_key(
    tmp_path: Path,
) -> None:
    """Mallory can write Alice's id into a signature. She cannot make it verify."""

    _, alice_public = keypair(tmp_path, "alice")
    mallory_key, _ = keypair(tmp_path, "mallory")

    record = sign_attestation(
        solid_record(),
        role=SignatureRole.CLAIMANT,
        actor_id="alice",
        signing_key=mallory_key,
    )

    verification = verify_attestation(record, public_keys={"alice": alice_public})

    assert verification.claimant_signature == "invalid"
    assert verification.authenticated_declaration is False
    assert assess_process_assurance(record, verification).level == (
        ProcessAssuranceLevel.UNSUBSTANTIATED
    )


def test_an_unverified_signature_is_not_reported_as_an_invalid_one(tmp_path: Path) -> None:
    """Supplying no key is a gap in the verifier's knowledge, not a defect in the record."""

    record, _ = countersigned(solid_record(), tmp_path)

    verification = verify_attestation(record)

    assert verification.claimant_signature == "unverified"
    assert verification.problems == ()


def test_a_signature_from_an_actor_the_record_never_names_is_refused(tmp_path: Path) -> None:
    """A record cannot be countersigned by somebody it does not list."""

    mallory_key, _ = keypair(tmp_path, "mallory")

    with pytest.raises(AttestationError, match="Unknown actor"):
        sign_attestation(
            solid_record(),
            role=SignatureRole.REVIEWER,
            actor_id="mallory",
            signing_key=mallory_key,
        )


def test_an_actor_the_record_does_name_can_countersign(tmp_path: Path) -> None:
    """The refusal above must be about membership, not about the key."""

    mallory_key, mallory_public = keypair(tmp_path, "mallory")
    record = solid_record(actors=(ALICE, ASSISTANT, BOB, MALLORY))

    record = sign_attestation(
        record, role=SignatureRole.REVIEWER, actor_id="mallory", signing_key=mallory_key
    )

    assert (
        verify_attestation(record, public_keys={"mallory": mallory_public}).reviewer_signature
        == "valid"
    )


def test_adding_a_signature_does_not_invalidate_the_existing_ones(tmp_path: Path) -> None:
    """Countersigning must be additive, or nobody will countersign anything."""

    record, keys = countersigned(solid_record(), tmp_path)

    verification = verify_attestation(record, public_keys=keys)

    assert verification.claimant_signature == "valid"
    assert verification.reviewer_signature == "valid"


# -- omitted AI roles ----------------------------------------------------------------


def test_machine_work_without_a_named_ai_actor_cannot_reach_evidenced(tmp_path: Path) -> None:
    """Omission is not a shortcut to a higher level."""

    record = issue_attestation(
        subject_sha256=DIGEST,
        subject_name="deliverable.md",
        actors=(ALICE, BOB),
        evidence=(TESTS, DIFF),
        claims=(
            claim(
                ContributionDimension.EXECUTION,
                "alice",
                autonomy=AiAutonomy.DELEGATED_EXECUTION,
                evidence=("diff",),
            ),
            claim(ContributionDimension.VALIDATION, "alice", evidence=("tests",)),
            claim(ContributionDimension.DECISION_CONTROL, "alice", evidence=("diff",)),
        ),
    )
    record, keys = countersigned(record, tmp_path)

    assurance = assess_process_assurance(record, verify_attestation(record, public_keys=keys))

    assert assurance.level == ProcessAssuranceLevel.DECLARED
    assert any("name the AI systems" in item for item in assurance.next_level_requires)


def test_stating_that_no_ai_participated_is_a_disclosure(tmp_path: Path) -> None:
    """The requirement is disclosure, not the presence of an AI."""

    record = issue_attestation(
        subject_sha256=DIGEST,
        subject_name="deliverable.md",
        actors=(ALICE, BOB),
        evidence=(TESTS, DIFF),
        claims=(
            claim(ContributionDimension.EXECUTION, "alice", evidence=("diff",)),
            claim(ContributionDimension.VALIDATION, "alice", evidence=("tests",)),
            claim(ContributionDimension.DECISION_CONTROL, "alice", evidence=("diff",)),
        ),
    )
    record, keys = countersigned(record, tmp_path)

    assurance = assess_process_assurance(record, verify_attestation(record, public_keys=keys))

    assert assurance.level == ProcessAssuranceLevel.EVIDENCED


# -- conflicting countersignatures ---------------------------------------------------


def test_recorded_dissent_blocks_the_reviewed_level(tmp_path: Path) -> None:
    """A dispute is not resolved by outranking it."""

    record = solid_record(
        evaluation=Evaluation(
            profile="software-delivery",
            rubric_version="0.1",
            assessor_actor_id="bob",
            assessed_at=NOW,
            results=(
                DimensionAssessment(
                    dimension=ContributionDimension.EXECUTION,
                    level=ContributionLevel.SUPPORTING,
                    confidence="medium",
                    dissent="The reviewer does not agree the execution claim is supported.",
                ),
            ),
        )
    )
    record, keys = countersigned(record, tmp_path)

    verification = verify_attestation(
        record, public_keys=keys, supported_profiles=frozenset({"software-delivery"})
    )
    assurance = assess_process_assurance(record, verification)

    assert verification.unresolved_dissent is True
    assert assurance.level == ProcessAssuranceLevel.EVIDENCED
    assert any("dissent" in item for item in assurance.next_level_requires)


def test_a_profile_result_reports_the_blocked_assurance_rather_than_hiding_it(
    tmp_path: Path,
) -> None:
    record = solid_record(
        evaluation=Evaluation(
            profile="software-delivery",
            rubric_version="0.1",
            assessor_actor_id="bob",
            assessed_at=NOW,
            dissent="The reviewer disputes the scope of the validation claim.",
        )
    )
    record, keys = countersigned(record, tmp_path)

    result = evaluate_with_profile(
        record,
        verify_attestation(
            record, public_keys=keys, supported_profiles=frozenset({"software-delivery"})
        ),
        get_profile("software-delivery"),
    )

    assert result.meets_review_requirements is False
    assert any("assurance" in item for item in result.unmet_requirements)


# -- redaction leaks -----------------------------------------------------------------


def test_a_public_variant_contains_none_of_the_private_material(tmp_path: Path) -> None:
    secret = "The anomaly is a reporting lag in the EU subsidiary ledger."
    notes = EvidenceReference(
        id="notes",
        kind=EvidenceKind.RESEARCH_NOTE,
        description=secret,
        sha256="d" * 64,
        disclosure=DisclosureStatus.PRIVATE,
    )
    record = solid_record(evidence=(TESTS, DIFF, notes))
    record, _ = countersigned(record, tmp_path)

    public = redact_for_public(record)
    rendered = attestation_json(public)

    for material in private_material(record):
        assert material not in rendered
    assert secret not in rendered
    assert public.attestation_id != record.attestation_id
    assert public.signatures == ()


def test_redaction_leaves_the_public_variant_verifiable_on_its_own_terms(
    tmp_path: Path,
) -> None:
    record, _ = countersigned(solid_record(), tmp_path)

    public = redact_for_public(record)
    verification = verify_attestation(public)

    assert verification.content_id_valid is True
    assert verification.claimant_signature == "absent"
    assert assess_process_assurance(public, verification).level == (
        ProcessAssuranceLevel.UNSUBSTANTIATED
    )


# -- changed artifacts ---------------------------------------------------------------


def test_one_changed_byte_unbinds_the_record(tmp_path: Path) -> None:
    artifact = tmp_path / "deliverable.md"
    artifact.write_text("# Report\n", encoding="utf-8")
    record = issue_attestation(
        subject_sha256=hashlib.sha256(artifact.read_bytes()).hexdigest(),
        subject_name="deliverable.md",
        actors=(ALICE, BOB),
        claims=(
            claim(
                ContributionDimension.ORIGINATION,
                "alice",
                evidence_status=EvidenceStatus.SELF_DECLARED,
            ),
        ),
    )
    record, keys = countersigned(record, tmp_path)
    artifact.write_text("# Report.\n", encoding="utf-8")

    verification = verify_attestation(record, artifact=artifact, public_keys=keys)

    assert verification.subject_bound is False
    assert assess_process_assurance(record, verification).level == (
        ProcessAssuranceLevel.UNSUBSTANTIATED
    )


def test_editing_a_claim_breaks_the_content_identifier(tmp_path: Path) -> None:
    """Upgrading a claim after signing must not survive verification."""

    record, keys = countersigned(solid_record(), tmp_path)
    tampered = record.model_copy(
        update={
            "claims": tuple(
                item.model_copy(update={"level": ContributionLevel.ORIGINATING_OR_CONTROLLING})
                for item in record.claims
            )
        }
    )

    verification = verify_attestation(tampered, public_keys=keys)

    assert verification.content_id_valid is False
    assert verification.claimant_signature == "invalid"


# -- expired claims ------------------------------------------------------------------


def test_an_expired_record_is_unsubstantiated_not_merely_noted(tmp_path: Path) -> None:
    record = solid_record(created_at=NOW - timedelta(days=400), expires_at=NOW - timedelta(days=1))
    record, keys = countersigned(record, tmp_path)

    verification = verify_attestation(record, public_keys=keys, now=NOW)

    assert verification.expired is True
    assert verification.authenticated_declaration is False
    assert assess_process_assurance(record, verification).level == (
        ProcessAssuranceLevel.UNSUBSTANTIATED
    )


def test_a_record_inside_its_window_is_unaffected(tmp_path: Path) -> None:
    record = solid_record(created_at=NOW - timedelta(days=1), expires_at=NOW + timedelta(days=30))
    record, keys = countersigned(record, tmp_path)

    verification = verify_attestation(record, public_keys=keys, now=NOW)

    assert verification.expired is False
    assert verification.authenticated_declaration is True


# -- revoked issuers -----------------------------------------------------------------


def test_a_binding_that_has_lapsed_returns_the_key_to_anonymity(tmp_path: Path) -> None:
    """A revoked issuer is a key again, not an organization with a warning label."""

    record, keys = countersigned(solid_record(), tmp_path)
    profile = TrustProfile(
        profile_id="acme",
        issued_at=NOW - timedelta(days=400),
        bindings=(
            IssuerBinding(
                key_id=public_key_id(keys["alice"]),
                organization="ACME Research",
                not_before=NOW - timedelta(days=400),
                not_after=NOW - timedelta(days=30),
            ),
        ),
    )

    verification = verify_attestation(record, public_keys=keys, trust_profile=profile, now=NOW)

    assert verification.authenticated_declaration is True
    assert verification.organizationally_attributed is False
    assert verification.claimant_identity is not None
    assert "no binding in force" in verification.claimant_identity.explanation


def test_a_binding_in_force_attributes_the_organization(tmp_path: Path) -> None:
    record, keys = countersigned(solid_record(), tmp_path)
    profile = TrustProfile(
        profile_id="acme",
        issued_at=NOW - timedelta(days=1),
        bindings=(
            IssuerBinding(
                key_id=public_key_id(keys["alice"]),
                organization="ACME Research",
                not_before=NOW - timedelta(days=1),
                not_after=NOW + timedelta(days=365),
            ),
        ),
    )

    verification = verify_attestation(record, public_keys=keys, trust_profile=profile, now=NOW)

    assert verification.organizationally_attributed is True


# -- unsupported evaluation profiles -------------------------------------------------


def test_an_unsupported_profile_is_reported_rather_than_interpreted(tmp_path: Path) -> None:
    """A verifier that does not know a rubric cannot read its levels."""

    record = solid_record(
        evaluation=Evaluation(
            profile="acme-internal-v9",
            rubric_version="9.0",
            assessor_actor_id="bob",
            assessed_at=NOW,
            results=(
                DimensionAssessment(
                    dimension=ContributionDimension.EXECUTION,
                    level=ContributionLevel.ORIGINATING_OR_CONTROLLING,
                    confidence="high",
                ),
            ),
        )
    )
    record, keys = countersigned(record, tmp_path)

    verification = verify_attestation(
        record, public_keys=keys, supported_profiles=frozenset({"software-delivery"})
    )

    assert verification.evaluation_profile_supported is False
    assert any("not supported here" in problem for problem in verification.problems)
    # An unknown rubric must not lift the record to independently assured.
    assert assess_process_assurance(record, verification).level != (
        ProcessAssuranceLevel.INDEPENDENTLY_ASSURED
    )


def test_the_cli_names_the_profiles_it_does_know(tmp_path: Path) -> None:
    record, _ = countersigned(solid_record(), tmp_path)
    path = tmp_path / "record.process.json"
    path.write_text(attestation_json(record) + "\n", encoding="utf-8")

    result = runner.invoke(
        app, ["attestations", "evaluate", str(path), "--profile", "acme-internal-v9"]
    )

    assert result.exit_code == 3
    assert "research" in result.output and "education" in result.output


# -- usability -----------------------------------------------------------------------


def test_the_portable_summary_states_what_it_does_not_establish(tmp_path: Path) -> None:
    """A recipient reading only the summary must not over-read it."""

    record, keys = countersigned(solid_record(), tmp_path)

    summary = portable_summary(record, verify_attestation(record, public_keys=keys))

    assert "%" not in summary
    assert "authored" not in summary.lower()
    assert "Limitations:" in summary
    # The four standing limitations are the part a reader is most likely to skip,
    # so the summary states each of them rather than referring to them.
    for statement in (limitation.statement for limitation in record.limitations):
        assert statement in summary
    assert "no overall human percentage" in summary.lower()


def test_a_failing_profile_result_reads_as_a_rule_not_an_accusation(tmp_path: Path) -> None:
    record, keys = countersigned(solid_record(), tmp_path)

    result = evaluate_with_profile(
        record, verify_attestation(record, public_keys=keys), get_profile("education")
    )
    rendered = " ".join(result.unmet_requirements) + " " + result.statement

    assert result.meets_review_requirements is False
    for word in ("cheat", "fraud", "plagiar", "dishonest", "suspicious"):
        assert word not in rendered.lower()
    assert "does not permit" in rendered


def test_the_next_step_is_stated_rather_than_left_to_be_inferred(tmp_path: Path) -> None:
    """An assurance level a team cannot act on is a grade, not a tool."""

    alice_key, alice_public = keypair(tmp_path, "alice")
    record = sign_attestation(
        solid_record(), role=SignatureRole.CLAIMANT, actor_id="alice", signing_key=alice_key
    )

    assurance = assess_process_assurance(
        record, verify_attestation(record, public_keys={"alice": alice_public})
    )

    assert assurance.level == ProcessAssuranceLevel.EVIDENCED
    assert assurance.next_level_requires
    assert any("countersign" in item for item in assurance.next_level_requires)


def test_verifying_without_keys_tells_the_reader_what_is_missing(tmp_path: Path) -> None:
    record, _ = countersigned(solid_record(), tmp_path)
    path = tmp_path / "record.process.json"
    path.write_text(attestation_json(record) + "\n", encoding="utf-8")

    result = runner.invoke(app, ["attestations", "verify", str(path)])

    assert "unverified (no key supplied)" in result.output
    assert "invalid" not in result.output.lower(), (
        "a missing key is the verifier's gap, and calling it invalid accuses the record"
    )


def test_the_json_verification_result_stays_machine_readable_under_attack(
    tmp_path: Path,
) -> None:
    """A hostile record must still produce parseable output, not a crash."""

    record, keys = countersigned(solid_record(), tmp_path)
    tampered = record.model_copy(update={"subject_name": "other‮.md"})
    path = tmp_path / "record.process.json"
    path.write_text(attestation_json(tampered) + "\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "attestations",
            "verify",
            str(path),
            "--format",
            "json",
            "--public-key",
            f"alice={keys['alice']}",
        ],
    )

    payload = json.loads(result.output)
    assert payload["content_id_valid"] is False
    assert payload["problems"]
