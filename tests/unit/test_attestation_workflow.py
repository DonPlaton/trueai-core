"""The attestation workflow: manifests, evidence adapters, redaction, and the CLI."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from trueai.cli.app import app
from trueai.core.attestation import (
    DisclosureStatus,
    EvidenceKind,
    SignatureRole,
    attestation_json,
    load_attestation,
    sign_attestation,
    verify_attestation,
)
from trueai.core.attestation_manifest import (
    build_attestation,
    load_manifest,
    private_material,
    redact_for_public,
    summarize,
    template_manifest,
)
from trueai.core.certificates import generate_ed25519_keypair
from trueai.core.errors import AttestationError

pytest.importorskip("cryptography", reason="Signing needs the attestation extra")

runner = CliRunner()

MANIFEST = """
project:
  title: Quarterly analysis
  purpose: Explain the revenue anomaly.

subject:
  name: analysis.md

actors:
  - id: alice
    kind: person
    display_name: Alice
  - id: assistant
    kind: ai_system
    display_name: Assistant
    version: "2.0"

evidence:
  - id: notes
    kind: research_note
    description: Private working notes naming the mechanism
    disclosure: private
    path: notes.md
  - id: citation
    kind: source_citation
    description: Public dataset used for the comparison
    disclosure: public
    locator: https://example.test/dataset

activities:
  - id: draft
    action: Generated the first draft
    actors: [assistant]
    ai_autonomy: delegated_execution
    review_decision: accepted_with_changes
    reviewer: alice

decisions:
  - id: approach
    question: Seasonal model or anomaly detection?
    alternatives: [seasonal, anomaly-detection]
    selected: anomaly-detection
    approved_by: alice

claims:
  - dimension: origination
    actor: alice
    claim_type: declaration
    level: originating_or_controlling
    evidence_status: self_declared
    explanation: Alice identified the reporting-lag mechanism behind the anomaly.
    evidence: [notes]
  - dimension: execution
    actor: assistant
    claim_type: declaration
    level: primary
    ai_autonomy: delegated_execution
    evidence_status: self_declared
    explanation: The assistant wrote the prose from Alice's stated mechanism.
  - dimension: accountability
    actor: alice
    claim_type: declaration
    level: originating_or_controlling
    evidence_status: self_declared
    explanation: Alice stands behind the delivered analysis.
"""


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """A manifest, its private note, and the subject artifact."""

    (tmp_path / "manifest.yaml").write_text(MANIFEST, encoding="utf-8")
    (tmp_path / "notes.md").write_text(
        "Private: the anomaly is a reporting lag, not a demand shift.\n", encoding="utf-8"
    )
    (tmp_path / "analysis.md").write_text(
        "# Quarterly analysis\n\nThe anomaly...\n", encoding="utf-8"
    )
    return tmp_path


# -- manifests -----------------------------------------------------------------------


def test_the_starter_manifest_builds_a_valid_record(tmp_path: Path) -> None:
    """A user who runs init and issue without editing gets an honest, narrow record."""

    manifest = tmp_path / "attestation.yaml"
    manifest.write_text(template_manifest(), encoding="utf-8")
    subject = tmp_path / "deliverable.md"
    subject.write_text("content\n", encoding="utf-8")

    record = build_attestation(load_manifest(manifest), artifact=subject, base_directory=tmp_path)

    assert record.attestation_id.startswith("TAIP1-")
    assert {claim.dimension.value for claim in record.claims} == {
        "origination",
        "execution",
        "accountability",
    }
    # Everything it does not claim stays not_claimed rather than being inferred.
    assert not record.claims_for(
        __import__(
            "trueai.core.attestation", fromlist=["ContributionDimension"]
        ).ContributionDimension.VALIDATION
    )


def test_a_manifest_binds_the_subject_and_its_evidence_by_digest(workspace: Path) -> None:
    record = build_attestation(
        load_manifest(workspace / "manifest.yaml"),
        artifact=workspace / "analysis.md",
        base_directory=workspace,
    )

    expected = hashlib.sha256((workspace / "analysis.md").read_bytes()).hexdigest()
    note_digest = hashlib.sha256((workspace / "notes.md").read_bytes()).hexdigest()
    assert record.subject_sha256 == expected
    notes = next(item for item in record.evidence if item.id == "notes")
    assert notes.sha256 == note_digest
    assert notes.disclosure == DisclosureStatus.PRIVATE


def test_an_unknown_enum_value_names_what_was_allowed(workspace: Path) -> None:
    manifest = load_manifest(workspace / "manifest.yaml")
    manifest["claims"][0]["level"] = "mostly_human"

    with pytest.raises(AttestationError, match="is not one of"):
        build_attestation(manifest, artifact=workspace / "analysis.md", base_directory=workspace)


def test_a_manifest_without_a_subject_digest_is_refused(workspace: Path) -> None:
    manifest = load_manifest(workspace / "manifest.yaml")

    with pytest.raises(AttestationError, match=r"subject\.sha256"):
        build_attestation(manifest, base_directory=workspace)


# -- evidence adapters ---------------------------------------------------------------


def test_a_file_adapter_records_a_digest_not_the_contents(workspace: Path) -> None:
    from trueai.core import evidence

    reference = evidence.research_note("notes", workspace / "notes.md")

    payload = json.dumps(reference.model_dump(mode="json"))
    assert reference.sha256 == hashlib.sha256((workspace / "notes.md").read_bytes()).hexdigest()
    assert "reporting lag" not in payload
    assert reference.locator is None, "a private note must not carry a path"


def test_a_commitment_is_salted_so_a_guess_cannot_confirm_itself() -> None:
    from trueai.core import evidence

    statement = b"we chose anomaly detection"
    first, salt = evidence.commitment(statement)
    second, _ = evidence.commitment(statement)

    assert first != second, "an unsalted commitment would let an adversary confirm a guess"
    assert evidence.open_commitment(statement, salt, first)
    assert not evidence.open_commitment(b"something else", salt, first)


def test_git_commit_evidence_records_hashes_without_messages(tmp_path: Path) -> None:
    from trueai.core import evidence

    repository = tmp_path / "repo"
    repository.mkdir()

    def git(*arguments: str) -> None:
        subprocess.run(["git", "-C", str(repository), *arguments], check=True, capture_output=True)

    git("init", "-q")
    git("config", "user.name", "Alice")
    git("config", "user.email", "alice@example.test")
    (repository / "file.txt").write_text("content\n", encoding="utf-8")
    git("add", "file.txt")
    git("commit", "-q", "-m", "Secret internal codename: project-thunder")

    references = evidence.git_commits(repository, limit=5)

    assert len(references) == 1
    payload = json.dumps(references[0].model_dump(mode="json"))
    assert "project-thunder" not in payload, "a private commit summary must not leak"
    assert references[0].kind == EvidenceKind.GIT_COMMIT


def test_a_command_receipt_commits_to_exactly_what_ran(tmp_path: Path) -> None:
    import sys

    from trueai.core import evidence

    reference, payload = evidence.test_run(
        "suite", [sys.executable, "-c", "print('4 passed')"], working_directory=tmp_path
    )

    assert reference.kind == EvidenceKind.TEST_RUN
    assert reference.sha256 == hashlib.sha256(payload).hexdigest()
    assert b"4 passed" in payload


def test_an_empty_command_is_refused() -> None:
    from trueai.core import evidence

    with pytest.raises(AttestationError, match="needs a command"):
        evidence.command_receipt("x", [], kind=EvidenceKind.TEST_RUN)


def test_duplicate_evidence_identifiers_are_refused_not_merged(workspace: Path) -> None:
    from trueai.core import evidence

    first = evidence.research_note("notes", workspace / "notes.md")
    second = evidence.research_note("notes", workspace / "analysis.md")

    with pytest.raises(AttestationError, match="Duplicate evidence identifier"):
        evidence.unique_identifiers([first, second])


def test_an_oversized_evidence_file_is_refused(tmp_path: Path, monkeypatch) -> None:
    from trueai.core import evidence

    big = tmp_path / "big.bin"
    big.write_bytes(b"x" * 4096)
    monkeypatch.setattr(evidence, "MAX_EVIDENCE_BYTES", 1024)

    with pytest.raises(AttestationError, match="limit is"):
        evidence.digest_file(big)


# -- redaction -----------------------------------------------------------------------


def test_redaction_removes_every_piece_of_withheld_material(workspace: Path) -> None:
    """The leakage check is executed, not assumed."""

    record = build_attestation(
        load_manifest(workspace / "manifest.yaml"),
        artifact=workspace / "analysis.md",
        base_directory=workspace,
    )
    secrets = private_material(record)
    assert secrets, "the fixture must contain something worth withholding"

    public = redact_for_public(record)

    rendered = attestation_json(public)
    for secret in secrets:
        assert secret not in rendered, f"redaction leaked {secret!r}"


def test_redaction_keeps_the_claims_it_exists_to_publish(workspace: Path) -> None:
    record = build_attestation(
        load_manifest(workspace / "manifest.yaml"),
        artifact=workspace / "analysis.md",
        base_directory=workspace,
    )

    public = redact_for_public(record)

    assert len(public.claims) == len(record.claims)
    assert public.subject_sha256 == record.subject_sha256
    assert {item.id for item in public.evidence} == {item.id for item in record.evidence}


def test_public_evidence_survives_redaction_intact(workspace: Path) -> None:
    record = build_attestation(
        load_manifest(workspace / "manifest.yaml"),
        artifact=workspace / "analysis.md",
        base_directory=workspace,
    )

    public = redact_for_public(record)

    citation = next(item for item in public.evidence if item.id == "citation")
    assert citation.locator == "https://example.test/dataset"
    assert citation.description.startswith("Public dataset")


def test_a_redacted_record_gets_a_new_identifier(workspace: Path) -> None:
    """It makes a narrower set of statements, so it is a different document."""

    record = build_attestation(
        load_manifest(workspace / "manifest.yaml"),
        artifact=workspace / "analysis.md",
        base_directory=workspace,
    )

    public = redact_for_public(record)

    assert public.attestation_id != record.attestation_id
    assert verify_attestation(public).content_id_valid


def test_redaction_drops_signatures_that_covered_the_full_record(
    workspace: Path, tmp_path: Path
) -> None:
    private_key, public_key = tmp_path / "a.key", tmp_path / "a.pub"
    generate_ed25519_keypair(private_key, public_key)
    record = sign_attestation(
        build_attestation(
            load_manifest(workspace / "manifest.yaml"),
            artifact=workspace / "analysis.md",
            base_directory=workspace,
        ),
        role=SignatureRole.CLAIMANT,
        actor_id="alice",
        signing_key=private_key,
    )

    public = redact_for_public(record)

    assert record.signatures
    assert public.signatures == ()


# -- summaries -----------------------------------------------------------------------


def test_a_summary_always_repeats_the_limitations(workspace: Path) -> None:
    """A summary is where a reader stops reading, so it must not stop before these."""

    record = build_attestation(
        load_manifest(workspace / "manifest.yaml"),
        artifact=workspace / "analysis.md",
        base_directory=workspace,
    )

    rendered = summarize(record)

    assert "Limitations:" in rendered
    for limitation in record.limitations:
        assert limitation.statement in rendered


def test_a_summary_shows_stages_rather_than_a_verdict(workspace: Path) -> None:
    record = build_attestation(
        load_manifest(workspace / "manifest.yaml"),
        artifact=workspace / "analysis.md",
        base_directory=workspace,
    )

    rendered = summarize(record)

    assert "origination" in rendered
    assert "execution" in rendered
    # Unclaimed dimensions are shown as unclaimed rather than omitted.
    assert "validation" in rendered and "not_claimed" in rendered
    assert "%" not in rendered, "a summary must not imply an aggregate percentage"


# -- CLI -----------------------------------------------------------------------------


def test_the_cli_runs_the_whole_workflow_offline(workspace: Path, tmp_path: Path) -> None:
    keys = tmp_path / "keys"
    keys.mkdir()
    private_key, public_key = keys / "alice.key", keys / "alice.pub"

    keygen = runner.invoke(app, ["attestations", "keygen", str(private_key), str(public_key)])
    assert keygen.exit_code == 0, keygen.output

    issued = workspace / "analysis.process.json"
    issue = runner.invoke(
        app,
        [
            "attestations",
            "issue",
            str(workspace / "manifest.yaml"),
            "--artifact",
            str(workspace / "analysis.md"),
            "--output",
            str(issued),
            "--signing-key",
            str(private_key),
            "--claimant",
            "alice",
        ],
    )
    assert issue.exit_code == 0, issue.output
    assert issued.is_file()

    verify = runner.invoke(
        app,
        [
            "attestations",
            "verify",
            str(issued),
            "--artifact",
            str(workspace / "analysis.md"),
            "--public-key",
            f"alice={public_key}",
        ],
    )
    assert verify.exit_code == 0, verify.output
    assert "Authenticated declaration" in verify.output
    # The wording must not promise more than a signature establishes.
    assert "not a verified human-contribution claim" in verify.output.lower()


def test_the_cli_reports_a_changed_artifact_as_a_violation(workspace: Path, tmp_path: Path) -> None:
    issued = workspace / "analysis.process.json"
    runner.invoke(
        app,
        [
            "attestations",
            "issue",
            str(workspace / "manifest.yaml"),
            "--artifact",
            str(workspace / "analysis.md"),
            "--output",
            str(issued),
        ],
    )
    (workspace / "analysis.md").write_text("rewritten after issuance\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "attestations",
            "verify",
            str(issued),
            "--artifact",
            str(workspace / "analysis.md"),
        ],
    )

    assert result.exit_code == 2, result.output


def test_the_cli_treats_an_unsigned_record_as_review_not_failure(workspace: Path) -> None:
    """Unsigned and self-declared are honest states, not errors."""

    issued = workspace / "analysis.process.json"
    runner.invoke(
        app,
        [
            "attestations",
            "issue",
            str(workspace / "manifest.yaml"),
            "--artifact",
            str(workspace / "analysis.md"),
            "--output",
            str(issued),
        ],
    )

    result = runner.invoke(app, ["attestations", "verify", str(issued)])

    assert result.exit_code == 1, result.output
    assert "Not an authenticated declaration" in result.output


def test_the_cli_verify_emits_machine_readable_results(workspace: Path) -> None:
    issued = workspace / "analysis.process.json"
    runner.invoke(
        app,
        [
            "attestations",
            "issue",
            str(workspace / "manifest.yaml"),
            "--artifact",
            str(workspace / "analysis.md"),
            "--output",
            str(issued),
        ],
    )

    result = runner.invoke(app, ["attestations", "verify", str(issued), "--format", "json"])

    payload = json.loads(result.output)
    assert payload["content_id_valid"] is True
    assert payload["claimant_signature"] == "absent"
    assert "authenticated_declaration" not in payload, (
        "the derived property is presentation, not a field consumers should key on"
    )


def test_the_cli_countersigns_without_invalidating_the_claimant(
    workspace: Path, tmp_path: Path
) -> None:
    alice_key, alice_public = tmp_path / "a.key", tmp_path / "a.pub"
    bob_key, bob_public = tmp_path / "b.key", tmp_path / "b.pub"
    generate_ed25519_keypair(alice_key, alice_public)
    generate_ed25519_keypair(bob_key, bob_public)
    manifest = load_manifest(workspace / "manifest.yaml")
    manifest["actors"].append({"id": "bob", "kind": "person", "display_name": "Bob"})
    (workspace / "manifest.yaml").write_text(json.dumps(manifest), encoding="utf-8")
    issued = workspace / "analysis.process.json"
    runner.invoke(
        app,
        [
            "attestations",
            "issue",
            str(workspace / "manifest.yaml"),
            "--artifact",
            str(workspace / "analysis.md"),
            "--output",
            str(issued),
            "--signing-key",
            str(alice_key),
            "--claimant",
            "alice",
        ],
    )

    countersign = runner.invoke(
        app,
        [
            "attestations",
            "sign",
            str(issued),
            "--signing-key",
            str(bob_key),
            "--actor",
            "bob",
            "--role",
            "reviewer",
        ],
    )

    assert countersign.exit_code == 0, countersign.output
    result = verify_attestation(
        load_attestation(issued), public_keys={"alice": alice_public, "bob": bob_public}
    )
    assert result.claimant_signature == "valid"
    assert result.reviewer_signature == "valid"


def test_the_cli_refuses_an_unknown_signature_role(workspace: Path, tmp_path: Path) -> None:
    private_key, public_key = tmp_path / "a.key", tmp_path / "a.pub"
    generate_ed25519_keypair(private_key, public_key)
    issued = workspace / "analysis.process.json"
    runner.invoke(
        app,
        [
            "attestations",
            "issue",
            str(workspace / "manifest.yaml"),
            "--artifact",
            str(workspace / "analysis.md"),
            "--output",
            str(issued),
        ],
    )

    result = runner.invoke(
        app,
        [
            "attestations",
            "sign",
            str(issued),
            "--signing-key",
            str(private_key),
            "--actor",
            "alice",
            "--role",
            "notary",
        ],
    )

    assert result.exit_code == 3
    assert "Unknown role" in result.output


def test_the_cli_redacts_to_a_public_variant(workspace: Path) -> None:
    issued = workspace / "analysis.process.json"
    runner.invoke(
        app,
        [
            "attestations",
            "issue",
            str(workspace / "manifest.yaml"),
            "--artifact",
            str(workspace / "analysis.md"),
            "--output",
            str(issued),
        ],
    )
    record = load_attestation(issued)

    result = runner.invoke(app, ["attestations", "redact", str(issued)])

    assert result.exit_code == 0, result.output
    public = load_attestation(workspace / "analysis.process.public.json")
    rendered = attestation_json(public)
    for secret in private_material(record):
        assert secret not in rendered


def test_the_cli_init_refuses_to_overwrite_without_force(tmp_path: Path) -> None:
    manifest = tmp_path / "attestation.yaml"
    manifest.write_text("existing: true\n", encoding="utf-8")

    result = runner.invoke(app, ["attestations", "init", str(manifest)])

    assert result.exit_code == 3
    assert manifest.read_text(encoding="utf-8") == "existing: true\n"


def test_the_cli_validate_reports_a_bad_manifest_without_writing(tmp_path: Path) -> None:
    manifest = tmp_path / "broken.yaml"
    manifest.write_text("actors: []\nsubject:\n  sha256: nope\n", encoding="utf-8")

    result = runner.invoke(app, ["attestations", "validate", str(manifest)])

    assert result.exit_code == 3
    assert not list(tmp_path.glob("*.process.json"))


def test_a_scan_finding_never_becomes_a_contribution_claim(workspace: Path) -> None:
    """The two records stay separate: a scan cannot manufacture process claims."""

    from trueai import TrueAIEngine

    report = TrueAIEngine.default(discover_plugins=False).scan(workspace / "analysis.md")
    record = build_attestation(
        load_manifest(workspace / "manifest.yaml"),
        artifact=workspace / "analysis.md",
        base_directory=workspace,
    )

    # Whatever the scanner saw, the claims are exactly what the manifest declared.
    assert len(record.claims) == 3
    assert all(claim.claim_type.value == "declaration" for claim in record.claims)
    assert report.findings is not None
