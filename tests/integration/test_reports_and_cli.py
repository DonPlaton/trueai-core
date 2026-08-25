import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from trueai import TrueAIEngine
from trueai.cli.app import app
from trueai.core.certificates import generate_ed25519_keypair
from trueai.core.models import FindingCategory
from trueai.core.policy import PolicyStore
from trueai.core.policy_bundle import (
    FindingSelector,
    PolicyBundleControls,
    PolicySuppression,
    issue_policy_bundle,
    policy_bundle_json,
)
from trueai.reporters import JSONReporter, SARIFReporter

runner = CliRunner()


def _riff_chunk(identifier: bytes, payload: bytes) -> bytes:
    return (
        identifier
        + len(payload).to_bytes(4, "little")
        + payload
        + (b"\x00" if len(payload) & 1 else b"")
    )


def _wave_with_software(software: str, audio: bytes) -> bytes:
    info = b"INFO" + _riff_chunk(b"ISFT", software.encode("latin-1") + b"\x00")
    body = b"WAVE" + _riff_chunk(b"fmt ", b"\x01\x00\x01\x00" + b"\x00" * 12)
    body += _riff_chunk(b"LIST", info) + _riff_chunk(b"data", audio)
    return b"RIFF" + len(body).to_bytes(4, "little") + body


def test_json_schema_is_stable_and_round_trips(tmp_path: Path) -> None:
    report = TrueAIEngine.default().scan_text("Text\u200b")
    rendered = JSONReporter().render(report)
    payload = json.loads(rendered)

    assert payload["schema_version"] == "0.1"
    assert set(payload) >= {"artifact", "summary", "findings", "integrity"}
    path = tmp_path / "report.json"
    path.write_text(rendered, encoding="utf-8")
    loaded = JSONReporter.load(path)
    assert loaded.findings == report.findings


def test_public_json_schema_has_versioned_top_level_and_finding_contract() -> None:
    schema = JSONReporter.schema()
    finding_schema = schema["$defs"]["Finding"]

    assert schema["properties"]["schema_version"]["const"] == "0.1"
    assert set(schema["properties"]) == {
        "schema_version",
        "package_version",
        "scan_id",
        "generated_at",
        "artifact",
        "artifacts",
        "summary",
        "findings",
        "diagnostics",
        "detectors_run",
        "policy",
        "policy_decisions",
        "policy_bundle_id",
        "policy_audit",
        "provenance_verifications",
        "integrity",
    }
    assert set(finding_schema["properties"]) == {
        "id",
        "detector_id",
        "category",
        "artifact_path",
        "provider",
        "confidence",
        "confidence_type",
        "severity",
        "evidence_type",
        "title",
        "description",
        "evidence",
        "location",
        "removable",
        "remediation_id",
        "provenance_class",
        "tags",
    }
    assert schema["$defs"]["ConfidenceType"]["enum"] == [
        "deterministic",
        "verified",
        "probabilistic",
        "heuristic",
    ]


def test_sarif_contains_fingerprints_and_evidence_properties() -> None:
    report = TrueAIEngine.default().scan_text("Text\u200b")
    payload = json.loads(SARIFReporter().render(report))
    result = payload["runs"][0]["results"][0]

    assert payload["version"] == "2.1.0"
    assert result["fingerprints"]["trueaiFindingId"].startswith("fnd_")
    assert result["properties"]["confidenceType"] == "deterministic"


def test_cli_help_scan_json_and_catalogs(tmp_path: Path) -> None:
    path = tmp_path / "README.md"
    path.write_text("Generated with ChatGPT\n", encoding="utf-8")

    assert runner.invoke(app, ["--help"]).exit_code == 0
    scan_result = runner.invoke(app, ["scan", str(path), "--format", "json"])
    assert scan_result.exit_code == 0
    assert json.loads(scan_result.stdout)["schema_version"] == "0.1"
    assert runner.invoke(app, ["detectors", "list"]).exit_code == 0
    assert runner.invoke(app, ["policies", "list"]).exit_code == 0


def test_cli_doctor_renders_optional_extra_name_literally() -> None:
    """Whichever extra is missing, its name has to survive Rich's markup parser.

    The square brackets are style syntax, so an unescaped `trueai-core[pdf]`
    would be read as a tag and vanish. The test used to name `[pdf]` specifically
    and passed only where pdf happened to be the missing one: on a runner with
    the pdf extra installed and c2pa absent, `OPTIONAL` appeared for a different
    row and the assertion looked for a string nothing had any reason to print.
    """

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0
    if "OPTIONAL" in result.stdout:
        assert "trueai-core[" in result.stdout


def test_cli_dry_run_does_not_write_output(tmp_path: Path) -> None:
    path = tmp_path / "notes.txt"
    path.write_text("Generated with ChatGPT\n", encoding="utf-8")

    result = runner.invoke(app, ["clean", str(path), "--dry-run"])

    assert result.exit_code == 0
    assert not (tmp_path / "notes.cleaned.txt").exists()
    assert "Dry run" in result.stdout


def test_cli_clean_rescans_output_and_can_issue_a_clear_certificate(tmp_path: Path) -> None:
    path = tmp_path / "notes.txt"
    certificate_path = tmp_path / "cleaned-certificate.json"
    path.write_text("Generated with ChatGPT\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "clean",
            str(path),
            "--certificate",
            str(certificate_path),
        ],
    )

    cleaned = tmp_path / "notes.cleaned.txt"
    assert result.exit_code == 0, result.output
    assert "Post-clean residue verification: CLEAR" in result.stdout
    assert "ChatGPT" not in cleaned.read_text(encoding="utf-8")
    certificate = json.loads(certificate_path.read_text(encoding="utf-8"))
    assert certificate["status"] == "clear"
    assert "does not prove human authorship" in certificate["limitations"][0]


def test_cli_clean_surgically_removes_wave_generator_metadata(tmp_path: Path) -> None:
    audio = b"\x01\x02\x03\x04"
    path = tmp_path / "audio.wav"
    path.write_bytes(_wave_with_software("Reference Generator", audio))

    result = runner.invoke(app, ["clean", str(path)])

    cleaned = tmp_path / "audio.cleaned.wav"
    assert result.exit_code == 0, result.output
    assert "Post-clean residue verification: CLEAR" in result.stdout
    assert cleaned.exists()
    assert b"Reference Generator" not in cleaned.read_bytes()
    assert _riff_chunk(b"data", audio) in cleaned.read_bytes()


def test_cli_certificate_issue_and_verify_round_trip(tmp_path: Path) -> None:
    artifact = tmp_path / "deliverable.txt"
    certificate = tmp_path / "deliverable.certificate.json"
    artifact.write_text("Ordinary delivery text.\n", encoding="utf-8")

    issued = runner.invoke(
        app,
        ["certificates", "issue", str(artifact), "--output", str(certificate)],
    )
    verified = runner.invoke(
        app,
        ["certificates", "verify", str(certificate), "--artifact", str(artifact)],
    )

    assert issued.exit_code == 0, issued.output
    assert "TAI1-" in issued.stdout
    assert verified.exit_code == 0, verified.output
    assert "Artifact bytes match" in verified.stdout


def test_cli_emits_certificate_schema() -> None:
    result = runner.invoke(app, ["certificates", "schema"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["properties"]["certificate_schema_version"]["const"] == "0.1"


def test_cli_signed_certificate_expiry_and_revocation_workflow(tmp_path: Path) -> None:
    artifact = tmp_path / "deliverable.txt"
    certificate = tmp_path / "deliverable.certificate.json"
    revocations = tmp_path / "issuer.revocations.json"
    private_key = tmp_path / "issuer-private.pem"
    public_key = tmp_path / "issuer-public.pem"
    artifact.write_text("Ordinary delivery text.\n", encoding="utf-8")
    generate_ed25519_keypair(private_key, public_key)

    issued = runner.invoke(
        app,
        [
            "certificates",
            "issue",
            str(artifact),
            "--output",
            str(certificate),
            "--signing-key",
            str(private_key),
            "--valid-for-days",
            "90",
        ],
    )
    revoked = runner.invoke(
        app,
        [
            "certificates",
            "revoke",
            str(certificate),
            "--revocation-list",
            str(revocations),
            "--signing-key",
            str(private_key),
            "--reason",
            "artifact_withdrawn",
        ],
    )
    verified = runner.invoke(
        app,
        [
            "certificates",
            "verify",
            str(certificate),
            "--artifact",
            str(artifact),
            "--public-key",
            str(public_key),
            "--revocation-list",
            str(revocations),
            "--require-revocation-check",
        ],
    )

    assert issued.exit_code == 0, issued.output
    assert json.loads(certificate.read_text(encoding="utf-8"))["expires_at"]
    assert revoked.exit_code == 0, revoked.output
    assert json.loads(revocations.read_text(encoding="utf-8"))["sequence"] == 1
    assert verified.exit_code == 2, verified.output
    assert "Certificate is revoked by the issuer" in verified.stdout


def test_cli_emits_revocation_list_schema() -> None:
    result = runner.invoke(app, ["certificates", "revocation-schema"])

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["properties"]["revocation_schema_version"]["const"] == "0.1"


def test_cli_certificate_reports_indicators_instead_of_issuing_false_clearance(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "flagged.txt"
    certificate = tmp_path / "flagged.certificate.json"
    artifact.write_text("Generated with ChatGPT\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["certificates", "issue", str(artifact), "--output", str(certificate)],
    )

    assert result.exit_code == 1, result.output
    assert json.loads(certificate.read_text(encoding="utf-8"))["status"] == "indicators_detected"


def test_cli_does_not_rewrite_style_to_evade_a_heuristic_detector(tmp_path: Path) -> None:
    artifact = tmp_path / "regular.txt"
    paragraph = " ".join(f"word{index}" for index in range(50)) + "."
    original = "\n\n".join([paragraph] * 4)
    artifact.write_text(original, encoding="utf-8")

    result = runner.invoke(app, ["clean", str(artifact), "--experimental"])

    assert result.exit_code == 1, result.output
    assert "INDICATORS_REMAIN" in result.stdout
    assert artifact.read_text(encoding="utf-8") == original
    assert not (tmp_path / "regular.cleaned.txt").exists()


def test_cli_refuses_certificate_output_inside_a_certified_directory(tmp_path: Path) -> None:
    root = tmp_path / "delivery"
    root.mkdir()
    (root / "notes.txt").write_text("Ordinary delivery text.\n", encoding="utf-8")
    certificate = root / "certificate.json"

    result = runner.invoke(
        app,
        ["certificates", "issue", str(root), "--output", str(certificate)],
    )

    assert result.exit_code == 3
    assert not certificate.exists()


def test_cli_unsupported_binary_exit_code(tmp_path: Path) -> None:
    path = tmp_path / "data.bin"
    path.write_bytes(b"\x00\x01\x02\x03")

    result = runner.invoke(app, ["scan", str(path)])

    assert result.exit_code == 3


def test_cli_machine_report_output_file_suppresses_document_on_stdout(tmp_path: Path) -> None:
    artifact = tmp_path / "notes.txt"
    report_path = tmp_path / "report.json"
    artifact.write_text("Ordinary text\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["scan", str(artifact), "--format", "json", "--output", str(report_path)],
    )

    assert result.exit_code == 0
    assert '"schema_version"' not in result.stdout
    assert json.loads(report_path.read_text(encoding="utf-8"))["schema_version"] == "0.1"


def test_cli_refuses_to_overwrite_scanned_artifact_with_report(tmp_path: Path) -> None:
    artifact = tmp_path / "deliverable.txt"
    original = "Keep this content\n"
    artifact.write_text(original, encoding="utf-8")

    result = runner.invoke(
        app,
        ["scan", str(artifact), "--format", "json", "--output", str(artifact)],
    )

    assert result.exit_code == 3
    assert artifact.read_text(encoding="utf-8") == original


def test_cli_clean_returns_policy_violation_for_strict_profile(tmp_path: Path) -> None:
    artifact = tmp_path / "strict.txt"
    artifact.write_text("Generated with ChatGPT\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["clean", str(artifact), "--policy", "strict", "--dry-run"],
    )

    assert result.exit_code == 2


def test_cli_incomplete_large_file_scan_returns_unsupported_code(tmp_path: Path) -> None:
    artifact = tmp_path / "large.txt"
    artifact.write_bytes(b"a" * (1024 * 1024 + 1))

    result = runner.invoke(
        app,
        ["scan", str(artifact), "--max-file-size-mb", "1"],
    )

    assert result.exit_code == 3
    assert "Skipped" in result.stdout


def test_cli_clean_rejects_corrupt_scan_before_planning(tmp_path: Path) -> None:
    artifact = tmp_path / "broken.svg"
    artifact.write_text("<svg><broken></svg>", encoding="utf-8")

    result = runner.invoke(app, ["clean", str(artifact), "--dry-run"])

    assert result.exit_code == 3
    assert not (tmp_path / "broken.cleaned.svg").exists()


def test_cli_applies_authenticated_policy_bundle_without_hiding_finding(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "delivery.txt"
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    bundle_path = tmp_path / "policy-bundle.json"
    artifact.write_text("Generated with ChatGPT" + chr(10), encoding="utf-8")
    generate_ed25519_keypair(private, public)
    bundle = issue_policy_bundle(
        PolicyStore.get("strict"),
        issuer="Test Security",
        signing_key=private,
        controls=PolicyBundleControls(
            suppressions=(
                PolicySuppression(
                    id="approved.cli-smoke",
                    selector=FindingSelector(category=FindingCategory.EXPLICIT_AI_ATTRIBUTION),
                    reason="Reviewed for CLI integration coverage.",
                    approved_by="test@example.test",
                    expires_at=datetime.now(UTC) + timedelta(days=1),
                ),
            )
        ),
    )
    bundle_path.write_text(policy_bundle_json(bundle), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "scan",
            str(artifact),
            "--policy-bundle",
            str(bundle_path),
            "--policy-key",
            str(public),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["findings"]
    assert payload["policy_bundle_id"] == bundle.bundle_id
    assert payload["policy_audit"][0]["source"] == "suppression"


def test_policy_bundle_cli_can_create_and_verify(tmp_path: Path) -> None:
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    bundle_path = tmp_path / "policy-bundle.json"
    generate_ed25519_keypair(private, public)

    created = runner.invoke(
        app,
        [
            "policies",
            "bundle-create",
            "audit",
            "--output",
            str(bundle_path),
            "--signing-key",
            str(private),
            "--issuer",
            "Test Security",
        ],
    )
    verified = runner.invoke(
        app,
        [
            "policies",
            "bundle-verify",
            str(bundle_path),
            "--public-key",
            str(public),
        ],
    )

    assert created.exit_code == 0
    assert verified.exit_code == 0
    assert "VALID" in verified.stdout


def test_module_entry_points_both_run_the_cli() -> None:
    """`python -m trueai` is what people reach for when the script is not on PATH."""

    import subprocess
    import sys

    for module in ("trueai", "trueai.cli"):
        completed = subprocess.run(
            [sys.executable, "-m", module, "--version"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        assert "TrueAI Core" in completed.stdout


def test_doctor_still_names_the_extra_on_a_narrow_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The install command is the only actionable text the table carries.

    Rich elides an overlong cell, and the widest row sets the width the narrower
    ones are cut to, so at 80 columns `install trueai-core[pdf]` rendered as a
    horizontal ellipsis: the check reported that something was missing and
    withheld what to do about it.
    """

    import importlib.util

    real = importlib.util.find_spec
    monkeypatch.setattr(
        importlib.util,
        "find_spec",
        lambda name, *a, **k: None if name == "pikepdf" else real(name, *a, **k),
    )
    monkeypatch.setenv("COLUMNS", "80")

    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0
    assert "OPTIONAL" in result.stdout
    assert "trueai-core[pdf]" in result.stdout
