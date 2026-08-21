import json
from pathlib import Path

from typer.testing import CliRunner

from trueai import TrueAIEngine
from trueai.cli.app import app
from trueai.reporters import JSONReporter, SARIFReporter

runner = CliRunner()


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
    result = runner.invoke(app, ["doctor"])

    assert result.exit_code == 0
    if "OPTIONAL" in result.stdout:
        assert "trueai-core[pdf]" in result.stdout


def test_cli_dry_run_does_not_write_output(tmp_path: Path) -> None:
    path = tmp_path / "notes.txt"
    path.write_text("Generated with ChatGPT\n", encoding="utf-8")

    result = runner.invoke(app, ["clean", str(path), "--dry-run"])

    assert result.exit_code == 0
    assert not (tmp_path / "notes.cleaned.txt").exists()
    assert "Dry run" in result.stdout


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
