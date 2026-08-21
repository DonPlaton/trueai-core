from pathlib import Path

import pytest

from tests.support import create_symlink
from trueai import TrueAIEngine
from trueai.core.artifact import ArtifactDiscovery, DiscoveryOptions
from trueai.core.models import ArtifactType, ScanOptions


def test_gitignore_and_trueaiignore_are_respected(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("ignored.md\n", encoding="utf-8")
    (tmp_path / ".trueaiignore").write_text("private.txt\n", encoding="utf-8")
    (tmp_path / "ignored.md").write_text("Generated with ChatGPT\n", encoding="utf-8")
    (tmp_path / "private.txt").write_text("Generated with Claude\n", encoding="utf-8")
    (tmp_path / "kept.md").write_text("Ordinary text\n", encoding="utf-8")

    report = TrueAIEngine.default().scan(tmp_path)

    paths = {item.path for item in report.artifacts}
    assert "ignored.md" not in paths
    assert "private.txt" not in paths
    assert "kept.md" in paths


def test_external_symlink_is_not_followed(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside.txt"
    outside.write_text("Generated with ChatGPT\n", encoding="utf-8")
    link = tmp_path / "external.txt"
    create_symlink(link, outside)

    report = TrueAIEngine.default().scan(tmp_path)

    assert "external.txt" not in {item.path for item in report.artifacts}


def test_embedded_svg_example_does_not_override_source_extension(tmp_path: Path) -> None:
    source = tmp_path / "example.py"
    source.write_text(
        'fixture = "<svg xmlns="http://www.w3.org/2000/svg"></svg>"\n',
        encoding="utf-8",
    )

    artifact = ArtifactDiscovery().identify(source)

    assert artifact.artifact_type == ArtifactType.SOURCE_CODE


def test_oversized_docx_is_classified_without_opening_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "oversized.docx"
    path.write_bytes(b"PK\x03\x04" + b"x" * 64)

    def fail_if_opened(_: Path) -> None:
        raise AssertionError("Oversized archive must not be opened during type sniffing")

    monkeypatch.setattr(ArtifactDiscovery, "_sniff_ooxml", fail_if_opened)
    discovery = ArtifactDiscovery(DiscoveryOptions(max_file_size=8))

    artifact = discovery.identify(path)

    assert artifact.artifact_type == ArtifactType.DOCX


def test_internal_symlink_cycle_is_visited_once(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "kept.txt").write_text("Ordinary text\n", encoding="utf-8")
    cycle = nested / "cycle"
    create_symlink(cycle, tmp_path, target_is_directory=True)

    report = TrueAIEngine.default().scan(
        tmp_path,
        options=ScanOptions(follow_symlinks=True, max_files=20),
    )

    assert [artifact.path for artifact in report.artifacts].count("nested/kept.txt") == 1
    assert len(report.artifacts) == 2


def test_file_discovery_limit_is_reported_as_incomplete(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("ordinary\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("Generated with ChatGPT\n", encoding="utf-8")

    report = TrueAIEngine.default().scan(tmp_path, options=ScanOptions(max_files=1))

    assert any(diagnostic.code == "discovery_truncated" for diagnostic in report.diagnostics)
    assert not [finding for finding in report.findings if finding.artifact_path == "b.txt"]


def test_utf16_text_is_identified_before_generic_binary_nul_check(tmp_path: Path) -> None:
    path = tmp_path / "utf16.txt"
    path.write_text("Visible text", encoding="utf-16")

    artifact = ArtifactDiscovery().identify(path)

    assert artifact.artifact_type == ArtifactType.TEXT
