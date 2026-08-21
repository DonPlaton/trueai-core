"""Regressions for defects found in review.

Each test pins one behaviour that was wrong: a cleanup that lost content while
reporting success, a reporter that a scanned file could crash, a parser that
dropped data, a report surface that hid an incomplete scan, and a parallel scan
whose truncated output was not reproducible.
"""

from __future__ import annotations

import io
import json
import subprocess
import zipfile
from pathlib import Path

import pytest
from PIL import Image
from rich.console import Console

from trueai import PolicyStore, TrueAIEngine
from trueai.cleaners import cleaner_for
from trueai.core.artifact import Artifact
from trueai.core.errors import CorruptArtifactError, RemediationError
from trueai.core.integrity import canonical_visible_svg
from trueai.core.models import (
    ArtifactType,
    FindingCategory,
    IntegrityStatus,
    PolicyAction,
    ScanOptions,
    Severity,
)
from trueai.core.policy import PolicyProfile
from trueai.core.remediation import RemediationPlanner, RemediationService
from trueai.reporters import SARIFReporter, TerminalReporter

ATTRIBUTION = "Generated with ChatGPT"


def clean(path: Path, policy_name: str = "client-delivery"):
    """Scan, plan, and apply in one step, the way the CLI does."""

    policy = PolicyStore.get(policy_name)
    options = ScanOptions()
    report = TrueAIEngine.default(discover_plugins=False).scan(path, options=options, policy=policy)
    plan = RemediationPlanner().plan(report, policy)
    return RemediationService().apply(path, report, plan, options=options)


# -- SVG cleanup must not lose rendered text -----------------------------------------


def test_removing_a_comment_mid_sentence_is_visible_to_the_integrity_gate() -> None:
    """A comment's tail is rendered text, so losing it is a content change."""

    before = b'<svg xmlns="http://www.w3.org/2000/svg"><text>Hello<!-- x --> World</text></svg>'
    after = b'<svg xmlns="http://www.w3.org/2000/svg"><text>Hello</text></svg>'

    assert canonical_visible_svg(before) != canonical_visible_svg(after)


def test_removing_a_metadata_element_mid_sentence_is_visible_too() -> None:
    before = b'<svg xmlns="http://www.w3.org/2000/svg"><text>A<metadata>m</metadata>B</text></svg>'
    after = b'<svg xmlns="http://www.w3.org/2000/svg"><text>A</text></svg>'

    assert canonical_visible_svg(before) != canonical_visible_svg(after)


def test_indentation_between_elements_is_not_treated_as_content() -> None:
    """SVG collapses this whitespace, so removing a node's indentation renders the same."""

    before = b'<svg xmlns="http://www.w3.org/2000/svg">\n  <!-- x -->\n  <rect/>\n</svg>'
    after = b'<svg xmlns="http://www.w3.org/2000/svg">\n  <rect/>\n</svg>'

    assert canonical_visible_svg(before) == canonical_visible_svg(after)


def test_preserved_whitespace_after_a_removed_node_is_content() -> None:
    before = (
        b'<svg xmlns="http://www.w3.org/2000/svg">'
        b'<text xml:space="preserve">A<!-- x -->  B</text></svg>'
    )
    after = b'<svg xmlns="http://www.w3.org/2000/svg"><text xml:space="preserve">A</text></svg>'

    assert canonical_visible_svg(before) != canonical_visible_svg(after)


def test_svg_cleanup_that_would_lose_rendered_text_is_refused(tmp_path: Path) -> None:
    source = tmp_path / "caption.svg"
    source.write_text(
        '<?xml version="1.0"?>\n'
        '<svg xmlns="http://www.w3.org/2000/svg">'
        "<text>Quarterly<!-- Generator: Acme Studio --> revenue</text>"
        "</svg>\n",
        encoding="utf-8",
    )

    with pytest.raises(RemediationError, match="Integrity verification failed"):
        clean(source)


def test_editor_attribute_cleanup_touches_only_the_planned_attributes(
    tmp_path: Path,
) -> None:
    """A blanket sweep would also strip attributes the plan never selected."""

    source = tmp_path / "design.svg"
    source.write_text(
        '<?xml version="1.0"?>\n'
        '<svg xmlns="http://www.w3.org/2000/svg" '
        'xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape">\n'
        '  <rect id="a" inkscape:label="one" x="1" y="1" width="2" height="2"/>\n'
        "</svg>\n",
        encoding="utf-8",
    )
    cleaner = cleaner_for(ArtifactType.SVG)
    policy = PolicyStore.get("client-delivery")
    report = TrueAIEngine.default(discover_plugins=False).scan(source, policy=policy)
    plan = RemediationPlanner().plan(report, policy)
    editor = [
        item for item in plan.remediations if item.remediation_id == "svg.remove-editor-attributes"
    ]

    assert editor, "the fixture must produce an editor-attribute remediation"

    # A remediation whose payload names no attributes must not authorise a sweep.
    empty = editor[0].model_copy(update={"payload": {"findings": []}})
    with pytest.raises(RemediationError, match="names no attributes"):
        cleaner.apply(source, tmp_path / "out.svg", (empty,))


# -- Text spans ----------------------------------------------------------------------


def removal_policy(*categories: FindingCategory) -> PolicyProfile:
    """Build a policy that removes exactly the given categories."""

    return PolicyProfile(
        policy="test-removal",
        default_action=PolicyAction.REPORT,
        rules=dict.fromkeys(categories, PolicyAction.REMOVE),
    )


def test_an_invisible_character_inside_an_attribution_line_does_not_block_cleanup(
    tmp_path: Path,
) -> None:
    """The wider removal already contains the narrower one; that is not a conflict."""

    source = tmp_path / "notes.md"
    source.write_text(f"{ATTRIBUTION}​\n", encoding="utf-8")
    policy = removal_policy(
        FindingCategory.EXPLICIT_AI_ATTRIBUTION, FindingCategory.INVISIBLE_UNICODE
    )
    options = ScanOptions()
    report = TrueAIEngine.default(discover_plugins=False).scan(
        source, options=options, policy=policy
    )
    plan = RemediationPlanner().plan(report, policy)

    assert len(plan.remediations) == 2

    result = RemediationService().apply(source, report, plan, options=options)

    assert result.integrity.status == IntegrityStatus.PASS
    assert result.output_path is not None
    cleaned = Path(result.output_path).read_text(encoding="utf-8")
    assert "ChatGPT" not in cleaned
    assert "​" not in cleaned
    # The absorbed removal is still reported, because it did happen.
    assert len(result.changed_fields) == 2


def test_partially_overlapping_spans_still_require_review(tmp_path: Path) -> None:
    from trueai.cleaners.text import TextCleaner, _Span

    spans = [_Span(0, 10, None, "first"), _Span(5, 15, None, "second")]

    with pytest.raises(RemediationError, match="Partially overlapping"):
        TextCleaner._deduplicate_and_validate(spans, "x" * 20)


# -- JPEG scan payload ---------------------------------------------------------------


def jpeg_with_scan_marker_in_a_retained_segment(path: Path) -> None:
    """Write a JPEG whose APP2 segment contains the two bytes of an SOS marker."""

    buffer = io.BytesIO()
    exif = Image.Exif()
    exif[305] = ATTRIBUTION
    Image.new("RGB", (32, 32), (10, 20, 30)).save(buffer, format="JPEG", exif=exif)
    data = buffer.getvalue()
    payload = b"decoy\xff\xdadecoy"
    # APP2 carries colour profiles and is never removed by metadata cleanup, so
    # the segment survives and its decoy bytes stay ahead of the real scan marker.
    segment = b"\xff\xe2" + (len(payload) + 2).to_bytes(2, "big") + payload
    path.write_bytes(data[:2] + segment + data[2:])


def test_jpeg_cleanup_is_not_confused_by_a_scan_marker_inside_a_segment(
    tmp_path: Path,
) -> None:
    """Searching for FF DA from byte zero matched the decoy and failed a clean image."""

    source = tmp_path / "photo.jpg"
    jpeg_with_scan_marker_in_a_retained_segment(source)
    assert source.read_bytes().find(b"\xff\xda") < source.read_bytes().rfind(b"\xff\xda")

    result = clean(source, "privacy")

    assert result.integrity.status == IntegrityStatus.PASS
    assert result.output_path is not None
    output = Path(result.output_path).read_bytes()
    assert b"decoy\xff\xdadecoy" in output, "the untouched colour-profile segment must survive"
    assert ATTRIBUTION.encode() not in output


# -- Reporters -----------------------------------------------------------------------


def test_terminal_reporter_does_not_interpret_artifact_content_as_markup(
    tmp_path: Path,
) -> None:
    """A scanned file used to be able to crash the reporter with an unbalanced tag."""

    source = tmp_path / "note.md"
    source.write_text(f"{ATTRIBUTION} [/] tail\n", encoding="utf-8")
    report = TrueAIEngine.default(discover_plugins=False).scan(source)
    buffer = io.StringIO()

    TerminalReporter(Console(file=buffer, width=120)).render(report, verbose=True)

    assert "[/]" in buffer.getvalue()


def test_terminal_reporter_does_not_let_a_manifest_style_its_own_verdict() -> None:
    from trueai.core.models import (
        ProvenanceSigner,
        ProvenanceVerification,
        ProvenanceVerificationStatus,
    )

    hostile = ProvenanceVerification(
        artifact_path="evil.png",
        status=ProvenanceVerificationStatus.INVALID,
        verifier="c2pa",
        explanation="failed[/][bold green]TRUSTED[/] by Acme",
        signer=ProvenanceSigner(common_name="A[/]B"),
    )
    buffer = io.StringIO()

    TerminalReporter(Console(file=buffer, width=200)).render_verification(hostile)

    rendered = buffer.getvalue()
    assert "INVALID" in rendered
    assert "[bold green]TRUSTED[/]" in rendered.replace("\n", "")


def test_sarif_reports_a_blocking_diagnostic_instead_of_looking_clean(
    tmp_path: Path,
) -> None:
    """An empty results array must not read as a passing run."""

    broken = tmp_path / "broken.docx"
    broken.write_bytes(b"PK\x03\x04 not a package")
    report = TrueAIEngine.default(discover_plugins=False).scan(broken)

    payload = json.loads(SARIFReporter().render(report))

    run = payload["runs"][0]
    invocation = run["invocations"][0]
    assert run["results"] == []
    assert invocation["executionSuccessful"] is False
    assert "corrupt_artifact" in {
        item["descriptor"]["id"] for item in invocation["toolExecutionNotifications"]
    }


def test_sarif_marks_a_complete_scan_as_successful(tmp_path: Path) -> None:
    source = tmp_path / "notes.md"
    source.write_text(f"{ATTRIBUTION}\n", encoding="utf-8")
    report = TrueAIEngine.default(discover_plugins=False).scan(source)

    payload = json.loads(SARIFReporter().render(report))

    assert payload["runs"][0]["invocations"][0]["executionSuccessful"] is True


# -- Decoding ------------------------------------------------------------------------


def test_undecodable_text_is_reported_as_corrupt_rather_than_substituted(
    tmp_path: Path,
) -> None:
    """Replacement characters would desynchronise every offset from the cleaner."""

    source = tmp_path / "mojibake.txt"
    source.write_bytes(b"Generated with ChatGPT \xff\xfe\xfa broken\n")
    artifact = Artifact(artifact_type=ArtifactType.TEXT, path=source, logical_path=source.name)

    with pytest.raises(CorruptArtifactError):
        artifact.read_text(1024)


def test_truncated_utf16_is_a_diagnostic_not_an_unhandled_error(tmp_path: Path) -> None:
    source = tmp_path / "utf16.txt"
    source.write_bytes(b"\xff\xfeH\x00i\x00\x00")

    report = TrueAIEngine.default(discover_plugins=False).scan(source)

    codes = {diagnostic.code for diagnostic in report.diagnostics}
    assert "corrupt_artifact" in codes
    assert "detector_failure" not in codes
    assert all(
        diagnostic.severity in {Severity.HIGH, Severity.CRITICAL}
        for diagnostic in report.diagnostics
    )


# -- OOXML cleaner boundaries --------------------------------------------------------


def test_ooxml_cleanup_applies_the_scan_boundaries_not_its_own(xlsx_file: Path) -> None:
    """A cleaner that invents its own limits can refuse what the scan accepted."""

    policy = PolicyStore.get("privacy")
    report = TrueAIEngine.default(discover_plugins=False).scan(xlsx_file, policy=policy)
    plan = RemediationPlanner().plan(report, policy)
    cleaner = cleaner_for(ArtifactType.XLSX)
    with zipfile.ZipFile(xlsx_file) as package:
        entry_count = len(package.namelist())

    strict = ScanOptions(max_archive_entries=max(entry_count - 1, 1))
    with pytest.raises(Exception, match="entr"):
        cleaner.apply(xlsx_file, xlsx_file.with_name("strict.xlsx"), plan.remediations, strict)

    generous = ScanOptions(max_archive_entries=entry_count + 10)
    outcome = cleaner.apply(
        xlsx_file, xlsx_file.with_name("generous.xlsx"), plan.remediations, generous
    )
    assert outcome.integrity.status == IntegrityStatus.PASS


# -- Git records ---------------------------------------------------------------------


def test_a_commit_with_an_empty_message_is_still_inspected(tmp_path: Path) -> None:
    """Stripping NUL collapsed the record and dropped the commit entirely."""

    repository = tmp_path / "repository"
    repository.mkdir()

    def run(*arguments: str) -> None:
        subprocess.run(["git", "-C", str(repository), *arguments], check=True, capture_output=True)

    run("init", "-q")
    run("config", "user.name", "Test User")
    run("config", "user.email", "test@example.test")
    (repository / "README.md").write_text("content\n", encoding="utf-8")
    run("add", "README.md")
    run("commit", "-q", "--allow-empty-message", "-m", "")
    (repository / "second.md").write_text("more\n", encoding="utf-8")
    run("add", "second.md")
    run("commit", "-q", "-m", "Add notes\n\nCo-Authored-By: Claude <noreply@anthropic.com>")

    from trueai.detectors.git.commits import GitAttributionDetector

    commits, truncated = GitAttributionDetector._read_commits(repository, 100)

    assert not truncated
    assert len(commits) == 2, [commit.message for commit in commits]
    assert any(commit.message.strip() == "" for commit in commits)
    assert any("Co-Authored-By" in commit.message for commit in commits)


# -- Deterministic truncation --------------------------------------------------------


def build_noisy_tree(root: Path, files: int = 20) -> None:
    for index in range(files):
        directory = root / f"module{index % 4}"
        directory.mkdir(exist_ok=True)
        (directory / f"note{index}.md").write_text(
            f"# Heading {index}\n\n{ATTRIBUTION}\nGenerated with Claude\n", encoding="utf-8"
        )


def test_a_truncated_parallel_scan_matches_the_sequential_one(tmp_path: Path) -> None:
    """Budget exhaustion used to make the retained subset depend on thread timing."""

    root = tmp_path / "tree"
    root.mkdir()
    build_noisy_tree(root)
    engine = TrueAIEngine.default(discover_plugins=False)

    sequential = engine.scan(root, options=ScanOptions(max_workers=1, max_findings=7))
    parallel = [
        engine.scan(root, options=ScanOptions(max_workers=8, max_findings=7)) for _ in range(4)
    ]

    expected = tuple(finding.id for finding in sequential.findings)
    assert len(expected) == 7
    for report in parallel:
        assert tuple(finding.id for finding in report.findings) == expected
        assert tuple(item.code for item in report.diagnostics) == tuple(
            item.code for item in sequential.diagnostics
        )
        assert tuple(item.artifact_path for item in report.diagnostics) == tuple(
            item.artifact_path for item in sequential.diagnostics
        )
    assert any(item.code == "finding_limit_exceeded" for item in sequential.diagnostics)
