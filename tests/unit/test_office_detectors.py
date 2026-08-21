"""PPTX and XLSX inspection, cleanup, and the shared OPC safety boundary."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from trueai import TrueAIEngine
from trueai.cleaners import cleaner_for
from trueai.core.artifact import ArtifactDiscovery
from trueai.core.integrity import XLSX_CONTENT_TAGS, verify_ooxml_metadata_only
from trueai.core.models import (
    ArtifactType,
    FindingCategory,
    IntegrityStatus,
    ProvenanceClass,
    Severity,
)
from trueai.core.policy import PolicyStore
from trueai.core.remediation import RemediationPlanner, RemediationService
from trueai.detectors.documents.ooxml import OfficeOpenXmlDetector

# -- identification ------------------------------------------------------------------


def test_presentation_and_workbook_are_identified_by_package_contents(
    pptx_file: Path, xlsx_file: Path
) -> None:
    discovery = ArtifactDiscovery()

    assert discovery.identify(pptx_file).artifact_type == ArtifactType.PPTX
    assert discovery.identify(xlsx_file).artifact_type == ArtifactType.XLSX


def test_misnamed_package_is_identified_by_its_required_part(
    tmp_path: Path, xlsx_file: Path
) -> None:
    disguised = tmp_path / "invoice.unknown"
    disguised.write_bytes(xlsx_file.read_bytes())

    assert ArtifactDiscovery().identify(disguised).artifact_type == ArtifactType.XLSX


def test_macro_enabled_extensions_map_to_the_same_package_family(
    tmp_path: Path, pptx_file: Path
) -> None:
    macro_enabled = tmp_path / "deck.pptm"
    macro_enabled.write_bytes(pptx_file.read_bytes())

    artifact = ArtifactDiscovery().identify(macro_enabled)

    assert artifact.artifact_type == ArtifactType.PPTX
    assert artifact.media_type == "application/vnd.ms-powerpoint.presentation.macroEnabled.12"


# -- PPTX ----------------------------------------------------------------------------


def test_pptx_reports_metadata_notes_comments_and_authors(pptx_file: Path) -> None:
    report = TrueAIEngine.default().scan(pptx_file)
    titles = {finding.title for finding in report.findings}

    assert "PPTX personal metadata: creator" in titles
    assert "PPTX creating application: Application" in titles
    assert "PPTX custom property" in titles
    assert "PPTX speaker notes" in titles
    assert "PPTX comment" in titles
    assert "PPTX comment author" in titles
    assert "PPTX slide inventory" in titles


def test_pptx_speaker_notes_are_reported_as_hidden_content(pptx_file: Path) -> None:
    report = TrueAIEngine.default().scan(pptx_file)

    notes = next(finding for finding in report.findings if finding.title == "PPTX speaker notes")

    assert "hidden-content" in notes.tags
    assert notes.evidence["part"] == "ppt/notesSlides/notesSlide1.xml"
    assert "tighten the revenue slide" in str(notes.evidence["text_excerpt"])


def test_pptx_attribution_inside_a_comment_is_deterministic_but_not_removable(
    pptx_file: Path,
) -> None:
    report = TrueAIEngine.default().scan(pptx_file)

    attribution = [
        finding
        for finding in report.findings
        if finding.category == FindingCategory.EXPLICIT_AI_ATTRIBUTION
        and finding.evidence.get("part") == "ppt/comments/comment1.xml"
    ]

    assert attribution, "literal attribution inside a comment must be reported"
    # Comment bodies are content, not a metadata field the cleaner knows how to edit.
    assert all(not finding.removable for finding in attribution)
    assert all(finding.remediation_id is None for finding in attribution)


def test_pptx_custom_property_attribution_is_removable(pptx_file: Path) -> None:
    report = TrueAIEngine.default().scan(pptx_file)

    attribution = next(
        finding
        for finding in report.findings
        if finding.category == FindingCategory.EXPLICIT_AI_ATTRIBUTION
        and finding.evidence.get("part") == "docProps/custom.xml"
    )

    assert attribution.removable
    assert attribution.remediation_id == "pptx.remove-custom-property"


# -- XLSX ----------------------------------------------------------------------------


def test_xlsx_reports_hidden_sheets_comments_identities_and_links(xlsx_file: Path) -> None:
    report = TrueAIEngine.default().scan(xlsx_file)
    titles = {finding.title for finding in report.findings}

    assert "XLSX hidden worksheet" in titles
    assert "XLSX defined name" in titles
    assert "XLSX comment author" in titles
    assert "XLSX cell comment" in titles
    assert "XLSX threaded comment" in titles
    assert "XLSX comment participant identity" in titles
    assert "XLSX external workbook links" in titles


def test_xlsx_hidden_sheet_records_its_state(xlsx_file: Path) -> None:
    report = TrueAIEngine.default().scan(xlsx_file)

    hidden = next(
        finding for finding in report.findings if finding.category == FindingCategory.HIDDEN_ELEMENT
    )

    assert hidden.evidence["sheet_name"] == "Scratch"
    assert hidden.evidence["state"] == "veryHidden"


def test_xlsx_participant_identity_reports_the_account_identifier(xlsx_file: Path) -> None:
    report = TrueAIEngine.default().scan(xlsx_file)

    identity = next(
        finding
        for finding in report.findings
        if finding.title == "XLSX comment participant identity"
    )

    assert identity.category == FindingCategory.PERSONAL_METADATA
    assert identity.evidence["user_id"] == "erin@example.test"


def test_xlsx_external_links_are_reported_without_being_resolved(xlsx_file: Path) -> None:
    report = TrueAIEngine.default().scan(xlsx_file)

    links = next(
        finding for finding in report.findings if finding.title == "XLSX external workbook links"
    )

    assert links.category == FindingCategory.SECURITY_ISSUE
    assert "passive-scan" in links.tags


# -- cleanup and integrity -----------------------------------------------------------


@pytest.mark.parametrize("fixture_name", ["pptx_file", "xlsx_file"])
def test_metadata_cleanup_preserves_content_and_proves_integrity(
    fixture_name: str, request: pytest.FixtureRequest
) -> None:
    source: Path = request.getfixturevalue(fixture_name)
    policy = PolicyStore.get("privacy")
    report = TrueAIEngine.default().scan(source, policy=policy)
    plan = RemediationPlanner().plan(report, policy)

    assert plan.remediations, "the privacy policy must produce metadata removals"

    result = RemediationService().apply(source, report, plan)

    assert result.output_path is not None
    assert result.integrity.status == IntegrityStatus.PASS
    output = Path(result.output_path)
    with zipfile.ZipFile(source) as before, zipfile.ZipFile(output) as after:
        assert set(before.namelist()) == set(after.namelist())
        content_parts = [name for name in before.namelist() if not name.startswith("docProps/")]
        for name in content_parts:
            assert before.read(name) == after.read(name), f"{name} must not change"
    assert b"Alice" not in output.read_bytes()


def test_content_change_during_cleanup_fails_the_integrity_gate(
    xlsx_file: Path, tmp_path: Path
) -> None:
    """A rewrite that also touches a worksheet must not be publishable."""

    tampered = tmp_path / "tampered.xlsx"
    with zipfile.ZipFile(xlsx_file) as before, zipfile.ZipFile(tampered, "w") as after:
        for info in before.infolist():
            data = before.read(info.filename)
            if info.filename == "xl/worksheets/sheet1.xml":
                data = data.replace(b"<v>42</v>", b"<v>4200</v>")
            after.writestr(info, data)

    verdict = verify_ooxml_metadata_only(
        xlsx_file,
        tampered,
        {"docProps/core.xml"},
        ["docProps/core.xml:creator"],
        content_prefix="xl/",
        content_tags=XLSX_CONTENT_TAGS,
        format_label="XLSX",
    )

    assert verdict.status == IntegrityStatus.FAIL
    assert "XLSX" in verdict.explanation


def test_cleaner_rejects_an_operation_from_another_format(pptx_file: Path) -> None:
    policy = PolicyStore.get("privacy")
    report = TrueAIEngine.default().scan(pptx_file, policy=policy)
    plan = RemediationPlanner().plan(report, policy)
    docx_cleaner = cleaner_for(ArtifactType.DOCX)

    with pytest.raises(Exception, match="does not support"):
        docx_cleaner.apply(pptx_file, pptx_file.with_name("out.pptx"), plan.remediations)


# -- shared safety boundary ----------------------------------------------------------


@pytest.mark.parametrize("suffix", [".pptx", ".xlsx"])
def test_archive_path_traversal_is_rejected_for_every_ooxml_family(
    tmp_path: Path, suffix: str
) -> None:
    path = tmp_path / f"hostile{suffix}"
    required = "ppt/presentation.xml" if suffix == ".pptx" else "xl/workbook.xml"
    with zipfile.ZipFile(path, "w") as package:
        package.writestr("[Content_Types].xml", "<Types/>")
        package.writestr(required, "<root/>")
        package.writestr("../outside.xml", "<x/>")

    report = TrueAIEngine.default().scan(path)

    assert any(diagnostic.code == "unsafe_artifact" for diagnostic in report.diagnostics)


@pytest.mark.parametrize("suffix", [".pptx", ".xlsx"])
def test_xml_entity_expansion_fails_closed_for_every_ooxml_family(
    tmp_path: Path, suffix: str
) -> None:
    path = tmp_path / f"entities{suffix}"
    required = "ppt/presentation.xml" if suffix == ".pptx" else "xl/workbook.xml"
    hostile = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE properties [<!ENTITY expand "aaaaaaaaaa">]>'
        "<properties>&expand;</properties>"
    )
    with zipfile.ZipFile(path, "w") as package:
        package.writestr("[Content_Types].xml", "<Types/>")
        package.writestr(required, "<root/>")
        package.writestr("docProps/core.xml", hostile)

    report = TrueAIEngine.default().scan(path)

    assert any(diagnostic.code == "corrupt_artifact" for diagnostic in report.diagnostics)
    assert all(
        diagnostic.severity in {Severity.HIGH, Severity.CRITICAL}
        for diagnostic in report.diagnostics
    )


@pytest.mark.parametrize("suffix", [".pptx", ".xlsx"])
def test_provenance_marker_blocks_metadata_cleanup_for_every_ooxml_family(
    tmp_path: Path, suffix: str
) -> None:
    path = tmp_path / f"credentialed{suffix}"
    required = "ppt/presentation.xml" if suffix == ".pptx" else "xl/workbook.xml"
    core = (
        '<?xml version="1.0"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/'
        'metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">'
        "<dc:creator>Alice</dc:creator></cp:coreProperties>"
    )
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as package:
        package.writestr("[Content_Types].xml", "<Types/>")
        package.writestr(required, "<root/>")
        package.writestr("docProps/core.xml", core)
        package.writestr(
            "customXml/item1.xml", "<credentials>c2pa Content Credentials</credentials>"
        )
    policy = PolicyStore.get("client-delivery")

    report = TrueAIEngine.default().scan(path, policy=policy)
    plan = RemediationPlanner().plan(report, policy)
    label = "PPTX" if suffix == ".pptx" else "XLSX"
    provenance = next(
        finding
        for finding in report.findings
        if finding.title == f"Provenance marker in {label} custom XML"
    )

    assert provenance.provenance_class == ProvenanceClass.PROVENANCE_METADATA
    assert provenance.id in plan.preserved_findings
    assert not plan.remediations


@pytest.mark.parametrize("suffix", [".pptx", ".xlsx"])
def test_macro_project_is_reported_for_every_ooxml_family(tmp_path: Path, suffix: str) -> None:
    path = tmp_path / f"macro{suffix}"
    prefix = "ppt" if suffix == ".pptx" else "xl"
    required = f"{prefix}/presentation.xml" if suffix == ".pptx" else f"{prefix}/workbook.xml"
    with zipfile.ZipFile(path, "w") as package:
        package.writestr("[Content_Types].xml", "<Types/>")
        package.writestr(required, "<root/>")
        package.writestr(f"{prefix}/vbaProject.bin", "not executed")

    report = TrueAIEngine.default().scan(path)

    macro = next(finding for finding in report.findings if finding.title.endswith("macro project"))
    assert macro.category == FindingCategory.SECURITY_ISSUE
    assert macro.severity == Severity.HIGH
    assert "passive-scan" in macro.tags


def test_every_ooxml_detector_declares_a_distinct_remediation_namespace() -> None:
    registry = TrueAIEngine.default(discover_plugins=False).registry
    detectors = [
        detector
        for detector in registry.detectors(include_disabled=True)
        if isinstance(detector, OfficeOpenXmlDetector)
    ]

    namespaces = [detector.format_tag for detector in detectors]

    assert len(detectors) == 3
    assert sorted(namespaces) == ["docx", "pptx", "xlsx"]
    for detector in detectors:
        cleaner = cleaner_for(next(iter(detector.supported_types)))
        assert detector.metadata_remediation_id in cleaner.supported_remediation_ids
        assert detector.custom_property_remediation_id in cleaner.supported_remediation_ids
