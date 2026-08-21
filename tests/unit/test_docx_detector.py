import zipfile
from pathlib import Path

from trueai import TrueAIEngine
from trueai.core.models import FindingCategory, ProvenanceClass
from trueai.core.policy import PolicyStore
from trueai.core.remediation import RemediationPlanner


def test_docx_inspects_properties_comments_revisions_and_relationships(docx_file: Path) -> None:
    report = TrueAIEngine.default().scan(docx_file)
    categories = {item.category for item in report.findings}

    assert FindingCategory.PERSONAL_METADATA in categories
    assert FindingCategory.DOCUMENT_METADATA in categories
    assert FindingCategory.GENERATOR_METADATA in categories
    assert FindingCategory.EXPLICIT_AI_ATTRIBUTION in categories
    assert FindingCategory.STRUCTURAL_SIGNAL in categories
    assert FindingCategory.SECURITY_ISSUE in categories
    assert any(
        item.evidence.get("field") == "creator" and item.evidence.get("value") == "Alice"
        for item in report.findings
    )


def test_docx_archive_path_traversal_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "hostile.docx"
    with zipfile.ZipFile(path, "w") as package:
        package.writestr("[Content_Types].xml", "<Types/>")
        package.writestr("word/document.xml", "<document/>")
        package.writestr("../outside.xml", "<x/>")

    report = TrueAIEngine.default().scan(path)

    assert any(item.code == "unsafe_artifact" for item in report.diagnostics)


def test_compressed_docx_custom_xml_provenance_blocks_metadata_cleanup(
    tmp_path: Path,
) -> None:
    path = tmp_path / "credentialed.docx"
    parts = {
        "[Content_Types].xml": (
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>'
        ),
        "word/document.xml": (
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            "<w:body/></w:document>"
        ),
        "docProps/core.xml": (
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/'
            'metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">'
            "<dc:creator>Alice</dc:creator></cp:coreProperties>"
        ),
        "customXml/item1.xml": "<credentials>c2pa Content Credentials</credentials>",
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as package:
        for name, content in parts.items():
            package.writestr(name, content)
    policy = PolicyStore.get("client-delivery")

    report = TrueAIEngine.default().scan(path, policy=policy)
    plan = RemediationPlanner().plan(report, policy)
    provenance = next(
        finding
        for finding in report.findings
        if finding.title == "Provenance marker in DOCX custom XML"
    )

    assert provenance.category == FindingCategory.C2PA_PROVENANCE
    assert provenance.provenance_class == ProvenanceClass.PROVENANCE_METADATA
    assert provenance.id in plan.preserved_findings
    assert plan.blocked_findings
    assert not plan.remediations
