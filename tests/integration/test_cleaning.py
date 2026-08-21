import zipfile
from pathlib import Path

import pytest
from PIL import Image, ImageOps

from trueai import TrueAIEngine
from trueai.core.errors import RemediationError
from trueai.core.models import FindingCategory, IntegrityStatus
from trueai.core.policy import PolicyProfile, PolicyStore
from trueai.core.remediation import RemediationPlanner, RemediationService


def _clean(path: Path, policy_name: str = "client-delivery"):
    policy = PolicyStore.get(policy_name)
    report = TrueAIEngine.default().scan(path, policy=policy)
    plan = RemediationPlanner().plan(report, policy)
    result = RemediationService().apply(path, report, plan)
    return report, plan, result


def test_text_cleaning_preserves_original_and_verifies_expected_transform(tmp_path: Path) -> None:
    path = tmp_path / "deliverable.md"
    original = "Visible content\nGenerated with ChatGPT\n"
    path.write_text(original, encoding="utf-8")

    _, _, result = _clean(path)

    assert path.read_text(encoding="utf-8") == original
    assert result.output_path is not None
    output = Path(result.output_path)
    assert output.read_text(encoding="utf-8") == "Visible content\n"
    assert result.integrity.status == IntegrityStatus.PASS
    assert result.integrity.before_sha256 != result.integrity.after_sha256


def test_docx_metadata_cleaning_keeps_logical_content(docx_file: Path) -> None:
    report, plan, result = _clean(docx_file)

    assert any(item.remediation_id.startswith("docx.") for item in plan.remediations)
    attribution_ids = {
        finding.id
        for finding in report.findings
        if finding.category == FindingCategory.EXPLICIT_AI_ATTRIBUTION
    }
    assert attribution_ids
    assert attribution_ids.isdisjoint(plan.blocked_findings)
    assert result.integrity.status == IntegrityStatus.PASS
    assert result.output_path is not None
    cleaned_report = TrueAIEngine.default().scan(Path(result.output_path))
    assert not [
        item
        for item in cleaned_report.findings
        if item.evidence.get("field") in {"creator", "lastModifiedBy", "Application", "Company"}
    ]


def test_svg_cleaning_preserves_visible_structure(svg_file: Path) -> None:
    _, _, result = _clean(svg_file)

    assert result.integrity.status == IntegrityStatus.PASS
    assert result.output_path is not None
    cleaned = Path(result.output_path).read_text(encoding="utf-8")
    assert "<metadata" not in cleaned
    assert "Generator:" not in cleaned
    assert 'id="visible"' in cleaned


def test_png_cleaning_preserves_pixel_payload(png_file: Path) -> None:
    _, _, result = _clean(png_file)

    assert result.integrity.status == IntegrityStatus.PASS
    assert result.integrity.logical_before_sha256 == result.integrity.logical_after_sha256
    assert result.output_path is not None
    cleaned_report = TrueAIEngine.default().scan(Path(result.output_path))
    assert not [
        item for item in cleaned_report.findings if item.remediation_id == "image.remove-metadata"
    ]


def test_jpeg_cleaning_preserves_compressed_scan_data(jpeg_file: Path) -> None:
    _, _, result = _clean(jpeg_file)

    assert result.integrity.status == IntegrityStatus.PASS
    assert result.integrity.logical_before_sha256 == result.integrity.logical_after_sha256
    assert result.output_path is not None


def test_in_place_requires_explicit_flag_and_creates_backup(tmp_path: Path) -> None:
    path = tmp_path / "notes.txt"
    path.write_text("Keep\nGenerated with ChatGPT\n", encoding="utf-8")
    policy = PolicyStore.get("client-delivery")
    report = TrueAIEngine.default().scan(path, policy=policy)
    plan = RemediationPlanner().plan(report, policy)

    result = RemediationService().apply(path, report, plan, in_place=True)

    assert result.backup_path is not None
    assert Path(result.backup_path).read_text(encoding="utf-8").endswith("Generated with ChatGPT\n")
    assert path.read_text(encoding="utf-8") == "Keep\n"


def test_css_attribution_cleanup_removes_exact_comment(tmp_path: Path) -> None:
    path = tmp_path / "styles.css"
    original = "/* Generated with ChatGPT */\n.card { display: block; }\n"
    path.write_text(original, encoding="utf-8")

    _, plan, result = _clean(path)

    assert any(
        item.remediation_id == "text.remove-attribution-comment" for item in plan.remediations
    )
    assert path.read_text(encoding="utf-8") == original
    assert result.integrity.status == IntegrityStatus.PASS
    assert result.changed_fields
    assert result.output_path is not None
    assert "Generated with ChatGPT" not in Path(result.output_path).read_text(encoding="utf-8")


def test_html_entity_encoded_generator_metadata_is_removed_by_exact_raw_span(
    tmp_path: Path,
) -> None:
    path = tmp_path / "page.html"
    path.write_text(
        '<meta name="generator" content="ChatGPT &amp; Co"><p>Keep &amp; display</p>\n',
        encoding="utf-8",
    )

    _, _, result = _clean(path)

    assert result.integrity.status == IntegrityStatus.PASS
    assert result.changed_fields
    assert result.output_path is not None
    cleaned = Path(result.output_path).read_text(encoding="utf-8")
    assert "<meta" not in cleaned
    assert "<p>Keep &amp; display</p>" in cleaned


def test_svg_cleanup_preserves_active_processing_instruction(tmp_path: Path) -> None:
    path = tmp_path / "styled.svg"
    path.write_text(
        """<?xml version="1.0"?>
<?xml-stylesheet type="text/css" href="theme.css"?>
<svg xmlns="http://www.w3.org/2000/svg"
 xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape"
 inkscape:version="1.3"><rect width="10" height="10"/></svg>""",
        encoding="utf-8",
    )

    _, _, result = _clean(path)

    assert result.integrity.status == IntegrityStatus.PASS
    assert result.output_path is not None
    cleaned = Path(result.output_path).read_text(encoding="utf-8")
    assert "xml-stylesheet" in cleaned
    assert "theme.css" in cleaned


def test_stale_text_plan_is_rejected_before_remediation(tmp_path: Path) -> None:
    path = tmp_path / "stale.txt"
    path.write_text("Head\nGenerated with ChatGPT\n", encoding="utf-8")
    policy = PolicyStore.get("client-delivery")
    report = TrueAIEngine.default().scan(path, policy=policy)
    plan = RemediationPlanner().plan(report, policy)
    path.write_text("Head\nUnreviewed replacement!\n", encoding="utf-8")

    with pytest.raises(RemediationError, match="changed after scanning"):
        RemediationService().apply(path, report, plan)
    assert not (tmp_path / "stale.cleaned.txt").exists()


def test_docx_cleanup_preserves_unselected_comments_and_properties(tmp_path: Path) -> None:
    path = tmp_path / "metadata.docx"
    content_types = (
        """<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>"""
    )
    document = """<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Keep</w:t></w:r></w:p></w:body></w:document>"""
    core = """<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><!--KEEP-UNSELECTED--><dc:creator>Alice</dc:creator><dc:title>Keep title</dc:title></cp:coreProperties>"""
    with zipfile.ZipFile(path, "w") as package:
        package.writestr("[Content_Types].xml", content_types)
        package.writestr("word/document.xml", document)
        package.writestr("docProps/core.xml", core)
    policy = PolicyProfile.model_validate(
        {"policy": "personal-only", "rules": {"personal_metadata": "remove"}}
    )
    report = TrueAIEngine.default().scan(path, policy=policy)
    plan = RemediationPlanner().plan(report, policy)

    result = RemediationService().apply(path, report, plan)

    assert result.integrity.status == IntegrityStatus.PASS
    assert result.output_path is not None
    with zipfile.ZipFile(result.output_path) as package:
        cleaned_core = package.read("docProps/core.xml").decode("utf-8")
    assert "KEEP-UNSELECTED" in cleaned_core
    assert "Keep title" in cleaned_core
    assert "Alice" not in cleaned_core


def test_rendering_orientation_is_preserved_during_jpeg_metadata_cleanup(tmp_path: Path) -> None:
    path = tmp_path / "oriented.jpg"
    image = Image.new("RGB", (4, 2), "red")
    exif = Image.Exif()
    exif[274] = 6
    exif[305] = "Example Generator"
    image.save(path, exif=exif)
    with Image.open(path) as before_image:
        displayed_before = ImageOps.exif_transpose(before_image).size

    report, plan, result = _clean(path)
    orientation = next(
        finding for finding in report.findings if finding.evidence.get("tag_id") == 274
    )

    assert orientation.id in plan.blocked_findings
    assert result.integrity.status == IntegrityStatus.PASS
    assert result.output_path is not None
    with Image.open(result.output_path) as cleaned_image:
        assert cleaned_image.getexif()[274] == 6
        assert ImageOps.exif_transpose(cleaned_image).size == displayed_before


def test_pdf_info_cleanup_verifies_every_nonselected_object(tmp_path: Path) -> None:
    pikepdf = pytest.importorskip("pikepdf")
    path = tmp_path / "metadata.pdf"
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(120, 80))
        pdf.docinfo["/Author"] = "Alice"
        pdf.docinfo["/Title"] = "Keep title"
        pdf.save(path)
    policy = PolicyProfile.model_validate(
        {"policy": "pdf-personal-only", "rules": {"personal_metadata": "remove"}}
    )
    report = TrueAIEngine.default().scan(path, policy=policy)
    plan = RemediationPlanner().plan(report, policy)

    result = RemediationService().apply(path, report, plan)

    assert result.integrity.status == IntegrityStatus.PASS
    assert result.output_path is not None
    assert result.integrity.logical_before_sha256 == result.integrity.logical_after_sha256
    with pikepdf.open(result.output_path) as cleaned:
        assert "/Author" not in cleaned.docinfo
        assert str(cleaned.docinfo["/Title"]) == "Keep title"
        assert len(cleaned.pages) == 1


def test_pdf_integrity_gate_rejects_unselected_page_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pikepdf = pytest.importorskip("pikepdf")
    path = tmp_path / "tamper-gate.pdf"
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(120, 80))
        pdf.docinfo["/Author"] = "Alice"
        pdf.save(path)
    policy = PolicyProfile.model_validate(
        {"policy": "pdf-personal-only", "rules": {"personal_metadata": "remove"}}
    )
    report = TrueAIEngine.default().scan(path, policy=policy)
    plan = RemediationPlanner().plan(report, policy)
    original_save = pikepdf.Pdf.save

    def mutating_save(pdf: object, *args: object, **kwargs: object) -> None:
        pdf.pages[0].obj["/MediaBox"] = pikepdf.Array([0, 0, 121, 80])
        original_save(pdf, *args, **kwargs)

    monkeypatch.setattr(pikepdf.Pdf, "save", mutating_save)

    with pytest.raises(RemediationError, match="Integrity verification failed"):
        RemediationService().apply(path, report, plan)
    assert not (tmp_path / "tamper-gate.cleaned.pdf").exists()


def test_pdf_uncompressed_xmp_cleanup_is_surgical(tmp_path: Path) -> None:
    pikepdf = pytest.importorskip("pikepdf")
    path = tmp_path / "xmp.pdf"
    packet = (
        b"<?xpacket begin='x'?><x:xmpmeta xmlns:x='adobe:ns:meta/'>"
        b"<note>ordinary workflow metadata</note></x:xmpmeta><?xpacket end='w'?>"
    )
    with pikepdf.new() as pdf:
        pdf.add_blank_page(page_size=(120, 80))
        metadata = pdf.make_stream(packet)
        metadata["/Type"] = pikepdf.Name.Metadata
        metadata["/Subtype"] = pikepdf.Name.XML
        pdf.Root["/Metadata"] = metadata
        pdf.save(path, compress_streams=False, fix_metadata_version=False)
    policy = PolicyProfile.model_validate(
        {"policy": "pdf-xmp-only", "rules": {"document_metadata": "remove"}}
    )
    report = TrueAIEngine.default().scan(path, policy=policy)
    plan = RemediationPlanner().plan(report, policy)

    result = RemediationService().apply(path, report, plan)

    assert result.integrity.status == IntegrityStatus.PASS
    assert result.output_path is not None
    assert result.integrity.logical_before_sha256 == result.integrity.logical_after_sha256
    with pikepdf.open(result.output_path) as cleaned:
        assert "/Metadata" not in cleaned.Root
        assert len(cleaned.pages) == 1
