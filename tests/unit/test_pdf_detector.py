from pathlib import Path

from trueai import TrueAIEngine
from trueai.core.models import FindingCategory, ProvenanceClass


def test_pdf_info_annotations_and_embedded_files(pdf_file: Path) -> None:
    report = TrueAIEngine.default().scan(pdf_file)

    fields = {
        item.evidence.get("field")
        for item in report.findings
        if item.category
        in {
            FindingCategory.DOCUMENT_METADATA,
            FindingCategory.PERSONAL_METADATA,
            FindingCategory.GENERATOR_METADATA,
        }
    }
    assert {"Author", "Creator", "Producer", "CreationDate"} <= fields
    assert any(item.title == "PDF embedded-file lexical marker" for item in report.findings)
    assert any(item.title == "PDF annotation lexical marker" for item in report.findings)


def test_malformed_pdf_reports_corruption(tmp_path: Path) -> None:
    path = tmp_path / "broken.pdf"
    path.write_bytes(b"%PDF-1.7\n1 0 obj <<>> endobj")

    report = TrueAIEngine.default().scan(path)

    assert any(item.code == "corrupt_artifact" for item in report.diagnostics)


def test_pdf_xmp_with_provenance_marker_is_not_removable(tmp_path: Path) -> None:
    path = tmp_path / "credentialed.pdf"
    packet = b"<?xpacket begin='x'?><x:xmpmeta>c2pa Content Credentials</x:xmpmeta>"
    path.write_bytes(
        b"%PDF-1.4\n"
        b"1 0 obj << /Type /Catalog /Metadata 2 0 R >> endobj\n"
        + b"2 0 obj << /Type /Metadata /Subtype /XML /Length "
        + str(len(packet)).encode("ascii")
        + b" >> stream\n"
        + packet
        + b"\nendstream endobj\n"
        + b"trailer << /Root 1 0 R >>\n%%EOF\n"
    )

    report = TrueAIEngine.default().scan(path)
    finding = next(
        item for item in report.findings if item.title == "PDF linked XMP metadata packet"
    )

    assert finding.removable is False
    assert finding.provenance_class == ProvenanceClass.PROVENANCE_METADATA
    assert finding.evidence["protected_provenance_marker"] is True


def test_pdf_page_content_tokens_are_not_reported_as_info_metadata(tmp_path: Path) -> None:
    path = tmp_path / "content-token.pdf"
    path.write_bytes(
        b"%PDF-1.4\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n"
        b"3 0 obj << /Type /Page /Parent 2 0 R /Contents 4 0 R >> endobj\n"
        b"4 0 obj << /Length 37 >> stream\n/Author (Generated with ChatGPT)\nendstream endobj\n"
        b"trailer << /Root 1 0 R >>\n%%EOF\n"
    )

    report = TrueAIEngine.default().scan(path)

    assert not [finding for finding in report.findings if finding.evidence.get("field") == "Author"]


def test_unlinked_xmp_bytes_are_not_planned_as_metadata(tmp_path: Path) -> None:
    path = tmp_path / "unlinked-xmp.pdf"
    path.write_bytes(
        b"%PDF-1.4\n"
        b"1 0 obj << /Type /Catalog >> endobj\n"
        b"2 0 obj << /Length 70 >> stream\n"
        b"<?xpacket begin='x'?><x:xmpmeta>page-like text</x:xmpmeta>\n"
        b"endstream endobj\n"
        b"trailer << /Root 1 0 R >>\n%%EOF\n"
    )

    report = TrueAIEngine.default().scan(path)

    assert not [
        finding for finding in report.findings if finding.remediation_id == "pdf.remove-xmp"
    ]


def test_pdf_info_provenance_value_is_not_removable(tmp_path: Path) -> None:
    path = tmp_path / "credential-info.pdf"
    path.write_bytes(
        b"%PDF-1.4\n"
        b"1 0 obj << /Type /Catalog >> endobj\n"
        b"2 0 obj << /Creator (c2pa Content Credentials) >> endobj\n"
        b"trailer << /Root 1 0 R /Info 2 0 R >>\n%%EOF\n"
    )

    report = TrueAIEngine.default().scan(path)
    finding = next(item for item in report.findings if item.evidence.get("field") == "Creator")

    assert finding.removable is False
    assert finding.provenance_class == ProvenanceClass.PROVENANCE_METADATA
