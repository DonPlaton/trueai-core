"""Synthetic, redistributable fixtures for TrueAI Core tests."""

from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path

import pytest
from PIL import Image, PngImagePlugin

from tests.fixtures_ooxml import build_pptx, build_xlsx


@pytest.fixture
def docx_file(tmp_path: Path) -> Path:
    """Create a minimal OPC package with metadata, comments, and revisions."""

    path = tmp_path / "report.docx"
    parts = {
        "[Content_Types].xml": """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/xml"/>
</Types>""",
        "word/document.xml": """<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>Visible report text</w:t></w:r></w:p>
  <w:ins w:author="Reviewer"><w:r><w:t>Tracked text</w:t></w:r></w:ins></w:body>
</w:document>""",
        "word/comments.xml": """<?xml version="1.0" encoding="UTF-8"?>
<w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:comment w:id="0" w:author="Alice"><w:p><w:r><w:t>Review this.</w:t></w:r></w:p></w:comment>
</w:comments>""",
        "docProps/core.xml": """<?xml version="1.0" encoding="UTF-8"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
 xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:creator>Alice</dc:creator><cp:lastModifiedBy>Bob</cp:lastModifiedBy>
  <dc:title>Client report</dc:title>
</cp:coreProperties>""",
        "docProps/app.xml": """<?xml version="1.0" encoding="UTF-8"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  <Application>Microsoft Word</Application><AppVersion>16.0</AppVersion><Company>Example Inc</Company>
</Properties>""",
        "docProps/custom.xml": """<?xml version="1.0" encoding="UTF-8"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"
 xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <property name="Workflow" fmtid="x" pid="2"><vt:lpwstr>Generated with Claude</vt:lpwstr></property>
</Properties>""",
        "word/_rels/document.xml.rels": """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="external" Target="https://example.test/template" TargetMode="External"/>
</Relationships>""",
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as package:
        for name, content in parts.items():
            package.writestr(name, content)
    return path


@pytest.fixture
def pptx_file(tmp_path: Path) -> Path:
    """Create a presentation with speaker notes, comments, and package metadata."""

    return build_pptx(tmp_path / "deck.pptx")


@pytest.fixture
def xlsx_file(tmp_path: Path) -> Path:
    """Create a workbook with a hidden sheet, comments, identities, and links."""

    return build_xlsx(tmp_path / "model.xlsx")


@pytest.fixture
def svg_file(tmp_path: Path) -> Path:
    path = tmp_path / "design.svg"
    path.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape"
 viewBox="0 0 100 100" inkscape:version="1.3">
  <!-- Generator: Generated with ChatGPT -->
  <metadata><rdf>Editor workflow</rdf></metadata>
  <rect id="visible" x="1" y="1" width="10" height="10" fill="#fff"/>
  <g id="hidden" style="display:none"><text>Hidden note</text></g>
  <path d="M0 0L10 10"/><path d="M0 0L10 10"/>
  <script>console.log('never executed')</script>
</svg>""",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def pdf_file(tmp_path: Path) -> Path:
    path = tmp_path / "report.pdf"
    path.write_bytes(
        b"%PDF-1.4\n"
        b"1 0 obj << /Type /Catalog >> endobj\n"
        b"2 0 obj << /Author (Alice) /Creator (ChatGPT) /Producer (Example PDF) "
        b"/CreationDate (D:20260101000000Z) >> endobj\n"
        b"3 0 obj << /Annots [] /Filespec true /EmbeddedFile true >> endobj\n"
        b"trailer << /Root 1 0 R /Info 2 0 R >>\n%%EOF\n"
    )
    return path


@pytest.fixture
def png_file(tmp_path: Path) -> Path:
    path = tmp_path / "image.png"
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("Software", "Generated with ChatGPT")
    metadata.add_text("Author", "Alice")
    Image.new("RGB", (8, 8), (10, 20, 30)).save(path, pnginfo=metadata)
    return path


@pytest.fixture
def jpeg_file(tmp_path: Path) -> Path:
    path = tmp_path / "image.jpg"
    image = Image.new("RGB", (8, 8), (40, 50, 60))
    exif = Image.Exif()
    exif[305] = "Generated with ChatGPT"  # Software
    exif[315] = "Alice"  # Artist
    image.save(path, quality=90, exif=exif)
    return path


@pytest.fixture
def git_repository(tmp_path: Path) -> Path:
    path = tmp_path / "repository"
    path.mkdir()

    def run(*args: str) -> None:
        subprocess.run(
            ["git", "-C", str(path), *args],
            check=True,
            capture_output=True,
            text=True,
        )

    run("init", "-q")
    run("config", "user.name", "Test User")
    run("config", "user.email", "test@example.test")
    (path / "README.md").write_text("Synthetic repository\n", encoding="utf-8")
    tooling = path / ".claude"
    tooling.mkdir()
    (tooling / "settings.json").write_text("{}\n", encoding="utf-8")
    run("add", "README.md", ".claude/settings.json")
    run("commit", "-q", "-m", "Add report\n\nCo-Authored-By: Claude <noreply@anthropic.com>")
    return path
