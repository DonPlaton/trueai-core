"""Rewriting one field in a document should not rename the whole document.

`ElementTree.tostring` invents a prefix for every namespace it was not told
about. Removing a single comment from an SVG returned `<ns0:svg xmlns:ns0="…">`
with every child renamed to match, and removing one Word property rewrote
`<cp:coreProperties>` as `<ns0:coreProperties>`. Both are equivalent XML and
every consumer of them disagrees: a diff shows the whole part changed.

That matters more here than it would elsewhere. This project's case for its
cleanup is that an edit touches what it says it touches -- same-length `free`
padding in MP4, a named object in a PDF graph, byte-identical audio payloads --
and handing back a file where every tag has a different name is the opposite
claim.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from xml.etree import ElementTree

from typer.testing import CliRunner

from trueai.cli.app import app
from trueai.core.xml_serialization import declared_prefixes, preferred_prefixes, serialize_like

runner = CliRunner()

INKSCAPE_SVG = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape"
     viewBox="0 0 10 10" inkscape:version="1.3">
  <!-- Generator: Generated with ChatGPT -->
  <metadata><rdf>Editor workflow</rdf></metadata>
  <rect id="a" x="1" y="1" width="5" height="5" fill="#fff"/>
  <text>Visible label</text>
</svg>
"""


# -- reading the prefixes back out of the source ----------------------------------------


def test_the_default_namespace_is_read_as_the_empty_prefix() -> None:
    mapping = declared_prefixes(b'<svg xmlns="http://www.w3.org/2000/svg"/>')

    assert mapping == {"http://www.w3.org/2000/svg": ""}


def test_a_prefixed_namespace_keeps_its_prefix() -> None:
    mapping = declared_prefixes(INKSCAPE_SVG.encode("utf-8"))

    assert mapping["http://www.w3.org/2000/svg"] == ""
    assert mapping["http://www.inkscape.org/namespaces/inkscape"] == "inkscape"


def test_single_quoted_declarations_are_read_too() -> None:
    assert declared_prefixes(b"<a xmlns:x='urn:x'/>") == {"urn:x": "x"}


def test_the_outermost_declaration_wins() -> None:
    """A prefix rebound on a child is not what a reader of the file would name."""

    source = b'<a xmlns:x="urn:first"><b xmlns:x="urn:second"/></a>'

    assert declared_prefixes(source) == {"urn:first": "x", "urn:second": "x"}


def test_a_document_declaring_thousands_is_bounded() -> None:
    source = b"".join(f'xmlns:p{index}="urn:{index}" '.encode() for index in range(500))

    assert len(declared_prefixes(source)) <= 64


# -- the table is put back ----------------------------------------------------------------


def test_the_global_prefix_table_is_restored_afterwards() -> None:
    """It is module-global, so borrowing it has to be temporary.

    A cleaner that permanently taught ElementTree to call the SVG namespace ""
    would change how every other part of the process serializes XML.
    """

    table = ElementTree._namespace_map
    before = dict(table)

    with preferred_prefixes({"urn:temporary": "tmp"}):
        assert table["urn:temporary"] == "tmp"

    assert dict(table) == before


def test_the_table_is_restored_even_when_serialization_fails() -> None:
    table = ElementTree._namespace_map
    before = dict(table)

    try:
        with preferred_prefixes({"urn:temporary": "tmp"}):
            raise RuntimeError("serialization failed")
    except RuntimeError:
        pass

    assert dict(table) == before


def test_a_document_without_namespaces_does_not_touch_the_table() -> None:
    """Nothing to install, so nothing is borrowed and no lock is taken."""

    table = ElementTree._namespace_map
    before = dict(table)
    root = ElementTree.fromstring("<note><body>text</body></note>")

    output = serialize_like(root, b"<note><body>text</body></note>")

    assert b"<note>" in output
    assert dict(table) == before


# -- end to end ---------------------------------------------------------------------------


def test_cleaning_an_svg_does_not_rename_every_element(tmp_path: Path) -> None:
    artifact = tmp_path / "logo.svg"
    artifact.write_text(INKSCAPE_SVG, encoding="utf-8")
    output = tmp_path / "cleaned.svg"

    runner.invoke(app, ["clean", str(artifact), "--output", str(output)])

    cleaned = output.read_text(encoding="utf-8")
    assert "ns0:" not in cleaned, cleaned
    assert '<svg xmlns="http://www.w3.org/2000/svg"' in cleaned
    assert "<rect" in cleaned and "<text>Visible label</text>" in cleaned
    assert "Generated with ChatGPT" not in cleaned


def test_cleaning_a_word_property_does_not_rename_the_part(tmp_path: Path) -> None:
    artifact = tmp_path / "report.docx"
    parts = {
        "[Content_Types].xml": (
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
            'package/2006/content-types"><Default Extension="xml" '
            'ContentType="application/xml"/></Types>'
        ),
        "word/document.xml": (
            '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/'
            'wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Visible text</w:t>'
            "</w:r></w:p></w:body></w:document>"
        ),
        "docProps/core.xml": (
            '<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.'
            'openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Alice</dc:creator>'
            "</cp:coreProperties>"
        ),
    }
    with zipfile.ZipFile(artifact, "w", compression=zipfile.ZIP_DEFLATED) as package:
        for name, content in parts.items():
            package.writestr(name, content)
    output = tmp_path / "cleaned.docx"

    runner.invoke(app, ["clean", str(artifact), "--policy", "privacy", "--output", str(output)])

    with zipfile.ZipFile(output) as package:
        core = package.read("docProps/core.xml").decode("utf-8")
        document = package.read("word/document.xml").decode("utf-8")

    assert "ns0:" not in core, core
    assert "cp:coreProperties" in core
    assert "Alice" not in core
    # An untouched part is not rewritten at all, which is the stronger version of
    # the same property.
    assert document == parts["word/document.xml"]
