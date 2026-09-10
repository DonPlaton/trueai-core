"""Write a small corpus with known traces planted in it, then scan it.

The first question anybody asks a forensic tool is "show me it finding
something". Answering that with a screenshot is worth nothing, because a
screenshot cannot be re-run, and answering it with an accuracy figure would be
worse: most of what this tool reports is the presence or absence of a byte
string, and averaging those into a rate manufactures exactly the probabilistic
claim the product refuses to make.

So the answer is a corpus somebody can build in one command and scan
themselves. Every file below has a declared list of what was put into it and
where. `tests/unit/test_demo_corpus.py` builds the corpus and asserts the
scanner finds every planted trace, which makes this a recall check over a known
set rather than a demonstration that happens to have been rehearsed.

The corpus is generated rather than committed. Binary fixtures in a repository
go stale, and a reader cannot tell what is in one by looking at it.

    python examples/demo_corpus/make_corpus.py --output ./demo
    trueai scan ./demo
    trueai scan ./demo --format json --output demo.json
    trueai clean ./demo/handoff-note.md --policy safe-clean
"""

from __future__ import annotations

import argparse
import zipfile
from dataclasses import dataclass
from pathlib import Path

#: A zero-width non-joiner: no width, no glyph, survives copy and paste, and
#: rides along in text moved between an assistant and a document.
ZERO_WIDTH = "‌"


@dataclass(frozen=True, slots=True)
class Planted:
    """One trace put into the corpus on purpose."""

    filename: str
    category: str
    description: str


#: What this corpus contains, declared rather than discovered. The test reads
#: this table, so a trace added here without the scanner finding it fails the
#: build rather than quietly becoming a claim nobody checks.
PLANTED: tuple[Planted, ...] = (
    Planted("handoff-note.md", "explicit_ai_attribution", "a line of text naming an assistant"),
    Planted("handoff-note.md", "invisible_unicode", "a zero-width non-joiner inside a word"),
    Planted("logo.svg", "generator_metadata", "an editor comment left by an export"),
    Planted("logo.svg", "hidden_element", "a group the renderer never draws"),
    Planted("brief.docx", "personal_metadata", "the names of two people who edited it"),
    Planted("brief.docx", "generator_metadata", "the application that wrote the package"),
    Planted("brief.docx", "document_metadata", "a title the author typed once and forgot"),
    Planted("contract.pdf", "generator_metadata", "a `/Producer` and a `/Creator` in the trailer"),
    Planted("contract.pdf", "personal_metadata", "an `/Author` in the trailer"),
)

MARKDOWN = f"""# Handover note

Draft prepared for the client meeting on Thursday. The summary section was
generated with ChatGPT and has not been checked against the source figures.

Please review the second para{ZERO_WIDTH}graph before this goes out.
"""

SVG = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
  <!-- Generator: Adobe Illustrator 28.0, SVG Export Plug-In -->
  <title>Placeholder mark</title>
  <rect x="8" y="8" width="48" height="48" rx="6" fill="#8B5CF6"/>
  <g id="working-notes" style="display:none">
    <text x="8" y="60">internal: replace before delivery</text>
  </g>
</svg>
"""

TEXT = """Meeting notes, typed by hand.

Agenda: budget, timeline, the question about the second supplier.
Nothing was pasted into this file and nothing exported it.
"""

DOCX_PARTS = {
    "[Content_Types].xml": """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/xml"/>
</Types>""",
    "word/document.xml": """<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>Project brief, second revision.</w:t></w:r></w:p></w:body>
</w:document>""",
    "docProps/core.xml": """<?xml version="1.0" encoding="UTF-8"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
 xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:creator>Dana Whitfield</dc:creator>
  <cp:lastModifiedBy>R. Okonkwo</cp:lastModifiedBy>
  <dc:title>Project brief</dc:title>
</cp:coreProperties>""",
    "docProps/app.xml": """<?xml version="1.0" encoding="UTF-8"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  <Application>Microsoft Word</Application><AppVersion>16.0</AppVersion>
</Properties>""",
}


def _pdf_bytes() -> bytes:
    """Build the smallest PDF that carries an information dictionary.

    Written out by hand rather than through a library so the corpus has no
    dependency the reader has to install before they can look at it, and so the
    offsets in the cross-reference table are visibly correct.
    """

    objects = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>\nendobj\n",
        b"4 0 obj\n<< /Producer (Acrobat Distiller 23.0) /Author (Dana Whitfield) "
        b"/Creator (Microsoft Word) >>\nendobj\n",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for body in objects:
        offsets.append(len(out))
        out += body
    start = len(out)
    out += b"xref\n0 %d\n" % (len(objects) + 1)
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += b"%010d 00000 n \n" % offset
    out += b"trailer\n<< /Size %d /Root 1 0 R /Info 4 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        start,
    )
    return bytes(out)


def build(destination: Path) -> Path:
    """Write the corpus into ``destination`` and return the directory."""

    destination.mkdir(parents=True, exist_ok=True)
    (destination / "handoff-note.md").write_text(MARKDOWN, encoding="utf-8")
    (destination / "logo.svg").write_text(SVG, encoding="utf-8")
    (destination / "typed-by-hand.txt").write_text(TEXT, encoding="utf-8")
    (destination / "contract.pdf").write_bytes(_pdf_bytes())
    with zipfile.ZipFile(destination / "brief.docx", "w", zipfile.ZIP_DEFLATED) as package:
        for name, content in DOCX_PARTS.items():
            package.writestr(name, content)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("demo"))
    arguments = parser.parse_args()
    directory = build(arguments.output)
    print(f"Wrote {len(list(directory.iterdir()))} files to {directory}")
    print()
    print("Planted on purpose:")
    for item in PLANTED:
        print(f"  {item.filename:20} {item.category:24} {item.description}")
    print()
    print("  typed-by-hand.txt    nothing, so a clean result has something to look like")
    print()
    print(f"Now run:  trueai scan {directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
