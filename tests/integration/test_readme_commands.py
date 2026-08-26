"""Every command the README shows, run in the order it shows them.

`scripts/check_docs.py` asserts that the commands and options named in the
documentation exist. Existing is not working: an option can be spelled
correctly, be accepted by the parser, and still fail — and a reader who copies a
line out of a README does not care which of the two it was.

Order matters and is the point. The block reads as a session, so a later line may
depend on a file an earlier one wrote. Following it exactly is what found
`certificates revoke` being demonstrated against the unsigned certificate the
example two lines above had just produced: refused, correctly, with "unsigned
certificates have no authenticated issuer to revoke them", in a README that
presented it as something a reader could run.
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.support import missing_modules

REPOSITORY = Path(__file__).resolve().parents[2]

#: Read off the exit-code table in the README itself. Zero is clean, one is
#: review-required, two is a policy violation -- all three are the command
#: working and reporting. Three is "unsupported, corrupt, unsafe, or
#: unavailable" and four is an internal error: those are the example not being
#: followable, which is what this test exists to catch.
WORKED = {0, 1, 2}

#: Lines that need something no test may conjure: a trust anchor from a real
#: certificate authority, or a package manager.
NEEDS_THE_WORLD = ("--trust-anchors", "roots.pem")

#: Commands whose optional dependency the lean test environment may not have.
OPTIONAL = {
    "verify": ("c2pa",),
    "certificates": ("cryptography",),
    "policies": ("cryptography",),
}


def documented_commands() -> list[str]:
    """Return each `trueai …` line from the README's console blocks, in order."""

    text = (REPOSITORY / "README.md").read_text(encoding="utf-8")
    found: list[str] = []
    for block in re.findall(r"```console\n(.*?)```", text, re.DOTALL):
        for raw in block.splitlines():
            line = raw.strip()
            if not line.startswith("trueai ") or any(marker in line for marker in NEEDS_THE_WORLD):
                continue
            found.append(line.split("#")[0].strip())
    return found


def build_fixtures(root: Path) -> None:
    """Create the files the README's placeholders name."""

    from PIL import Image, PngImagePlugin

    from tests.fixtures_ooxml import build_pptx, build_xlsx

    repository = root / "repository"
    repository.mkdir()
    (repository / "notes.md").write_text("Generated with ChatGPT\n", encoding="utf-8")
    (repository / "code.py").write_text("# Written by Claude\nvalue = 1\n", encoding="utf-8")

    (root / "README.md").write_text(
        "# Title\n\nDrafted with help.\nInvisible​space.\n", encoding="utf-8"
    )

    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("Software", "Generated with ChatGPT")
    Image.new("RGB", (16, 16), (1, 2, 3)).save(root / "design.png", pnginfo=metadata)

    (root / "deliverable.pdf").write_bytes(
        b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n"
        b"2 0 obj << /Creator (ChatGPT) >> endobj\n"
        b"trailer << /Root 1 0 R /Info 2 0 R >>\nstartxref\n0\n%%EOF\n"
    )

    build_pptx(root / "deck.pptx")
    build_xlsx(root / "model.xlsx")

    parts = {
        "[Content_Types].xml": (
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
            'package/2006/content-types"><Default Extension="xml" '
            'ContentType="application/xml"/></Types>'
        ),
        "word/document.xml": (
            '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/'
            'wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Text</w:t></w:r>'
            "</w:p></w:body></w:document>"
        ),
        "docProps/core.xml": (
            '<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.'
            'openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Alice</dc:creator>'
            "</cp:coreProperties>"
        ),
    }
    with zipfile.ZipFile(root / "report.docx", "w", zipfile.ZIP_DEFLATED) as package:
        for name, content in parts.items():
            package.writestr(name, content)


def test_the_readme_shows_at_least_a_dozen_commands() -> None:
    """A parser that silently matched nothing would make every check below pass."""

    assert len(documented_commands()) >= 12


def test_every_documented_command_runs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """In README order, in one directory, the way a reader would follow it."""

    build_fixtures(tmp_path)
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    from trueai.cli.app import app

    failures: list[str] = []
    for command in documented_commands():
        arguments = command.split()[1:]
        needed = OPTIONAL.get(arguments[0] if arguments else "", ())
        if needed and missing_modules(*needed):
            continue
        result = runner.invoke(app, arguments)
        if result.exit_code not in WORKED:
            detail = (result.output or "").strip().splitlines()
            failures.append(f"{command} -> exit {result.exit_code}: {' '.join(detail[-2:])[:200]}")

    assert failures == [], "\n".join(failures)
