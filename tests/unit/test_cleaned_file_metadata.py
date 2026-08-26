"""What survives an edit, and what must not.

`shutil.copystat` copies permission bits and timestamps together, and it is what
both cleanup paths reached for. So a cleaned file came back with a modification
time saying its content had not changed.

Permission bits describe the file's place in the filesystem and should survive.
The modification time is a claim about when the content last changed, and it just
did — resetting it hides the edit from rsync, from build systems, and from
anybody reading timestamps as evidence. In a forensic tool that is the behaviour
being complained about rather than performed.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from trueai.cli.app import app

runner = CliRunner()

SVG = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10">
  <!-- Generator: Generated with ChatGPT -->
  <rect x="1" y="1" width="5" height="5"/>
</svg>
"""


def aged(path: Path) -> float:
    """Backdate a file and return the timestamp it now claims."""

    stamp = time.time() - 86_400
    os.utime(path, (stamp, stamp))
    return path.stat().st_mtime


def test_cleaning_in_place_does_not_restore_the_modification_time(tmp_path: Path) -> None:
    artifact = tmp_path / "logo.svg"
    artifact.write_text(SVG, encoding="utf-8")
    before = aged(artifact)

    result = runner.invoke(app, ["clean", str(artifact), "--in-place"])

    assert "Generated with ChatGPT" not in artifact.read_text(encoding="utf-8"), result.output
    assert artifact.stat().st_mtime > before


def test_cleaning_to_a_new_file_does_not_inherit_the_original_time(tmp_path: Path) -> None:
    artifact = tmp_path / "logo.svg"
    artifact.write_text(SVG, encoding="utf-8")
    before = aged(artifact)
    output = tmp_path / "cleaned.svg"

    runner.invoke(app, ["clean", str(artifact), "--output", str(output)])

    assert output.is_file()
    assert output.stat().st_mtime > before


def test_the_backup_still_carries_the_original_time(tmp_path: Path) -> None:
    """The backup *is* the original content, so its timestamp is honest."""

    artifact = tmp_path / "logo.svg"
    artifact.write_text(SVG, encoding="utf-8")
    before = aged(artifact)

    runner.invoke(app, ["clean", str(artifact), "--in-place"])

    backup = tmp_path / "logo.svg.trueai.bak"
    assert backup.is_file()
    assert backup.stat().st_mtime == pytest.approx(before, abs=2)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_permission_bits_survive_the_edit(tmp_path: Path) -> None:
    """They describe where the file sits, not when it changed."""

    artifact = tmp_path / "logo.svg"
    artifact.write_text(SVG, encoding="utf-8")
    artifact.chmod(0o640)

    runner.invoke(app, ["clean", str(artifact), "--in-place"])

    assert artifact.stat().st_mode & 0o777 == 0o640


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_permission_bits_survive_a_copy_out(tmp_path: Path) -> None:
    artifact = tmp_path / "logo.svg"
    artifact.write_text(SVG, encoding="utf-8")
    artifact.chmod(0o600)
    output = tmp_path / "cleaned.svg"

    runner.invoke(app, ["clean", str(artifact), "--output", str(output)])

    assert output.stat().st_mode & 0o777 == 0o600
