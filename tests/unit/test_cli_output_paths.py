"""What `--output` does with a path that cannot be written.

`trueai scan notes.md -o no/where/out.json` used to scan the tree, render the
report, print all of it, and then say `Internal error: FileNotFoundError` with
exit 4. Three things wrong, none of them the exception:

* exit 4 is the code for the tool breaking, and what happened is that the
  operator named a directory that does not exist;
* the failure arrived after the work, so a typo in an option cost a full scan and
  produced terminal output nobody had asked to read;
* `clean --output` created the parent directory and `scan --output` did not, so
  the same option meant two things.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from trueai.cli.app import ExitCode, app

runner = CliRunner()


@pytest.fixture
def artifact(tmp_path: Path) -> Path:
    path = tmp_path / "notes.md"
    path.write_text("Generated with ChatGPT\n", encoding="utf-8")
    return path


def test_a_missing_parent_directory_is_created_like_clean_does(
    artifact: Path, tmp_path: Path
) -> None:
    output = tmp_path / "reports" / "nested" / "scan.json"

    result = runner.invoke(app, ["scan", str(artifact), "--format", "json", "-o", str(output)])

    assert result.exit_code in {0, 1, 3}, result.output
    assert output.is_file()


def test_an_output_path_that_is_a_directory_is_refused_before_the_scan(
    artifact: Path, tmp_path: Path
) -> None:
    """Refused, and named. Not an internal error."""

    directory = tmp_path / "somewhere"
    directory.mkdir()

    result = runner.invoke(app, ["scan", str(artifact), "-o", str(directory)])

    assert result.exit_code == ExitCode.UNSUPPORTED_OR_CORRUPT
    assert "is a directory" in result.output
    # Nothing was scanned, so nothing was printed about findings.
    assert "DETERMINISTIC" not in result.output


def test_a_parent_that_is_a_file_is_refused_rather_than_crashing(
    artifact: Path, tmp_path: Path
) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(artifact), "-o", str(blocker / "out.json")])

    assert result.exit_code == ExitCode.UNSUPPORTED_OR_CORRUPT
    assert "Cannot write to" in result.output
    assert "Internal error" not in result.output


def test_the_refusal_happens_before_the_scan_not_after_it(artifact: Path, tmp_path: Path) -> None:
    """The property that makes the difference to somebody with a large repository.

    Checked by observing that the engine was never constructed rather than by
    timing it, because a timing assertion on a two-file fixture proves nothing.
    """

    from trueai.cli import app as module

    started = False
    original = module.TrueAIEngine.default

    def record(*arguments: object, **keywords: object) -> object:
        nonlocal started
        started = True
        return original(*arguments, **keywords)

    directory = tmp_path / "somewhere"
    directory.mkdir()
    monkeypatched = pytest.MonkeyPatch()
    monkeypatched.setattr(module.TrueAIEngine, "default", staticmethod(record))
    try:
        runner.invoke(app, ["scan", str(artifact), "-o", str(directory)])
    finally:
        monkeypatched.undo()

    assert not started


def test_refusing_to_overwrite_the_scanned_artifact_still_holds(artifact: Path) -> None:
    """The check that was already there, and still is."""

    result = runner.invoke(app, ["scan", str(artifact), "-o", str(artifact)])

    assert result.exit_code == ExitCode.UNSUPPORTED_OR_CORRUPT
    assert "must not overwrite" in result.output
