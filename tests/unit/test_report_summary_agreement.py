"""A report whose summary contradicts its own findings.

Found by `scripts/fuzz_parsers.py --target report`, which mutates a real report
and reloads it: a document declaring `finding_count: 2` with an empty `findings`
list validated cleanly, and every reader of the headline then reported a number
nothing in the document supported — `trueai explain`, the terminal renderer, any
consumer of `JSONReporter.load`.

The summary exists so a client does not have to recount. That only works if it
cannot disagree with the list beside it, so the derivable fields are now checked
against the findings and a report that contradicts itself is refused at load.

`artifact_count`, `review_count`, and `violation_count` are deliberately not
checked: the first counts files rather than findings, and the other two depend on
a policy the report does not carry.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from trueai.cli.app import app
from trueai.reporters import JSONReporter

runner = CliRunner()


@pytest.fixture
def report_path(tmp_path: Path) -> Path:
    artifact = tmp_path / "notes.md"
    artifact.write_text("Generated with ChatGPT\n", encoding="utf-8")
    destination = tmp_path / "report.json"
    runner.invoke(app, ["scan", str(artifact), "--format", "json", "--output", str(destination)])
    return destination


def rewritten(path: Path, mutate) -> Path:  # type: ignore[no-untyped-def]
    document = json.loads(path.read_text(encoding="utf-8"))
    mutate(document)
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_a_count_larger_than_the_findings_is_refused(report_path: Path) -> None:
    def inflate(document: dict) -> None:  # type: ignore[type-arg]
        document["summary"]["finding_count"] = len(document["findings"]) + 2

    rewritten(report_path, inflate)

    with pytest.raises(ValidationError, match="summary disagrees with the findings"):
        JSONReporter.load(report_path)


def test_findings_removed_without_the_count_is_refused(report_path: Path) -> None:
    """The shape the fuzzer actually produced: the list emptied, the count left."""

    def empty(document: dict) -> None:  # type: ignore[type-arg]
        document["findings"] = []

    rewritten(report_path, empty)

    with pytest.raises(ValidationError, match="summary disagrees with the findings"):
        JSONReporter.load(report_path)


def test_a_severity_map_that_does_not_match_is_refused(report_path: Path) -> None:
    """The maps are derivable too, and a client may render them instead of recounting."""

    def relabel(document: dict) -> None:  # type: ignore[type-arg]
        document["summary"]["by_severity"] = {"critical": document["summary"]["finding_count"]}

    rewritten(report_path, relabel)

    with pytest.raises(ValidationError, match="by_severity"):
        JSONReporter.load(report_path)


def test_an_untouched_report_still_loads(report_path: Path) -> None:
    """Paired with the tests above: the rule refuses contradictions, not reports."""

    report = JSONReporter.load(report_path)

    assert report.summary.finding_count == len(report.findings)


def test_explain_rebuilds_the_summary_rather_than_editing_it(report_path: Path) -> None:
    """`explain` narrows a report to one finding, and the maps have to follow.

    It edited `finding_count` alone, leaving the category, severity, and
    confidence maps describing the whole report — which the rule above now
    catches, so the command would have started failing on its own output.
    """

    document = json.loads(report_path.read_text(encoding="utf-8"))
    finding_id = document["findings"][0]["id"]

    result = runner.invoke(app, ["explain", finding_id, "--report", str(report_path)])

    assert result.exit_code == 0, result.output
    assert "1 finding across" in result.output
