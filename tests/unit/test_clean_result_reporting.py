"""What `clean` tells an operator it did.

It said "Changed fields: 1". The result carries the names — `changed_fields` is a
tuple of them — and the terminal printed the length. Somebody sanitizing a client
deliverable needs to know that `Software` went and `Author` stayed, and a count
cannot tell them that.

`applied_remediation_ids` had no reader anywhere in the package: written into
every result and rendered by nothing.

And a dry run filled `changed_fields` with the operations it *would* run, giving
one field two vocabularies — field names after a real clean, operation
identifiers after a preview — in a record a JSON consumer reads.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from PIL import Image, PngImagePlugin
from typer.testing import CliRunner

from trueai.cli.app import app

runner = CliRunner()


@pytest.fixture
def image(tmp_path: Path) -> Path:
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("Software", "Generated with ChatGPT")
    path = tmp_path / "art.png"
    Image.new("RGB", (8, 8), (1, 2, 3)).save(path, pnginfo=metadata)
    return path


def test_the_changed_field_is_named_not_counted(image: Path) -> None:
    result = runner.invoke(app, ["clean", str(image)])

    assert "Changed fields (1)" in result.output
    assert "Software" in result.output


def test_the_operation_is_named_rather_than_hashed(image: Path) -> None:
    """The result records `rem_5f3c1dcf`, which is right for an audit trail.

    It is the wrong thing to show a person, and the plan is where those
    identifiers have names.
    """

    result = runner.invoke(app, ["clean", str(image)])

    assert "image.remove-metadata" in result.output
    assert "rem_" not in result.output


def test_a_dry_run_reports_that_nothing_changed(image: Path) -> None:
    """Because nothing did. What would happen is the plan, printed above it."""

    result = runner.invoke(app, ["clean", str(image), "--dry-run"])

    assert "Changed fields: none" in result.output
    assert "Operations applied: none" in result.output
    # The preview table is still there and still names the operation.
    assert "image.remove-metadata" in result.output


def test_a_dry_run_does_not_call_a_path_it_never_wrote_an_output(image: Path) -> None:
    result = runner.invoke(app, ["clean", str(image), "--dry-run"])

    assert "Would write" in result.output
    assert not (image.parent / "art.cleaned.png").exists()


def test_the_dry_run_record_says_nothing_was_applied(image: Path, tmp_path: Path) -> None:
    """The same distinction where a machine consumer reads it."""

    from trueai import PolicyStore, TrueAIEngine
    from trueai.core.remediation import RemediationPlanner, RemediationService

    policy = PolicyStore.get("safe-clean")
    report = TrueAIEngine.default(discover_plugins=False).scan(image, policy=policy)
    plan = RemediationPlanner().plan(report, policy)

    preview = RemediationService().apply(image, report, plan, dry_run=True)

    assert preview.dry_run is True
    assert preview.changed_fields == ()
    assert preview.applied_remediation_ids == ()
    assert plan.remediations, "the plan is where what-would-happen lives"


def test_a_real_run_records_both(image: Path) -> None:
    from trueai import PolicyStore, TrueAIEngine
    from trueai.core.remediation import RemediationPlanner, RemediationService

    policy = PolicyStore.get("safe-clean")
    report = TrueAIEngine.default(discover_plugins=False).scan(image, policy=policy)
    plan = RemediationPlanner().plan(report, policy)

    result = RemediationService().apply(image, report, plan)

    assert result.applied_remediation_ids
    assert any("Software" in field for field in result.changed_fields)
