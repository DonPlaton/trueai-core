"""One fixture per removable field, naming the operation it pins.

The suite already exercised most of these — a privacy-policy run over a workbook
removes metadata whether or not any test says `xlsx.remove-metadata-field`. What
it did not do is make the coverage auditable: nothing could answer "which
removable fields have a regression fixture", so nothing could notice a new one
shipping without one.

`tests/unit/test_remediation_catalog.py` asks that question by comparing the
catalogue against the identifiers named in this tree. These tests are the
answers for the six it found missing, and each pins one operation specifically:
that it is planned, that it is applied, and that the integrity gate agrees the
change was the one intended.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from trueai import TrueAIEngine
from trueai.core.models import IntegrityStatus, RemediationSafety
from trueai.core.policy import PolicyStore
from trueai.core.remediation import RemediationPlanner, RemediationService


def planned(source: Path, policy_name: str = "privacy"):
    """Scan and plan, returning the report and the plan."""

    policy = PolicyStore.get(policy_name)
    report = TrueAIEngine.default(discover_plugins=False).scan(source, policy=policy)
    return report, RemediationPlanner().plan(report, policy)


def operations(plan) -> set[str]:
    return {item.remediation_id for item in plan.remediations}


def applied(source: Path, policy_name: str = "privacy"):
    report, plan = planned(source, policy_name)
    return plan, RemediationService().apply(source, report, plan)


def parts(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as package:
        return {name: package.read(name) for name in package.namelist()}


# -- OOXML custom properties ----------------------------------------------------------


def test_docx_remove_custom_property_is_planned_and_applied(docx_file: Path) -> None:
    """A custom property carrying an attribution string, removed by name."""

    plan, result = applied(docx_file)

    assert "docx.remove-custom-property" in operations(plan)
    assert result.output_path is not None
    after = parts(Path(result.output_path))
    assert b"Generated with Claude" not in after["docProps/custom.xml"]


def test_docx_remove_custom_property_leaves_the_document_body_alone(docx_file: Path) -> None:
    """It is catalogued as metadata, so the body has to be byte-identical."""

    plan, result = applied(docx_file)

    assert "docx.remove-custom-property" in operations(plan)
    assert result.output_path is not None
    before, after = parts(docx_file), parts(Path(result.output_path))
    assert before["word/document.xml"] == after["word/document.xml"]
    assert result.integrity.status is IntegrityStatus.PASS


def test_xlsx_remove_custom_property_is_planned_and_applied(xlsx_file: Path) -> None:
    plan, result = applied(xlsx_file)

    assert "xlsx.remove-custom-property" in operations(plan)
    assert result.output_path is not None
    assert b"Generated with Claude" not in Path(result.output_path).read_bytes()


# -- OOXML core and app properties -----------------------------------------------------


def test_xlsx_remove_metadata_field_is_planned_and_applied(xlsx_file: Path) -> None:
    plan, result = applied(xlsx_file)

    assert "xlsx.remove-metadata-field" in operations(plan)
    assert result.output_path is not None
    after = parts(Path(result.output_path))
    assert b"Dana" not in after["docProps/app.xml"]


def test_xlsx_remove_metadata_field_leaves_every_worksheet_untouched(xlsx_file: Path) -> None:
    plan, result = applied(xlsx_file)

    assert "xlsx.remove-metadata-field" in operations(plan)
    assert result.output_path is not None
    before, after = parts(xlsx_file), parts(Path(result.output_path))
    for name in before:
        if not name.startswith("docProps/"):
            assert before[name] == after[name], name


def test_pptx_remove_metadata_field_is_planned_and_applied(pptx_file: Path) -> None:
    plan, result = applied(pptx_file)

    assert "pptx.remove-metadata-field" in operations(plan)
    assert result.output_path is not None
    assert result.integrity.status is IntegrityStatus.PASS


def test_pptx_remove_metadata_field_is_classified_as_metadata(pptx_file: Path) -> None:
    """docProps is a separate part, so nothing a reader sees can change."""

    _, plan = planned(pptx_file)
    step = next(
        item for item in plan.remediations if item.remediation_id == "pptx.remove-metadata-field"
    )

    assert step.safety is RemediationSafety.SAFE_METADATA


# -- markup: the removal is inside the content ----------------------------------------


def test_svg_remove_generator_comment_is_planned_and_applied(tmp_path: Path) -> None:
    """A comment's tail is rendered text, which is why this is a content change."""

    source = tmp_path / "drawing.svg"
    source.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10">'
        "<!-- Created with Inkscape 1.3 -->"
        "<text>Kept</text></svg>\n",
        encoding="utf-8",
    )

    plan, result = applied(source, "client-delivery")

    assert "svg.remove-generator-comment" in operations(plan)
    assert result.output_path is not None
    output = Path(result.output_path).read_text(encoding="utf-8")
    assert "Inkscape" not in output
    assert "Kept" in output


def test_svg_remove_generator_comment_is_a_content_change(tmp_path: Path) -> None:
    source = tmp_path / "drawing.svg"
    source.write_text(
        '<svg xmlns="http://www.w3.org/2000/svg">'
        "<!-- Created with Inkscape 1.3 -->"
        "<text>Kept</text></svg>\n",
        encoding="utf-8",
    )

    _, plan = planned(source, "client-delivery")
    step = next(
        item for item in plan.remediations if item.remediation_id == "svg.remove-generator-comment"
    )

    assert step.safety is RemediationSafety.PREDICTABLE_CONTENT


def test_html_remove_attribution_comment_is_planned_and_applied(tmp_path: Path) -> None:
    source = tmp_path / "page.html"
    source.write_text(
        "<!doctype html><html><head><title>Page</title></head>"
        "<body><!-- Generated with ChatGPT --><p>Kept text</p></body></html>\n",
        encoding="utf-8",
    )

    plan, result = applied(source, "client-delivery")

    assert "html.remove-attribution-comment" in operations(plan)
    assert result.output_path is not None
    output = Path(result.output_path).read_text(encoding="utf-8")
    assert "ChatGPT" not in output
    assert "Kept text" in output


def test_html_remove_attribution_comment_does_not_join_two_text_nodes(tmp_path: Path) -> None:
    """The failure a comment removal has: a sentence closing over the gap."""

    source = tmp_path / "page.html"
    source.write_text(
        "<!doctype html><html><body>"
        "<p>Before <!-- Generated with ChatGPT --> after</p>"
        "</body></html>\n",
        encoding="utf-8",
    )

    plan, result = applied(source, "client-delivery")

    assert "html.remove-attribution-comment" in operations(plan)
    assert result.output_path is not None
    output = Path(result.output_path).read_text(encoding="utf-8")
    assert "Before " in output
    assert " after" in output
    assert "Beforeafter" not in output


# -- the whole catalogue, end to end ---------------------------------------------------


@pytest.mark.parametrize(
    ("fixture_name", "expected"),
    [
        ("docx_file", "docx.remove-custom-property"),
        ("xlsx_file", "xlsx.remove-metadata-field"),
        ("pptx_file", "pptx.remove-metadata-field"),
    ],
)
def test_each_ooxml_operation_survives_the_integrity_gate(
    fixture_name: str, expected: str, request: pytest.FixtureRequest
) -> None:
    """A cleanup that cannot pass the gate is one nobody may publish."""

    source: Path = request.getfixturevalue(fixture_name)

    plan, result = applied(source)

    assert expected in operations(plan)
    assert result.integrity.status is IntegrityStatus.PASS
