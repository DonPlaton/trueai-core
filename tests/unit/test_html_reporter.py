"""An HTML report a hostile artifact cannot turn into a page.

Every string in a report came from the file under examination, and the report is
then opened in a browser by the person examining it. That is the attack in one
sentence: put script in a document, have it run in the analyst's browser when
they read about it.

So most of what follows is adversarial. A finding whose title is a script tag, a
path that tries to close an attribute, a detector id carrying an event handler —
each is put through the reporter and the output is parsed to check that nothing
became markup.
"""

from __future__ import annotations

import html as html_module
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from trueai.cli.app import app
from trueai.core.models import (
    ArtifactDescriptor,
    ArtifactType,
    ConfidenceType,
    EvidenceType,
    Finding,
    FindingCategory,
    IntegrityReport,
    IntegrityStatus,
    ProvenanceSigner,
    ProvenanceVerification,
    ProvenanceVerificationStatus,
    ScanDiagnostic,
    ScanReport,
    ScanSummary,
    Severity,
)
from trueai.reporters import HTMLReporter
from trueai.reporters.html import CONTENT_SECURITY_POLICY

runner = CliRunner()

PAYLOAD = '<script>alert("xss")</script>'
ATTRIBUTE_BREAK = '" onmouseover="alert(1)'

#: Every element the reporter is allowed to emit. Anything else in the parsed
#: document came from an artifact, which would mean an escaping hole.
ALLOWED_TAGS = {
    "html",
    "head",
    "meta",
    "title",
    "style",
    "body",
    "h1",
    "h2",
    "h3",
    "p",
    "dl",
    "dt",
    "dd",
    "table",
    "tr",
    "th",
    "td",
    "span",
    "strong",
    "br",
    "ul",
    "li",
    "footer",
    "doctype",
}


def finding(**extra: Any) -> Finding:
    fields: dict[str, Any] = {
        "id": "finding-000000000001",
        "detector_id": "example.detector.v1",
        "category": FindingCategory.EXPLICIT_AI_ATTRIBUTION,
        "artifact_path": "notes.md",
        "confidence": 1.0,
        "confidence_type": ConfidenceType.DETERMINISTIC,
        "severity": Severity.HIGH,
        "evidence_type": EvidenceType.TEXT,
        "title": "Attribution string",
        "description": "The document says it was generated with a tool.",
    }
    fields.update(extra)
    return Finding.model_validate(fields)


def report(**extra: Any) -> ScanReport:
    descriptor = ArtifactDescriptor(
        path="notes.md", artifact_type=ArtifactType.MARKDOWN, size=42, sha256="0" * 64
    )
    findings = extra.pop("findings", (finding(),))
    fields: dict[str, Any] = {
        "artifact": descriptor,
        "artifacts": (descriptor,),
        "summary": ScanSummary.over(findings, artifact_count=1),
        "findings": findings,
        "integrity": IntegrityReport(
            status=IntegrityStatus.NOT_MODIFIED, explanation="Scan-only operation."
        ),
    }
    fields.update(extra)
    return ScanReport.model_validate(fields)


def rendered(**extra: Any) -> str:
    return HTMLReporter().render(report(**extra))


class Collector(HTMLParser):
    """Records what a browser would actually build from the document.

    Substring checks read escaped text as markup — ``onmouseover=&quot;`` looks
    like an event handler to ``in`` and is inert to a parser. Asking the parser
    what elements and attributes exist is the question that matters.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.attributes: list[tuple[str, str, str | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        self.attributes.extend((tag, name, value) for name, value in attrs)

    handle_startendtag = handle_starttag


def parsed(output: str) -> Collector:
    collector = Collector()
    collector.feed(output)
    collector.close()
    return collector


# -- nothing artifact-derived becomes markup -----------------------------------------


def test_a_script_tag_in_a_finding_title_is_not_a_script_tag() -> None:
    output = rendered(findings=(finding(title=PAYLOAD),))

    assert "<script>" not in output
    assert "&lt;script&gt;" in output


def test_a_script_tag_in_a_description_is_not_a_script_tag() -> None:
    output = rendered(findings=(finding(description=PAYLOAD),))

    assert "<script" not in output.lower()


def test_a_path_cannot_close_the_attribute_it_sits_in() -> None:
    """The classic: a quote that escapes an attribute and adds a handler."""

    output = rendered(findings=(finding(artifact_path=ATTRIBUTE_BREAK),))

    handlers = [name for _, name, _ in parsed(output).attributes if name.startswith("on")]

    assert handlers == []
    assert "&quot;" in output


def test_a_detector_id_cannot_inject_an_event_handler() -> None:
    output = rendered(findings=(finding(detector_id=f"x{ATTRIBUTE_BREAK}"),))

    handlers = [name for _, name, _ in parsed(output).attributes if name.startswith("on")]

    assert handlers == []


def test_a_hostile_value_produces_no_element_the_reporter_did_not_write() -> None:
    """The parser's view: every tag in the document is one of ours."""

    output = rendered(
        findings=(
            finding(title=PAYLOAD, description=f"<b>{ATTRIBUTE_BREAK}</b>"),
            finding(id="finding-000000000002", artifact_path=f"<i>{PAYLOAD}</i>"),
        )
    )

    assert set(parsed(output).tags) <= ALLOWED_TAGS


def test_a_diagnostic_message_is_escaped() -> None:
    output = rendered(
        diagnostics=(
            ScanDiagnostic(code="detector_failure", message=PAYLOAD, severity=Severity.HIGH),
        )
    )

    assert "<script" not in output.lower()
    assert "&lt;script&gt;" in output


def test_a_provenance_signer_name_is_escaped() -> None:
    output = rendered(
        provenance_verifications=(
            ProvenanceVerification(
                artifact_path="photo.jpg",
                status=ProvenanceVerificationStatus.VALID,
                verifier="c2pa",
                explanation=PAYLOAD,
                trust_anchors_configured=True,
                signer=ProvenanceSigner(common_name=PAYLOAD),
            ),
        )
    )

    assert "<script" not in output.lower()


def test_an_ampersand_is_not_double_escaped() -> None:
    output = rendered(findings=(finding(title="Tom & Jerry"),))

    assert "Tom &amp; Jerry" in output
    assert "&amp;amp;" not in output


def test_every_angle_bracket_in_the_output_belongs_to_a_tag_we_wrote() -> None:
    """A blunt check that catches an escaping hole anywhere in the document."""

    output = rendered(
        findings=(
            finding(title=PAYLOAD, description=f"<b>{ATTRIBUTE_BREAK}</b>"),
            finding(id="finding-000000000002", artifact_path=f"<i>{PAYLOAD}</i>"),
        )
    )

    tags = {tag.lower() for tag in re.findall(r"<\s*/?\s*([a-zA-Z][a-zA-Z0-9]*)", output)}

    assert tags <= ALLOWED_TAGS, sorted(tags - ALLOWED_TAGS)


# -- the document refers to nothing --------------------------------------------------


def test_the_document_contains_no_script_element() -> None:
    assert "<script" not in rendered().lower()


def test_the_document_has_no_event_handler_attributes() -> None:
    collector = parsed(rendered())

    assert [name for _, name, _ in collector.attributes if name.startswith("on")] == []


def test_no_element_carries_a_url_bearing_attribute() -> None:
    """Nothing to fetch means nothing to fetch from somewhere hostile."""

    collector = parsed(rendered())

    fetching = {"src", "href", "action", "data", "poster", "srcset", "background"}
    assert [name for _, name, _ in collector.attributes if name in fetching] == []


def test_the_document_references_no_external_resource() -> None:
    """It has to open from a USB stick on a machine with no network."""

    output = rendered().lower()

    for forbidden in ("http://", "https://", "<img", "<link", "<iframe", "@import", "url("):
        assert forbidden not in output, forbidden


def test_the_document_declares_a_policy_it_satisfies() -> None:
    output = rendered()

    match = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]*)"', output)

    assert match is not None
    # Entity-encoded quotes are decoded by the HTML parser before the policy is
    # applied, so escaping a constant we control costs nothing and keeps the
    # "one function turns values into markup" rule free of exceptions.
    assert html_module.unescape(match.group(1)) == CONTENT_SECURITY_POLICY
    assert "script-src 'none'" in CONTENT_SECURITY_POLICY
    assert "default-src 'none'" in CONTENT_SECURITY_POLICY


def test_the_stylesheet_is_inline_rather_than_fetched() -> None:
    output = rendered()

    assert "<style>" in output
    assert 'rel="stylesheet"' not in output


# -- it keeps the distinctions the rest of the project keeps -------------------------


def test_findings_are_grouped_by_what_the_confidence_class_claims() -> None:
    output = rendered(
        findings=(
            finding(),
            finding(
                id="finding-000000000002",
                confidence_type=ConfidenceType.HEURISTIC,
                confidence=0.6,
                title="Stylistic signal",
                category=FindingCategory.STYLISTIC_SIGNAL,
            ),
        )
    )

    assert "deterministic (1)" in output
    assert "heuristic (1)" in output
    assert "never evidence of authorship" in output
    assert "does not claim the artifact was AI-generated" in output


def test_a_deterministic_group_appears_before_a_heuristic_one() -> None:
    """A reader should meet the strongest claim first, not last."""

    output = rendered(
        findings=(
            finding(
                id="finding-000000000002",
                confidence_type=ConfidenceType.HEURISTIC,
                confidence=0.6,
            ),
            finding(),
        )
    )

    assert output.index("deterministic (1)") < output.index("heuristic (1)")


def test_provenance_is_four_columns_not_one_badge() -> None:
    output = rendered(
        provenance_verifications=(
            ProvenanceVerification(
                artifact_path="photo.jpg",
                status=ProvenanceVerificationStatus.VALID,
                verifier="c2pa",
                explanation="signature verified",
                trust_anchors_configured=True,
            ),
        )
    )

    for column in ("Marker", "Signature", "Signer trust", "Provider"):
        assert f"<th>{column}</th>" in output


def test_an_unanswered_provenance_question_is_styled_as_unanswered() -> None:
    """Not as a negative result: those are different facts."""

    output = rendered(
        provenance_verifications=(
            ProvenanceVerification(
                artifact_path="photo.jpg",
                status=ProvenanceVerificationStatus.VERIFIER_UNAVAILABLE,
                verifier="c2pa",
                explanation="no verifier installed",
            ),
        )
    )

    assert "tag unknown" in output
    assert "not determined" in output


def test_the_caveats_are_printed_rather_than_left_to_the_reader() -> None:
    output = rendered(
        provenance_verifications=(
            ProvenanceVerification(
                artifact_path="photo.jpg",
                status=ProvenanceVerificationStatus.VALID,
                verifier="c2pa",
                explanation="signature verified",
                trust_anchors_configured=True,
            ),
        )
    )

    assert "What these results do not say" in output
    assert "has not been altered since" in output


def test_diagnostics_bound_what_the_findings_are_evidence_of() -> None:
    output = rendered(
        diagnostics=(
            ScanDiagnostic(
                code="artifact_too_large",
                message="Skipped a 40 MB file.",
                artifact_path="huge.bin",
                severity=Severity.HIGH,
            ),
        )
    )

    assert "Coverage and diagnostics (1)" in output
    assert "did not find it clean" in output
    assert "huge.bin" in output


def test_a_clean_report_says_what_it_actually_checked() -> None:
    output = rendered(findings=())

    assert "No findings within the detector scope that ran" in output
    assert "does not claim the artifact was generated by AI" in output


def test_the_severity_order_puts_the_worst_first() -> None:
    output = rendered(
        findings=(
            finding(id="finding-000000000001", severity=Severity.LOW, title="Low one"),
            finding(id="finding-000000000002", severity=Severity.CRITICAL, title="Critical one"),
        )
    )

    assert output.index("Critical one") < output.index("Low one")


# -- it is stable ---------------------------------------------------------------------


def test_the_same_report_renders_byte_identically() -> None:
    """A report that differs between runs cannot be diffed or attached to a record."""

    subject = report()

    assert HTMLReporter().render(subject) == HTMLReporter().render(subject)


def test_the_document_records_which_scanner_produced_it() -> None:
    subject = report()
    output = HTMLReporter().render(subject)

    assert str(subject.scan_id) in output
    assert subject.package_version in output
    assert subject.schema_version in output


def test_a_custom_title_is_escaped_too() -> None:
    output = HTMLReporter().render(report(), title=PAYLOAD)

    assert "<script" not in output.lower()


def test_writing_produces_utf8_on_disk(tmp_path: Path) -> None:
    target = tmp_path / "report.html"

    HTMLReporter().write(report(findings=(finding(title="Ünïcödé — ✓"),)), target)

    assert "Ünïcödé — ✓" in target.read_text(encoding="utf-8")
    assert target.read_text(encoding="utf-8").startswith("<!doctype html>")


# -- through the command line ---------------------------------------------------------


def test_the_cli_emits_html(tmp_path: Path) -> None:
    target = tmp_path / "note.md"
    target.write_text("Generated with ChatGPT\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(target), "-f", "html"])

    assert "<!doctype html>" in result.output
    assert "Content-Security-Policy" in result.output


def test_the_cli_writes_html_to_a_file(tmp_path: Path) -> None:
    target = tmp_path / "note.md"
    target.write_text("Generated with ChatGPT\n", encoding="utf-8")
    destination = tmp_path / "report.html"

    runner.invoke(app, ["scan", str(target), "-f", "html", "-o", str(destination)])

    assert destination.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_a_hostile_filename_survives_the_whole_pipeline(tmp_path: Path) -> None:
    """End to end: a file whose name is markup, scanned and rendered.

    The characters are the ones a filesystem actually permits — Windows refuses
    ``<`` and ``>`` in a name, so a test using those would prove nothing on the
    platform where it ran.
    """

    target = tmp_path / "note&'quote.md"
    target.write_text("Generated with ChatGPT\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(target), "-f", "html"])

    assert "note&amp;" in result.output
    assert "note&'quote" not in result.output
    assert set(parsed(result.output).tags) <= ALLOWED_TAGS


@pytest.mark.parametrize("payload", [PAYLOAD, ATTRIBUTE_BREAK, "</style><script>x</script>"])
def test_no_payload_reaches_the_output_intact(payload: str) -> None:
    output = rendered(findings=(finding(title=payload, description=payload),))

    assert payload not in output
