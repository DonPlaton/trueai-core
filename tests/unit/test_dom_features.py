"""DOM topology and stylesheet features: measurements, bounded, and not verdicts.

Two things are under test and the second matters as much as the first. The
measurements have to be right, and they have to stay measurements — a count that
acquires a threshold becomes a claim about authorship, which is the error this
project exists to avoid making.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from trueai.core.artifact import Artifact
from trueai.core.dom_features import (
    FeatureBudget,
    FeatureLimitExceeded,
    extract_dom_topology,
    extract_stylesheet_features,
    selector_specificity,
)
from trueai.core.models import (
    ArtifactType,
    ConfidenceType,
    FindingCategory,
    ProvenanceClass,
    ScanContext,
    ScanOptions,
    Severity,
)

PAGE = """<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Example</title>
    <link rel="stylesheet" href="/site.css">
  </head>
  <body>
    <div class="wrapper outer">
      <div class="inner">
        <p id="lead" style="color: red">Some visible text.</p>
        <p id="lead">A duplicate identifier.</p>
      </div>
    </div>
    <!-- a comment -->
    <script>var noise = "not document text at all, and quite long";</script>
  </body>
</html>
"""

STYLESHEET = """
/* a comment */
@media screen and (min-width: 40em) {
  .a { color: red; }
}
#main .row > .cell:hover { padding: 1px !important; -webkit-box-shadow: none; }
.a { color: blue; }
.a { color: green; }
:root { --brand: #123456; }
.icon { background: url(data:image/png;base64,AAAA); }
"""


# -- HTML topology --------------------------------------------------------------------


def test_the_element_count_and_depth_are_measured() -> None:
    topology = extract_dom_topology(PAGE)

    assert topology.complete, topology.truncated_by
    assert topology.elements == 11
    assert topology.max_depth >= 4
    assert topology.tag_histogram["div"] == 2


def test_void_elements_are_not_counted_as_unclosed() -> None:
    """Otherwise every ordinary document would report itself malformed."""

    topology = extract_dom_topology(PAGE)

    assert topology.void_elements >= 2
    assert topology.unclosed_elements == 0


def test_a_genuinely_unclosed_element_is_counted() -> None:
    topology = extract_dom_topology("<div><span>text")

    assert topology.unclosed_elements == 2


def test_a_close_with_no_open_is_counted_separately() -> None:
    """A stray close and an unclosed open are different shapes, not one error."""

    topology = extract_dom_topology("<div>text</div></span>")

    assert topology.mismatched_closes == 1
    assert topology.unclosed_elements == 0


def test_duplicate_identifiers_are_counted() -> None:
    topology = extract_dom_topology(PAGE)

    assert topology.distinct_ids == 1
    assert topology.duplicate_ids == 1


def test_class_tokens_are_counted_by_token_not_by_attribute() -> None:
    topology = extract_dom_topology(PAGE)

    assert topology.class_tokens == 3
    assert topology.distinct_class_tokens == 3


def test_wrapper_only_elements_are_counted() -> None:
    """An element whose only child is one element and which holds no text."""

    topology = extract_dom_topology("<div><section><p>text</p></section></div>")

    assert topology.wrapper_only_elements == 2


def test_an_element_with_text_is_not_a_wrapper() -> None:
    topology = extract_dom_topology("<div>text<span>more</span></div>")

    assert topology.wrapper_only_elements == 0


def test_script_bodies_are_not_counted_as_document_text() -> None:
    """A page with one large bundle must not look text-heavy."""

    topology = extract_dom_topology(PAGE)

    assert "not document text at all" not in str(topology.text_characters)
    plain = extract_dom_topology("<p>Some visible text.</p>")
    assert topology.text_characters < plain.text_characters + 60


def test_inline_styles_and_external_references_are_counted() -> None:
    topology = extract_dom_topology(PAGE)

    assert topology.inline_styles == 1
    assert topology.external_references == 1


def test_a_fragment_reference_is_not_external() -> None:
    topology = extract_dom_topology('<a href="#section">jump</a>')

    assert topology.external_references == 0


def test_a_data_uri_is_not_an_external_reference() -> None:
    topology = extract_dom_topology('<img src="data:image/png;base64,AAAA">')

    assert topology.external_references == 0


def test_an_empty_document_measures_zero_rather_than_failing() -> None:
    topology = extract_dom_topology("")

    assert topology.elements == 0
    assert topology.complete


# -- the measurements stay measurements -----------------------------------------------


def test_the_topology_carries_no_score_or_verdict() -> None:
    """The guard on the whole module: counts, never conclusions."""

    topology = extract_dom_topology(PAGE)
    evidence = topology.as_evidence()

    for key in evidence:
        assert not any(
            word in key.lower()
            for word in ("score", "likelihood", "probability", "generated", "ai", "human")
        ), key
    assert all(isinstance(value, (int, bool)) for value in evidence.values())


def test_the_stylesheet_features_carry_no_score_or_verdict() -> None:
    features = extract_stylesheet_features(STYLESHEET)
    evidence = features.as_evidence()

    for key in evidence:
        assert not any(
            word in key.lower()
            for word in ("score", "likelihood", "probability", "generated", "ai", "human")
        ), key
    assert all(isinstance(value, (int, bool)) for value in evidence.values())


# -- budgets --------------------------------------------------------------------------


def test_too_many_elements_stops_the_walk_and_says_so() -> None:
    """A partial measurement is useful. A partial measurement presented as whole is not."""

    topology = extract_dom_topology("<div>" * 100, FeatureBudget(max_nodes=10, max_depth=1000))

    assert not topology.complete
    assert "10 elements" in (topology.truncated_by or "")
    assert topology.elements == 10


def test_deep_nesting_stops_the_walk() -> None:
    topology = extract_dom_topology("<div>" * 100, FeatureBudget(max_depth=8))

    assert not topology.complete
    assert "deeper than 8" in (topology.truncated_by or "")


def test_a_parser_event_budget_stops_the_walk() -> None:
    topology = extract_dom_topology(PAGE, FeatureBudget(max_events=3))

    assert not topology.complete
    assert "parser events" in (topology.truncated_by or "")


def test_retained_bytes_are_bounded() -> None:
    """Bytes the extractor keeps, not bytes it passes over."""

    document = "".join(f'<div class="{"x" * 200}">' for _ in range(200))

    topology = extract_dom_topology(document, FeatureBudget(max_retained_bytes=1024))

    assert not topology.complete
    assert "Retained more than" in (topology.truncated_by or "")


def test_a_budget_exhaustion_returns_partial_measurements() -> None:
    """ "As far as N elements, it looks like this" beats an exception."""

    topology = extract_dom_topology("<div>" * 50, FeatureBudget(max_nodes=5, max_depth=1000))

    assert topology.elements == 5
    assert topology.max_depth == 5


def test_the_budget_type_is_raised_directly_when_charged() -> None:
    budget = FeatureBudget(max_nodes=1)
    budget.charge_node()

    with pytest.raises(FeatureLimitExceeded):
        budget.charge_node()


# -- stylesheet features ---------------------------------------------------------------


def test_rules_selectors_and_declarations_are_counted() -> None:
    features = extract_stylesheet_features(STYLESHEET)

    assert features.complete, features.truncated_by
    assert features.rules >= 6
    assert features.selectors >= 6
    assert features.declarations >= 6


def test_important_and_vendor_prefixes_are_counted() -> None:
    features = extract_stylesheet_features(STYLESHEET)

    assert features.important_declarations == 1
    assert features.vendor_prefixed_properties == 1


def test_custom_properties_and_data_uris_are_counted() -> None:
    features = extract_stylesheet_features(STYLESHEET)

    assert features.custom_properties == 1
    assert features.embedded_data_uris == 1


def test_duplicate_selectors_are_counted() -> None:
    features = extract_stylesheet_features(STYLESHEET)

    assert features.duplicate_selectors == 1


def test_at_rules_are_counted_by_name() -> None:
    features = extract_stylesheet_features(STYLESHEET)

    assert features.at_rules.get("media") == 1


def test_an_at_rule_prelude_is_not_counted_as_a_selector() -> None:
    """`@media screen and (min-width: 40em)` is not a selector list."""

    features = extract_stylesheet_features("@media screen { .a { color: red; } }")

    assert features.selectors == 1


def test_specificity_follows_the_cascade_definition() -> None:
    """A reader comparing stylesheets needs the number the browser would use."""

    assert selector_specificity("#main") == (1, 0, 0)
    assert selector_specificity(".row") == (0, 1, 0)
    assert selector_specificity("div") == (0, 0, 1)
    assert selector_specificity("#main .row > div:hover") == (1, 2, 1)
    assert selector_specificity('a[href^="http"]') == (0, 1, 1)


def test_the_specificity_histogram_is_populated() -> None:
    features = extract_stylesheet_features(STYLESHEET)

    assert features.specificity_histogram
    assert sum(features.specificity_histogram.values()) == features.selectors


def test_comments_are_counted_and_not_parsed_as_rules() -> None:
    features = extract_stylesheet_features("/* { a: b; } */ .x { color: red; }")

    assert features.comments == 1
    assert features.rules == 1


def test_a_rule_budget_stops_the_scan_and_says_so() -> None:
    stylesheet = ".a { color: red; }" * 100

    features = extract_stylesheet_features(stylesheet, FeatureBudget(max_rules=5))

    assert not features.complete
    assert "5 rules" in (features.truncated_by or "")


def test_an_unclosed_brace_does_not_hang_the_scan() -> None:
    features = extract_stylesheet_features(".a { color: red;")

    assert features.rules == 0
    assert features.complete


def test_an_empty_stylesheet_measures_zero() -> None:
    features = extract_stylesheet_features("")

    assert features.rules == 0
    assert features.complete


# -- the detectors report them ---------------------------------------------------------


def scan_html(text: str, tmp_path: Path):
    from trueai.detectors.web.html import HTMLDetector

    path = tmp_path / "page.html"
    path.write_text(text, encoding="utf-8")
    artifact = Artifact(artifact_type=ArtifactType.HTML, path=path, logical_path=path.name)
    return HTMLDetector().scan(artifact, ScanContext(options=ScanOptions()))


def scan_css(text: str, tmp_path: Path):
    from trueai.detectors.web.css import CSSDetector

    path = tmp_path / "site.css"
    path.write_text(text, encoding="utf-8")
    artifact = Artifact(artifact_type=ArtifactType.CSS, path=path, logical_path=path.name)
    return CSSDetector().scan(artifact, ScanContext(options=ScanOptions()))


def test_the_html_detector_reports_topology(tmp_path: Path) -> None:
    findings = scan_html(PAGE, tmp_path)

    topology = [item for item in findings if item.title == "HTML document topology"]
    assert topology
    assert topology[0].evidence["elements"] == 11


def test_the_topology_finding_is_not_provenance(tmp_path: Path) -> None:
    """A structural signal presented as provenance is the error being avoided."""

    finding = next(
        item for item in scan_html(PAGE, tmp_path) if item.title == "HTML document topology"
    )

    assert finding.provenance_class == ProvenanceClass.NONE
    assert finding.category == FindingCategory.STRUCTURAL_SIGNAL
    assert finding.severity == Severity.INFO
    assert finding.confidence_type == ConfidenceType.DETERMINISTIC
    assert not finding.removable
    assert finding.remediation_id is None
    assert "not evidence of authorship" in finding.description


def test_the_css_detector_reports_features(tmp_path: Path) -> None:
    findings = scan_css(STYLESHEET, tmp_path)

    features = [item for item in findings if item.title == "Stylesheet feature summary"]
    assert features
    assert features[0].evidence["important_declarations"] == 1


def test_the_feature_finding_is_not_provenance(tmp_path: Path) -> None:
    finding = next(
        item
        for item in scan_css(STYLESHEET, tmp_path)
        if item.title == "Stylesheet feature summary"
    )

    assert finding.provenance_class == ProvenanceClass.NONE
    assert finding.severity == Severity.INFO
    assert not finding.removable
    assert "not evidence of authorship" in finding.description


def test_a_document_with_no_elements_produces_no_topology_finding(tmp_path: Path) -> None:
    """Reporting a topology of nothing would be noise, not information."""

    findings = scan_html("just some text\n", tmp_path)

    assert not [item for item in findings if item.title == "HTML document topology"]
