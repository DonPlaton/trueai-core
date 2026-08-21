from pathlib import Path

from trueai import TrueAIEngine
from trueai.core.models import FindingCategory, ProvenanceClass


def test_html_reports_metadata_hidden_structure_script_and_data_uri(tmp_path: Path) -> None:
    path = tmp_path / "page.html"
    path.write_text(
        """<!doctype html>
<meta name="generator" content="Example Builder">
<!-- Generated with ChatGPT -->
<div hidden><img src="data:image/png;base64,AA=="></div>
<script>window.example = true;</script>
""",
        encoding="utf-8",
    )

    report = TrueAIEngine.default().scan(path)
    categories = {finding.category for finding in report.findings}

    assert FindingCategory.GENERATOR_METADATA in categories
    assert FindingCategory.GENERATED_COMMENT in categories
    assert FindingCategory.HIDDEN_ELEMENT in categories
    assert FindingCategory.SECURITY_ISSUE in categories
    assert FindingCategory.STRUCTURAL_SIGNAL in categories
    assert all(
        finding.provenance_class != ProvenanceClass.AUTHENTICATED_PROVENANCE
        for finding in report.findings
    )


def test_css_reports_literal_comment_hidden_rule_and_embedded_data(tmp_path: Path) -> None:
    path = tmp_path / "styles.css"
    path.write_text(
        """/* Generated with Claude */
.hidden { display: none; }
.icon { background: url(data:image/svg+xml;base64,AA==); }
""",
        encoding="utf-8",
    )

    report = TrueAIEngine.default().scan(path)
    categories = {finding.category for finding in report.findings}

    assert FindingCategory.GENERATED_COMMENT in categories
    assert FindingCategory.HIDDEN_ELEMENT in categories
    assert FindingCategory.STRUCTURAL_SIGNAL in categories


def test_css_comment_syntax_inside_string_is_not_a_comment(tmp_path: Path) -> None:
    path = tmp_path / "strings.css"
    original = '.label::before { content: "/* Generated with ChatGPT */"; }\n'
    path.write_text(original, encoding="utf-8")

    report = TrueAIEngine.default().scan(path)

    assert not [
        finding
        for finding in report.findings
        if finding.category == FindingCategory.GENERATED_COMMENT
    ]
    assert path.read_text(encoding="utf-8") == original
