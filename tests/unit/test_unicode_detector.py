from trueai import TrueAIEngine
from trueai.core.models import FindingCategory, UnicodeSafetyClass


def test_unicode_detector_reports_precise_location_and_context() -> None:
    report = TrueAIEngine.default().scan_text("alpha\nbe\u200btа")
    finding = next(
        item for item in report.findings if item.category == FindingCategory.INVISIBLE_UNICODE
    )

    assert finding.evidence["code_point"] == "U+200B"
    assert finding.evidence["unicode_name"] == "ZERO WIDTH SPACE"
    assert finding.evidence["safety_class"] == UnicodeSafetyClass.INVISIBLE.value
    assert finding.location is not None
    assert finding.location.line == 2
    assert finding.location.column == 3
    assert finding.removable is True
    assert "⟦U+200B⟧" in str(finding.evidence["context"])


def test_semantic_joiners_and_variation_selectors_are_not_auto_removable() -> None:
    report = TrueAIEngine.default().scan_text("a\u200db\ufe0f c\u200cd")
    findings = [
        item for item in report.findings if item.category == FindingCategory.INVISIBLE_UNICODE
    ]

    assert len(findings) == 3
    assert all(item.removable is False for item in findings)
    assert all(item.remediation_id is None for item in findings)


def test_leading_bom_is_reported_as_safe_encoding_metadata() -> None:
    report = TrueAIEngine.default().scan_text("\ufeffVisible")
    finding = report.findings[0]

    assert finding.evidence["safety_class"] == UnicodeSafetyClass.SAFE.value
    assert finding.removable is False
