import random

from trueai import TrueAIEngine
from trueai.core.artifact import Artifact
from trueai.core.models import FindingCategory, ScanContext, ScanOptions, UnicodeSafetyClass
from trueai.detectors.text.unicode import UnicodeForensicsDetector

#: Ordinary characters mixed with every class the detector can report, so the
#: prefiltered scan and a full character walk have plenty to disagree about.
_MIXED_ALPHABET = "abcdef \n\tXY0123.,;:'\"(){}[]​‌‍⁠ ­ ‎‪⁦﻿\x00\x0b\x85 　Ж漢é"


def _walk_every_character(
    detector: UnicodeForensicsDetector, text: str
) -> list[tuple[int, int, int]]:
    """Classify each character in turn, tracking line and column by hand."""

    located: list[tuple[int, int, int]] = []
    line, column = 1, 1
    for offset, character in enumerate(text):
        if detector._classify(character, offset) is not None:
            located.append((offset, line, column))
        if character == "\n":
            line, column = line + 1, 1
        else:
            column += 1
    return located


def test_candidate_prefilter_matches_a_full_character_walk() -> None:
    """The fast path must report exactly what per-character classification reports."""

    detector = UnicodeForensicsDetector()
    context = ScanContext(options=ScanOptions())
    random.seed(20260821)

    for index in range(25):
        body = "".join(random.choice(_MIXED_ALPHABET) for _ in range(300))
        artifact = Artifact.from_text(body, name=f"case{index}.txt")

        reported = [
            (item.location.offset, item.location.line, item.location.column)
            for item in detector.scan(artifact, context)
            if item.location is not None and item.location.offset is not None
        ]

        assert reported == _walk_every_character(detector, body), f"case {index} diverged"


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
