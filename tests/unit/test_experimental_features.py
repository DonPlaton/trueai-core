from trueai import TrueAIEngine
from trueai.core.artifact import Artifact
from trueai.core.models import ArtifactType, ConfidenceType, FindingCategory, ScanOptions
from trueai.detectors.design.heuristics import DesignStyleFeatureExtractor
from trueai.detectors.text.stylometry import StylometryFeatureExtractor


def test_stylometry_exposes_measurements_before_optional_scoring() -> None:
    features = StylometryFeatureExtractor().extract(
        "# Heading\n\nAlpha beta gamma; alpha beta.\n\n- Item one\n- Item two\n"
    )

    assert features.word_count == 10
    assert features.heading_count == 1
    assert features.list_item_count == 2
    assert features.semicolon_frequency_per_1000_words > 0


def test_design_features_measure_reuse_without_provenance_claim() -> None:
    css = "\n".join(
        f".card-{index} {{ border-radius: 8px; padding: 16px; color: #123456; }}"
        for index in range(8)
    )
    features = DesignStyleFeatureExtractor().extract(css)
    report = TrueAIEngine.default(include_experimental=True).scan(
        Artifact(
            artifact_type=ArtifactType.CSS,
            logical_path="design.css",
            size=len(css.encode("utf-8")),
            media_type="text/css",
            text_content=css,
        ),
        options=ScanOptions(include_experimental=True),
    )

    assert features.border_radius_counts["8px"] == 8
    assert features.spacing_counts["16px"] == 8
    design_findings = [
        finding
        for finding in report.findings
        if finding.category == FindingCategory.DESIGN_STYLE_SIGNAL
    ]
    assert design_findings
    assert design_findings[0].confidence_type == ConfidenceType.HEURISTIC
    assert "not-provenance" in design_findings[0].tags
