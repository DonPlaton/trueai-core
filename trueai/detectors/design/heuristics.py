"""Measurable design features and replaceable experimental heuristic model."""

from __future__ import annotations

import re
from collections import Counter

from pydantic import BaseModel, ConfigDict, Field

from trueai.core.artifact import Artifact
from trueai.core.models import (
    ArtifactType,
    ConfidenceType,
    EvidenceType,
    Finding,
    FindingCategory,
    ProvenanceClass,
    ScanContext,
    Severity,
)
from trueai.detectors.base import BaseDetector


class DesignFeatureVector(BaseModel):
    """Provider-neutral measurements for HTML/CSS/SVG design systems."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    border_radius_counts: dict[str, int] = Field(default_factory=dict)
    spacing_counts: dict[str, int] = Field(default_factory=dict)
    color_counts: dict[str, int] = Field(default_factory=dict)
    gradient_count: int = 0
    shadow_counts: dict[str, int] = Field(default_factory=dict)
    typography_size_counts: dict[str, int] = Field(default_factory=dict)
    duplicated_path_groups: int = 0
    distinct_spacing_values: int = 0
    distinct_colors: int = 0


class DesignStyleFeatureExtractor:
    """Extract repeatable design measurements without making provenance claims."""

    _DECLARATION = re.compile(r"(?i)([\w-]+)\s*:\s*([^;}{]+)")

    def extract(self, text: str) -> DesignFeatureVector:
        """Extract CSS-like and SVG path features from bounded text."""

        radius: Counter[str] = Counter()
        spacing: Counter[str] = Counter()
        colors: Counter[str] = Counter()
        shadows: Counter[str] = Counter()
        font_sizes: Counter[str] = Counter()
        gradients = 0
        for match in self._DECLARATION.finditer(text):
            name = match.group(1).casefold()
            value = " ".join(match.group(2).split()).casefold()
            if name == "border-radius":
                radius[value] += 1
            if name in {"margin", "padding", "gap", "row-gap", "column-gap"}:
                for number in re.findall(r"[-+]?\d+(?:\.\d+)?(?:px|rem|em|%)", value):
                    spacing[number] += 1
            for color in re.findall(r"#[0-9a-f]{3,8}\b|rgba?\([^)]*\)|hsla?\([^)]*\)", value):
                colors[color] += 1
            if "gradient(" in value:
                gradients += 1
            if name in {"box-shadow", "filter"} and ("shadow" in name or "drop-shadow" in value):
                shadows[value] += 1
            if name == "font-size":
                font_sizes[value] += 1
        path_counts = Counter(re.findall(r"(?is)<path\b[^>]*\bd=['\"]([^'\"]+)['\"]", text))
        return DesignFeatureVector(
            border_radius_counts=dict(radius),
            spacing_counts=dict(spacing),
            color_counts=dict(colors),
            gradient_count=gradients,
            shadow_counts=dict(shadows),
            typography_size_counts=dict(font_sizes),
            duplicated_path_groups=sum(1 for count in path_counts.values() if count > 1),
            distinct_spacing_values=len(spacing),
            distinct_colors=len(colors),
        )


class ExperimentalDesignHeuristicModel:
    """Optional interpretable scoring layer; output is never provenance."""

    def score(self, features: DesignFeatureVector) -> tuple[float, tuple[str, ...]]:
        """Return a bounded regularity score and human-readable contributing features."""

        components: list[float] = []
        reasons: list[str] = []
        repeated_radius = sum(
            count for count in features.border_radius_counts.values() if count >= 3
        )
        if repeated_radius:
            components.append(min(repeated_radius / 20, 1.0))
            reasons.append(f"{repeated_radius} repeated border-radius declarations")
        repeated_spacing = sum(count for count in features.spacing_counts.values() if count >= 4)
        if repeated_spacing:
            components.append(min(repeated_spacing / 30, 1.0))
            reasons.append(f"{repeated_spacing} repeated spacing tokens")
        if features.duplicated_path_groups:
            components.append(min(features.duplicated_path_groups / 10, 1.0))
            reasons.append(f"{features.duplicated_path_groups} duplicated SVG path groups")
        if not components:
            return 0.0, ()
        return sum(components) / len(components), tuple(reasons)


class DesignStyleDetector(BaseDetector):
    """Experimental feature consumer that explicitly avoids provenance claims."""

    id = "design.style-experimental.v1"
    supported_types = frozenset({ArtifactType.HTML, ArtifactType.CSS, ArtifactType.SVG})
    categories = frozenset({FindingCategory.DESIGN_STYLE_SIGNAL})
    experimental = True

    def __init__(self) -> None:
        self.extractor = DesignStyleFeatureExtractor()
        self.model = ExperimentalDesignHeuristicModel()

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        text = artifact.read_text(context.options.max_file_size)
        features = self.extractor.extract(text)
        score, reasons = self.model.score(features)
        if score < 0.25:
            return []
        return [
            self.finding(
                artifact=artifact,
                category=FindingCategory.DESIGN_STYLE_SIGNAL,
                confidence=score,
                confidence_type=ConfidenceType.HEURISTIC,
                severity=Severity.INFO,
                evidence_type=EvidenceType.STATISTICAL,
                title="DESIGN STYLE SIGNAL — NOT PROVENANCE",
                description=(
                    "Repeated design-system measurements crossed an experimental regularity "
                    "threshold. This does not identify the author or generating tool."
                ),
                evidence={
                    "features": features.model_dump(mode="json"),
                    "contributing_signals": list(reasons),
                    "model": "transparent-design-heuristic-v1",
                },
                provenance_class=ProvenanceClass.HEURISTIC,
                tags=("design", "experimental", "heuristic", "not-provenance"),
            )
        ]
