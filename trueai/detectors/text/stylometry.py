"""Conservative non-ML stylometry features and replaceable experimental model."""

from __future__ import annotations

import math
import re
from collections import Counter
from statistics import fmean, pstdev

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

_TRANSITIONS = (
    "moreover",
    "furthermore",
    "in addition",
    "however",
    "therefore",
    "consequently",
    "on the other hand",
    "in conclusion",
)


class StylometryFeatureVector(BaseModel):
    """Measured text features before any experimental score."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    character_count: int
    word_count: int
    sentence_count: int
    paragraph_count: int
    mean_sentence_words: float
    sentence_word_stddev: float
    mean_paragraph_words: float
    paragraph_word_stddev: float
    lexical_diversity: float
    em_dash_frequency_per_1000_words: float
    semicolon_frequency_per_1000_words: float
    heading_count: int
    list_item_count: int
    list_density: float
    transition_counts: dict[str, int] = Field(default_factory=dict)
    repeated_fourgram_count: int
    paragraph_symmetry: float


class StylometryFeatureExtractor:
    """Extract language-agnostic approximations without claiming authorship."""

    def extract(self, text: str) -> StylometryFeatureVector:
        words = re.findall(r"[^\W_]+(?:['’][^\W_]+)?", text.casefold(), flags=re.UNICODE)
        sentences = [
            item for item in re.split(r"(?<=[.!?])(?:[\"'”’)]*)\s+", text.strip()) if item.strip()
        ]
        paragraphs = [item for item in re.split(r"\r?\n\s*\r?\n", text) if item.strip()]
        sentence_lengths = [len(re.findall(r"[^\W_]+", sentence)) for sentence in sentences]
        paragraph_lengths = [len(re.findall(r"[^\W_]+", paragraph)) for paragraph in paragraphs]
        word_count = len(words)
        unique_words = len(set(words))
        transitions = {
            phrase: len(re.findall(rf"\b{re.escape(phrase)}\b", text, flags=re.IGNORECASE))
            for phrase in _TRANSITIONS
        }
        transitions = {key: value for key, value in transitions.items() if value}
        fourgrams = Counter(
            tuple(words[index : index + 4]) for index in range(max(0, word_count - 3))
        )
        paragraph_mean = fmean(paragraph_lengths) if paragraph_lengths else 0.0
        paragraph_stddev = pstdev(paragraph_lengths) if len(paragraph_lengths) > 1 else 0.0
        symmetry = max(0.0, 1.0 - paragraph_stddev / paragraph_mean) if paragraph_mean else 0.0
        heading_count = len(re.findall(r"(?m)^#{1,6}\s+\S", text))
        list_item_count = len(re.findall(r"(?m)^\s*(?:[-*+] |\d+[.)] )", text))
        return StylometryFeatureVector(
            character_count=len(text),
            word_count=word_count,
            sentence_count=len(sentences),
            paragraph_count=len(paragraphs),
            mean_sentence_words=fmean(sentence_lengths) if sentence_lengths else 0.0,
            sentence_word_stddev=pstdev(sentence_lengths) if len(sentence_lengths) > 1 else 0.0,
            mean_paragraph_words=paragraph_mean,
            paragraph_word_stddev=paragraph_stddev,
            lexical_diversity=unique_words / word_count if word_count else 0.0,
            em_dash_frequency_per_1000_words=text.count("—") * 1000 / max(word_count, 1),
            semicolon_frequency_per_1000_words=text.count(";") * 1000 / max(word_count, 1),
            heading_count=heading_count,
            list_item_count=list_item_count,
            list_density=list_item_count / max(len(text.splitlines()), 1),
            transition_counts=transitions,
            repeated_fourgram_count=sum(1 for count in fourgrams.values() if count >= 3),
            paragraph_symmetry=symmetry,
        )


class ExperimentalStylometryHeuristicModel:
    """Replaceable transparent score over measured features."""

    def score(self, features: StylometryFeatureVector) -> tuple[float, tuple[str, ...]]:
        """Return an interpretable repetition/regularity score, not an AI probability."""

        components: list[float] = []
        reasons: list[str] = []
        transition_repetition = sum(
            max(0, count - 2) for count in features.transition_counts.values()
        )
        if transition_repetition:
            components.append(min(transition_repetition / 8, 1.0))
            reasons.append("repeated transition phrases")
        if features.repeated_fourgram_count:
            components.append(min(features.repeated_fourgram_count / 12, 1.0))
            reasons.append("repeated four-word constructions")
        if features.paragraph_count >= 4 and features.paragraph_symmetry > 0.82:
            components.append((features.paragraph_symmetry - 0.82) / 0.18)
            reasons.append("high paragraph-length symmetry")
        if not components:
            return 0.0, ()
        return min(1.0, math.fsum(components) / len(components)), tuple(reasons)


class StylometryDetector(BaseDetector):
    """Experimental finding layer over feature measurements."""

    id = "text.stylometry-experimental.v1"
    supported_types = frozenset({ArtifactType.TEXT, ArtifactType.MARKDOWN})
    categories = frozenset({FindingCategory.STYLISTIC_SIGNAL})
    experimental = True

    def __init__(self) -> None:
        self.extractor = StylometryFeatureExtractor()
        self.model = ExperimentalStylometryHeuristicModel()

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        text = artifact.read_text(context.options.max_file_size)
        features = self.extractor.extract(text)
        if features.word_count < 200:
            return []
        score, reasons = self.model.score(features)
        if score < 0.25:
            return []
        return [
            self.finding(
                artifact=artifact,
                category=FindingCategory.STYLISTIC_SIGNAL,
                confidence=score,
                confidence_type=ConfidenceType.HEURISTIC,
                severity=Severity.INFO,
                evidence_type=EvidenceType.STATISTICAL,
                title="Experimental repetitive style signal — not provenance",
                description=(
                    "Measured regularities crossed an experimental reporting threshold. The score "
                    "is not a probability of AI authorship and must not be used as provenance."
                ),
                evidence={
                    "features": features.model_dump(mode="json"),
                    "contributing_signals": list(reasons),
                    "model": "transparent-heuristic-v1",
                },
                provenance_class=ProvenanceClass.HEURISTIC,
                tags=("stylometry", "experimental", "heuristic", "not-provenance"),
            )
        ]
