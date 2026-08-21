"""Helpers for interpreting confidence without conflating evidence classes."""

from trueai.core.models import ConfidenceType


def confidence_explanation(confidence: float, confidence_type: ConfidenceType) -> str:
    """Return a concise semantic explanation for a confidence pair."""

    percentage = round(confidence * 100)
    explanations = {
        ConfidenceType.DETERMINISTIC: (
            f"Deterministic observation ({percentage}% parser/rule certainty); no authorship claim."
        ),
        ConfidenceType.VERIFIED: (
            f"Verified by an authenticated mechanism ({percentage}% verification confidence)."
        ),
        ConfidenceType.PROBABILISTIC: (
            f"Probabilistic signal ({percentage}% model or statistical confidence)."
        ),
        ConfidenceType.HEURISTIC: (
            f"Heuristic style signal ({percentage}% rule score); not proof of provenance."
        ),
    }
    return explanations[confidence_type]
