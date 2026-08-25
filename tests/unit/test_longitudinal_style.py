"""A style comparison that stays a question.

The thing being guarded is not a metric. It is that this module never becomes a
verdict, never becomes a probability, and never ships a ready-made objective
function for making a document look like someone else's.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trueai.research import (
    BaselineDocument,
    FeatureSet,
    LongitudinalError,
    ShiftBand,
    StyleBaseline,
    StyleComparison,
    build_vector,
    compare,
)

NOW = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)

SET = FeatureSet(version="1", names=("burstiness", "clause_depth", "rare_word_share"))
OTHER_SET = FeatureSet(version="2", names=("burstiness", "clause_depth"))


def vector(
    values: tuple[float, float, float], *, feature_set: FeatureSet = SET, path: str = "d.md"
):
    return build_vector(
        feature_set, dict(zip(feature_set.names, values, strict=True)), artifact_path=path
    )


def baseline(
    *,
    count: int = 12,
    span_days: int = 200,
    spread: float = 0.05,
    genre: str | None = None,
) -> StyleBaseline:
    documents = tuple(
        BaselineDocument(
            vector=vector(
                (0.5 + spread * (index % 3 - 1), 0.4 + spread * (index % 2), 0.3),
                path=f"past{index}.md",
            ),
            written_at=NOW - timedelta(days=span_days * index // max(count - 1, 1)),
        )
        for index in range(count)
    )
    return StyleBaseline(feature_set=SET, documents=documents, genre=genre)


# -- it produces no verdict -----------------------------------------------------------


def test_a_comparison_has_no_authorship_field() -> None:
    """The fields that would let a caller manufacture a verdict are absent."""

    result = compare(vector((0.5, 0.4, 0.3)), baseline())

    for forbidden in ("same_author", "different_author", "probability", "is_ai", "verdict"):
        assert not hasattr(result, forbidden)


def test_a_comparison_states_what_it_is_not() -> None:
    limits = compare(vector((0.5, 0.4, 0.3)), baseline()).what_this_is_not()

    joined = " ".join(limits)
    assert "not evidence that a different person wrote" in joined
    assert "not a probability" in joined
    assert "ask the writer a question" in joined


def test_every_comparison_carries_the_other_explanations() -> None:
    """A caveat that lives in documentation does not travel with the number."""

    result = compare(vector((3.0, 3.0, 3.0)), baseline())

    joined = " ".join(result.alternative_explanations)
    assert "co-author" in joined
    assert "second language" in joined
    assert "different topic" in joined


def test_the_explanations_are_present_even_on_a_marked_shift() -> None:
    result = compare(vector((9.0, 9.0, 9.0)), baseline())

    assert result.band is ShiftBand.MARKED
    assert result.alternative_explanations


# -- an insufficient baseline yields no number ----------------------------------------


def test_too_few_documents_produce_no_measurement() -> None:
    """A number attached to an insufficient baseline gets quoted without the caveat."""

    result = compare(vector((0.9, 0.9, 0.9)), baseline(count=4))

    assert result.band is ShiftBand.UNDETERMINED
    assert result.sigma is None
    assert any("documents" in item for item in result.insufficiency)


def test_too_short_a_span_produces_no_measurement() -> None:
    """Three documents from one week describe a mood, not a style."""

    result = compare(vector((0.9, 0.9, 0.9)), baseline(span_days=5))

    assert result.band is ShiftBand.UNDETERMINED
    assert any("spans" in item for item in result.insufficiency)


def test_a_baseline_with_no_variability_produces_no_measurement() -> None:
    result = compare(vector((0.9, 0.9, 0.9)), baseline(spread=0.0))

    assert result.band is ShiftBand.UNDETERMINED
    assert any("no variability" in item for item in result.insufficiency)


def test_undetermined_is_described_as_an_absence_not_as_no_change() -> None:
    described = compare(vector((0.9, 0.9, 0.9)), baseline(count=3)).describe()

    assert "absence of measurement, not a finding of no change" in described


def test_an_unmeasured_comparison_says_it_was_not_measured() -> None:
    result = compare(vector((0.9, 0.9, 0.9)), baseline(count=3))

    assert not result.measured


# -- distance is relative to the writer's own variability ----------------------------


def test_a_document_inside_the_usual_range_is_within_variation() -> None:
    result = compare(vector((0.5, 0.42, 0.3)), baseline())

    assert result.band is ShiftBand.WITHIN_VARIATION
    assert "inside what this writer's work already varies by" in result.describe()


def test_a_document_well_outside_the_range_is_marked() -> None:
    result = compare(vector((2.0, 2.0, 0.3)), baseline())

    assert result.band is ShiftBand.MARKED
    assert result.sigma is not None and result.sigma >= 3.5


def test_a_consistent_writer_is_not_penalised_for_being_consistent() -> None:
    """A fixed threshold would flag the consistent and excuse the erratic."""

    tight = compare(vector((0.6, 0.4, 0.3)), baseline(spread=0.02))
    loose = compare(vector((0.6, 0.4, 0.3)), baseline(spread=0.30))

    assert tight.sigma is not None and loose.sigma is not None
    assert tight.sigma > loose.sigma


def test_a_feature_with_no_variability_is_skipped_rather_than_dividing_by_zero() -> None:
    """The third feature is constant across the baseline in every fixture here."""

    result = compare(vector((0.5, 0.4, 99.0)), baseline())

    assert result.sigma is not None
    assert result.band is ShiftBand.WITHIN_VARIATION


# -- feature deltas are not offered by default ----------------------------------------


def test_per_feature_deltas_are_absent_unless_asked_for() -> None:
    """ "Which feature moved and by how much" is a recipe for moving it back."""

    result = compare(vector((2.0, 2.0, 0.3)), baseline())

    assert result.feature_deltas is None
    assert not result.feature_deltas_requested


def test_asking_for_deltas_is_recorded_in_the_result() -> None:
    """A report can show that somebody asked."""

    result = compare(vector((2.0, 2.0, 0.3)), baseline(), include_feature_deltas=True)

    assert result.feature_deltas is not None
    assert result.feature_deltas_requested
    assert set(result.feature_deltas) <= set(SET.names)


def test_the_request_is_recorded_even_when_nothing_could_be_measured() -> None:
    result = compare(vector((2.0, 2.0, 0.3)), baseline(count=3), include_feature_deltas=True)

    assert result.feature_deltas is None
    assert result.feature_deltas_requested


# -- genre is the dominant confound ---------------------------------------------------


def test_crossing_a_declared_genre_boundary_is_flagged() -> None:
    """A register change moves style more than most other causes."""

    result = compare(vector((0.5, 0.4, 0.3)), baseline(genre="email"), genre="legal-brief")

    assert result.cross_genre
    assert any("register change" in item for item in result.notes)
    assert "crossed a declared genre boundary" in result.describe()


def test_the_same_genre_is_not_flagged() -> None:
    result = compare(vector((0.5, 0.4, 0.3)), baseline(genre="email"), genre="email")

    assert not result.cross_genre


def test_an_undeclared_genre_is_not_guessed_at() -> None:
    result = compare(vector((0.5, 0.4, 0.3)), baseline())

    assert not result.cross_genre


# -- the feature set has to line up ---------------------------------------------------


def test_comparing_across_feature_sets_is_refused() -> None:
    with pytest.raises(LongitudinalError, match="do not mean the same thing"):
        compare(vector((0.5, 0.4), feature_set=OTHER_SET), baseline())


def test_a_baseline_document_from_another_feature_set_is_refused() -> None:
    mixed = StyleBaseline(
        feature_set=SET,
        documents=(
            *baseline().documents,
            BaselineDocument(vector=vector((0.5, 0.4), feature_set=OTHER_SET), written_at=NOW),
        ),
    )

    with pytest.raises(LongitudinalError, match="different feature set"):
        compare(vector((0.5, 0.4, 0.3)), mixed)


def test_an_empty_baseline_is_refused() -> None:
    with pytest.raises(LongitudinalError, match="needs a baseline"):
        compare(vector((0.5, 0.4, 0.3)), StyleBaseline(feature_set=SET, documents=()))


def test_a_baseline_date_needs_an_offset() -> None:
    with pytest.raises(ValueError, match="UTC offset"):
        BaselineDocument(vector=vector((0.5, 0.4, 0.3)), written_at=datetime(2026, 1, 1))


# -- the module keeps its promise about what it is ------------------------------------


def test_the_module_defines_no_authorship_conclusion_anywhere() -> None:
    """A blunt check on the source: the vocabulary of a verdict is not in it."""

    source = (
        Path(__file__).resolve().parents[2] / "trueai" / "research" / "longitudinal.py"
    ).read_text(encoding="utf-8")
    tree = ast.parse(source)

    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
        elif isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names.add(node.name)

    forbidden = {"same_author", "different_author", "authorship_probability", "is_ai", "verdict"}
    assert names & forbidden == set()


def test_the_bands_are_coarse_because_a_score_invites_a_threshold() -> None:
    assert len([band for band in ShiftBand if band is not ShiftBand.UNDETERMINED]) == 3


def test_a_comparison_can_be_rendered_without_reading_the_sigma() -> None:
    """An interface should be able to show the band and the limits and stop."""

    result: StyleComparison = compare(vector((2.0, 2.0, 0.3)), baseline())

    assert result.band.value in {"within_variation", "notable", "marked"}
    assert result.what_this_is_not()
