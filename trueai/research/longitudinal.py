"""Comparing a writer's style against their own past — as a question, not a verdict.

Somebody's writing changes.  A document sits further from their previous work
than their previous work sits from itself.  That is worth asking about, and it
is worth asking about **as a question put to a person**, because the list of
things that move a writer's style is long and almost none of the entries are
"someone else wrote this":

a new topic, a new genre, a co-author, an editor, a template, a house style, a
translation, a decade of practice, a deadline, grief, a different keyboard.

So this module produces no verdict.  There is no ``same_author`` field, no
probability that a document is someone else's, and no score to threshold —
:meth:`StyleComparison.what_this_is_not` exists to be printed next to whatever
an interface shows.  A style comparison is a **review aid**: it tells a reader
where to look, and the looking is done by the reader.

Three things follow.

**A comparison needs a baseline worth comparing to.**  Three documents from one
week describe a mood, not a style.  Below a floor of documents and of elapsed
time the result is ``UNDETERMINED`` and carries no distance at all, because a
number attached to an insufficient baseline gets quoted without the word
"insufficient".

**Distance is measured against the author's own variability.**  A writer whose
work varies widely has to move further before it means anything.  A fixed
threshold across writers penalises the consistent ones and excuses the erratic.

**Per-feature deltas are not returned by default.**  "Which feature moved, and by
how much" is a recipe for moving it back, and that is the one use this project
will not make convenient.  It is available behind an explicit flag for debugging
a detector, and the flag is recorded in the result so a report shows it was
asked for.  This does not prevent anyone from computing the deltas themselves —
they have the extractor — and claiming otherwise would be a lie.  What it does
is decline to ship a ready-made objective function, and leave a record when
somebody asks for one anyway.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Final

from trueai.core.errors import TrueAIError
from trueai.research.features import FeatureSet, FeatureVector

#: A baseline smaller than this describes a mood, not a style.
MIN_BASELINE_DOCUMENTS: Final = 8

#: A baseline shorter than this catches one project rather than a way of writing.
MIN_BASELINE_SPAN_DAYS: Final = 30

#: Where the bands sit, in units of the author's own standard deviation. Coarse
#: on purpose: a continuous score invites a threshold, and a threshold invites a
#: verdict this module refuses to produce.
NOTABLE_SIGMA: Final = 2.0
MARKED_SIGMA: Final = 3.5

#: The reasons a style moves, in rough order of how often they are the answer.
#: Returned with every comparison rather than kept in documentation, because a
#: caveat that lives elsewhere does not travel with the number.
ALTERNATIVE_EXPLANATIONS: Final[tuple[str, ...]] = (
    "a different topic or subject matter",
    "a different genre, register, or audience",
    "a co-author, an editor, or a reviewer",
    "a template, a house style, or a style guide",
    "translation, or writing in a second language",
    "ordinary change over time, including practice and deliberate change",
    "time pressure, illness, or circumstance",
    "a different tool, keyboard, or dictation",
)


class LongitudinalError(TrueAIError):
    """Raised when a comparison cannot honestly be made."""


class ShiftBand(StrEnum):
    """How far a document sits from a writer's own past, coarsely."""

    #: Inside what this writer's work already varies by.
    WITHIN_VARIATION = "within_variation"
    NOTABLE = "notable"
    MARKED = "marked"
    #: The baseline could not support a comparison. Not a small shift — no
    #: measurement at all, and an interface must not render it as one.
    UNDETERMINED = "undetermined"


@dataclass(frozen=True, slots=True)
class BaselineDocument:
    """One earlier document by the same writer."""

    vector: FeatureVector
    written_at: datetime

    def __post_init__(self) -> None:
        if self.written_at.tzinfo is None or self.written_at.utcoffset() is None:
            raise ValueError("A baseline document's date must include a UTC offset")


@dataclass(frozen=True, slots=True)
class StyleBaseline:
    """A writer's own past, and how much it already varies."""

    feature_set: FeatureSet
    documents: tuple[BaselineDocument, ...]
    #: Genre or register the baseline was drawn from, when it is known. A
    #: comparison across genres is measuring the genre.
    genre: str | None = None

    @property
    def span_days(self) -> float:
        if len(self.documents) < 2:
            return 0.0
        dates = sorted(item.written_at for item in self.documents)
        return (dates[-1] - dates[0]).total_seconds() / 86400.0

    def means(self) -> tuple[float, ...]:
        columns = zip(*(item.vector.values for item in self.documents), strict=True)
        return tuple(statistics.fmean(column) for column in columns)

    def deviations(self) -> tuple[float, ...]:
        """Per-feature standard deviation — this writer's own variability."""

        columns = zip(*(item.vector.values for item in self.documents), strict=True)
        return tuple(
            statistics.stdev(column) if len(self.documents) > 1 else 0.0 for column in columns
        )

    def insufficiency(self) -> tuple[str, ...]:
        """Why this baseline cannot support a comparison, if it cannot."""

        reasons: list[str] = []
        if len(self.documents) < MIN_BASELINE_DOCUMENTS:
            reasons.append(
                f"{len(self.documents)} documents; at least {MIN_BASELINE_DOCUMENTS} are needed "
                "before a spread means anything"
            )
        if self.span_days < MIN_BASELINE_SPAN_DAYS:
            reasons.append(
                f"the baseline spans {self.span_days:.0f} days; at least "
                f"{MIN_BASELINE_SPAN_DAYS} are needed to describe a way of writing rather "
                "than one project"
            )
        if not any(self.deviations()):
            reasons.append(
                "every feature is identical across the baseline, so there is no variability "
                "to measure a change against"
            )
        return tuple(reasons)


@dataclass(frozen=True, slots=True)
class StyleComparison:
    """Where a document sits relative to a writer's own past.

    Carries no verdict, and the fields that would let a caller manufacture one
    are absent by construction.
    """

    band: ShiftBand
    #: Distance in units of the writer's own variability, or ``None`` when the
    #: baseline could not support a measurement. ``None`` is not zero.
    sigma: float | None
    baseline_documents: int
    baseline_span_days: float
    #: Why no measurement was made, when none was.
    insufficiency: tuple[str, ...] = ()
    #: Everything that moves a style other than a change of author.
    alternative_explanations: tuple[str, ...] = ALTERNATIVE_EXPLANATIONS
    #: Present only when explicitly requested, and recorded so a report shows it.
    feature_deltas: dict[str, float] | None = None
    feature_deltas_requested: bool = False
    #: Set when the comparison crossed a genre boundary the caller declared.
    cross_genre: bool = False
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def measured(self) -> bool:
        return self.band is not ShiftBand.UNDETERMINED

    def what_this_is_not(self) -> tuple[str, ...]:
        """Print this next to the result. It is the result's other half."""

        return (
            "This is not evidence that a different person wrote the document.",
            "This is not a probability, and there is no threshold at which it becomes one.",
            "A style comparison is a prompt to ask the writer a question, and the answer "
            "comes from them rather than from this number.",
        )

    def describe(self) -> str:
        if not self.measured:
            return (
                "No comparison was made: "
                + "; ".join(self.insufficiency)
                + ". This is an absence of measurement, not a finding of no change."
            )
        assert self.sigma is not None
        lead = {
            ShiftBand.WITHIN_VARIATION: (
                "The document sits inside what this writer's work already varies by."
            ),
            ShiftBand.NOTABLE: "The document sits outside this writer's usual range.",
            ShiftBand.MARKED: "The document sits well outside this writer's usual range.",
        }[self.band]
        genre = (
            " The comparison crossed a declared genre boundary, which on its own moves style "
            "more than most other causes."
            if self.cross_genre
            else ""
        )
        return (
            f"{lead} ({self.sigma:.1f} standard deviations, over "
            f"{self.baseline_documents} documents spanning "
            f"{self.baseline_span_days:.0f} days.){genre}"
        )


def compare(
    document: FeatureVector,
    baseline: StyleBaseline,
    *,
    genre: str | None = None,
    include_feature_deltas: bool = False,
) -> StyleComparison:
    """Place a document relative to a writer's own past.

    ``include_feature_deltas`` exists for debugging a detector, not for steering
    a document. It is recorded in the result so a report can show it was asked
    for, and it is off by default because "which feature moved and by how much"
    is a recipe for moving it back.
    """

    if not baseline.documents:
        raise LongitudinalError("A comparison needs a baseline to compare against")
    if not document.matches(baseline.feature_set):
        raise LongitudinalError(
            "The document and the baseline belong to different feature sets, so their "
            "columns do not mean the same thing"
        )
    for item in baseline.documents:
        if not item.vector.matches(baseline.feature_set):
            raise LongitudinalError(
                "A baseline document belongs to a different feature set than the baseline"
            )

    reasons = baseline.insufficiency()
    cross_genre = bool(genre and baseline.genre and genre != baseline.genre)

    if reasons:
        # No distance at all. A number attached to an insufficient baseline gets
        # quoted without the word "insufficient".
        return StyleComparison(
            band=ShiftBand.UNDETERMINED,
            sigma=None,
            baseline_documents=len(baseline.documents),
            baseline_span_days=baseline.span_days,
            insufficiency=reasons,
            feature_deltas_requested=include_feature_deltas,
            cross_genre=cross_genre,
        )

    means = baseline.means()
    deviations = baseline.deviations()
    # Measured against this writer's own spread: a fixed threshold across writers
    # penalises the consistent ones and excuses the erratic.
    scores: list[float] = []
    per_feature: dict[str, float] = {}
    for name, value, mean, deviation in zip(
        baseline.feature_set.names, document.values, means, deviations, strict=True
    ):
        if deviation == 0.0:
            continue
        score = (value - mean) / deviation
        scores.append(score)
        per_feature[name] = score

    sigma = math.sqrt(sum(score**2 for score in scores) / len(scores)) if scores else 0.0
    if sigma >= MARKED_SIGMA:
        band = ShiftBand.MARKED
    elif sigma >= NOTABLE_SIGMA:
        band = ShiftBand.NOTABLE
    else:
        band = ShiftBand.WITHIN_VARIATION

    notes: list[str] = []
    if cross_genre:
        notes.append(
            f"the baseline is {baseline.genre!r} and the document is {genre!r}; a register "
            "change moves style more than most other causes and should be ruled out first"
        )

    return StyleComparison(
        band=band,
        sigma=sigma,
        baseline_documents=len(baseline.documents),
        baseline_span_days=baseline.span_days,
        feature_deltas=dict(sorted(per_feature.items())) if include_feature_deltas else None,
        feature_deltas_requested=include_feature_deltas,
        cross_genre=cross_genre,
        notes=tuple(notes),
    )


__all__ = [
    "ALTERNATIVE_EXPLANATIONS",
    "MARKED_SIGMA",
    "MIN_BASELINE_DOCUMENTS",
    "MIN_BASELINE_SPAN_DAYS",
    "NOTABLE_SIGMA",
    "BaselineDocument",
    "LongitudinalError",
    "ShiftBand",
    "StyleBaseline",
    "StyleComparison",
    "compare",
]
