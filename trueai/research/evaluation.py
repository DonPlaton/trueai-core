"""How a detector is evaluated, and which numbers may not be published alone.

The headline number for a detector like this is not accuracy.  It is the **false
positive rate**: the rate at which the tool tells someone a human-written
document was machine-generated.  Accuracy averages that harm together with the
harmless kind of mistake and reports one number that hides it, which is why
:meth:`EvaluationResult.summary` will not produce a figure without the false
positive rate and the worst subgroup's false positive rate beside it.

Six things this protocol requires, each because leaving it out produces a number
that looks better than the detector is:

**False positives, at a stated operating point.**  A rate quoted without the
threshold it was computed at is not a measurement.

**Calibration.**  A score of 0.9 should be wrong about one time in ten.  An
uncalibrated score is a number wearing a probability's clothes, and every
downstream policy that thresholds it inherits the lie.

**Domain shift.**  One aggregate over a mixed corpus hides that the detector
works on one domain and not another.  Per-domain rates and the spread between
best and worst are reported, because that spread is what a new deployment will
meet.

**Subgroups.**  A detector with a 3% overall false positive rate and 15% on
non-native English writing is not a 3% detector; it is a tool that penalises
non-native speakers.  Worst-group rate is reported next to the overall one, and
the gap between them is a finding.

**Abstention.**  A detector allowed to say "I do not know" can reach any accuracy
by answering only the easy cases.  Coverage is reported with every metric, and a
metric computed on the answered subset is labelled as such.

**Reproducibility.**  A number without the corpus digest, model identifier,
threshold, and seed that produced it cannot be recomputed, and a number that
cannot be recomputed is an anecdote.  :class:`ProtocolRecord` requires all four.

One more rule that is easy to skip and expensive to skip: a rate over a handful
of samples is noise, and printing "0.0%" for a subgroup of five is worse than
printing nothing.  Every rate carries a Wilson interval and a flag saying whether
the group was large enough to support it.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Final, Self

from pydantic import Field, model_validator

from trueai.core.errors import TrueAIError
from trueai.core.models import FrozenModel

EVALUATION_SCHEMA_VERSION: Final = "0.1"

#: Below this, a rate is noise. Reporting "0.0%" for a group of five is worse
#: than reporting nothing, because a reader treats it as a measurement.
DEFAULT_MIN_GROUP_SIZE: Final = 30

#: Bins for the reliability diagram. Ten is conventional and keeps each bin
#: populated on a corpus of realistic size.
DEFAULT_CALIBRATION_BINS: Final = 10

#: 1.96 — the two-sided 95% normal quantile the Wilson interval uses.
_Z: Final = 1.959963984540054


class EvaluationError(TrueAIError):
    """Raised when a protocol requirement cannot be satisfied."""


@dataclass(frozen=True, slots=True)
class Prediction:
    """One detector output, with everything needed to score it fairly."""

    sample_id: str
    #: Ground truth. True when the sample really is machine-generated.
    is_positive: bool
    #: The detector's score in [0, 1], or ``None`` when it abstained.
    score: float | None
    #: The domain the sample came from, for domain-shift analysis.
    domain: str = "unspecified"
    #: The subgroup this sample belongs to — writing in a second language, a
    #: particular register, an author cohort. Named by the evaluator, because
    #: only they know which axis matters for their deployment.
    subgroup: str = "unspecified"

    @property
    def abstained(self) -> bool:
        return self.score is None

    def __post_init__(self) -> None:
        if self.score is not None and not 0.0 <= self.score <= 1.0:
            raise ValueError(f"A score must be in [0, 1]; {self.sample_id} has {self.score}")


@dataclass(frozen=True, slots=True)
class RateEstimate:
    """A rate with an interval and an honest answer about whether it means anything."""

    successes: int
    total: int
    #: True when the sample was large enough for the rate to be worth reading.
    sufficient: bool

    @property
    def rate(self) -> float | None:
        """The point estimate, or ``None`` when nothing was measured."""

        return self.successes / self.total if self.total else None

    @property
    def interval(self) -> tuple[float, float] | None:
        """A 95% Wilson interval, which stays sensible at 0 and at 1.

        The normal approximation gives a zero-width interval at a rate of zero,
        which is exactly where a small sample most needs one.
        """

        if not self.total:
            return None
        proportion = self.successes / self.total
        denominator = 1 + _Z**2 / self.total
        centre = proportion + _Z**2 / (2 * self.total)
        spread = _Z * math.sqrt(
            proportion * (1 - proportion) / self.total + _Z**2 / (4 * self.total**2)
        )
        return (
            max(0.0, (centre - spread) / denominator),
            min(1.0, (centre + spread) / denominator),
        )

    def describe(self) -> str:
        if not self.total:
            return "not measured"
        interval = self.interval
        assert interval is not None
        text = f"{self.successes}/{self.total} = {self.rate:.1%} (95% CI {interval[0]:.1%}–{interval[1]:.1%})"
        return text if self.sufficient else f"{text} — too few samples to rely on"


@dataclass(frozen=True, slots=True)
class GroupResult:
    """One domain or subgroup, scored on its own."""

    name: str
    answered: int
    abstained: int
    false_positive: RateEstimate
    false_negative: RateEstimate

    @property
    def total(self) -> int:
        return self.answered + self.abstained

    @property
    def coverage(self) -> float | None:
        """Fraction of samples the detector was willing to answer."""

        return self.answered / self.total if self.total else None


@dataclass(frozen=True, slots=True)
class CalibrationBin:
    """One bucket of a reliability diagram."""

    lower: float
    upper: float
    count: int
    mean_score: float
    observed_rate: float

    @property
    def gap(self) -> float:
        return abs(self.mean_score - self.observed_rate)


@dataclass(frozen=True, slots=True)
class CalibrationResult:
    """Whether the scores mean what they say."""

    bins: tuple[CalibrationBin, ...]
    #: Expected calibration error: the count-weighted mean gap between the score
    #: a bin claimed and the rate it actually achieved.
    expected_error: float
    sufficient: bool

    def worst_bin(self) -> CalibrationBin | None:
        return max(self.bins, key=lambda item: item.gap, default=None)


class ProtocolRecord(FrozenModel):
    """Everything needed to recompute a number, required rather than optional.

    A result without these is an anecdote: nobody, including its author six
    months later, can reproduce it.
    """

    schema_version: str = EVALUATION_SCHEMA_VERSION
    #: The digest from ``CorpusManifest.digest()``, so the exact corpus is named.
    corpus_digest: str = Field(min_length=1, max_length=120)
    model_identifier: str = Field(min_length=1, max_length=300)
    #: The operating point. A rate without its threshold is not a measurement.
    threshold: float = Field(ge=0.0, le=1.0)
    seed: int
    code_version: str = Field(min_length=1, max_length=120)
    evaluated_at: datetime
    notes: str = Field(default="", max_length=2000)

    @model_validator(mode="after")
    def check_time(self) -> Self:
        if self.evaluated_at.tzinfo is None or self.evaluated_at.utcoffset() is None:
            raise ValueError("Evaluation time must include a UTC offset")
        return self


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    """One evaluation, with the numbers that must travel together."""

    record: ProtocolRecord
    total: int
    answered: int
    abstained: int
    false_positive: RateEstimate
    false_negative: RateEstimate
    calibration: CalibrationResult
    by_domain: tuple[GroupResult, ...] = ()
    by_subgroup: tuple[GroupResult, ...] = ()
    min_group_size: int = DEFAULT_MIN_GROUP_SIZE
    #: Groups too small to score, named rather than silently dropped.
    undersized_groups: tuple[str, ...] = field(default_factory=tuple)

    @property
    def coverage(self) -> float | None:
        return self.answered / self.total if self.total else None

    def worst_subgroup(self) -> GroupResult | None:
        """The subgroup with the highest false positive rate that is large enough.

        The number that decides whether a detector is fair to deploy. A 3%
        overall rate with 15% on one cohort is not a 3% detector.
        """

        eligible = [item for item in self.by_subgroup if item.false_positive.sufficient]
        return max(
            eligible,
            key=lambda item: item.false_positive.rate or 0.0,
            default=None,
        )

    def domain_spread(self) -> float | None:
        """Best-to-worst false positive gap across domains.

        What a new deployment will meet, and what one aggregate hides.
        """

        rates = [
            item.false_positive.rate
            for item in self.by_domain
            if item.false_positive.sufficient and item.false_positive.rate is not None
        ]
        return max(rates) - min(rates) if len(rates) >= 2 else None

    def problems(self) -> tuple[str, ...]:
        """Reasons this result must not be quoted as a headline figure."""

        issues: list[str] = []
        if not self.false_positive.sufficient:
            issues.append(
                "the negative class is too small for a false positive rate to mean anything"
            )
        worst = self.worst_subgroup()
        overall = self.false_positive.rate
        if worst is not None and overall is not None:
            gap = (worst.false_positive.rate or 0.0) - overall
            if gap > 0.05:
                issues.append(
                    f"subgroup {worst.name!r} has a false positive rate "
                    f"{gap:.1%} above the overall rate"
                )
        if self.undersized_groups:
            issues.append(
                "not scored, too few samples: " + ", ".join(sorted(self.undersized_groups))
            )
        if not self.calibration.sufficient:
            issues.append("too few scored samples to assess calibration")
        elif self.calibration.expected_error > 0.1:
            issues.append(
                f"scores are poorly calibrated (expected calibration error "
                f"{self.calibration.expected_error:.1%})"
            )
        coverage = self.coverage
        if coverage is not None and coverage < 0.9:
            issues.append(
                f"the detector abstained on {1 - coverage:.1%} of samples; every rate above "
                "describes only what it chose to answer"
            )
        spread = self.domain_spread()
        if spread is not None and spread > 0.1:
            issues.append(f"false positive rate varies {spread:.1%} between domains")
        return tuple(issues)

    def summary(self) -> str:
        """The one-paragraph result, with what it hides attached.

        There is deliberately no accuracy figure. Accuracy averages the harm of
        accusing a human together with the harm of missing a machine, and the
        two are not comparable.
        """

        worst = self.worst_subgroup()
        parts = [
            f"False positives: {self.false_positive.describe()}.",
            f"False negatives: {self.false_negative.describe()}.",
        ]
        if worst is not None:
            parts.append(f"Worst subgroup ({worst.name}): {worst.false_positive.describe()}.")
        else:
            parts.append("No subgroup was large enough to score separately.")
        coverage = self.coverage
        if coverage is not None:
            parts.append(f"Answered {coverage:.1%} of {self.total} samples.")
        parts.append(f"Expected calibration error {self.calibration.expected_error:.1%}.")
        parts.append(
            f"Corpus {self.record.corpus_digest}, model {self.record.model_identifier}, "
            f"threshold {self.record.threshold}, seed {self.record.seed}."
        )
        for problem in self.problems():
            parts.append(f"Caveat: {problem}.")
        return " ".join(parts)


# -- computation -----------------------------------------------------------------------


def _rate(successes: int, total: int, minimum: int) -> RateEstimate:
    return RateEstimate(successes=successes, total=total, sufficient=total >= minimum)


def _group(name: str, predictions: list[Prediction], threshold: float, minimum: int) -> GroupResult:
    answered = [item for item in predictions if not item.abstained]
    abstained = len(predictions) - len(answered)
    negatives = [item for item in answered if not item.is_positive]
    positives = [item for item in answered if item.is_positive]
    false_positives = sum(1 for item in negatives if (item.score or 0.0) >= threshold)
    false_negatives = sum(1 for item in positives if (item.score or 0.0) < threshold)
    return GroupResult(
        name=name,
        answered=len(answered),
        abstained=abstained,
        false_positive=_rate(false_positives, len(negatives), minimum),
        false_negative=_rate(false_negatives, len(positives), minimum),
    )


def calibration(
    predictions: list[Prediction],
    *,
    bins: int = DEFAULT_CALIBRATION_BINS,
    minimum: int = DEFAULT_MIN_GROUP_SIZE,
) -> CalibrationResult:
    """Bin the scores and compare what each bin claimed to what it achieved."""

    if bins < 2:
        raise EvaluationError("Calibration needs at least two bins")
    answered = [item for item in predictions if item.score is not None]
    buckets: dict[int, list[Prediction]] = defaultdict(list)
    for item in answered:
        assert item.score is not None
        # The top of the range belongs to the last bin rather than to a bin of
        # its own.
        index = min(bins - 1, int(item.score * bins))
        buckets[index].append(item)

    built: list[CalibrationBin] = []
    weighted_gap = 0.0
    for index in sorted(buckets):
        members = buckets[index]
        scores = [item.score for item in members if item.score is not None]
        mean_score = sum(scores) / len(scores)
        observed = sum(1 for item in members if item.is_positive) / len(members)
        built.append(
            CalibrationBin(
                lower=index / bins,
                upper=(index + 1) / bins,
                count=len(members),
                mean_score=mean_score,
                observed_rate=observed,
            )
        )
        weighted_gap += len(members) * abs(mean_score - observed)

    expected = weighted_gap / len(answered) if answered else 0.0
    return CalibrationResult(
        bins=tuple(built),
        expected_error=expected,
        sufficient=len(answered) >= minimum,
    )


def evaluate(
    predictions: list[Prediction],
    *,
    record: ProtocolRecord,
    min_group_size: int = DEFAULT_MIN_GROUP_SIZE,
    bins: int = DEFAULT_CALIBRATION_BINS,
) -> EvaluationResult:
    """Score a detector under the protocol, keeping every required number."""

    if not predictions:
        raise EvaluationError("An evaluation needs at least one prediction")
    identifiers = Counter(item.sample_id for item in predictions)
    repeated = [name for name, count in identifiers.items() if count > 1]
    if repeated:
        # A sample counted twice weights itself, and the weighting is invisible
        # in the result.
        raise EvaluationError(
            f"Each sample may appear once; repeated: {', '.join(sorted(repeated)[:5])}"
        )

    overall = _group("overall", predictions, record.threshold, min_group_size)

    by_domain: list[GroupResult] = []
    by_subgroup: list[GroupResult] = []
    undersized: list[str] = []
    for label, key in (("domain", "domain"), ("subgroup", "subgroup")):
        grouped: dict[str, list[Prediction]] = defaultdict(list)
        for item in predictions:
            grouped[getattr(item, key)].append(item)
        for name, members in sorted(grouped.items()):
            result = _group(name, members, record.threshold, min_group_size)
            (by_domain if label == "domain" else by_subgroup).append(result)
            if not result.false_positive.sufficient:
                undersized.append(f"{label} {name}")

    return EvaluationResult(
        record=record,
        total=len(predictions),
        answered=overall.answered,
        abstained=overall.abstained,
        false_positive=overall.false_positive,
        false_negative=overall.false_negative,
        calibration=calibration(predictions, bins=bins, minimum=min_group_size),
        by_domain=tuple(by_domain),
        by_subgroup=tuple(by_subgroup),
        min_group_size=min_group_size,
        undersized_groups=tuple(sorted(set(undersized))),
    )


__all__ = [
    "DEFAULT_CALIBRATION_BINS",
    "DEFAULT_MIN_GROUP_SIZE",
    "EVALUATION_SCHEMA_VERSION",
    "CalibrationBin",
    "CalibrationResult",
    "EvaluationError",
    "EvaluationResult",
    "GroupResult",
    "Prediction",
    "ProtocolRecord",
    "RateEstimate",
    "calibration",
    "evaluate",
]
