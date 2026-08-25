"""The evaluation protocol, and the numbers it refuses to publish alone.

The failure mode being guarded against is a detector that looks good. Accuracy
averages the harm of accusing a human together with the harm of missing a
machine; an aggregate rate hides a subgroup it fails on; an abstaining detector
reaches any figure by answering only the easy cases; and a rate over five
samples reads like a measurement.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from trueai.research import (
    EvaluationError,
    Prediction,
    ProtocolRecord,
    calibration,
    evaluate,
)
from trueai.research.evaluation import DEFAULT_MIN_GROUP_SIZE, RateEstimate

NOW = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)


def record(**extra: object) -> ProtocolRecord:
    fields: dict[str, object] = {
        "corpus_digest": "sha256:" + "a" * 64,
        "model_identifier": "trueai-style-v0",
        "threshold": 0.5,
        "seed": 7,
        "code_version": "0.1.0",
        "evaluated_at": NOW,
    }
    fields.update(extra)
    return ProtocolRecord.model_validate(fields)


def predictions(
    *,
    negatives: int = 100,
    positives: int = 100,
    false_positives: int = 0,
    false_negatives: int = 0,
    domain: str = "software",
    subgroup: str = "native",
    offset: int = 0,
) -> list[Prediction]:
    """Build a labelled set with an exact number of each mistake."""

    items: list[Prediction] = []
    for index in range(negatives):
        wrong = index < false_positives
        items.append(
            Prediction(
                sample_id=f"n{offset + index}",
                is_positive=False,
                score=0.9 if wrong else 0.1,
                domain=domain,
                subgroup=subgroup,
            )
        )
    for index in range(positives):
        wrong = index < false_negatives
        items.append(
            Prediction(
                sample_id=f"p{offset + index}",
                is_positive=True,
                score=0.1 if wrong else 0.9,
                domain=domain,
                subgroup=subgroup,
            )
        )
    return items


# -- the headline is the false positive rate -----------------------------------------


def test_the_summary_leads_with_false_positives_and_carries_no_accuracy() -> None:
    """Accuracy averages accusing a human with missing a machine. They differ."""

    result = evaluate(predictions(false_positives=3), record=record())
    summary = result.summary()

    assert summary.startswith("False positives:")
    assert "accuracy" not in summary.lower()


def test_a_false_positive_rate_is_counted_at_the_stated_threshold() -> None:
    result = evaluate(predictions(false_positives=7), record=record())

    assert result.false_positive.successes == 7
    assert result.false_positive.total == 100
    assert result.false_positive.rate == 0.07


def test_moving_the_threshold_moves_the_rate() -> None:
    """A rate without its operating point is not a measurement."""

    subject = predictions(false_positives=0)

    strict = evaluate(subject, record=record(threshold=0.05))
    lenient = evaluate(subject, record=record(threshold=0.95))

    assert strict.false_positive.rate == 1.0
    assert lenient.false_positive.rate == 0.0


def test_false_negatives_are_counted_separately() -> None:
    result = evaluate(predictions(false_negatives=4), record=record())

    assert result.false_negative.successes == 4
    assert result.false_positive.successes == 0


# -- a small sample is not a measurement ---------------------------------------------


def test_a_rate_over_a_handful_of_samples_is_flagged_as_unreliable() -> None:
    """Printing "0.0%" for a group of five is worse than printing nothing."""

    result = evaluate(predictions(negatives=5, positives=5), record=record())

    assert not result.false_positive.sufficient
    assert "too few samples to rely on" in result.false_positive.describe()
    assert "too small for a false positive rate" in " ".join(result.problems())


def test_a_zero_rate_still_carries_an_interval() -> None:
    """The normal approximation gives zero width at zero, where it is needed most."""

    estimate = RateEstimate(successes=0, total=30, sufficient=True)
    interval = estimate.interval

    assert estimate.rate == 0.0
    assert interval is not None
    assert interval[0] == 0.0
    assert interval[1] > 0.0


def test_a_rate_of_one_stays_inside_the_unit_interval() -> None:
    estimate = RateEstimate(successes=40, total=40, sufficient=True)
    interval = estimate.interval

    assert interval is not None
    assert interval[1] <= 1.0
    assert interval[0] < 1.0


def test_a_rate_with_nothing_measured_says_so() -> None:
    estimate = RateEstimate(successes=0, total=0, sufficient=False)

    assert estimate.rate is None
    assert estimate.interval is None
    assert estimate.describe() == "not measured"


def test_an_undersized_group_is_named_rather_than_dropped() -> None:
    subject = predictions(negatives=100, positives=100)
    subject += predictions(negatives=4, positives=4, subgroup="rare", offset=500)

    result = evaluate(subject, record=record())

    assert any("subgroup rare" in item for item in result.undersized_groups)
    assert any("too few samples" in item for item in result.problems())


# -- subgroups -----------------------------------------------------------------------


def test_a_subgroup_the_detector_fails_is_reported_beside_the_overall_rate() -> None:
    """A 3% overall rate with 15% on one cohort is not a 3% detector."""

    subject = predictions(negatives=200, positives=200, false_positives=2)
    subject += predictions(
        negatives=100, positives=100, false_positives=20, subgroup="second-language", offset=900
    )

    result = evaluate(subject, record=record())
    worst = result.worst_subgroup()

    assert worst is not None
    assert worst.name == "second-language"
    assert worst.false_positive.rate == 0.2
    assert "second-language" in result.summary()


def test_a_subgroup_gap_is_reported_as_a_problem() -> None:
    subject = predictions(negatives=200, positives=200, false_positives=2)
    subject += predictions(
        negatives=100, positives=100, false_positives=20, subgroup="second-language", offset=900
    )

    problems = evaluate(subject, record=record()).problems()

    assert any("above the overall rate" in item for item in problems)


def test_a_small_gap_between_subgroups_is_not_reported_as_a_problem() -> None:
    subject = predictions(negatives=200, positives=200, false_positives=4)
    subject += predictions(
        negatives=100, positives=100, false_positives=3, subgroup="second-language", offset=900
    )

    problems = evaluate(subject, record=record()).problems()

    assert not any("above the overall rate" in item for item in problems)


def test_a_subgroup_too_small_to_score_is_not_chosen_as_the_worst() -> None:
    """Otherwise a five-sample group with one mistake becomes the headline."""

    subject = predictions(negatives=200, positives=200, false_positives=2)
    subject += predictions(negatives=4, positives=4, false_positives=4, subgroup="tiny", offset=900)

    worst = evaluate(subject, record=record()).worst_subgroup()

    assert worst is not None
    assert worst.name != "tiny"


def test_the_summary_says_so_when_no_subgroup_could_be_scored() -> None:
    result = evaluate(predictions(negatives=10, positives=10), record=record())

    assert "No subgroup was large enough" in result.summary()


# -- domain shift ---------------------------------------------------------------------


def test_per_domain_rates_are_reported_separately() -> None:
    subject = predictions(negatives=100, positives=100, false_positives=1, domain="software")
    subject += predictions(
        negatives=100, positives=100, false_positives=25, domain="legal", offset=900
    )

    result = evaluate(subject, record=record())
    rates = {item.name: item.false_positive.rate for item in result.by_domain}

    assert rates == {"software": 0.01, "legal": 0.25}


def test_the_spread_between_domains_is_what_a_new_deployment_meets() -> None:
    subject = predictions(negatives=100, positives=100, false_positives=1, domain="software")
    subject += predictions(
        negatives=100, positives=100, false_positives=25, domain="legal", offset=900
    )

    result = evaluate(subject, record=record())

    assert result.domain_spread() == pytest.approx(0.24)
    assert any("varies" in item for item in result.problems())


def test_a_single_domain_has_no_spread_to_report() -> None:
    result = evaluate(predictions(), record=record())

    assert result.domain_spread() is None


# -- abstention -----------------------------------------------------------------------


def test_an_abstaining_detector_reports_coverage_with_every_rate() -> None:
    """Answering only the easy cases reaches any figure otherwise."""

    subject = predictions(negatives=50, positives=50)
    subject += [
        Prediction(sample_id=f"a{index}", is_positive=index % 2 == 0, score=None)
        for index in range(100)
    ]

    result = evaluate(subject, record=record())

    assert result.abstained == 100
    assert result.coverage == 0.5
    assert "Answered 50.0% of 200 samples" in result.summary()


def test_heavy_abstention_is_reported_as_a_caveat_on_every_rate() -> None:
    subject = predictions(negatives=50, positives=50)
    subject += [
        Prediction(sample_id=f"a{index}", is_positive=False, score=None) for index in range(100)
    ]

    problems = evaluate(subject, record=record()).problems()

    assert any("describes only what it chose to answer" in item for item in problems)


def test_an_abstention_is_not_counted_as_a_correct_answer() -> None:
    subject = [
        Prediction(sample_id="abstained-0", is_positive=False, score=None),
        *predictions(negatives=40, positives=40, false_positives=4),
    ]

    result = evaluate(subject, record=record())

    assert result.false_positive.total == 40
    assert result.false_positive.rate == 0.1


def test_full_coverage_produces_no_abstention_caveat() -> None:
    problems = evaluate(predictions(), record=record()).problems()

    assert not any("chose to answer" in item for item in problems)


# -- calibration ----------------------------------------------------------------------


def test_a_well_calibrated_detector_has_a_small_expected_error() -> None:
    """A score of 0.9 should be wrong about one time in ten."""

    subject = [
        Prediction(sample_id=f"c{index}", is_positive=index % 10 != 0, score=0.9)
        for index in range(100)
    ]

    result = calibration(subject)

    assert result.expected_error == pytest.approx(0.0, abs=0.02)


def test_an_overconfident_detector_is_caught() -> None:
    subject = [
        Prediction(sample_id=f"c{index}", is_positive=index % 2 == 0, score=0.99)
        for index in range(100)
    ]

    result = calibration(subject)

    assert result.expected_error == pytest.approx(0.49, abs=0.01)
    assert result.worst_bin() is not None


def test_poor_calibration_is_reported_as_a_problem() -> None:
    subject = [
        Prediction(sample_id=f"c{index}", is_positive=index % 2 == 0, score=0.99)
        for index in range(100)
    ]

    problems = evaluate(subject, record=record()).problems()

    assert any("poorly calibrated" in item for item in problems)


def test_a_score_of_one_lands_in_the_top_bin_rather_than_off_the_end() -> None:
    subject = [Prediction(sample_id=f"c{index}", is_positive=True, score=1.0) for index in range(5)]

    result = calibration(subject, minimum=1)

    assert len(result.bins) == 1
    assert result.bins[0].upper == 1.0


def test_calibration_over_too_few_samples_is_marked_insufficient() -> None:
    subject = [Prediction(sample_id="c0", is_positive=True, score=0.9)]

    result = calibration(subject)

    assert not result.sufficient


def test_abstentions_do_not_enter_the_reliability_diagram() -> None:
    subject = [
        Prediction(sample_id="a0", is_positive=True, score=None),
        Prediction(sample_id="c0", is_positive=True, score=0.9),
    ]

    result = calibration(subject, minimum=1)

    assert sum(item.count for item in result.bins) == 1


def test_calibration_needs_at_least_two_bins() -> None:
    with pytest.raises(EvaluationError, match="at least two bins"):
        calibration(predictions(), bins=1)


# -- reproducibility ------------------------------------------------------------------


def test_a_result_names_the_corpus_model_threshold_and_seed() -> None:
    """A number that cannot be recomputed is an anecdote."""

    summary = evaluate(predictions(), record=record()).summary()

    assert "sha256:" in summary
    assert "trueai-style-v0" in summary
    assert "threshold 0.5" in summary
    assert "seed 7" in summary


def test_a_protocol_record_cannot_omit_the_corpus_it_scored() -> None:
    with pytest.raises(ValueError):
        ProtocolRecord(
            corpus_digest="",
            model_identifier="m",
            threshold=0.5,
            seed=1,
            code_version="0.1.0",
            evaluated_at=NOW,
        )


def test_a_protocol_record_needs_an_offset_on_its_timestamp() -> None:
    with pytest.raises(ValueError, match="UTC offset"):
        record(evaluated_at=datetime(2026, 1, 1))


def test_a_threshold_outside_the_unit_interval_is_refused() -> None:
    with pytest.raises(ValueError):
        record(threshold=1.5)


# -- what the protocol refuses ---------------------------------------------------------


def test_an_evaluation_needs_predictions() -> None:
    with pytest.raises(EvaluationError, match="at least one prediction"):
        evaluate([], record=record())


def test_a_sample_counted_twice_weights_itself_invisibly() -> None:
    subject = predictions(negatives=40, positives=40)
    subject.append(subject[0])

    with pytest.raises(EvaluationError, match="may appear once"):
        evaluate(subject, record=record())


def test_a_score_outside_the_unit_interval_is_refused_at_construction() -> None:
    with pytest.raises(ValueError, match=r"must be in \[0, 1\]"):
        Prediction(sample_id="x", is_positive=True, score=1.4)


def test_a_clean_evaluation_reports_no_problems() -> None:
    subject = [
        Prediction(
            sample_id=f"n{index}",
            is_positive=False,
            score=0.05,
            subgroup="a" if index % 2 else "b",
        )
        for index in range(100)
    ] + [
        Prediction(
            sample_id=f"p{index}",
            is_positive=True,
            score=0.95,
            subgroup="a" if index % 2 else "b",
        )
        for index in range(100)
    ]

    result = evaluate(subject, record=record())

    assert result.problems() == ()
    assert "Caveat" not in result.summary()


def test_the_group_size_floor_is_configurable_and_stated() -> None:
    result = evaluate(predictions(negatives=10, positives=10), record=record(), min_group_size=5)

    assert result.min_group_size == 5
    assert result.false_positive.sufficient
    assert DEFAULT_MIN_GROUP_SIZE == 30
