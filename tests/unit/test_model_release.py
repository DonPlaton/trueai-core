"""What must exist before a learned score is shown to anyone.

The rule the whole file turns on: a rise in the false positive rate blocks a
release even when everything else improved. Averages let a model get better at
finding machine text while getting worse at accusing people, and only one of
those two costs a person something.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from trueai.research import (
    DatasetStatement,
    ModelCard,
    ModelFile,
    ModelManifest,
    OperatingPoint,
    Prediction,
    ProtocolRecord,
    ReleaseError,
    ThresholdSet,
    build_manifest,
    check_regression,
    compute_manifest_id,
    evaluate,
    may_expose,
    sign_manifest,
    verify_manifest,
)

pytest.importorskip("cryptography", reason="Signing needs the attestation extra")

NOW = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
CORPUS = "sha256:" + "a" * 64


def card(**extra: Any) -> ModelCard:
    fields: dict[str, Any] = {
        "identifier": "trueai-style-v0",
        "version": "0.1",
        "feature_set_version": "1",
        "trained_on": CORPUS,
        "intended_use": "A review aid for a human reader.",
        "known_limitations": ("Untested on writing in a second language.",),
        "created_at": NOW,
    }
    fields.update(extra)
    return ModelCard.model_validate(fields)


def statement(**extra: Any) -> DatasetStatement:
    fields: dict[str, Any] = {
        "corpus_digest": CORPUS,
        "curation_rationale": "To measure stylistic regularity, not authorship.",
        "collection_process": "Contributed under written agreement by four partners.",
        "annotation_process": "Two annotators per sample, disagreements adjudicated.",
        "language_varieties": ("English (published technical writing)",),
        "does_not_represent": (
            "Writing by second-language authors.",
            "Any language other than English.",
        ),
    }
    fields.update(extra)
    return DatasetStatement.model_validate(fields)


def thresholds(**extra: Any) -> ThresholdSet:
    fields: dict[str, Any] = {
        "model_version": "0.1",
        "feature_set_version": "1",
        "evaluation_digest": "sha256:" + "e" * 64,
        "points": (
            OperatingPoint(
                name="review-triage",
                threshold=0.5,
                intended_use="Flag for a human to look at.",
                measured_false_positive_rate=0.02,
            ),
        ),
    }
    fields.update(extra)
    return ThresholdSet.model_validate(fields)


def model_files(root: Path) -> tuple[ModelFile, ...]:
    weights = root / "weights.bin"
    weights.write_bytes(b"not really weights")
    data = weights.read_bytes()
    return (
        ModelFile(
            path="weights.bin",
            sha256=hashlib.sha256(data).hexdigest(),
            size_bytes=len(data),
        ),
    )


def manifest(root: Path, **extra: Any) -> ModelManifest:
    return build_manifest(
        card=extra.pop("card", card()),
        dataset=extra.pop("dataset", statement()),
        thresholds=extra.pop("thresholds", thresholds()),
        files=extra.pop("files", model_files(root)),
        created_at=NOW,
    )


def predictions(*, false_positives: int, subgroup_false_positives: int = 0, abstentions: int = 0):
    items = [
        Prediction(
            sample_id=f"n{index}",
            is_positive=False,
            score=0.9 if index < false_positives else 0.1,
            subgroup="native",
        )
        for index in range(100)
    ]
    items += [
        Prediction(sample_id=f"p{index}", is_positive=True, score=0.9, subgroup="native")
        for index in range(100)
    ]
    items += [
        Prediction(
            sample_id=f"sn{index}",
            is_positive=False,
            score=0.9 if index < subgroup_false_positives else 0.1,
            subgroup="second-language",
        )
        for index in range(100)
    ]
    items += [
        Prediction(sample_id=f"sp{index}", is_positive=True, score=0.9, subgroup="second-language")
        for index in range(100)
    ]
    items += [
        Prediction(sample_id=f"a{index}", is_positive=False, score=None)
        for index in range(abstentions)
    ]
    return items


def evaluation(**extra: Any):
    record = ProtocolRecord(
        corpus_digest=extra.pop("corpus_digest", CORPUS),
        model_identifier=extra.pop("model_identifier", "trueai-style-v0"),
        threshold=extra.pop("threshold", 0.5),
        seed=1,
        code_version="0.1.0",
        evaluated_at=NOW,
    )
    return evaluate(predictions(**extra), record=record)


# -- the dataset statement -------------------------------------------------------------


def test_a_statement_must_say_what_the_corpus_does_not_represent() -> None:
    """The field the whole document exists for."""

    with pytest.raises(ValueError):
        statement(does_not_represent=())


def test_a_statement_must_name_its_language_varieties() -> None:
    with pytest.raises(ValueError):
        statement(language_varieties=())


def test_listing_demographics_while_claiming_none_were_collected_is_refused() -> None:
    """One of the two is wrong and a reader cannot tell which."""

    with pytest.raises(ValueError, match="cannot tell which"):
        statement(author_demographics=("age band",), demographics_collected=False)


def test_no_demographics_is_a_fact_about_the_corpus_not_about_the_population() -> None:
    subject = statement()

    assert subject.author_demographics == ()
    assert not subject.demographics_collected


# -- thresholds are bound to a model ---------------------------------------------------


def test_thresholds_carry_the_evaluation_that_chose_them() -> None:
    assert thresholds().evaluation_digest.startswith("sha256:")


def test_an_operating_point_must_say_what_it_is_for() -> None:
    """A threshold without a use is a number waiting to be misapplied."""

    with pytest.raises(ValueError):
        OperatingPoint(name="x", threshold=0.5, intended_use="", measured_false_positive_rate=0.01)


def test_duplicate_operating_point_names_are_refused() -> None:
    point = OperatingPoint(
        name="triage", threshold=0.5, intended_use="use", measured_false_positive_rate=0.02
    )

    with pytest.raises(ValueError, match="must be unique"):
        thresholds(points=(point, point))


def test_a_manifest_refuses_thresholds_from_another_model_version(tmp_path: Path) -> None:
    """A threshold copied from a previous model is a number nobody measured."""

    with pytest.raises(ValueError, match="were measured on"):
        manifest(tmp_path, thresholds=thresholds(model_version="0.2"))


def test_a_manifest_refuses_thresholds_from_another_feature_set(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="one of them is stale"):
        manifest(tmp_path, thresholds=thresholds(feature_set_version="2"))


def test_a_manifest_refuses_a_statement_about_another_corpus(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="different corpus"):
        manifest(tmp_path, dataset=statement(corpus_digest="sha256:" + "b" * 64))


# -- the signed manifest ---------------------------------------------------------------


def test_a_manifest_is_content_addressed(tmp_path: Path) -> None:
    subject = manifest(tmp_path)

    assert subject.manifest_id.startswith("TAIMDL1-")
    assert compute_manifest_id(subject) == subject.manifest_id


def test_editing_a_manifest_breaks_its_identifier(tmp_path: Path) -> None:
    subject = manifest(tmp_path)

    edited = subject.model_copy(update={"card": card(intended_use="Something else entirely.")})

    assert compute_manifest_id(edited) != edited.manifest_id


def test_an_edited_manifest_cannot_be_signed(tmp_path: Path) -> None:
    from trueai.core.certificates import generate_ed25519_keypair

    private, _ = tmp_path / "k", tmp_path / "k.pub"
    generate_ed25519_keypair(private, tmp_path / "k.pub")
    edited = manifest(tmp_path).model_copy(update={"created_at": NOW.replace(year=2027)})

    with pytest.raises(ReleaseError, match="does not match its contents"):
        sign_manifest(edited, signing_key=private)


def test_a_signed_manifest_verifies(tmp_path: Path) -> None:
    from trueai.core.certificates import generate_ed25519_keypair

    private, public = tmp_path / "k", tmp_path / "k.pub"
    generate_ed25519_keypair(private, public)
    signed = sign_manifest(manifest(tmp_path), signing_key=private)

    valid, problems = verify_manifest(signed, public_key=public, root=tmp_path)

    assert valid, problems


def test_an_unsigned_manifest_is_refused(tmp_path: Path) -> None:
    from trueai.core.certificates import generate_ed25519_keypair

    generate_ed25519_keypair(tmp_path / "k", tmp_path / "k.pub")

    valid, problems = verify_manifest(manifest(tmp_path), public_key=tmp_path / "k.pub")

    assert not valid
    assert "the manifest is unsigned" in problems


def test_a_changed_model_file_is_caught_by_digest(tmp_path: Path) -> None:
    """The question is whether these are the bytes that were evaluated."""

    from trueai.core.certificates import generate_ed25519_keypair

    private, public = tmp_path / "k", tmp_path / "k.pub"
    generate_ed25519_keypair(private, public)
    signed = sign_manifest(manifest(tmp_path), signing_key=private)
    (tmp_path / "weights.bin").write_bytes(b"different weights entirely")

    valid, problems = verify_manifest(signed, public_key=public, root=tmp_path)

    assert not valid
    assert any("does not match the digest" in item for item in problems)


def test_a_missing_model_file_is_reported(tmp_path: Path) -> None:
    from trueai.core.certificates import generate_ed25519_keypair

    private, public = tmp_path / "k", tmp_path / "k.pub"
    generate_ed25519_keypair(private, public)
    signed = sign_manifest(manifest(tmp_path), signing_key=private)
    (tmp_path / "weights.bin").unlink()

    valid, problems = verify_manifest(signed, public_key=public, root=tmp_path)

    assert not valid
    assert any("could not be read" in item for item in problems)


def test_a_file_may_appear_only_once(tmp_path: Path) -> None:
    files = model_files(tmp_path)

    with pytest.raises(ValueError, match="only once"):
        manifest(tmp_path, files=files + files)


# -- the regression gate ---------------------------------------------------------------


def test_a_rise_in_false_positives_blocks_a_release() -> None:
    """Even when every other number improved."""

    baseline = evaluation(false_positives=2)
    candidate = evaluation(false_positives=8)

    verdict = check_regression(baseline, candidate)

    assert not verdict.passed
    assert any("false positive rate rose" in item for item in verdict.reasons)


def test_a_fall_in_false_positives_passes() -> None:
    verdict = check_regression(evaluation(false_positives=8), evaluation(false_positives=2))

    assert verdict.passed
    assert any("false positives" in item for item in verdict.deltas)


def test_a_rise_inside_the_tolerance_passes() -> None:
    verdict = check_regression(
        evaluation(false_positives=2),
        evaluation(false_positives=3),
        false_positive_tolerance=0.02,
    )

    assert verdict.passed


def test_an_improvement_taken_out_of_one_cohort_is_not_an_improvement() -> None:
    """The mean falls, one subgroup gets much worse, and the release is blocked."""

    baseline = evaluation(false_positives=10, subgroup_false_positives=10)
    candidate = evaluation(false_positives=0, subgroup_false_positives=25)

    verdict = check_regression(baseline, candidate)

    assert not verdict.passed
    assert any("worst subgroup" in item for item in verdict.reasons)


def test_abstaining_more_does_not_buy_a_better_release() -> None:
    """Coverage falling improves every other number for free."""

    baseline = evaluation(false_positives=2)
    candidate = evaluation(false_positives=0, abstentions=200)

    verdict = check_regression(baseline, candidate)

    assert not verdict.passed
    assert any("coverage fell" in item for item in verdict.reasons)


def test_dropping_the_subgroup_that_was_scored_is_blocked() -> None:
    """Otherwise the comparison hides whichever cohort went missing."""

    baseline = evaluation(false_positives=2)
    record = ProtocolRecord(
        corpus_digest=CORPUS,
        model_identifier="trueai-style-v0",
        threshold=0.5,
        seed=1,
        code_version="0.1.0",
        evaluated_at=NOW,
    )
    candidate = evaluate(
        [
            Prediction(sample_id=f"n{index}", is_positive=False, score=0.1, subgroup=f"g{index}")
            for index in range(40)
        ],
        record=record,
    )

    verdict = check_regression(baseline, candidate)

    assert not verdict.passed
    assert any("scored none" in item for item in verdict.reasons)


def test_a_clean_comparison_reports_what_moved() -> None:
    verdict = check_regression(evaluation(false_positives=4), evaluation(false_positives=3))

    assert verdict.passed
    assert "No regression" in verdict.explain()
    assert any("calibration error" in item for item in verdict.deltas)


# -- the release gate ------------------------------------------------------------------


def released(tmp_path: Path, **extra: Any):
    from trueai.core.certificates import generate_ed25519_keypair

    private, public = tmp_path / "k", tmp_path / "k.pub"
    if not private.exists():
        generate_ed25519_keypair(private, public)
    signed = sign_manifest(manifest(tmp_path, **extra.pop("manifest", {})), signing_key=private)
    return may_expose(
        signed,
        verification=verify_manifest(signed, public_key=public, root=tmp_path),
        evaluation=extra.pop("evaluation", evaluation(false_positives=1)),
        regression=extra.pop("regression", None),
    )


def test_a_complete_release_may_be_exposed(tmp_path: Path) -> None:
    decision = released(tmp_path)

    assert decision.may_expose, decision.refusals
    assert "may be exposed" in decision.explain()


def test_an_unsigned_manifest_blocks_exposure(tmp_path: Path) -> None:
    subject = manifest(tmp_path)

    decision = may_expose(
        subject,
        verification=(False, ("the manifest is unsigned",)),
        evaluation=evaluation(false_positives=1),
    )

    assert not decision.may_expose
    assert any("unsigned" in item for item in decision.refusals)


def test_an_evaluation_of_a_different_model_blocks_exposure(tmp_path: Path) -> None:
    decision = released(
        tmp_path, evaluation=evaluation(false_positives=1, model_identifier="some-other-model")
    )

    assert not decision.may_expose
    assert any("some-other-model" in item for item in decision.refusals)


def test_an_evaluation_over_a_different_corpus_blocks_exposure(tmp_path: Path) -> None:
    decision = released(
        tmp_path, evaluation=evaluation(false_positives=1, corpus_digest="sha256:" + "c" * 64)
    )

    assert not decision.may_expose
    assert any("different corpus" in item for item in decision.refusals)


def test_shipping_a_threshold_nobody_measured_blocks_exposure(tmp_path: Path) -> None:
    """An operating point nobody evaluated is a number waiting to be quoted."""

    decision = released(tmp_path, evaluation=evaluation(false_positives=1, threshold=0.77))

    assert not decision.may_expose
    assert any("never measured" in item for item in decision.refusals)


def test_a_problem_in_the_evaluation_blocks_exposure(tmp_path: Path) -> None:
    decision = released(
        tmp_path, evaluation=evaluation(false_positives=1, subgroup_false_positives=40)
    )

    assert not decision.may_expose
    assert any("evaluation:" in item for item in decision.refusals)


def test_a_failed_regression_gate_blocks_exposure(tmp_path: Path) -> None:
    verdict = check_regression(evaluation(false_positives=1), evaluation(false_positives=9))

    decision = released(tmp_path, regression=verdict)

    assert not decision.may_expose
    assert any("regression:" in item for item in decision.refusals)


def test_a_first_release_has_nothing_to_regress_against(tmp_path: Path) -> None:
    decision = released(tmp_path, regression=None)

    assert decision.may_expose


def test_every_refusal_is_reported_together(tmp_path: Path) -> None:
    """An operator fixing one should see the rest."""

    subject = manifest(tmp_path)

    decision = may_expose(
        subject,
        verification=(False, ("the manifest is unsigned",)),
        evaluation=evaluation(
            false_positives=1, corpus_digest="sha256:" + "d" * 64, model_identifier="other"
        ),
    )

    assert len(decision.refusals) >= 3
