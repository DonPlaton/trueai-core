"""A versioned feature contract, and the heavy dependency that must not appear.

Two claims are under test. That a model and the code feeding it disagree loudly
rather than quietly — a v2 model handed a v1 vector produces a confident number
over columns that changed meaning, with no symptom until somebody acts on it.
And that the core package imports nothing that needs a GPU, which is the whole
reason a model can be optional at all.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path

import pytest

from trueai.research import (
    FeatureError,
    FeatureSet,
    ModelCard,
    ModelScore,
    ScoreModel,
    build_vector,
    score_with,
    try_score,
)
from trueai.research.features import FeatureVector

NOW = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)

SET_V1 = FeatureSet(
    version="1",
    names=("burstiness", "sentence_length_variance", "rare_word_share"),
    descriptions={"burstiness": "Variation in sentence-length spacing."},
)
SET_V2 = FeatureSet(
    version="2",
    names=("burstiness", "sentence_length_variance", "rare_word_share", "punctuation_entropy"),
)


class StubModel:
    """A model with no dependencies, which is the point of the protocol."""

    def __init__(self, version: str = "1", value: float = 0.4) -> None:
        self.identifier = "stub-model-v1"
        self.feature_set_version = version
        self._value = value

    def score(self, vector: FeatureVector, /) -> ModelScore:
        return ModelScore(
            value=self._value,
            model_identifier=self.identifier,
            feature_set_version=vector.feature_set_version,
        )


def vector(feature_set: FeatureSet = SET_V1, **values: float) -> FeatureVector:
    filled = {name: 0.5 for name in feature_set.names}
    filled.update(values)
    return build_vector(feature_set, filled, artifact_path="notes.md")


# -- the contract ---------------------------------------------------------------------


def test_a_feature_set_digest_covers_order_as_well_as_names() -> None:
    """A vector is positional; the same names reordered permute every column."""

    reordered = FeatureSet(version="1", names=tuple(reversed(SET_V1.names)))

    assert reordered.digest != SET_V1.digest


def test_a_feature_set_digest_changes_with_its_version() -> None:
    same_names = FeatureSet(version="2", names=SET_V1.names)

    assert same_names.digest != SET_V1.digest


def test_duplicate_feature_names_are_refused() -> None:
    with pytest.raises(ValueError, match="must be unique"):
        FeatureSet(version="1", names=("a", "a"))


def test_describing_a_feature_that_is_not_in_the_set_is_refused() -> None:
    """A description for a column that does not exist is a stale contract."""

    with pytest.raises(ValueError, match="not in the set"):
        FeatureSet(version="1", names=("a",), descriptions={"b": "gone"})


def test_a_vector_knows_which_set_it_belongs_to() -> None:
    subject = vector()

    assert subject.matches(SET_V1)
    assert not subject.matches(SET_V2)


def test_a_vector_can_be_read_by_name() -> None:
    subject = vector(burstiness=0.9)

    assert subject.named(SET_V1)["burstiness"] == 0.9


def test_reading_a_vector_against_the_wrong_set_is_refused() -> None:
    with pytest.raises(FeatureError, match="does not belong to feature set"):
        vector().named(SET_V2)


# -- building a vector ----------------------------------------------------------------


def test_a_missing_feature_is_refused_rather_than_padded_with_zero() -> None:
    """A zero is a measurement; an absence is not, and a model cannot tell them apart."""

    with pytest.raises(FeatureError, match="cannot be padded"):
        build_vector(SET_V1, {"burstiness": 0.5}, artifact_path="notes.md")


def test_an_extra_feature_is_refused_rather_than_silently_dropped() -> None:
    """Adding one changes the contract, so it has to change the version too."""

    values = dict.fromkeys(SET_V1.names, 0.5)
    values["something_new"] = 0.1

    with pytest.raises(FeatureError, match="bump the version"):
        build_vector(SET_V1, values, artifact_path="notes.md")


def test_a_vector_is_ordered_by_the_set_not_by_the_mapping() -> None:
    """A dict has an order; the contract is what decides the columns."""

    values = {name: index / 10 for index, name in enumerate(reversed(SET_V1.names))}

    built = build_vector(SET_V1, values, artifact_path="notes.md")

    assert built.values == tuple(values[name] for name in SET_V1.names)


# -- version mismatch refuses ---------------------------------------------------------


def test_a_model_refuses_a_vector_from_another_feature_set() -> None:
    """The refusal is the point: the alternative is a confident wrong number."""

    model = StubModel(version="2")

    with pytest.raises(FeatureError, match="changed meaning"):
        score_with(model, vector())


def test_a_matching_model_scores_normally() -> None:
    result = score_with(StubModel(), vector())

    assert result.value == 0.4
    assert result.model_identifier == "stub-model-v1"


def test_a_model_that_mislabels_its_own_output_is_caught() -> None:
    """A model claiming a different set than it was handed is not to be trusted."""

    class Liar(StubModel):
        def score(self, vector: FeatureVector, /) -> ModelScore:
            return ModelScore(value=0.9, model_identifier=self.identifier, feature_set_version="9")

    with pytest.raises(FeatureError, match="not the one it was given"):
        score_with(Liar(), vector())


def test_a_stub_model_satisfies_the_protocol_without_any_dependency() -> None:
    assert isinstance(StubModel(), ScoreModel)


# -- a model is optional --------------------------------------------------------------


def test_no_model_means_not_measured_rather_than_an_error() -> None:
    assert try_score(None, vector()) is None


def test_a_score_is_a_measurement_and_carries_no_author() -> None:
    """The fields that would let a caller promote it into a claim are absent."""

    result = ModelScore(value=0.7, model_identifier="m", feature_set_version="1")

    for forbidden in ("author", "attribution", "provenance_class", "provenance"):
        assert not hasattr(result, forbidden)


def test_a_score_says_what_it_is_not() -> None:
    described = ModelScore(value=0.7, model_identifier="m", feature_set_version="1").describe()

    assert "not a statement about who wrote it" in described


def test_a_score_outside_the_unit_interval_is_refused() -> None:
    with pytest.raises(ValueError, match=r"must be in \[0, 1\]"):
        ModelScore(value=1.2, model_identifier="m", feature_set_version="1")


def test_a_score_records_the_threshold_it_was_calibrated_at() -> None:
    result = ModelScore(
        value=0.7, model_identifier="m", feature_set_version="1", calibrated_threshold=0.62
    )

    assert result.calibrated_threshold == 0.62


# -- model cards ----------------------------------------------------------------------


def card(**extra: object) -> ModelCard:
    fields: dict[str, object] = {
        "identifier": "trueai-style-v0",
        "version": "0.1",
        "feature_set_version": "1",
        "trained_on": "sha256:" + "a" * 64,
        "intended_use": "A review aid for a human reader.",
        "known_limitations": ("Untested on writing in a second language.",),
        "created_at": NOW,
    }
    fields.update(extra)
    return ModelCard.model_validate(fields)


def test_a_model_card_must_state_a_known_limitation() -> None:
    """Every model has some; a card without them is a card nobody looked hard at."""

    with pytest.raises(ValueError):
        card(known_limitations=())


def test_a_model_card_names_the_corpus_it_was_trained_on() -> None:
    assert card().trained_on.startswith("sha256:")


def test_a_model_card_needs_an_offset_on_its_timestamp() -> None:
    with pytest.raises(ValueError, match="UTC offset"):
        card(created_at=datetime(2026, 1, 1))


def test_a_model_card_records_which_subgroups_were_evaluated() -> None:
    """So a reader can tell which ones were not."""

    assert card(evaluated_subgroups=("native", "second-language")).evaluated_subgroups == (
        "native",
        "second-language",
    )


# -- the core stays free of heavy dependencies ---------------------------------------


HEAVY = {
    "torch",
    "tensorflow",
    "jax",
    "sklearn",
    "scikit_learn",
    "numpy",
    "scipy",
    "pandas",
    "transformers",
    "onnxruntime",
    "xgboost",
    "lightgbm",
}


def imported_top_level(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return names


def test_no_module_in_the_package_imports_a_machine_learning_runtime() -> None:
    """The reason a model can be optional at all."""

    package = Path(__file__).resolve().parents[2] / "trueai"
    offenders: list[str] = []
    for module in sorted(package.rglob("*.py")):
        found = imported_top_level(module) & HEAVY
        if found:
            offenders.append(f"{module.relative_to(package).as_posix()}: {sorted(found)}")

    assert offenders == [], offenders


def test_the_check_would_notice_a_heavy_import() -> None:
    """A guard that cannot fail is not a guard."""

    import tempfile

    with tempfile.TemporaryDirectory() as directory:
        offender = Path(directory) / "sample.py"
        offender.write_text("import torch\nfrom sklearn import svm\n", encoding="utf-8")

        assert imported_top_level(offender) & HEAVY == {"torch", "sklearn"}


def test_the_feature_module_itself_needs_nothing_beyond_the_standard_library() -> None:
    module = Path(__file__).resolve().parents[2] / "trueai" / "research" / "features.py"

    external = imported_top_level(module) - {"trueai"}

    assert external <= {"hashlib", "dataclasses", "datetime", "typing", "pydantic", "__future__"}
