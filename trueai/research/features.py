"""A versioned feature contract, so a model and the code that feeds it can disagree loudly.

The arrangement this file exists to make possible: TrueAI computes features, a
model somewhere else consumes them, and neither imports the other's
dependencies.  The core stays free of anything that needs a GPU, and a model is
a thing you can add, replace, or delete without touching a detector.

That only works if the boundary between them is versioned.  A feature set is a
named, ordered list of features, and a model records which version it was
trained against.  Feed a v2 model a v1 vector and it **refuses** — because the
alternative is scoring a vector whose third column used to mean one thing and now
means another, which produces a confident number with nothing behind it and no
symptom until someone acts on it.

Two rules follow from what a model here is allowed to be:

**A model is optional.**  Its absence is not an error and, more importantly, not
a clean result.  A scan with no model available reports fewer findings, and
nothing anywhere may read that as "nothing was found".

**A model output is never provenance.**  It is a `PROBABILISTIC` measurement — a
number about a text, not a statement about who wrote it.  :class:`ModelScore`
carries no author, no attribution, and no provenance class, so a caller cannot
promote one into a claim it was never entitled to make.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Final, Protocol, Self, runtime_checkable

from pydantic import Field, model_validator

from trueai.core.errors import TrueAIError
from trueai.core.models import FrozenModel

#: Bumped whenever a feature is added, removed, reordered, or redefined. A model
#: trained against one version refuses a vector from another.
FEATURE_SET_VERSION: Final = "1"

#: A vector wider than this is a bug in an extractor, not a rich feature set.
MAX_FEATURES: Final = 4096


class FeatureError(TrueAIError):
    """Raised when a feature vector and its consumer do not agree."""


class FeatureSet(FrozenModel):
    """The names and order of the features a model was trained on.

    Order is part of the contract because a vector is positional. Two feature
    sets with the same names in a different order are different feature sets,
    and treating them as interchangeable silently permutes every column.
    """

    version: str = Field(min_length=1, max_length=32)
    names: tuple[str, ...] = Field(min_length=1, max_length=MAX_FEATURES)
    #: What each feature measures, so a model card can say what it consumed
    #: rather than listing opaque column names.
    descriptions: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def check_names(self) -> Self:
        if len(set(self.names)) != len(self.names):
            raise ValueError("Feature names must be unique within a set")
        unknown = set(self.descriptions) - set(self.names)
        if unknown:
            raise ValueError(f"Described features that are not in the set: {sorted(unknown)}")
        return self

    @property
    def digest(self) -> str:
        """A digest over version, names, and order — the whole contract."""

        joined = self.version + "\x00" + "\x00".join(self.names)
        return "sha256:" + hashlib.sha256(joined.encode("utf-8")).hexdigest()


class FeatureVector(FrozenModel):
    """One artifact's features, tagged with the set they belong to."""

    feature_set_version: str = Field(min_length=1, max_length=32)
    feature_set_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    values: tuple[float, ...] = Field(min_length=1, max_length=MAX_FEATURES)
    #: What the vector was computed from, so a score can be traced back.
    artifact_path: str = Field(min_length=1, max_length=1000)

    def matches(self, feature_set: FeatureSet) -> bool:
        """Whether this vector belongs to a feature set, contract and all."""

        return (
            self.feature_set_version == feature_set.version
            and self.feature_set_digest == feature_set.digest
            and len(self.values) == len(feature_set.names)
        )

    def named(self, feature_set: FeatureSet) -> dict[str, float]:
        """Return the vector as a mapping, refusing a set it does not match."""

        if not self.matches(feature_set):
            raise FeatureError(
                f"Vector for {self.artifact_path} does not belong to feature set "
                f"{feature_set.version}"
            )
        return dict(zip(feature_set.names, self.values, strict=True))


def build_vector(
    feature_set: FeatureSet, values: dict[str, float], *, artifact_path: str
) -> FeatureVector:
    """Order a mapping into a vector, refusing a mapping that does not fit.

    Refusing rather than filling missing features with zero: a zero is a value a
    model will happily consume, and "this feature was not computed" is not the
    same statement as "this feature measured zero".
    """

    missing = [name for name in feature_set.names if name not in values]
    if missing:
        raise FeatureError(
            f"Missing features {missing[:5]}; a vector is positional and cannot be "
            "padded, because a zero is a measurement and an absence is not"
        )
    extra = sorted(set(values) - set(feature_set.names))
    if extra:
        raise FeatureError(
            f"Features not in set {feature_set.version}: {extra[:5]}; adding one changes the "
            "contract, so bump the version rather than passing it through"
        )
    return FeatureVector(
        feature_set_version=feature_set.version,
        feature_set_digest=feature_set.digest,
        values=tuple(values[name] for name in feature_set.names),
        artifact_path=artifact_path,
    )


@dataclass(frozen=True, slots=True)
class ModelScore:
    """A model's output: a measurement, and deliberately nothing more.

    No author, no attribution, no provenance class. A caller cannot promote this
    into a claim about who wrote something, because the fields that would let
    them do it are not here.
    """

    value: float
    model_identifier: str
    feature_set_version: str
    #: The operating point the model was calibrated at, so a caller comparing
    #: against a threshold knows which one the number was meant for.
    calibrated_threshold: float | None = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.value <= 1.0:
            raise ValueError(f"A model score must be in [0, 1]; got {self.value}")

    def describe(self) -> str:
        return (
            f"{self.model_identifier} scored {self.value:.3f} on feature set "
            f"{self.feature_set_version}. This is a measurement about the text, not a "
            "statement about who wrote it."
        )


@runtime_checkable
class ScoreModel(Protocol):
    """What a model must be. Deliberately small, and importable without a GPU."""

    #: What the model is called, recorded on every score it produces.
    identifier: str
    #: The feature set it was trained against. A mismatch refuses.
    feature_set_version: str

    def score(self, vector: FeatureVector, /) -> ModelScore: ...


class ModelCard(FrozenModel):
    """What a model is, what it was trained on, and where it should not be used.

    Required alongside the model rather than encouraged: a score whose training
    data, intended use, and known failure modes are undocumented is a number
    nobody can responsibly act on, and the moment to write them down is before
    it ships.
    """

    identifier: str = Field(min_length=1, max_length=300)
    version: str = Field(min_length=1, max_length=32)
    feature_set_version: str = Field(min_length=1, max_length=32)
    #: The corpus digest from `CorpusManifest.digest()`.
    trained_on: str = Field(min_length=1, max_length=120)
    intended_use: str = Field(min_length=1, max_length=2000)
    #: Where it is known to fail. Required, because every model has some and a
    #: card without them is a card nobody looked hard at.
    known_limitations: tuple[str, ...] = Field(min_length=1)
    #: The subgroups it was evaluated on, so a reader can tell which were not.
    evaluated_subgroups: tuple[str, ...] = ()
    created_at: datetime

    @model_validator(mode="after")
    def check_card(self) -> Self:
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("Model creation time must include a UTC offset")
        return self


def score_with(model: ScoreModel, vector: FeatureVector) -> ModelScore:
    """Score a vector, refusing one the model was not trained for.

    The refusal is the point. A v2 model handed a v1 vector would otherwise
    produce a confident number over columns that changed meaning, with no
    symptom until somebody acts on it.
    """

    if model.feature_set_version != vector.feature_set_version:
        raise FeatureError(
            f"Model {model.identifier} was trained on feature set "
            f"{model.feature_set_version} and was given {vector.feature_set_version}; "
            "scoring it would compare columns that changed meaning"
        )
    result = model.score(vector)
    if result.feature_set_version != vector.feature_set_version:
        raise FeatureError(
            f"Model {model.identifier} returned a score tagged with feature set "
            f"{result.feature_set_version}, which is not the one it was given"
        )
    return result


def try_score(model: ScoreModel | None, vector: FeatureVector) -> ModelScore | None:
    """Score if a model is available, and return ``None`` if none is.

    ``None`` means *not measured*. It is never "clean", and a caller that renders
    it as an absence of findings is making a claim this function did not.
    """

    if model is None:
        return None
    return score_with(model, vector)


__all__ = [
    "FEATURE_SET_VERSION",
    "MAX_FEATURES",
    "FeatureError",
    "FeatureSet",
    "FeatureVector",
    "ModelCard",
    "ModelScore",
    "ScoreModel",
    "build_vector",
    "score_with",
    "try_score",
]
