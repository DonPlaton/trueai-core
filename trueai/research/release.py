"""What must exist before a learned score is shown to anyone.

A model that scores text about whether a person wrote it is not shipped because
it works.  It is shipped because someone can answer, afterwards and under
pressure, four questions: what was it trained on, what is it for, what does it
get wrong, and is this the model I think it is.

So the release gate requires five artifacts and refuses without them:

**A model card** — identifier, feature set, corpus digest, intended use, and at
least one known limitation.  Defined in :mod:`trueai.research.features`.

**A dataset statement** — what the corpus is, how it was assembled, and, the
field that matters most, **what it does not represent**.  A corpus of published
English technical writing does not represent a student writing in a second
language, and the moment to say so is before a model trained on it is used to
judge one.

**A signed manifest** — content-addressed over the card, the statement, the
thresholds, and the digests of the model's own files, so "is this the model that
was evaluated" has an answer that does not depend on a filename.

**Versioned thresholds** — an operating point belongs to one model version and
one feature set version, and it carries the digest of the evaluation that
justified it.  A threshold copied from a previous model is a number nobody
measured.

**A regression gate** — and the rule that makes it worth having: a rise in the
false positive rate blocks a release *even when the overall numbers improved*.
Averages let a model get better at finding machine text while getting worse at
accusing people, and only one of those two costs a person something.  The
worst-subgroup rate is gated separately for the same reason at a smaller scale:
an improvement in the mean that comes out of one cohort is not an improvement.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Final, Self

from pydantic import Field, model_validator

from trueai.core.certificates import (
    CertificateSignature,
    canonical_json_bytes,
    sign_detached_payload,
    verify_detached_payload,
)
from trueai.core.errors import TrueAIError
from trueai.core.models import FrozenModel
from trueai.research.evaluation import EvaluationResult
from trueai.research.features import ModelCard

MODEL_MANIFEST_SCHEMA_VERSION: Final = "0.1"

#: Model manifests get their own prefix. A certificate, an attestation, a plugin
#: distribution, a trust store, and a model manifest are five different claims.
MODEL_MANIFEST_ID_PREFIX: Final = "TAIMDL1-"

#: How much the false positive rate may rise before a release is blocked.
#: Deliberately small: this is the number that decides whether more people get
#: told their own writing was machine-generated.
DEFAULT_FALSE_POSITIVE_TOLERANCE: Final = 0.005


class ReleaseError(TrueAIError):
    """Raised when a model release requirement cannot be satisfied."""


class DatasetStatement(FrozenModel):
    """What a corpus is, and — the part that matters — what it is not.

    Every field is required. A dataset statement with the awkward sections left
    blank is the one that gets written, and the awkward sections are the reason
    to write one at all.
    """

    corpus_digest: str = Field(min_length=1, max_length=120)
    #: Why this data was gathered, in the collectors' own words.
    curation_rationale: str = Field(min_length=1, max_length=4000)
    #: How it was obtained. "Scraped" and "contributed under agreement" produce
    #: very different corpora and very different obligations.
    collection_process: str = Field(min_length=1, max_length=4000)
    #: How labels were produced and by whom. A label is a judgement, and whose
    #: judgement it was belongs in the record.
    annotation_process: str = Field(min_length=1, max_length=4000)
    #: Language varieties present — dialect, register, whether writing by
    #: second-language authors is included and in what proportion.
    language_varieties: tuple[str, ...] = Field(min_length=1)
    #: Demographic information *if it was collected*. Empty means it was not
    #: collected, which is a fact about the corpus rather than a fact about the
    #: population, and a reader must be able to tell those apart.
    author_demographics: tuple[str, ...] = ()
    demographics_collected: bool = False
    #: The field this whole model exists for. A corpus of published English
    #: technical writing does not represent a student writing in a second
    #: language, and saying so before a model judges one is the point.
    does_not_represent: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def check_statement(self) -> Self:
        if self.author_demographics and not self.demographics_collected:
            raise ValueError(
                "Demographics are listed but the statement says none were collected; "
                "one of the two is wrong and a reader cannot tell which"
            )
        return self


class OperatingPoint(FrozenModel):
    """One threshold, and the evidence that chose it."""

    name: str = Field(min_length=1, max_length=120)
    threshold: float = Field(ge=0.0, le=1.0)
    #: What this operating point is for — screening, review triage, a report
    #: footnote. A threshold without a use is a number waiting to be misapplied.
    intended_use: str = Field(min_length=1, max_length=1000)
    #: The false positive rate measured at this threshold, so a caller does not
    #: have to go looking for it.
    measured_false_positive_rate: float = Field(ge=0.0, le=1.0)


class ThresholdSet(FrozenModel):
    """Operating points bound to one model version and one feature set.

    Bound, because a threshold copied from a previous model is a number nobody
    measured on the model it is being applied to.
    """

    model_version: str = Field(min_length=1, max_length=32)
    feature_set_version: str = Field(min_length=1, max_length=32)
    #: Digest of the evaluation that produced these numbers.
    evaluation_digest: str = Field(min_length=1, max_length=120)
    points: tuple[OperatingPoint, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def check_points(self) -> Self:
        names = [point.name for point in self.points]
        if len(set(names)) != len(names):
            raise ValueError("Operating point names must be unique within a set")
        return self

    def point(self, name: str) -> OperatingPoint | None:
        return next((item for item in self.points if item.name == name), None)


class ModelFile(FrozenModel):
    """One file the manifest covers, by digest rather than by name."""

    path: str = Field(min_length=1, max_length=1000)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=0)


class ModelManifest(FrozenModel):
    """Everything about one model release, content-addressed and signable."""

    schema_version: str = MODEL_MANIFEST_SCHEMA_VERSION
    manifest_id: str = Field(pattern=r"^TAIMDL1-[A-Z2-7]{32}$")
    card: ModelCard
    dataset: DatasetStatement
    thresholds: ThresholdSet
    files: tuple[ModelFile, ...] = Field(min_length=1)
    created_at: datetime
    signature: CertificateSignature | None = None

    @model_validator(mode="after")
    def check_manifest(self) -> Self:
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("Manifest creation time must include a UTC offset")
        if self.card.feature_set_version != self.thresholds.feature_set_version:
            raise ValueError(
                f"The card was built for feature set {self.card.feature_set_version} and the "
                f"thresholds for {self.thresholds.feature_set_version}; one of them is stale"
            )
        if self.card.version != self.thresholds.model_version:
            raise ValueError(
                f"The card describes model {self.card.version} and the thresholds were "
                f"measured on {self.thresholds.model_version}"
            )
        if self.card.trained_on != self.dataset.corpus_digest:
            raise ValueError(
                "The card names a different corpus than the dataset statement describes"
            )
        paths = [item.path for item in self.files]
        if len(set(paths)) != len(paths):
            raise ValueError("A file may appear only once in a manifest")
        return self

    def signed_payload(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json", exclude={"signature"}))


@dataclass(frozen=True, slots=True)
class RegressionVerdict:
    """Whether a candidate may replace a baseline, and every reason it may not."""

    passed: bool
    reasons: tuple[str, ...] = ()
    #: What moved, for a release note that says something.
    deltas: tuple[str, ...] = ()

    def explain(self) -> str:
        if self.passed:
            note = f" Changes: {'; '.join(self.deltas)}." if self.deltas else ""
            return f"No regression.{note}"
        return "Blocked: " + "; ".join(self.reasons)


@dataclass(frozen=True, slots=True)
class ReleaseDecision:
    """Whether a learned score may be shown to anyone."""

    may_expose: bool
    refusals: tuple[str, ...] = ()

    def explain(self) -> str:
        if self.may_expose:
            return "The model may be exposed."
        return "The model may not be exposed: " + "; ".join(self.refusals)


# -- building and signing ---------------------------------------------------------------


def compute_manifest_id(manifest: ModelManifest) -> str:
    """Derive the identifier from everything the manifest claims."""

    payload = manifest.model_dump(mode="json", exclude={"manifest_id", "signature"})
    digest = hashlib.sha256(canonical_json_bytes(payload)).digest()
    return MODEL_MANIFEST_ID_PREFIX + base64.b32encode(digest)[:32].decode("ascii")


def build_manifest(
    *,
    card: ModelCard,
    dataset: DatasetStatement,
    thresholds: ThresholdSet,
    files: tuple[ModelFile, ...],
    created_at: datetime,
) -> ModelManifest:
    """Build an unsigned, content-addressed model manifest."""

    draft = ModelManifest(
        manifest_id=MODEL_MANIFEST_ID_PREFIX + "A" * 32,
        card=card,
        dataset=dataset,
        thresholds=thresholds,
        files=files,
        created_at=created_at,
    )
    return draft.model_copy(update={"manifest_id": compute_manifest_id(draft)})


def sign_manifest(manifest: ModelManifest, *, signing_key: str | Path) -> ModelManifest:
    """Sign a manifest, refusing one whose identifier no longer fits its contents."""

    if compute_manifest_id(manifest) != manifest.manifest_id:
        raise ReleaseError(
            "The manifest identifier does not match its contents; rebuild it before signing"
        )
    signature = sign_detached_payload(manifest.signed_payload(), signing_key)
    return manifest.model_copy(update={"signature": signature})


def verify_manifest(
    manifest: ModelManifest,
    *,
    public_key: str | Path,
    root: Path | None,
) -> tuple[bool, tuple[str, ...]]:
    """Check a manifest's identity, signature, and — when given a root — its files.

    ``root`` has no default. A signature proves the digests in the manifest are
    the ones the signer recorded; only reading the files proves the bytes on
    this disk are those digests. Defaulting to ``None`` made the weaker check
    the one a caller got by writing less, and :func:`may_expose` receives the
    verdict as a pair it cannot interrogate — a manifest whose files were never
    opened reached the gate indistinguishable from one whose files matched.
    Passing ``None`` is still allowed and still means "signature only"; it is
    now a decision visible at the call site, which is the same rule this module
    already applies to a skipped regression check.
    """

    problems: list[str] = []
    if compute_manifest_id(manifest) != manifest.manifest_id:
        problems.append("the manifest identifier does not match its own contents")
    if manifest.signature is None:
        problems.append("the manifest is unsigned")
    else:
        try:
            verified = verify_detached_payload(
                manifest.signature, manifest.signed_payload(), public_key
            )
        except Exception as exc:  # the key is caller-supplied and may be anything
            problems.append(f"the public key could not be read: {exc}")
        else:
            if not verified:
                problems.append("the signature does not verify")

    if root is not None:
        for item in manifest.files:
            candidate = root / item.path
            # Compared by digest, never by name: the question is whether these
            # are the bytes that were evaluated.
            try:
                data = candidate.read_bytes()
            except OSError as exc:
                problems.append(f"{item.path} could not be read: {exc}")
                continue
            if hashlib.sha256(data).hexdigest() != item.sha256:
                problems.append(f"{item.path} does not match the digest in the manifest")
            elif len(data) != item.size_bytes:
                problems.append(f"{item.path} is a different size than the manifest records")
    return not problems, tuple(problems)


# -- regression -------------------------------------------------------------------------


def check_regression(
    baseline: EvaluationResult,
    candidate: EvaluationResult,
    *,
    false_positive_tolerance: float = DEFAULT_FALSE_POSITIVE_TOLERANCE,
) -> RegressionVerdict:
    """Decide whether a candidate may replace a baseline.

    A rise in the false positive rate blocks the release even when everything
    else improved. Averages let a model get better at finding machine text while
    getting worse at accusing people, and only one of those two costs a person
    something.
    """

    reasons: list[str] = []
    deltas: list[str] = []

    before = baseline.false_positive.rate
    after = candidate.false_positive.rate
    if before is None or after is None:
        reasons.append("one of the two evaluations has no false positive rate to compare")
    else:
        change = after - before
        deltas.append(f"false positives {before:.2%} → {after:.2%}")
        if change > false_positive_tolerance:
            reasons.append(
                f"the false positive rate rose {change:.2%}, above the "
                f"{false_positive_tolerance:.2%} tolerance"
            )

    # Gated separately: an improvement in the mean that comes out of one cohort
    # is not an improvement.
    worst_before = baseline.worst_subgroup()
    worst_after = candidate.worst_subgroup()
    if worst_before is not None and worst_after is not None:
        first = worst_before.false_positive.rate or 0.0
        second = worst_after.false_positive.rate or 0.0
        deltas.append(f"worst subgroup {first:.2%} → {second:.2%} ({worst_after.name})")
        if second - first > false_positive_tolerance:
            reasons.append(
                f"the worst subgroup's false positive rate rose {second - first:.2%} "
                f"({worst_after.name})"
            )
    elif worst_before is not None and worst_after is None:
        reasons.append(
            "the baseline scored a worst subgroup and the candidate scored none, so the "
            "comparison would hide whichever cohort was dropped"
        )

    coverage_before = baseline.coverage
    coverage_after = candidate.coverage
    if coverage_before is not None and coverage_after is not None:
        deltas.append(f"coverage {coverage_before:.1%} → {coverage_after:.1%}")
        if coverage_after < coverage_before - 0.05:
            # Abstaining more is an easy way to improve every other number.
            reasons.append(
                f"coverage fell {coverage_before - coverage_after:.1%}; abstaining more "
                "improves every other number for free"
            )

    calibration_change = candidate.calibration.expected_error - baseline.calibration.expected_error
    deltas.append(
        f"calibration error {baseline.calibration.expected_error:.2%} → "
        f"{candidate.calibration.expected_error:.2%}"
    )
    if calibration_change > 0.05:
        reasons.append(f"calibration error rose {calibration_change:.2%}")

    return RegressionVerdict(passed=not reasons, reasons=tuple(reasons), deltas=tuple(deltas))


# -- the gate ---------------------------------------------------------------------------


def may_expose(
    manifest: ModelManifest,
    *,
    verification: tuple[bool, tuple[str, ...]],
    evaluation: EvaluationResult,
    regression: RegressionVerdict | None = None,
) -> ReleaseDecision:
    """Decide whether a learned score may be shown to anyone.

    ``regression`` is ``None`` for a first release, which is allowed — there is
    nothing to regress against. It is not a way to skip the check on a later
    one: passing ``None`` for a replacement is a decision someone has to make
    deliberately, and it will be visible in whatever calls this.
    """

    refusals: list[str] = []

    valid, problems = verification
    if not valid:
        refusals.extend(f"manifest: {item}" for item in problems)

    if evaluation.record.model_identifier != manifest.card.identifier:
        refusals.append(
            f"the evaluation scored {evaluation.record.model_identifier!r} and the manifest "
            f"describes {manifest.card.identifier!r}"
        )

    if evaluation.record.corpus_digest != manifest.dataset.corpus_digest:
        refusals.append(
            "the evaluation was run over a different corpus than the dataset statement describes"
        )

    # The thresholds being shipped have to be ones somebody measured on this
    # model. An operating point nobody evaluated is a number waiting to be quoted.
    evaluated = evaluation.record.threshold
    if not any(point.threshold == evaluated for point in manifest.thresholds.points):
        refusals.append(
            f"the evaluation was run at threshold {evaluated} and no operating point in the "
            "manifest uses it, so the shipped thresholds were never measured"
        )

    for problem in evaluation.problems():
        refusals.append(f"evaluation: {problem}")

    if regression is not None and not regression.passed:
        refusals.extend(f"regression: {reason}" for reason in regression.reasons)

    return ReleaseDecision(may_expose=not refusals, refusals=tuple(refusals))


__all__ = [
    "DEFAULT_FALSE_POSITIVE_TOLERANCE",
    "MODEL_MANIFEST_ID_PREFIX",
    "MODEL_MANIFEST_SCHEMA_VERSION",
    "DatasetStatement",
    "ModelFile",
    "ModelManifest",
    "OperatingPoint",
    "RegressionVerdict",
    "ReleaseDecision",
    "ReleaseError",
    "ThresholdSet",
    "build_manifest",
    "check_regression",
    "compute_manifest_id",
    "may_expose",
    "sign_manifest",
    "verify_manifest",
]
