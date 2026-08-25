"""Rules a labelled corpus must satisfy, written as code before one is collected.

Corpus governance stated as prose gets read once and then contradicted by
whoever is actually collecting the data, usually without noticing.  So these are
constructors that refuse, not guidance that advises: a sample without a consent
record cannot be admitted, and a corpus without a policy cannot be built.

Five rules, and the reason each is separate:

**Consent** is a person agreeing that their work may be used.  It is scoped, it
expires, and it can be **withdrawn** — and withdrawal has to reach backwards
through everything already collected under it, which is the requirement most
easily written down and least often implemented.

**Licensing** is the rights holder permitting the use.  It is *not* consent, and
conflating them is the mistake this separation exists to prevent: the person who
hands over a document is frequently not the person who owns it.  A sample needs
both, and either one missing refuses it.

**Domain balance** decides what a model trained on the corpus actually learns.
A corpus that is ninety percent one domain produces a domain detector wearing an
AI-detector label, and it will be most confident exactly where it is least
entitled to be.

**Contamination control** compares content digests, never paths.  The same
document under two names in two splits is one document, and an evaluation number
computed over it is a memory test.

**Retention** is when the data must be gone.  Recorded per sample, because a
corpus assembled from many sources inherits many different obligations, and the
shortest one governs each sample rather than the corpus.

Nothing here ships a default policy, for the same reason no default trust store
ships: deciding what may be collected is not a decision a library gets to make
on an operator's behalf.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final, Self

from pydantic import Field, model_validator

from trueai.core.errors import TrueAIError
from trueai.core.models import FrozenModel

CORPUS_SCHEMA_VERSION: Final = "0.1"

#: A corpus large enough to matter is large enough to need a bound.
MAX_SAMPLES: Final = 1_000_000


class CorpusError(TrueAIError):
    """Raised when a corpus rule is violated rather than merely reported."""


class Split(StrEnum):
    """Which part of an evaluation a sample belongs to."""

    TRAIN = "train"
    VALIDATION = "validation"
    #: Held out. A sample here must never have been seen during training, which
    #: is the property `contamination` exists to check.
    TEST = "test"


class ConsentStatus(StrEnum):
    """Where a consent record stands right now."""

    GRANTED = "granted"
    #: Withdrawn by the person who gave it. Retroactive by design.
    WITHDRAWN = "withdrawn"
    EXPIRED = "expired"


class LicenseUse(StrEnum):
    """What a license permits, as it bears on a corpus."""

    #: Training a model on the content.
    MODEL_TRAINING = "model_training"
    #: Redistributing the content itself, as opposed to a model derived from it.
    REDISTRIBUTION = "redistribution"
    #: Publishing excerpts in a paper or a report.
    QUOTATION = "quotation"


class ConsentRecord(FrozenModel):
    """One person's agreement, with its scope, its clock, and its off switch."""

    consent_id: str = Field(min_length=1, max_length=120)
    #: Who agreed. An organization is not a person; if an organization agreed on
    #: someone's behalf, that belongs in `granted_by` with the arrangement named.
    granted_by: str = Field(min_length=1, max_length=300)
    granted_at: datetime
    #: What they agreed to. Consent to research use is not consent to
    #: redistribution, and a record that does not say which is not a record.
    purposes: tuple[str, ...] = Field(min_length=1)
    status: ConsentStatus = ConsentStatus.GRANTED
    expires_at: datetime | None = None
    withdrawn_at: datetime | None = None
    #: How the person withdraws. Recorded because consent nobody can revoke is
    #: not consent, and an address that stops working makes it permanent.
    withdrawal_contact: str = Field(min_length=1, max_length=300)

    @model_validator(mode="after")
    def check_record(self) -> Self:
        for label, value in (
            ("grant", self.granted_at),
            ("expiry", self.expires_at),
            ("withdrawal", self.withdrawn_at),
        ):
            if value is not None and (value.tzinfo is None or value.utcoffset() is None):
                raise ValueError(f"Consent {label} time must include a UTC offset")
        if self.expires_at is not None and self.expires_at <= self.granted_at:
            raise ValueError("Consent that expires before it is granted was never given")
        if self.status is ConsentStatus.WITHDRAWN and self.withdrawn_at is None:
            raise ValueError("A withdrawn consent must record when it was withdrawn")
        if self.withdrawn_at is not None and self.status is not ConsentStatus.WITHDRAWN:
            raise ValueError("A record with a withdrawal time must be marked withdrawn")
        return self

    def covers(self, purpose: str, moment: datetime) -> bool:
        """Return whether this consent permits a purpose at a moment."""

        if self.status is not ConsentStatus.GRANTED:
            return False
        if moment < self.granted_at:
            return False
        if self.expires_at is not None and moment >= self.expires_at:
            return False
        return purpose in self.purposes


class LicenseTerms(FrozenModel):
    """What the rights holder permits. A different question from consent."""

    identifier: str = Field(min_length=1, max_length=120)
    #: The rights holder, who is often not the person who handed the file over.
    holder: str = Field(min_length=1, max_length=300)
    permits: frozenset[LicenseUse] = frozenset()
    #: Obligations that travel with the sample — attribution, share-alike, a
    #: notice file. Recorded so they are not discovered at publication time.
    obligations: tuple[str, ...] = ()

    def permits_use(self, use: LicenseUse) -> bool:
        return use in self.permits


class RetentionRule(FrozenModel):
    """When data must be gone, and what "gone" means."""

    #: Days from collection. `None` means indefinite, which must be a deliberate
    #: statement rather than the result of nobody choosing.
    retain_days: int | None = Field(default=None, ge=1)
    #: How deletion is performed and verified. A rule with no mechanism is a
    #: sentence in a policy document.
    deletion_method: str = Field(min_length=1, max_length=500)
    #: Whether withdrawing consent obliges deletion of everything derived from
    #: the sample, or only of the sample itself. Both are defensible; leaving it
    #: unstated is not.
    withdrawal_requires_derivative_deletion: bool = True

    def expires_at(self, collected_at: datetime) -> datetime | None:
        if self.retain_days is None:
            return None
        return collected_at + timedelta(days=self.retain_days)


class DomainBalance(FrozenModel):
    """What mix of domains the corpus is supposed to have."""

    #: Domain name to intended share, summing to 1. Written down in advance,
    #: because a target chosen after the data arrives is a description.
    targets: dict[str, float] = Field(min_length=1)
    #: How far an actual share may drift from its target before the corpus is
    #: reported as imbalanced.
    tolerance: float = Field(default=0.1, gt=0.0, le=1.0)

    @model_validator(mode="after")
    def check_targets(self) -> Self:
        total = sum(self.targets.values())
        if not 0.99 <= total <= 1.01:
            raise ValueError(f"Domain targets must sum to 1, not {total:.3f}")
        if any(share <= 0 for share in self.targets.values()):
            raise ValueError("A domain with a zero target does not belong in the plan")
        return self


class ContaminationControl(FrozenModel):
    """How train and test are kept apart."""

    #: Compare content digests rather than paths. The same document under two
    #: names is one document, and an evaluation over it is a memory test.
    compare_by_content_digest: bool = True
    #: Whether near-duplicates must also be excluded, and by what method. Exact
    #: digests miss a reformatted copy.
    near_duplicate_method: str | None = Field(default=None, max_length=300)
    #: Sources that may appear only in the held-out split, so a model cannot
    #: learn a source-specific shortcut and be scored on it.
    holdout_only_sources: tuple[str, ...] = ()

    @model_validator(mode="after")
    def check_control(self) -> Self:
        if not self.compare_by_content_digest:
            raise ValueError(
                "Contamination control that does not compare content digests compares paths, "
                "and the same document under two names would pass"
            )
        return self


class CorpusPolicy(FrozenModel):
    """The five rules together. A corpus cannot be built without one."""

    schema_version: str = CORPUS_SCHEMA_VERSION
    policy_id: str = Field(min_length=1, max_length=120)
    #: Who is accountable for this policy. A policy nobody owns is not enforced.
    owner: str = Field(min_length=1, max_length=300)
    #: The purpose samples are collected for, matched against each consent
    #: record. One policy, one purpose: a policy covering several purposes lets
    #: consent for the narrow one authorise the broad one.
    purpose: str = Field(min_length=1, max_length=300)
    required_license_uses: frozenset[LicenseUse] = frozenset({LicenseUse.MODEL_TRAINING})
    balance: DomainBalance
    contamination: ContaminationControl
    retention: RetentionRule


class CorpusSample(FrozenModel):
    """One labelled sample and everything needed to decide it may be here."""

    sample_id: str = Field(min_length=1, max_length=120)
    #: The content digest, which is what contamination is checked on.
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    domain: str = Field(min_length=1, max_length=120)
    split: Split
    source: str = Field(min_length=1, max_length=300)
    collected_at: datetime
    consent_id: str = Field(min_length=1, max_length=120)
    license: LicenseTerms
    #: The label, kept as free text: this module governs collection and takes no
    #: position on a labelling scheme.
    label: str = Field(min_length=1, max_length=300)

    @model_validator(mode="after")
    def check_time(self) -> Self:
        if self.collected_at.tzinfo is None or self.collected_at.utcoffset() is None:
            raise ValueError("Collection time must include a UTC offset")
        return self


class AdmissionDecision(FrozenModel):
    """Whether one sample may be collected, and every reason it may not."""

    sample_id: str
    admitted: bool
    #: Plural: an operator fixing one refusal should see the others rather than
    #: discovering them one submission at a time.
    refusals: tuple[str, ...] = ()

    def explain(self) -> str:
        if self.admitted:
            return f"{self.sample_id}: admitted."
        return f"{self.sample_id}: refused — " + "; ".join(self.refusals)


class CorpusAudit(FrozenModel):
    """What is wrong with a corpus as it stands."""

    sample_count: int
    #: Samples whose consent was withdrawn or expired since collection. These
    #: are a deletion obligation, not a warning.
    must_delete: tuple[str, ...] = ()
    #: Digests appearing in more than one split.
    contaminated: tuple[str, ...] = ()
    #: Domain to (actual share, target share) where the drift exceeds tolerance.
    imbalanced: dict[str, tuple[float, float]] = Field(default_factory=dict)
    #: Sources the policy reserves for the held-out split that appear elsewhere.
    leaked_sources: tuple[str, ...] = ()
    #: Samples past their retention period.
    overdue: tuple[str, ...] = ()

    @property
    def usable(self) -> bool:
        """Whether the corpus may be used for training or evaluation at all.

        Imbalance does not block: it is a property to report alongside any
        result, and a corpus can be legitimately imbalanced on purpose. The
        other four do block, because each of them makes a number meaningless or
        makes holding the data unlawful.
        """

        return not (self.must_delete or self.contaminated or self.leaked_sources or self.overdue)

    def explain(self) -> str:
        if self.usable and not self.imbalanced:
            return f"{self.sample_count} samples, no findings."
        parts = []
        if self.must_delete:
            parts.append(f"{len(self.must_delete)} samples must be deleted")
        if self.contaminated:
            parts.append(f"{len(self.contaminated)} digests appear in more than one split")
        if self.leaked_sources:
            parts.append(f"{len(self.leaked_sources)} held-out sources appear in training")
        if self.overdue:
            parts.append(f"{len(self.overdue)} samples are past retention")
        if self.imbalanced:
            parts.append(f"{len(self.imbalanced)} domains are outside tolerance")
        return f"{self.sample_count} samples: " + "; ".join(parts) + "."


class CorpusManifest(FrozenModel):
    """A corpus, its policy, and the consent records behind it.

    Constructed together on purpose. A manifest that could hold samples without
    a policy would be a corpus collected first and governed afterwards, which is
    the order this module exists to prevent.
    """

    schema_version: str = CORPUS_SCHEMA_VERSION
    policy: CorpusPolicy
    consents: tuple[ConsentRecord, ...] = ()
    samples: tuple[CorpusSample, ...] = Field(default=(), max_length=MAX_SAMPLES)

    @model_validator(mode="after")
    def check_manifest(self) -> Self:
        identifiers = [sample.sample_id for sample in self.samples]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("Sample identifiers must be unique within a corpus")
        consent_ids = [record.consent_id for record in self.consents]
        if len(set(consent_ids)) != len(consent_ids):
            raise ValueError("Consent identifiers must be unique within a corpus")
        return self

    def consent(self, consent_id: str) -> ConsentRecord | None:
        return next((record for record in self.consents if record.consent_id == consent_id), None)

    def digest(self) -> str:
        """A digest over the sample identities, so a corpus can be cited."""

        joined = "\x00".join(
            f"{sample.sample_id}:{sample.content_sha256}:{sample.split.value}"
            for sample in sorted(self.samples, key=lambda item: item.sample_id)
        )
        return "sha256:" + hashlib.sha256(joined.encode("utf-8")).hexdigest()


# -- admission -------------------------------------------------------------------------


def admit(
    sample: CorpusSample,
    *,
    policy: CorpusPolicy,
    consent: ConsentRecord | None,
    existing: tuple[CorpusSample, ...] = (),
    now: datetime | None = None,
) -> AdmissionDecision:
    """Decide whether one sample may enter the corpus, before it is collected."""

    moment = now or datetime.now(UTC)
    refusals: list[str] = []

    if consent is None:
        refusals.append(f"no consent record {sample.consent_id} exists")
    elif consent.status is ConsentStatus.WITHDRAWN:
        refusals.append(f"consent {consent.consent_id} was withdrawn")
    elif not consent.covers(policy.purpose, moment):
        refusals.append(
            f"consent {consent.consent_id} does not cover {policy.purpose!r} at this time"
        )

    # Checked separately from consent on purpose: the person who handed over a
    # document is frequently not the person who owns it.
    missing = policy.required_license_uses - sample.license.permits
    if missing:
        refusals.append(
            "license "
            + sample.license.identifier
            + " does not permit "
            + ", ".join(sorted(use.value for use in missing))
        )

    if policy.balance.targets and sample.domain not in policy.balance.targets:
        refusals.append(
            f"domain {sample.domain!r} is not in the collection plan; add it deliberately "
            "rather than letting the corpus drift"
        )

    expiry = policy.retention.expires_at(sample.collected_at)
    if expiry is not None and moment >= expiry:
        refusals.append("the sample is already past its retention period")

    duplicate = next(
        (
            item
            for item in existing
            if item.content_sha256 == sample.content_sha256 and item.split is not sample.split
        ),
        None,
    )
    if duplicate is not None:
        refusals.append(
            f"the same content is already in the {duplicate.split.value} split as "
            f"{duplicate.sample_id}"
        )

    if (
        sample.source in policy.contamination.holdout_only_sources
        and sample.split is not Split.TEST
    ):
        refusals.append(
            f"source {sample.source!r} is reserved for the held-out split, so a model cannot "
            "learn a source-specific shortcut and then be scored on it"
        )

    return AdmissionDecision(
        sample_id=sample.sample_id, admitted=not refusals, refusals=tuple(refusals)
    )


def admit_all(
    manifest: CorpusManifest,
    candidates: tuple[CorpusSample, ...],
    *,
    now: datetime | None = None,
) -> tuple[AdmissionDecision, ...]:
    """Decide a batch, each candidate against the corpus *and* the ones before it."""

    accumulated = list(manifest.samples)
    decisions: list[AdmissionDecision] = []
    for candidate in candidates:
        decision = admit(
            candidate,
            policy=manifest.policy,
            consent=manifest.consent(candidate.consent_id),
            existing=tuple(accumulated),
            now=now,
        )
        decisions.append(decision)
        if decision.admitted:
            # Added before the next candidate is judged, so two copies of the
            # same content in one batch cannot both slip in.
            accumulated.append(candidate)
    return tuple(decisions)


# -- auditing --------------------------------------------------------------------------


def audit_corpus(manifest: CorpusManifest, *, now: datetime | None = None) -> CorpusAudit:
    """Report everything wrong with a corpus that already exists."""

    moment = now or datetime.now(UTC)
    policy = manifest.policy

    must_delete: list[str] = []
    overdue: list[str] = []
    leaked: list[str] = []
    by_digest: dict[str, set[Split]] = {}
    domains: Counter[str] = Counter()

    for sample in manifest.samples:
        consent = manifest.consent(sample.consent_id)
        # Withdrawal reaches backwards: this is the requirement most often
        # written down and least often implemented.
        if consent is None or not consent.covers(policy.purpose, moment):
            must_delete.append(sample.sample_id)
        expiry = policy.retention.expires_at(sample.collected_at)
        if expiry is not None and moment >= expiry:
            overdue.append(sample.sample_id)
        if (
            sample.source in policy.contamination.holdout_only_sources
            and sample.split is not Split.TEST
        ):
            leaked.append(sample.sample_id)
        by_digest.setdefault(sample.content_sha256, set()).add(sample.split)
        domains[sample.domain] += 1

    contaminated = tuple(sorted(digest for digest, splits in by_digest.items() if len(splits) > 1))

    imbalanced: dict[str, tuple[float, float]] = {}
    total = sum(domains.values())
    if total:
        for domain, target in policy.balance.targets.items():
            actual = domains.get(domain, 0) / total
            if abs(actual - target) > policy.balance.tolerance:
                imbalanced[domain] = (round(actual, 4), target)

    return CorpusAudit(
        sample_count=len(manifest.samples),
        must_delete=tuple(sorted(must_delete)),
        contaminated=contaminated,
        imbalanced=imbalanced,
        leaked_sources=tuple(sorted(leaked)),
        overdue=tuple(sorted(overdue)),
    )


def withdraw_consent(
    manifest: CorpusManifest, consent_id: str, *, withdrawn_at: datetime
) -> tuple[CorpusManifest, tuple[str, ...]]:
    """Withdraw a consent and return the manifest plus what must now be deleted.

    The samples are *not* removed here. Deleting them is a filesystem operation
    with its own obligations under the retention rule, and a function that
    silently dropped rows from a manifest would let an operator believe data was
    gone when only its record was.
    """

    record = manifest.consent(consent_id)
    if record is None:
        raise CorpusError(f"No consent record {consent_id} to withdraw")
    if withdrawn_at.tzinfo is None or withdrawn_at.utcoffset() is None:
        raise CorpusError("Withdrawal time must include a UTC offset")
    updated = record.model_copy(
        update={"status": ConsentStatus.WITHDRAWN, "withdrawn_at": withdrawn_at}
    )
    consents = tuple(
        updated if item.consent_id == consent_id else item for item in manifest.consents
    )
    affected = tuple(
        sorted(sample.sample_id for sample in manifest.samples if sample.consent_id == consent_id)
    )
    return manifest.model_copy(update={"consents": consents}), affected


__all__ = [
    "CORPUS_SCHEMA_VERSION",
    "MAX_SAMPLES",
    "AdmissionDecision",
    "ConsentRecord",
    "ConsentStatus",
    "ContaminationControl",
    "CorpusAudit",
    "CorpusError",
    "CorpusManifest",
    "CorpusPolicy",
    "CorpusSample",
    "DomainBalance",
    "LicenseTerms",
    "LicenseUse",
    "RetentionRule",
    "Split",
    "admit",
    "admit_all",
    "audit_corpus",
    "withdraw_consent",
]
