"""Corpus rules that refuse rather than advise.

Governance written as prose gets read once and contradicted by whoever is
actually collecting the data. These tests are about the difference: each one
takes a sample that violates a rule and checks the sample does not get in.

Three distinctions carry most of the weight — consent is not a license, a
withdrawal reaches backwards through everything already collected, and
contamination is a question about content rather than about paths.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from trueai.research import (
    ConsentRecord,
    ConsentStatus,
    ContaminationControl,
    CorpusError,
    CorpusManifest,
    CorpusPolicy,
    CorpusSample,
    DomainBalance,
    LicenseTerms,
    LicenseUse,
    RetentionRule,
    Split,
    admit,
    admit_all,
    audit_corpus,
    withdraw_consent,
)

NOW = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
TRAINING = frozenset({LicenseUse.MODEL_TRAINING})


def consent(**extra: Any) -> ConsentRecord:
    fields: dict[str, Any] = {
        "consent_id": "consent-1",
        "granted_by": "A contributor",
        "granted_at": NOW - timedelta(days=30),
        "purposes": ("detector-evaluation",),
        "withdrawal_contact": "privacy@example.test",
    }
    fields.update(extra)
    return ConsentRecord.model_validate(fields)


def licence(**extra: Any) -> LicenseTerms:
    fields: dict[str, Any] = {
        "identifier": "CC-BY-4.0",
        "holder": "The rights holder",
        "permits": TRAINING,
    }
    fields.update(extra)
    return LicenseTerms.model_validate(fields)


def policy(**extra: Any) -> CorpusPolicy:
    fields: dict[str, Any] = {
        "policy_id": "corpus-2026",
        "owner": "The research lead",
        "purpose": "detector-evaluation",
        "balance": DomainBalance(targets={"legal": 0.5, "software": 0.5}, tolerance=0.1),
        "contamination": ContaminationControl(),
        "retention": RetentionRule(retain_days=365, deletion_method="shred and verify"),
    }
    fields.update(extra)
    return CorpusPolicy.model_validate(fields)


def sample(**extra: Any) -> CorpusSample:
    fields: dict[str, Any] = {
        "sample_id": "sample-1",
        "content_sha256": "a" * 64,
        "domain": "legal",
        "split": Split.TRAIN,
        "source": "partner-a",
        "collected_at": NOW - timedelta(days=1),
        "consent_id": "consent-1",
        "license": licence(),
        "label": "human-written",
    }
    fields.update(extra)
    return CorpusSample.model_validate(fields)


def decide(**extra: Any):
    return admit(
        sample(**extra.pop("sample", {})),
        policy=extra.pop("policy", policy()),
        consent=extra.pop("consent", consent()),
        existing=extra.pop("existing", ()),
        now=extra.pop("now", NOW),
    )


# -- consent ---------------------------------------------------------------------------


def test_a_clean_sample_is_admitted() -> None:
    decision = decide()

    assert decision.admitted
    assert decision.refusals == ()
    assert "admitted" in decision.explain()


def test_a_sample_with_no_consent_record_is_refused() -> None:
    """Refused, not warned. Governance that advises is governance that is ignored."""

    decision = decide(consent=None)

    assert not decision.admitted
    assert any("no consent record" in item for item in decision.refusals)


def test_a_withdrawn_consent_refuses_new_samples() -> None:
    decision = decide(
        consent=consent(status=ConsentStatus.WITHDRAWN, withdrawn_at=NOW - timedelta(days=1))
    )

    assert not decision.admitted
    assert any("was withdrawn" in item for item in decision.refusals)


def test_an_expired_consent_refuses_new_samples() -> None:
    decision = decide(consent=consent(expires_at=NOW - timedelta(days=1)))

    assert not decision.admitted
    assert any("does not cover" in item for item in decision.refusals)


def test_consent_for_one_purpose_does_not_authorise_another() -> None:
    """The narrow grant must not stretch to cover the broad use."""

    decision = decide(consent=consent(purposes=("internal-review",)))

    assert not decision.admitted
    assert any("detector-evaluation" in item for item in decision.refusals)


def test_a_consent_record_must_say_how_to_withdraw_it() -> None:
    """Consent nobody can revoke is not consent."""

    with pytest.raises(ValueError):
        ConsentRecord(
            consent_id="consent-2",
            granted_by="Someone",
            granted_at=NOW,
            purposes=("x",),
            withdrawal_contact="",
        )


def test_a_consent_record_must_state_at_least_one_purpose() -> None:
    with pytest.raises(ValueError):
        consent(purposes=())


def test_a_withdrawn_record_must_say_when() -> None:
    with pytest.raises(ValueError, match="must record when"):
        consent(status=ConsentStatus.WITHDRAWN)


def test_a_withdrawal_time_without_the_status_is_refused() -> None:
    with pytest.raises(ValueError, match="must be marked withdrawn"):
        consent(withdrawn_at=NOW)


def test_a_consent_time_without_an_offset_is_refused() -> None:
    with pytest.raises(ValueError, match="must include a UTC offset"):
        consent(granted_at=datetime(2026, 1, 1))


def test_consent_expiring_before_it_was_granted_never_existed() -> None:
    with pytest.raises(ValueError, match="never given"):
        consent(expires_at=NOW - timedelta(days=365))


# -- licence is a different question ---------------------------------------------------


def test_consent_without_a_permitting_license_is_not_enough() -> None:
    """The person who hands over a document is often not the person who owns it."""

    decision = decide(sample={"license": licence(permits=frozenset({LicenseUse.QUOTATION}))})

    assert not decision.admitted
    assert any("does not permit model_training" in item for item in decision.refusals)


def test_a_license_permitting_nothing_refuses_the_sample() -> None:
    decision = decide(sample={"license": licence(permits=frozenset())})

    assert not decision.admitted


def test_both_failures_are_reported_together() -> None:
    """An operator fixing one should see the other, not discover it next time."""

    decision = decide(consent=None, sample={"license": licence(permits=frozenset())})

    assert len(decision.refusals) == 2


def test_a_policy_can_require_more_than_training_rights() -> None:
    strict = policy(
        required_license_uses=frozenset({LicenseUse.MODEL_TRAINING, LicenseUse.REDISTRIBUTION})
    )

    decision = decide(policy=strict)

    assert not decision.admitted
    assert any("redistribution" in item for item in decision.refusals)


def test_license_obligations_travel_with_the_sample() -> None:
    """So share-alike is not discovered at publication time."""

    terms = licence(obligations=("attribution", "share-alike"))

    assert terms.obligations == ("attribution", "share-alike")
    assert terms.permits_use(LicenseUse.MODEL_TRAINING)


# -- domain balance --------------------------------------------------------------------


def test_a_domain_outside_the_plan_is_refused_rather_than_absorbed() -> None:
    decision = decide(sample={"domain": "poetry"})

    assert not decision.admitted
    assert any("not in the collection plan" in item for item in decision.refusals)


def test_targets_that_do_not_sum_to_one_are_refused() -> None:
    """A plan that does not add up is a description of whatever arrived."""

    with pytest.raises(ValueError, match="must sum to 1"):
        DomainBalance(targets={"legal": 0.5, "software": 0.2})


def test_a_domain_with_a_zero_target_does_not_belong_in_a_plan() -> None:
    with pytest.raises(ValueError):
        DomainBalance(targets={"legal": 1.0, "software": 0.0})


def test_an_imbalanced_corpus_is_reported_with_both_numbers() -> None:
    manifest = CorpusManifest(
        policy=policy(),
        consents=(consent(),),
        samples=(
            *(
                sample(sample_id=f"s{index}", content_sha256=f"{index:064x}", domain="legal")
                for index in range(9)
            ),
            sample(sample_id="s9", content_sha256="9" * 64, domain="software"),
        ),
    )

    audit = audit_corpus(manifest, now=NOW)

    assert audit.imbalanced["legal"] == (0.9, 0.5)
    assert audit.imbalanced["software"] == (0.1, 0.5)


def test_imbalance_does_not_by_itself_make_a_corpus_unusable() -> None:
    """A corpus can be imbalanced on purpose; it must be reported, not blocked."""

    manifest = CorpusManifest(
        policy=policy(),
        consents=(consent(),),
        samples=(sample(),),
    )

    audit = audit_corpus(manifest, now=NOW)

    assert audit.imbalanced
    assert audit.usable


# -- contamination ---------------------------------------------------------------------


def test_the_same_content_cannot_be_in_two_splits() -> None:
    """A copy under another name is the same document, and scoring it is a memory test."""

    already = sample(sample_id="sample-0", split=Split.TRAIN)

    decision = decide(sample={"sample_id": "sample-1", "split": Split.TEST}, existing=(already,))

    assert not decision.admitted
    assert any("already in the train split" in item for item in decision.refusals)


def test_the_same_content_twice_in_one_split_is_allowed() -> None:
    """Duplication inside a split is a weighting question, not contamination."""

    already = sample(sample_id="sample-0", split=Split.TRAIN)

    decision = decide(sample={"sample_id": "sample-1", "split": Split.TRAIN}, existing=(already,))

    assert decision.admitted


def test_a_batch_cannot_slip_two_copies_past_each_other() -> None:
    """Each candidate is judged against the ones already accepted from the batch."""

    manifest = CorpusManifest(policy=policy(), consents=(consent(),))
    candidates = (
        sample(sample_id="a", split=Split.TRAIN),
        sample(sample_id="b", split=Split.TEST),
    )

    decisions = admit_all(manifest, candidates, now=NOW)

    assert decisions[0].admitted
    assert not decisions[1].admitted


def test_contamination_control_cannot_be_turned_off() -> None:
    """Without digests it compares paths, and the same file renamed would pass."""

    with pytest.raises(ValueError, match="compares paths"):
        ContaminationControl(compare_by_content_digest=False)


def test_a_holdout_only_source_may_not_appear_in_training() -> None:
    """Otherwise a model learns a source-specific shortcut and is scored on it."""

    reserved = policy(contamination=ContaminationControl(holdout_only_sources=("partner-a",)))

    decision = decide(policy=reserved)

    assert not decision.admitted
    assert any("reserved for the held-out split" in item for item in decision.refusals)


def test_a_holdout_only_source_is_admitted_into_the_held_out_split() -> None:
    reserved = policy(contamination=ContaminationControl(holdout_only_sources=("partner-a",)))

    decision = decide(policy=reserved, sample={"split": Split.TEST})

    assert decision.admitted


def test_an_audit_finds_contamination_that_admission_never_saw() -> None:
    """Samples can arrive by another route; the audit is the second line."""

    manifest = CorpusManifest(
        policy=policy(),
        consents=(consent(),),
        samples=(
            sample(sample_id="a", split=Split.TRAIN),
            sample(sample_id="b", split=Split.TEST),
        ),
    )

    audit = audit_corpus(manifest, now=NOW)

    assert audit.contaminated == ("a" * 64,)
    assert not audit.usable


# -- retention -------------------------------------------------------------------------


def test_a_sample_already_past_retention_is_refused_on_arrival() -> None:
    decision = decide(sample={"collected_at": NOW - timedelta(days=400)})

    assert not decision.admitted
    assert any("past its retention period" in item for item in decision.refusals)


def test_an_audit_lists_samples_that_have_aged_out() -> None:
    manifest = CorpusManifest(
        policy=policy(),
        consents=(consent(),),
        samples=(sample(collected_at=NOW - timedelta(days=400)),),
    )

    audit = audit_corpus(manifest, now=NOW)

    assert audit.overdue == ("sample-1",)
    assert not audit.usable


def test_indefinite_retention_must_be_stated_rather_than_defaulted_into() -> None:
    rule = RetentionRule(retain_days=None, deletion_method="documented erasure")

    assert rule.expires_at(NOW) is None


def test_a_retention_rule_must_say_how_deletion_happens() -> None:
    """A rule with no mechanism is a sentence in a policy document."""

    with pytest.raises(ValueError):
        RetentionRule(retain_days=30, deletion_method="")


# -- withdrawal reaches backwards ------------------------------------------------------


def test_withdrawal_names_every_sample_collected_under_the_consent() -> None:
    """The requirement most often written down and least often implemented."""

    manifest = CorpusManifest(
        policy=policy(),
        consents=(consent(),),
        samples=(
            sample(sample_id="a"),
            sample(sample_id="b", content_sha256="b" * 64, split=Split.TRAIN),
        ),
    )

    updated, affected = withdraw_consent(manifest, "consent-1", withdrawn_at=NOW)

    assert affected == ("a", "b")
    assert updated.consent("consent-1").status is ConsentStatus.WITHDRAWN


def test_withdrawal_does_not_silently_drop_rows_from_the_manifest() -> None:
    """Deleting the record while the bytes remain is worse than not deleting."""

    manifest = CorpusManifest(policy=policy(), consents=(consent(),), samples=(sample(),))

    updated, _ = withdraw_consent(manifest, "consent-1", withdrawn_at=NOW)

    assert len(updated.samples) == 1


def test_an_audit_after_withdrawal_lists_a_deletion_obligation() -> None:
    manifest = CorpusManifest(policy=policy(), consents=(consent(),), samples=(sample(),))
    updated, _ = withdraw_consent(manifest, "consent-1", withdrawn_at=NOW)

    audit = audit_corpus(updated, now=NOW)

    assert audit.must_delete == ("sample-1",)
    assert not audit.usable
    assert "must be deleted" in audit.explain()


def test_withdrawing_an_unknown_consent_is_an_error_not_a_no_op() -> None:
    manifest = CorpusManifest(policy=policy(), consents=(consent(),))

    with pytest.raises(CorpusError, match="No consent record"):
        withdraw_consent(manifest, "consent-absent", withdrawn_at=NOW)


def test_a_withdrawal_time_needs_an_offset() -> None:
    manifest = CorpusManifest(policy=policy(), consents=(consent(),))

    with pytest.raises(CorpusError, match="UTC offset"):
        withdraw_consent(manifest, "consent-1", withdrawn_at=datetime(2026, 1, 1))


def test_a_sample_whose_consent_vanished_is_a_deletion_obligation() -> None:
    """A manifest can lose a consent record; the samples do not stop being governed."""

    manifest = CorpusManifest(policy=policy(), consents=(), samples=(sample(),))

    audit = audit_corpus(manifest, now=NOW)

    assert audit.must_delete == ("sample-1",)


# -- the manifest itself ---------------------------------------------------------------


def test_a_corpus_cannot_be_built_without_a_policy() -> None:
    """Collected first and governed afterwards is the order this prevents."""

    with pytest.raises(ValueError):
        CorpusManifest(samples=(sample(),))  # type: ignore[call-arg]


def test_duplicate_sample_identifiers_are_refused() -> None:
    with pytest.raises(ValueError, match="must be unique"):
        CorpusManifest(
            policy=policy(),
            consents=(consent(),),
            samples=(sample(), sample(content_sha256="b" * 64)),
        )


def test_duplicate_consent_identifiers_are_refused() -> None:
    with pytest.raises(ValueError, match="must be unique"):
        CorpusManifest(policy=policy(), consents=(consent(), consent()))


def test_a_corpus_has_a_digest_so_a_result_can_cite_it() -> None:
    first = CorpusManifest(policy=policy(), consents=(consent(),), samples=(sample(),))
    reordered = CorpusManifest(
        policy=policy(),
        consents=(consent(),),
        samples=(sample(sample_id="b", content_sha256="b" * 64), sample()),
    )

    assert first.digest().startswith("sha256:")
    assert first.digest() != reordered.digest()


def test_the_digest_does_not_depend_on_sample_order() -> None:
    """Two people assembling the same corpus must be able to compare numbers."""

    forwards = CorpusManifest(
        policy=policy(),
        consents=(consent(),),
        samples=(sample(), sample(sample_id="b", content_sha256="b" * 64)),
    )
    backwards = CorpusManifest(
        policy=policy(),
        consents=(consent(),),
        samples=(sample(sample_id="b", content_sha256="b" * 64), sample()),
    )

    assert forwards.digest() == backwards.digest()


def test_a_clean_corpus_reports_nothing_to_fix() -> None:
    manifest = CorpusManifest(
        policy=policy(balance=DomainBalance(targets={"legal": 1.0}, tolerance=0.1)),
        consents=(consent(),),
        samples=(sample(),),
    )

    audit = audit_corpus(manifest, now=NOW)

    assert audit.usable
    assert audit.explain() == "1 samples, no findings."


def test_an_empty_corpus_audits_without_dividing_by_zero() -> None:
    audit = audit_corpus(CorpusManifest(policy=policy()), now=NOW)

    assert audit.sample_count == 0
    assert audit.usable
