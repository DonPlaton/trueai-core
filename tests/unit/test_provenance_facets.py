"""Four provenance answers that must not collapse into one badge.

The failure this guards is not exaggeration, it is erasure. `NO_MANIFEST` and
`VERIFIER_UNAVAILABLE` are both "not green", so a single status column renders
them identically — and "this artifact carries no provenance" then looks exactly
like "we were unable to look". One is a result; the other is a hole in the scan.
"""

from __future__ import annotations

import io

import pytest
from rich.console import Console

from trueai.core.models import (
    ArtifactDescriptor,
    ArtifactType,
    ConfidenceType,
    EvidenceType,
    Finding,
    FindingCategory,
    ProvenanceClass,
    ProvenanceSigner,
    ProvenanceValidationEntry,
    ProvenanceVerification,
    ProvenanceVerificationStatus,
    ScanReport,
    ScanSummary,
    Severity,
    ValidationOutcome,
    WatermarkSupportStatus,
    WatermarkVerificationResult,
)
from trueai.core.provenance_view import (
    UNKNOWN_ANSWERS,
    MarkerPresence,
    ProviderVerification,
    SignatureState,
    SignerTrust,
    facets_for_report,
    facets_from_verification,
)
from trueai.reporters import TerminalReporter


def verification(status: ProvenanceVerificationStatus, **extra: object) -> ProvenanceVerification:
    fields: dict[str, object] = {
        "artifact_path": "photo.jpg",
        "status": status,
        "verifier": "c2pa-rs",
        "explanation": "as reported by the verifier",
    }
    fields.update(extra)
    return ProvenanceVerification.model_validate(fields)


def facets(status: ProvenanceVerificationStatus, **extra: object):
    return facets_from_verification(verification(status, **extra))


# -- the distinction the single status erased ----------------------------------------


def test_nothing_found_and_nothing_looked_at_are_different_answers() -> None:
    """The whole point. One is a result; the other is a gap in the scan."""

    found_nothing = facets(ProvenanceVerificationStatus.NO_MANIFEST)
    looked_at_nothing = facets(ProvenanceVerificationStatus.VERIFIER_UNAVAILABLE)

    assert found_nothing.marker is MarkerPresence.ABSENT
    assert looked_at_nothing.marker is MarkerPresence.NOT_EXAMINED
    assert found_nothing.marker is not looked_at_nothing.marker


def test_an_unexamined_artifact_reports_the_gap_rather_than_a_conclusion() -> None:
    unexamined = facets(ProvenanceVerificationStatus.VERIFIER_UNAVAILABLE)

    assert unexamined.headline() == "Provenance was not examined."
    assert any("no conclusion" in note for note in unexamined.caveats())
    assert [row.key for row in unexamined.unknowns()] == [
        "marker",
        "signature",
        "signer_trust",
        "provider",
    ]


def test_an_unsupported_container_is_not_a_clean_one() -> None:
    unsupported = facets(ProvenanceVerificationStatus.UNSUPPORTED_CONTAINER)

    assert unsupported.marker is MarkerPresence.NOT_EXAMINED
    assert unsupported.signature is SignatureState.UNCHECKED


def test_finding_no_manifest_states_the_limit_of_that_finding() -> None:
    absent = facets(ProvenanceVerificationStatus.NO_MANIFEST)

    assert absent.signature is SignatureState.NO_SIGNATURE
    assert absent.signer_trust is SignerTrust.NOT_APPLICABLE
    assert any("verifier does not read would look the same" in note for note in absent.caveats())


# -- signature and signer are separate questions -------------------------------------


def test_a_valid_signature_without_anchors_is_not_an_untrusted_signer() -> None:
    """Blaming an artifact for a missing configuration is a different claim."""

    unanchored = facets(ProvenanceVerificationStatus.VALID, trust_anchors_configured=False)

    assert unanchored.signature is SignatureState.VALID
    assert unanchored.signer_trust is SignerTrust.NO_ANCHORS_CONFIGURED
    assert any("property of the scan, not of the artifact" in n for n in unanchored.caveats())


def test_a_valid_signature_with_anchors_that_do_not_cover_it_is_untrusted() -> None:
    outside = facets(
        ProvenanceVerificationStatus.VALID,
        trust_anchors_configured=True,
        signer=ProvenanceSigner(common_name="Acme Studios"),
    )

    assert outside.signer_trust is SignerTrust.NOT_TRUSTED
    assert "Acme Studios" in outside.signer_detail
    assert any("has not been altered since" in note for note in outside.caveats())


def test_an_untrusted_signer_is_not_reported_as_a_forged_one() -> None:
    outside = facets(ProvenanceVerificationStatus.VALID, trust_anchors_configured=True)

    assert "not covered by any configured anchor" in outside.signer_detail
    assert "forg" not in " ".join(outside.caveats()).lower()


def test_a_failed_signature_leaves_the_signer_unestablished() -> None:
    """A signer identity carried by a signature that failed proves nothing."""

    broken = facets(
        ProvenanceVerificationStatus.INVALID,
        trust_anchors_configured=True,
        signer=ProvenanceSigner(common_name="Acme Studios"),
    )

    assert broken.signer_trust is SignerTrust.NOT_ESTABLISHED
    assert broken.signer_trust is not SignerTrust.NOT_TRUSTED


def test_a_failed_signature_reports_the_checks_that_failed() -> None:
    broken = facets(
        ProvenanceVerificationStatus.INVALID,
        validation=(
            ProvenanceValidationEntry(
                code="claimSignature.mismatch",
                outcome=ValidationOutcome.FAILURE,
                explanation="the claim hash does not match the asset",
            ),
        ),
    )

    assert "claim hash does not match" in broken.signature_detail


def test_a_failed_signature_without_detail_still_says_what_happened() -> None:
    assert facets(ProvenanceVerificationStatus.INVALID).signature_detail.startswith(
        "The verifier rejected"
    )


# -- what establishes provenance -----------------------------------------------------


def test_only_a_trusted_result_establishes_provenance() -> None:
    trusted = facets_from_verification(
        verification(
            ProvenanceVerificationStatus.TRUSTED,
            trust_anchors_configured=True,
            signer=ProvenanceSigner(common_name="Acme Studios"),
        ),
        provider=WatermarkVerificationResult(
            provider="Example",
            status=WatermarkSupportStatus.SUPPORTED,
            verified=False,
            explanation="the official verifier found no watermark",
        ),
    )

    assert trusted.establishes_provenance
    assert trusted.caveats() == ()
    assert trusted.unknowns() == ()
    assert "trusted anchor" in trusted.headline()


def test_a_trusted_chain_still_reports_that_no_provider_adapter_ran() -> None:
    """Three settled answers do not settle the fourth."""

    trusted = facets(
        ProvenanceVerificationStatus.TRUSTED,
        trust_anchors_configured=True,
        signer=ProvenanceSigner(common_name="Acme Studios"),
    )

    assert trusted.establishes_provenance
    assert [row.key for row in trusted.unknowns()] == ["provider"]


@pytest.mark.parametrize(
    "status",
    [
        ProvenanceVerificationStatus.VALID,
        ProvenanceVerificationStatus.INVALID,
        ProvenanceVerificationStatus.NO_MANIFEST,
        ProvenanceVerificationStatus.UNSUPPORTED_CONTAINER,
        ProvenanceVerificationStatus.VERIFIER_UNAVAILABLE,
    ],
)
def test_nothing_else_establishes_provenance(status: ProvenanceVerificationStatus) -> None:
    assert not facets(status, trust_anchors_configured=True).establishes_provenance


def test_a_verified_provider_watermark_does_not_establish_provenance() -> None:
    """A watermark says which tool made something. It carries no signed chain."""

    result = facets_from_verification(
        verification(ProvenanceVerificationStatus.NO_MANIFEST),
        provider=WatermarkVerificationResult(
            provider="Example",
            status=WatermarkSupportStatus.SUPPORTED,
            verified=True,
            explanation="the official verifier confirmed a watermark",
        ),
    )

    assert result.provider is ProviderVerification.VERIFIED
    assert not result.establishes_provenance


def test_the_headline_never_claims_more_than_the_facets_do() -> None:
    for status in ProvenanceVerificationStatus:
        headline = facets(status, trust_anchors_configured=True).headline()
        established = facets(status, trust_anchors_configured=True).establishes_provenance
        assert established == ("verified and signed by a trusted anchor" in headline)


# -- the provider question is its own -----------------------------------------------


def test_an_unavailable_adapter_leaves_the_watermark_question_unanswered() -> None:
    result = facets_from_verification(
        verification(ProvenanceVerificationStatus.NO_MANIFEST),
        provider=WatermarkVerificationResult(
            provider="Example",
            status=WatermarkSupportStatus.VERIFICATION_UNAVAILABLE,
            explanation="no official public verifier is integrated",
        ),
    )

    assert result.provider is ProviderVerification.UNAVAILABLE
    assert any("unanswered rather than answered in the negative" in n for n in result.caveats())


def test_an_adapter_that_ran_and_found_nothing_is_a_settled_answer() -> None:
    result = facets_from_verification(
        verification(ProvenanceVerificationStatus.NO_MANIFEST),
        provider=WatermarkVerificationResult(
            provider="Example",
            status=WatermarkSupportStatus.SUPPORTED,
            verified=False,
            explanation="the official verifier found no watermark",
        ),
    )

    assert result.provider is ProviderVerification.NOT_VERIFIED
    assert result.provider.value not in UNKNOWN_ANSWERS


def test_an_unsupported_container_for_a_provider_is_reported_as_such() -> None:
    result = facets_from_verification(
        verification(ProvenanceVerificationStatus.NO_MANIFEST),
        provider=WatermarkVerificationResult(
            provider="Example",
            status=WatermarkSupportStatus.NOT_SUPPORTED,
            explanation="this container is out of scope for the adapter",
        ),
    )

    assert result.provider is ProviderVerification.NOT_SUPPORTED


def test_no_adapter_and_no_findings_is_not_attempted() -> None:
    result = facets(ProvenanceVerificationStatus.TRUSTED)

    assert result.provider is ProviderVerification.NOT_ATTEMPTED
    assert result.provider.value in UNKNOWN_ANSWERS


def test_a_detected_marker_is_reported_as_an_observation_not_a_verification() -> None:
    result = facets_from_verification(
        verification(ProvenanceVerificationStatus.NO_MANIFEST),
        provider_findings=(provider_finding("photo.jpg"),),
    )

    assert result.provider is ProviderVerification.NOT_VERIFIED
    assert "not a verification" in result.provider_detail
    assert "1 provider marker finding" in result.provider_detail


# -- shape any interface can consume -------------------------------------------------


def test_the_four_facets_are_always_four_with_stable_keys() -> None:
    for status in ProvenanceVerificationStatus:
        rows = facets(status).rows()
        assert [row.key for row in rows] == ["marker", "signature", "signer_trust", "provider"]


def test_every_unknown_answer_is_flagged_as_unknown() -> None:
    for status in ProvenanceVerificationStatus:
        for row in facets(status).rows():
            assert row.unknown == (row.answer in UNKNOWN_ANSWERS)


def test_every_answer_is_classified_as_a_result_or_as_unknown() -> None:
    """A new enum member added without a decision would fail here."""

    from trueai.reporters.terminal import _FACET_STYLE

    members = (
        list(MarkerPresence) + list(SignatureState) + list(SignerTrust) + list(ProviderVerification)
    )
    undecided = [
        member.value
        for member in members
        if member.value not in UNKNOWN_ANSWERS and member.value not in _FACET_STYLE
    ]

    assert undecided == []


def test_every_facet_carries_a_reason(monkeypatch: pytest.MonkeyPatch) -> None:
    for status in ProvenanceVerificationStatus:
        for row in facets(status).rows():
            assert row.detail.strip()
            assert row.question.endswith("?")


# -- a whole report ------------------------------------------------------------------


def provider_finding(artifact_path: str) -> Finding:
    return Finding(
        id="provider-marker-0001",
        detector_id="provenance.provider",
        category=FindingCategory.PROVIDER_WATERMARK,
        title="Provider marker",
        description="a provider marker was observed",
        artifact_path=artifact_path,
        severity=Severity.INFO,
        confidence=1.0,
        confidence_type=ConfidenceType.DETERMINISTIC,
        evidence_type=EvidenceType.STRUCTURAL,
        provenance_class=ProvenanceClass.PROVIDER_WATERMARK,
    )


def report_with(*verifications: ProvenanceVerification, findings: tuple[Finding, ...] = ()):
    descriptor = ArtifactDescriptor(
        path="photo.jpg", artifact_type=ArtifactType.PNG, size=1, sha256="0" * 64
    )
    return ScanReport(
        artifact=descriptor,
        artifacts=(descriptor,),
        summary=ScanSummary.over(findings, artifact_count=1),
        findings=findings,
        provenance_verifications=verifications,
    )


def test_provider_findings_attach_to_the_artifact_they_were_found_in() -> None:
    report = report_with(
        verification(ProvenanceVerificationStatus.NO_MANIFEST, artifact_path="photo.jpg"),
        verification(ProvenanceVerificationStatus.NO_MANIFEST, artifact_path="other.jpg"),
        findings=(provider_finding("photo.jpg"),),
    )

    first, second = facets_for_report(report)

    assert first.provider is ProviderVerification.NOT_VERIFIED
    assert second.provider is ProviderVerification.NOT_ATTEMPTED


def test_a_report_without_verifications_produces_no_facets() -> None:
    assert facets_for_report(report_with()) == ()


# -- what an operator actually sees --------------------------------------------------


def rendered(*verifications: ProvenanceVerification) -> str:
    buffer = io.StringIO()
    TerminalReporter(Console(file=buffer, width=200)).render(report_with(*verifications))
    return buffer.getvalue()


def test_the_terminal_distinguishes_nothing_found_from_nothing_checked() -> None:
    output = rendered(
        verification(ProvenanceVerificationStatus.NO_MANIFEST, artifact_path="found-nothing.jpg"),
        verification(
            ProvenanceVerificationStatus.VERIFIER_UNAVAILABLE, artifact_path="not-checked.jpg"
        ),
    )

    assert "ABSENT" in output
    assert "NOT EXAMINED" in output
    assert "Not determined" in output


def test_the_terminal_shows_four_answers_rather_than_one_verdict() -> None:
    output = rendered(
        verification(
            ProvenanceVerificationStatus.TRUSTED,
            trust_anchors_configured=True,
            signer=ProvenanceSigner(common_name="Acme Studios"),
        )
    )

    for column in ("Marker", "Signature", "Signer trust", "Provider"):
        assert column in output


def test_the_terminal_names_the_unanswered_question_even_in_a_trusted_report() -> None:
    """A green chain does not answer whether a provider adapter ran."""

    output = rendered(
        verification(
            ProvenanceVerificationStatus.TRUSTED,
            trust_anchors_configured=True,
            signer=ProvenanceSigner(common_name="Acme Studios"),
        )
    )

    assert "Not determined" in output
    assert "provider adapter verify a watermark" in output


def test_the_detail_panel_separates_the_questions_and_states_the_caveats() -> None:
    buffer = io.StringIO()
    TerminalReporter(Console(file=buffer, width=200)).render_verification(
        verification(
            ProvenanceVerificationStatus.VALID,
            trust_anchors_configured=True,
            signer=ProvenanceSigner(common_name="Acme Studios"),
        )
    )
    output = buffer.getvalue()

    assert "Is a provenance marker present?" in output
    assert "Is the signer one you trust?" in output
    assert "has not been altered since" in output


def test_a_hostile_manifest_still_cannot_style_a_facet() -> None:
    """Escaping survives the facet rewrite."""

    buffer = io.StringIO()
    TerminalReporter(Console(file=buffer, width=200)).render_verification(
        verification(
            ProvenanceVerificationStatus.INVALID,
            explanation="failed[/][bold green]TRUSTED[/] by Acme",
            signer=ProvenanceSigner(common_name="A[/]B"),
        )
    )

    assert "[/]" in buffer.getvalue()
