"""Four provenance questions that no interface may merge into one badge.

`ProvenanceVerificationStatus` is a single enum, and a single enum is what a UI
turns into a single badge.  ``TRUSTED`` bundles three separate findings — a
marker exists, its signature checks out, and its signer is one you hold an anchor
for — and a reader who sees one green tick cannot tell which of the three the
tool actually established.

Worse is the other end.  ``NO_MANIFEST`` and ``VERIFIER_UNAVAILABLE`` are both
"not green", so they render the same way, and "this artifact carries no
provenance" becomes indistinguishable from "we were unable to look".  For a
forensic tool that is the more damaging confusion of the two: the first is a
result and the second is a gap in the scan.

This module projects a verification into four independent facets, each of which
can answer "I do not know" without that reading as "no".  It is a projection,
not report content: everything here is derived from :class:`ScanReport`, and
adding derived state to a frozen schema would create a second source of truth
that can disagree with the first.

The four are deliberately not combinable into a score.  A provider watermark is
not a signature, an untrusted signer is not a forged one, and an unexamined
container is not a clean one.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from trueai.core.models import (
    Finding,
    FrozenModel,
    ProvenanceClass,
    ProvenanceVerification,
    ProvenanceVerificationStatus,
    ScanReport,
    WatermarkSupportStatus,
    WatermarkVerificationResult,
)


class MarkerPresence(StrEnum):
    """Whether a provenance marker is in the bytes at all."""

    PRESENT = "present"
    ABSENT = "absent"
    #: Nothing was determined.  Not the same as ``ABSENT``, and the distinction
    #: is the whole reason this enum is separate from the others.
    NOT_EXAMINED = "not_examined"


class SignatureState(StrEnum):
    """Whether the cryptography over that marker checks out."""

    VALID = "valid"
    INVALID = "invalid"
    #: A marker may exist, but its signature was never checked.
    UNCHECKED = "unchecked"
    #: There is no marker, so there is nothing to check.
    NO_SIGNATURE = "no_signature"


class SignerTrust(StrEnum):
    """Whether the signer is one the operator decided to trust."""

    TRUSTED = "trusted"
    #: Identified, and not among the anchors in use.  Not an accusation.
    NOT_TRUSTED = "not_trusted"
    #: The question could not be asked, because no anchors were configured.
    #: Rendering this as "not trusted" would blame an artifact for a missing
    #: configuration.
    NO_ANCHORS_CONFIGURED = "no_anchors_configured"
    #: The signature failed or was never checked, so a signer identity means
    #: nothing yet.
    NOT_ESTABLISHED = "not_established"
    NOT_APPLICABLE = "not_applicable"


class ProviderVerification(StrEnum):
    """What a provider watermark adapter reported, if one ran."""

    VERIFIED = "verified"
    #: An admitted adapter ran and did not confirm a watermark.
    NOT_VERIFIED = "not_verified"
    #: No adapter exists for this provider.  Says nothing about the artifact.
    UNAVAILABLE = "unavailable"
    NOT_SUPPORTED = "not_supported"
    NOT_ATTEMPTED = "not_attempted"


#: Every answer that means "this was not determined".  An interface must not
#: style these the way it styles a negative result.
UNKNOWN_ANSWERS: Final[frozenset[str]] = frozenset(
    {
        MarkerPresence.NOT_EXAMINED.value,
        SignatureState.UNCHECKED.value,
        SignerTrust.NO_ANCHORS_CONFIGURED.value,
        SignerTrust.NOT_ESTABLISHED.value,
        ProviderVerification.UNAVAILABLE.value,
        ProviderVerification.NOT_ATTEMPTED.value,
    }
)


class FacetRow(FrozenModel):
    """One question, its answer, and why — in whatever an interface renders."""

    key: str
    question: str
    answer: str
    detail: str
    #: True when the answer is an absence of knowledge rather than a result.
    unknown: bool


class ProvenanceFacets(FrozenModel):
    """One artifact's provenance, kept as four answers instead of one verdict."""

    artifact_path: str
    marker: MarkerPresence
    marker_detail: str
    signature: SignatureState
    signature_detail: str
    signer_trust: SignerTrust
    signer_detail: str
    provider: ProviderVerification
    provider_detail: str

    @property
    def establishes_provenance(self) -> bool:
        """True only when all three C2PA facets line up.

        The provider facet cannot contribute.  A provider watermark says which
        tool produced something; it does not carry a signed, verifiable chain,
        and letting it raise this flag would be exactly the conflation the whole
        module exists to prevent.
        """

        return (
            self.marker is MarkerPresence.PRESENT
            and self.signature is SignatureState.VALID
            and self.signer_trust is SignerTrust.TRUSTED
        )

    def rows(self) -> tuple[FacetRow, ...]:
        """Return the four facets in a shape any interface can lay out."""

        return (
            FacetRow(
                key="marker",
                question="Is a provenance marker present?",
                answer=self.marker.value,
                detail=self.marker_detail,
                unknown=self.marker.value in UNKNOWN_ANSWERS,
            ),
            FacetRow(
                key="signature",
                question="Does its signature verify?",
                answer=self.signature.value,
                detail=self.signature_detail,
                unknown=self.signature.value in UNKNOWN_ANSWERS,
            ),
            FacetRow(
                key="signer_trust",
                question="Is the signer one you trust?",
                answer=self.signer_trust.value,
                detail=self.signer_detail,
                unknown=self.signer_trust.value in UNKNOWN_ANSWERS,
            ),
            FacetRow(
                key="provider",
                question="Did a provider adapter verify a watermark?",
                answer=self.provider.value,
                detail=self.provider_detail,
                unknown=self.provider.value in UNKNOWN_ANSWERS,
            ),
        )

    def unknowns(self) -> tuple[FacetRow, ...]:
        """Return the facets that were not determined, for a UI to surface."""

        return tuple(row for row in self.rows() if row.unknown)

    def caveats(self) -> tuple[str, ...]:
        """Return the ways a facet is weaker than a glance at it suggests."""

        notes: list[str] = []
        if self.signature is SignatureState.VALID and self.signer_trust is SignerTrust.NOT_TRUSTED:
            notes.append(
                "The signature is valid, which means the manifest has not been altered since "
                "it was signed. It does not mean the signer is anyone in particular: no "
                "configured anchor covers this key."
            )
        if self.signer_trust is SignerTrust.NO_ANCHORS_CONFIGURED:
            notes.append(
                "No trust anchors were configured, so signer trust was never evaluated. This "
                "is a property of the scan, not of the artifact."
            )
        if self.marker is MarkerPresence.NOT_EXAMINED:
            notes.append(
                "Provenance was not examined for this artifact, so no conclusion — including "
                "'no provenance' — follows from this scan."
            )
        if self.provider is ProviderVerification.UNAVAILABLE:
            notes.append(
                "No official verifier is integrated for this provider, so the watermark "
                "question is unanswered rather than answered in the negative."
            )
        if self.marker is MarkerPresence.ABSENT:
            notes.append(
                "No manifest was found by the verifier that ran. A marker in a form that "
                "verifier does not read would look the same."
            )
        return tuple(notes)

    def headline(self) -> str:
        """Return the single sentence that is safe to put at the top."""

        if self.establishes_provenance:
            return "Signed provenance verified and signed by a trusted anchor."
        if self.marker is MarkerPresence.NOT_EXAMINED:
            return "Provenance was not examined."
        if self.marker is MarkerPresence.ABSENT:
            return "No signed provenance was found."
        if self.signature is SignatureState.INVALID:
            return "A provenance manifest is present and its signature does not verify."
        if self.signature is SignatureState.UNCHECKED:
            return "A provenance manifest is present; its signature was not checked."
        if self.signer_trust is SignerTrust.NO_ANCHORS_CONFIGURED:
            return "Signature verified; signer trust not evaluated — no anchors configured."
        return "Signature verified; the signer is not covered by a configured anchor."


# -- projection ----------------------------------------------------------------------


_MARKER_BY_STATUS: Final[dict[ProvenanceVerificationStatus, MarkerPresence]] = {
    ProvenanceVerificationStatus.TRUSTED: MarkerPresence.PRESENT,
    ProvenanceVerificationStatus.VALID: MarkerPresence.PRESENT,
    ProvenanceVerificationStatus.INVALID: MarkerPresence.PRESENT,
    ProvenanceVerificationStatus.NO_MANIFEST: MarkerPresence.ABSENT,
    ProvenanceVerificationStatus.UNSUPPORTED_CONTAINER: MarkerPresence.NOT_EXAMINED,
    ProvenanceVerificationStatus.VERIFIER_UNAVAILABLE: MarkerPresence.NOT_EXAMINED,
}

_MARKER_DETAIL: Final[dict[ProvenanceVerificationStatus, str]] = {
    ProvenanceVerificationStatus.TRUSTED: "A C2PA manifest is embedded or attached.",
    ProvenanceVerificationStatus.VALID: "A C2PA manifest is embedded or attached.",
    ProvenanceVerificationStatus.INVALID: "A C2PA manifest is embedded or attached.",
    ProvenanceVerificationStatus.NO_MANIFEST: (
        "The verifier found no manifest. A marker in a form it does not read would look the same."
    ),
    ProvenanceVerificationStatus.UNSUPPORTED_CONTAINER: (
        "The verifier does not read this container, so nothing was determined either way."
    ),
    ProvenanceVerificationStatus.VERIFIER_UNAVAILABLE: (
        "No verifier was available to run. This is a gap in the scan, not a result."
    ),
}

_SIGNATURE_BY_STATUS: Final[dict[ProvenanceVerificationStatus, SignatureState]] = {
    ProvenanceVerificationStatus.TRUSTED: SignatureState.VALID,
    ProvenanceVerificationStatus.VALID: SignatureState.VALID,
    ProvenanceVerificationStatus.INVALID: SignatureState.INVALID,
    ProvenanceVerificationStatus.NO_MANIFEST: SignatureState.NO_SIGNATURE,
    ProvenanceVerificationStatus.UNSUPPORTED_CONTAINER: SignatureState.UNCHECKED,
    ProvenanceVerificationStatus.VERIFIER_UNAVAILABLE: SignatureState.UNCHECKED,
}


def facets_from_verification(
    result: ProvenanceVerification,
    *,
    provider: WatermarkVerificationResult | None = None,
    provider_findings: tuple[Finding, ...] = (),
) -> ProvenanceFacets:
    """Split one verification into four answers that stand on their own."""

    marker = _MARKER_BY_STATUS[result.status]
    signature = _SIGNATURE_BY_STATUS[result.status]
    signer_trust, signer_detail = _signer_facet(result, signature)
    provider_state, provider_detail = _provider_facet(provider, provider_findings)
    return ProvenanceFacets(
        artifact_path=result.artifact_path,
        marker=marker,
        marker_detail=_MARKER_DETAIL[result.status],
        signature=signature,
        signature_detail=_signature_detail(result, signature),
        signer_trust=signer_trust,
        signer_detail=signer_detail,
        provider=provider_state,
        provider_detail=provider_detail,
    )


def _signature_detail(result: ProvenanceVerification, state: SignatureState) -> str:
    if state is SignatureState.VALID:
        return f"{result.verifier} verified the signature and the content hashes it covers."
    if state is SignatureState.INVALID:
        failures = result.failures()
        if failures:
            return "; ".join(entry.explanation for entry in failures)
        return "The verifier rejected the signature."
    if state is SignatureState.NO_SIGNATURE:
        return "There is no manifest, so there is no signature to check."
    return "The signature was not checked."


def _signer_facet(
    result: ProvenanceVerification, signature: SignatureState
) -> tuple[SignerTrust, str]:
    if signature is SignatureState.NO_SIGNATURE:
        return SignerTrust.NOT_APPLICABLE, "There is no signer, because there is no manifest."
    if signature is not SignatureState.VALID:
        # Asking whether an unverified signer is trusted invites reading the
        # answer as though the signature had held.
        return (
            SignerTrust.NOT_ESTABLISHED,
            "The signature did not verify, so the identity it carries establishes nothing.",
        )
    named = result.signer.common_name if result.signer and result.signer.common_name else None
    if result.status is ProvenanceVerificationStatus.TRUSTED:
        who = named or "the signer"
        return SignerTrust.TRUSTED, f"{who} chains to a trust anchor configured for this scan."
    if not result.trust_anchors_configured:
        return (
            SignerTrust.NO_ANCHORS_CONFIGURED,
            "No trust anchors were configured, so this question was never asked. That is a "
            "property of the scan, not of the artifact.",
        )
    who = named or "The signer"
    return (
        SignerTrust.NOT_TRUSTED,
        f"{who} is not covered by any configured anchor. The manifest is intact; whose it "
        "is remains unestablished.",
    )


def _provider_facet(
    provider: WatermarkVerificationResult | None, findings: tuple[Finding, ...]
) -> tuple[ProviderVerification, str]:
    if provider is None:
        if findings:
            return (
                ProviderVerification.NOT_VERIFIED,
                f"{len(findings)} provider marker finding(s) were recorded by detection, which "
                "is a marker observation and not a verification.",
            )
        return ProviderVerification.NOT_ATTEMPTED, "No provider watermark adapter was run."
    if provider.status is WatermarkSupportStatus.VERIFICATION_UNAVAILABLE:
        return ProviderVerification.UNAVAILABLE, provider.explanation
    if provider.status is WatermarkSupportStatus.NOT_SUPPORTED:
        return ProviderVerification.NOT_SUPPORTED, provider.explanation
    if provider.verified:
        return ProviderVerification.VERIFIED, provider.explanation
    return ProviderVerification.NOT_VERIFIED, provider.explanation


def facets_for_report(report: ScanReport) -> tuple[ProvenanceFacets, ...]:
    """Return one set of facets per verified artifact in a report."""

    by_path: dict[str, list[Finding]] = {}
    for finding in report.findings:
        if finding.provenance_class is ProvenanceClass.PROVIDER_WATERMARK:
            by_path.setdefault(finding.artifact_path, []).append(finding)
    return tuple(
        facets_from_verification(
            verification,
            provider_findings=tuple(by_path.get(verification.artifact_path, ())),
        )
        for verification in report.provenance_verifications
    )


__all__ = [
    "UNKNOWN_ANSWERS",
    "FacetRow",
    "MarkerPresence",
    "ProvenanceFacets",
    "ProviderVerification",
    "SignatureState",
    "SignerTrust",
    "facets_for_report",
    "facets_from_verification",
]
