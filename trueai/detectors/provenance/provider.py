"""Provider watermark verification: what admits an adapter, and what it may reach.

An adapter is added when a provider publishes something a third party can
actually run — an API with a specification, an open verifier, or a documented
format. It is not added because a provider is known to watermark, or because a
paper describes an approach, or because a detection heuristic seems to work.
Those produce a plausible answer with nothing behind it, and a plausible answer
about provenance is worse than an honest "unavailable".

:class:`AdmissionCriteria` writes the standard down so adding an adapter is a
decision measured against it rather than a judgement call, and
:data:`PROVIDER_ASSESSMENTS` records where each known provider stands. A provider
that does not meet the bar keeps reporting
:attr:`WatermarkSupportStatus.VERIFICATION_UNAVAILABLE`, and a test enforces that
it stays that way.

Where an adapter does need the network it goes through
:class:`trueai.core.network.NetworkGate` and nowhere else, so "did this tool
contact anything" has one answer and one audit trail.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Final

from trueai.core.artifact import Artifact
from trueai.core.models import (
    ArtifactType,
    FrozenModel,
    WatermarkSupportStatus,
    WatermarkVerificationResult,
)
from trueai.core.network import NetworkGate, NetworkRefused, offline_gate


class AdmissionCriteria(FrozenModel):
    """What a provider must publish before an adapter is written for it.

    All four. Three out of four is a provider whose watermark someone has
    reverse-engineered, and shipping that would mean presenting a guess as a
    verification.
    """

    #: A verifier, API, or format specification the provider published.
    published_mechanism: bool = False
    #: Runnable by a third party without a private agreement or a secret key.
    independently_runnable: bool = False
    #: Documented well enough that a wrong answer can be distinguished from a
    #: bug in this code.
    specified_semantics: bool = False
    #: Stable enough to depend on: versioned, or with a deprecation policy.
    stable_contract: bool = False

    @property
    def admitted(self) -> bool:
        return (
            self.published_mechanism
            and self.independently_runnable
            and self.specified_semantics
            and self.stable_contract
        )

    def unmet(self) -> tuple[str, ...]:
        """Return the criteria this provider does not meet."""

        missing: list[str] = []
        if not self.published_mechanism:
            missing.append("no published verifier, API, or specification")
        if not self.independently_runnable:
            missing.append("not runnable by a third party")
        if not self.specified_semantics:
            missing.append("semantics not specified well enough to interpret a result")
        if not self.stable_contract:
            missing.append("no stable, versioned contract")
        return tuple(missing)


class ProviderAssessment(FrozenModel):
    """One provider, measured against the criteria, with the evidence."""

    provider: str
    criteria: AdmissionCriteria
    note: str

    @property
    def admitted(self) -> bool:
        return self.criteria.admitted


#: Where each known provider stands, as of this release. Recorded here rather
#: than only in prose so the reasoning ships with the code and a change to it is
#: a change to a test.
PROVIDER_ASSESSMENTS: Final[tuple[ProviderAssessment, ...]] = (
    ProviderAssessment(
        provider="c2pa",
        criteria=AdmissionCriteria(
            published_mechanism=True,
            independently_runnable=True,
            specified_semantics=True,
            stable_contract=True,
        ),
        note=(
            "C2PA publishes a specification and an open implementation. TrueAI verifies "
            "through that implementation rather than reimplementing it, and reports "
            "verifier-unavailable when the optional extra is not installed."
        ),
    ),
    ProviderAssessment(
        provider="google",
        criteria=AdmissionCriteria(published_mechanism=False),
        note=(
            "SynthID detection is offered through Google's own surfaces, not as a "
            "specification or a verifier a third party can run. Inferring the watermark "
            "would mean presenting a guess as a verification."
        ),
    ),
    ProviderAssessment(
        provider="openai",
        criteria=AdmissionCriteria(published_mechanism=False),
        note="No public verifier, API, or specification for watermark verification.",
    ),
    ProviderAssessment(
        provider="anthropic",
        criteria=AdmissionCriteria(published_mechanism=False),
        note="No public verifier, API, or specification for watermark verification.",
    ),
    ProviderAssessment(
        provider="generic",
        criteria=AdmissionCriteria(published_mechanism=False),
        note=(
            "A placeholder for providers with no published mechanism at all. It exists so "
            "an unrecognised marker has somewhere honest to land."
        ),
    ),
)


def assessment_for(provider: str) -> ProviderAssessment | None:
    """Return the recorded assessment for a provider, if there is one."""

    return next(
        (item for item in PROVIDER_ASSESSMENTS if item.provider == provider.casefold()), None
    )


class ProviderWatermarkDetector(ABC):
    """Interface for official/public provider verification mechanisms."""

    id: str
    provider: str
    supported_types: frozenset[ArtifactType]
    network_required: bool = False

    def __init__(self, gate: NetworkGate | None = None) -> None:
        # Offline unless a caller hands over a configured gate. An adapter that
        # defaulted to a usable network would make the boundary depend on
        # remembering to close it.
        self.gate = gate or offline_gate()

    def supports(self, artifact: Artifact) -> bool:
        """Return whether this adapter understands the artifact container."""

        return artifact.artifact_type in self.supported_types

    def network_refusal(self, endpoint: str, purpose: str) -> str | None:
        """Return why a remote call would be refused, or None if it would proceed.

        Adapters ask before doing anything expensive, so an operator who has not
        configured the gate learns that from the result rather than from a
        timeout.
        """

        return self.gate.check(endpoint, purpose)

    def fetch(self, endpoint: str, *, purpose: str, payload: bytes = b"") -> bytes:
        """Make a request through the gate. There is no other way out."""

        if not self.network_required:
            raise NetworkRefused(
                f"{self.provider} adapter does not declare network_required, so it may "
                "not make requests"
            )
        return self.gate.request(endpoint, purpose=purpose, payload=payload)

    @abstractmethod
    def verify(self, artifact: Artifact) -> WatermarkVerificationResult:
        """Verify through an official mechanism or report unavailability explicitly."""


class UnavailableProviderWatermarkAdapter(ProviderWatermarkDetector):
    """The honest answer for a provider that has not met the admission bar.

    Says why, using the recorded assessment, so "unavailable" is a position with
    reasons rather than a shrug.
    """

    status = WatermarkSupportStatus.VERIFICATION_UNAVAILABLE

    def verify(self, artifact: Artifact) -> WatermarkVerificationResult:
        del artifact
        assessment = assessment_for(self.provider)
        reasons = ""
        if assessment is not None and not assessment.admitted:
            reasons = " Not integrated because: " + "; ".join(assessment.criteria.unmet()) + "."
        return WatermarkVerificationResult(
            provider=self.provider,
            status=self.status,
            verified=False,
            explanation=(
                "TrueAI has no official public verifier integrated for this provider."
                + reasons
                + " No watermark algorithm, secret key, or removal method is inferred."
            ),
        )


__all__ = [
    "PROVIDER_ASSESSMENTS",
    "AdmissionCriteria",
    "ProviderAssessment",
    "ProviderWatermarkDetector",
    "UnavailableProviderWatermarkAdapter",
    "assessment_for",
]
