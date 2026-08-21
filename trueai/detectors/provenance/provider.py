"""Provider watermark verification boundary; no invented algorithms or keys."""

from __future__ import annotations

from abc import ABC, abstractmethod

from trueai.core.artifact import Artifact
from trueai.core.models import (
    ArtifactType,
    WatermarkSupportStatus,
    WatermarkVerificationResult,
)


class ProviderWatermarkDetector(ABC):
    """Interface for official/public provider verification mechanisms."""

    id: str
    provider: str
    supported_types: frozenset[ArtifactType]
    network_required: bool = False

    def supports(self, artifact: Artifact) -> bool:
        """Return whether this adapter understands the artifact container."""

        return artifact.artifact_type in self.supported_types

    @abstractmethod
    def verify(self, artifact: Artifact) -> WatermarkVerificationResult:
        """Verify through an official mechanism or report unavailability explicitly."""


class UnavailableProviderWatermarkAdapter(ProviderWatermarkDetector):
    """Honest v0.1 adapter when no public verifier is integrated."""

    status = WatermarkSupportStatus.VERIFICATION_UNAVAILABLE

    def verify(self, artifact: Artifact) -> WatermarkVerificationResult:
        del artifact
        return WatermarkVerificationResult(
            provider=self.provider,
            status=self.status,
            verified=False,
            explanation=(
                "TrueAI Core v0.1 has no official public verifier integrated for this provider. "
                "No watermark algorithm, secret key, or removal method is inferred."
            ),
        )
