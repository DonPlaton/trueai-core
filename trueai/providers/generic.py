"""Conservative provider-neutral explicit attribution rules."""

from trueai.core.models import ArtifactType, WatermarkSupportStatus
from trueai.detectors.provenance.provider import UnavailableProviderWatermarkAdapter
from trueai.providers.base import AttributionContext as Context
from trueai.providers.base import AttributionRule

RULES = (
    AttributionRule(
        id="generic.explicit-ai-generated",
        provider="generic",
        pattern=(
            r"\b(?:this\s+(?:file|document|code|content)\s+(?:was|is)\s+AI[- ]generated"
            r"|AI[- ]generated\s+(?:by|with)\s+(?:an?\s+)?AI\s+(?:assistant|tool|system)"
            r"|generated\s+(?:by|with)\s+an?\s+AI\s+(?:assistant|tool|system))\b"
        ),
        contexts=frozenset(
            {
                Context.TEXT,
                Context.COMMENT,
                Context.HTML_COMMENT,
                Context.GIT_COMMIT,
                Context.METADATA,
            }
        ),
        confidence=0.96,
        explanation="The text contains an explicit provider-neutral AI-generation statement.",
        remediation_type="remove_line",
    ),
)


class GenericWatermarkAdapter(UnavailableProviderWatermarkAdapter):
    """Provider-neutral status when no verifier can be selected."""

    id = "generic.watermark-verification.v1"
    provider = "generic"
    status = WatermarkSupportStatus.NOT_SUPPORTED
    supported_types = frozenset(ArtifactType)
