"""OpenAI-specific explicit attribution rules."""

from trueai.core.models import ArtifactType
from trueai.detectors.provenance.provider import UnavailableProviderWatermarkAdapter
from trueai.providers.base import AttributionContext as Context
from trueai.providers.base import AttributionRule

RULES = (
    AttributionRule(
        id="openai.coauthor",
        provider="openai",
        # Same overlapping quantifiers as the Anthropic trailer, same fix.
        pattern=(
            r"Co-Authored-By:[ \t]*(?:ChatGPT|OpenAI Codex|Codex)"
            r"(?:[ \t][^<\r\n]*)?<[^>\r\n]{1,320}>"
        ),
        contexts=frozenset({Context.TEXT, Context.COMMENT, Context.GIT_COMMIT}),
        confidence=1.0,
        explanation="An explicit OpenAI tool co-author trailer is present.",
        remediation_type="remove_line",
    ),
    AttributionRule(
        id="openai.generated-with",
        provider="openai",
        pattern=r"\b(?:generated|written|created)\s+(?:by|with)\s+(?:OpenAI(?:\s+Codex)?|ChatGPT|Codex)\b",
        contexts=frozenset(
            {
                Context.TEXT,
                Context.COMMENT,
                Context.HTML_COMMENT,
                Context.GIT_COMMIT,
                Context.METADATA,
            }
        ),
        confidence=0.99,
        explanation="The artifact explicitly attributes generation to an OpenAI tool.",
        remediation_type="remove_line",
    ),
    AttributionRule(
        id="openai.chat-url",
        provider="openai",
        pattern=r"https?://(?:chatgpt\.com|chat\.openai\.com)/(?:share|c)/[A-Za-z0-9_-]+",
        contexts=frozenset({Context.TEXT, Context.COMMENT, Context.GIT_COMMIT}),
        confidence=0.98,
        explanation="A ChatGPT conversation or share URL is embedded in the artifact.",
        remediation_type="remove_line",
    ),
)


class OpenAIWatermarkAdapter(UnavailableProviderWatermarkAdapter):
    """OpenAI verification status for v0.1."""

    id = "openai.watermark-verification.v1"
    provider = "openai"
    supported_types = frozenset(
        {ArtifactType.TEXT, ArtifactType.PNG, ArtifactType.JPEG, ArtifactType.PDF}
    )
