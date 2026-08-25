"""Anthropic-specific explicit attribution rules."""

from trueai.core.models import ArtifactType
from trueai.detectors.provenance.provider import UnavailableProviderWatermarkAdapter
from trueai.providers.base import AttributionContext as Context
from trueai.providers.base import AttributionRule

RULES = (
    AttributionRule(
        id="anthropic.coauthor-claude",
        provider="anthropic",
        # `[^<\r\n]*` and a following `\s*` both accept a space, so a line of
        # them can be divided between the two quantifiers in as many ways as it
        # is long. The first already accepts everything the second did.
        pattern=r"Co-Authored-By:[ \t]*Claude(?:[ \t][^<\r\n]*)?<[^>\r\n]{1,320}>",
        contexts=frozenset({Context.TEXT, Context.COMMENT, Context.GIT_COMMIT}),
        confidence=1.0,
        explanation="An explicit Claude co-author trailer is present.",
        remediation_type="remove_line",
    ),
    AttributionRule(
        id="anthropic.generated-with-claude",
        provider="anthropic",
        pattern=r"\b(?:generated|written|created)\s+(?:by|with)\s+(?:Anthropic['’]s\s+)?Claude\b",
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
        explanation="The artifact explicitly attributes generation to Claude.",
        remediation_type="remove_line",
    ),
    AttributionRule(
        id="anthropic.session-url",
        provider="anthropic",
        pattern=r"https?://(?:www\.)?claude\.ai/(?:chat|share)/[A-Za-z0-9_-]+",
        contexts=frozenset({Context.TEXT, Context.COMMENT, Context.GIT_COMMIT}),
        confidence=0.98,
        explanation="A Claude session or share URL is embedded in the artifact.",
        remediation_type="remove_line",
    ),
)


class AnthropicWatermarkAdapter(UnavailableProviderWatermarkAdapter):
    """Anthropic verification status for v0.1."""

    id = "anthropic.watermark-verification.v1"
    provider = "anthropic"
    supported_types = frozenset(
        {ArtifactType.TEXT, ArtifactType.PNG, ArtifactType.JPEG, ArtifactType.PDF}
    )
