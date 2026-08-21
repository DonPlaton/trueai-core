"""Google-specific explicit attribution rules."""

from trueai.core.models import ArtifactType
from trueai.detectors.provenance.provider import UnavailableProviderWatermarkAdapter
from trueai.providers.base import AttributionContext as Context
from trueai.providers.base import AttributionRule

RULES = (
    AttributionRule(
        id="google.generated-with-gemini",
        provider="google",
        pattern=r"\b(?:generated|written|created)\s+(?:by|with)\s+(?:Google\s+)?Gemini\b",
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
        explanation="The artifact explicitly attributes generation to Google Gemini.",
        remediation_type="remove_line",
    ),
    AttributionRule(
        id="google.gemini-share-url",
        provider="google",
        pattern=r"https?://g\.co/gemini/share/[A-Za-z0-9_-]+",
        contexts=frozenset({Context.TEXT, Context.COMMENT, Context.GIT_COMMIT}),
        confidence=0.98,
        explanation="A Gemini share URL is embedded in the artifact.",
        remediation_type="remove_line",
    ),
)


class GoogleWatermarkAdapter(UnavailableProviderWatermarkAdapter):
    """Google verification status for v0.1."""

    id = "google.watermark-verification.v1"
    provider = "google"
    supported_types = frozenset(
        {ArtifactType.TEXT, ArtifactType.PNG, ArtifactType.JPEG, ArtifactType.PDF}
    )
