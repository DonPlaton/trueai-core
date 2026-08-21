"""Provider-specific rule definitions and verification adapters."""

from trueai.providers.anthropic import RULES as ANTHROPIC_RULES
from trueai.providers.anthropic import AnthropicWatermarkAdapter
from trueai.providers.base import AttributionContext, AttributionRule, is_standalone_attribution
from trueai.providers.generic import RULES as GENERIC_RULES
from trueai.providers.generic import GenericWatermarkAdapter
from trueai.providers.google import RULES as GOOGLE_RULES
from trueai.providers.google import GoogleWatermarkAdapter
from trueai.providers.openai import RULES as OPENAI_RULES
from trueai.providers.openai import OpenAIWatermarkAdapter


def attribution_rules() -> tuple[AttributionRule, ...]:
    """Return all provider rule packs in stable order."""

    return ANTHROPIC_RULES + OPENAI_RULES + GOOGLE_RULES + GENERIC_RULES


def watermark_adapters() -> tuple[
    AnthropicWatermarkAdapter,
    OpenAIWatermarkAdapter,
    GoogleWatermarkAdapter,
    GenericWatermarkAdapter,
]:
    """Return provider verification adapters and their honest support statuses."""

    return (
        AnthropicWatermarkAdapter(),
        OpenAIWatermarkAdapter(),
        GoogleWatermarkAdapter(),
        GenericWatermarkAdapter(),
    )


__all__ = [
    "AttributionContext",
    "AttributionRule",
    "attribution_rules",
    "is_standalone_attribution",
    "watermark_adapters",
]
