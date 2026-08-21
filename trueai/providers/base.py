"""Schema for external provider-specific attribution rules."""

from __future__ import annotations

import re
from collections.abc import Iterator
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class AttributionContext(StrEnum):
    """Contexts where a rule is precise enough to run."""

    TEXT = "text"
    COMMENT = "comment"
    HTML_COMMENT = "html_comment"
    GIT_COMMIT = "git_commit"
    METADATA = "metadata"


class AttributionRule(BaseModel):
    """Provider-owned pattern with explanation and remediation semantics."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9.-]+$")
    provider: str
    pattern: str
    contexts: frozenset[AttributionContext]
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str
    remediation_type: str | None = None
    flags: int = re.IGNORECASE

    def finditer(self, text: str) -> Iterator[re.Match[str]]:
        """Return non-overlapping matches for this rule."""

        return re.finditer(self.pattern, text, self.flags)


def is_standalone_attribution(text: str, start: int, end: int) -> bool:
    """Return whether the surrounding line/comment contains only attribution syntax."""

    remainder = f"{text[:start]}{text[end:]}"
    return re.fullmatch(r"[\s\W_]*", remainder, flags=re.UNICODE) is not None
