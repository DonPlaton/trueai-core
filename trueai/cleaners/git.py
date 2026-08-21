"""Explicit refusal boundary for destructive Git history rewriting."""

from pathlib import Path

from trueai.cleaners.base import CleanerOutcome
from trueai.core.errors import RemediationError
from trueai.core.models import Remediation


class GitCleaner:
    """Never rewrite Git history automatically."""

    supported_remediation_ids: frozenset[str] = frozenset()

    def apply(
        self,
        source: Path,
        destination: Path,
        remediations: tuple[Remediation, ...],
    ) -> CleanerOutcome:
        del source, destination, remediations
        raise RemediationError(
            "Git history rewriting is destructive and is not implemented by TrueAI Core clean."
        )
