"""Cleaner protocol and verified outcome."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from trueai.core.models import IntegrityReport, Remediation, ScanOptions


@dataclass(frozen=True, slots=True)
class CleanerOutcome:
    """Internal cleaner result consumed by the remediation service."""

    changed_fields: tuple[str, ...]
    integrity: IntegrityReport


class Cleaner(Protocol):
    """Predictable mutation interface; cleaners never select policy actions."""

    supported_remediation_ids: frozenset[str]

    def apply(
        self,
        source: Path,
        destination: Path,
        remediations: tuple[Remediation, ...],
        options: ScanOptions | None = None,
    ) -> CleanerOutcome:
        """Write a new artifact and verify its content integrity.

        ``options`` carries the boundaries the scan ran under. A cleaner that
        re-reads the artifact must apply the same limits the detector did.
        """
