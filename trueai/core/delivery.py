"""Post-remediation verification of observable machine/tool indicators."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from trueai.core.certificates import machine_indicator_findings
from trueai.core.engine import TrueAIEngine
from trueai.core.models import FrozenModel, ScanOptions, ScanReport
from trueai.core.policy import PolicyStore


class DeliveryStatus(StrEnum):
    """Outcome of rescanning an artifact after predictable remediation."""

    CLEAR = "clear"
    INDICATORS_REMAIN = "indicators_remain"
    INCOMPLETE = "incomplete"


class DeliveryVerification(FrozenModel):
    """Explainable post-clean scan result, never an authorship verdict."""

    status: DeliveryStatus
    artifact_path: str
    explanation: str
    indicator_finding_ids: tuple[str, ...] = ()
    diagnostic_codes: tuple[str, ...] = ()
    report: ScanReport


def verify_clean_delivery(
    target: str | Path,
    *,
    options: ScanOptions | None = None,
    engine: TrueAIEngine | None = None,
) -> DeliveryVerification:
    """Rescan cleaned bytes and report whether scoped indicators remain.

    This verifies detector-visible residue, not human authorship. Heuristic style
    findings remain findings and are never mutated to make another detector fail.
    """

    boundaries = options or ScanOptions()
    scanner = engine or TrueAIEngine.default(include_experimental=boundaries.include_experimental)
    report = scanner.scan(target, options=boundaries, policy=PolicyStore.get("audit"))
    diagnostics = tuple(sorted({item.code for item in report.diagnostics}))
    indicators = machine_indicator_findings(report)
    if diagnostics:
        status = DeliveryStatus.INCOMPLETE
        explanation = "The post-clean scan was incomplete, so residue clearance cannot be issued."
    elif indicators:
        status = DeliveryStatus.INDICATORS_REMAIN
        explanation = (
            "One or more machine-assistance, generator-tool, watermark, or heuristic style "
            "indicators remain. Each remains an individual finding, not an authorship verdict."
        )
    else:
        status = DeliveryStatus.CLEAR
        explanation = (
            "No machine-assistance, generator-tool, watermark, or heuristic style indicators "
            "were detected within the configured post-clean scan scope."
        )
    return DeliveryVerification(
        status=status,
        artifact_path=report.artifact.path,
        explanation=explanation,
        indicator_finding_ids=tuple(item.id for item in indicators),
        diagnostic_codes=diagnostics,
        report=report,
    )
