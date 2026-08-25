"""Editor diagnostics, shaped like LSP without depending on an LSP library.

An editor extension wants one thing: diagnostics keyed by file, with ranges,
severities, and a message. The Language Server Protocol already specifies that
shape, so this emits plain dictionaries in it rather than inventing a fourth
one — and takes no dependency, because a scanner should not pull an LSP
implementation into a CI image that will never open an editor.

Two decisions worth stating.

**A missing range is omitted, not invented.** Most detectors report a byte
offset, and an editor needs a line and a character. Converting one to the other
needs the file, its encoding, and its line endings, and getting any of them wrong
puts a squiggle under the wrong text — which is worse than no squiggle, because
it looks authoritative. A finding without line information gets a
zero-length range at the start of the file and says so in the message.

**Severity is mapped, not equated.** TrueAI has five levels and LSP has four.
`CRITICAL` and `HIGH` both become `Error`; nothing below `MEDIUM` ever does. An
extension that turned every `INFO` finding into a red underline would be turned
off within a day, and a tool nobody runs finds nothing.
"""

from __future__ import annotations

from typing import Any, Final

from trueai.adapters.views import explain_finding, explain_findings, lsp_severity
from trueai.core.models import Finding, ScanReport

#: The source name an editor shows beside a diagnostic.
SOURCE: Final = "trueai"

_NO_LOCATION_NOTE: Final = (
    "This detector reported no line information, so the marker sits at the start of the file."
)


def _range(finding: Finding) -> dict[str, Any]:
    """Return an LSP range, zero-based, or the file start when unknown."""

    location = finding.location
    if location is None or location.line is None:
        return {
            "start": {"line": 0, "character": 0},
            "end": {"line": 0, "character": 0},
        }
    # LSP counts from zero; TrueAI's line and column count from one.
    line = location.line - 1
    character = (location.column - 1) if location.column is not None else 0
    return {
        "start": {"line": line, "character": character},
        "end": {"line": line, "character": character},
    }


def diagnostic(finding: Finding) -> dict[str, Any]:
    """Return one LSP-shaped diagnostic for a finding."""

    explanation = explain_finding(finding)
    message = " ".join([explanation.evidence_summary, *explanation.does_not_claim])
    if finding.location is None or finding.location.line is None:
        message = f"{message} {_NO_LOCATION_NOTE}"
    return {
        "range": _range(finding),
        "severity": lsp_severity(finding.severity),
        "code": finding.category.value,
        "source": SOURCE,
        "message": message,
        "data": {
            "finding_id": finding.id,
            "detector_id": finding.detector_id,
            "confidence_type": finding.confidence_type.value,
            "provenance_class": finding.provenance_class.value,
            "removable": finding.removable,
            "claims": explanation.claims,
            "does_not_claim": list(explanation.does_not_claim),
        },
    }


def diagnostics_by_file(report: ScanReport) -> dict[str, list[dict[str, Any]]]:
    """Group diagnostics by artifact path, the way an editor consumes them.

    Every scanned artifact appears, including ones with nothing to report, so an
    editor can clear stale markers on a clean file rather than leaving yesterday's
    squiggles under text that no longer has a problem.
    """

    grouped: dict[str, list[dict[str, Any]]] = {
        descriptor.path: [] for descriptor in report.artifacts
    }
    for finding in report.findings:
        grouped.setdefault(finding.artifact_path, []).append(diagnostic(finding))
    return grouped


def publish_payloads(report: ScanReport, *, root: str = "") -> tuple[dict[str, Any], ...]:
    """Return one `textDocument/publishDiagnostics` payload per artifact.

    The transport is the caller's: this is the message body an extension sends,
    not a client that sends it.
    """

    prefix = root.rstrip("/") + "/" if root else ""
    return tuple(
        {"uri": f"{prefix}{path}", "diagnostics": items}
        for path, items in sorted(diagnostics_by_file(report).items())
    )


def hover(report: ScanReport, finding_id: str) -> dict[str, Any] | None:
    """Return Markdown hover content for one finding, or ``None`` if unknown."""

    for explanation in explain_findings(report):
        if explanation.finding_id != finding_id:
            continue
        limits = "\n".join(f"- {item}" for item in explanation.does_not_claim)
        return {
            "contents": {
                "kind": "markdown",
                "value": (
                    f"**{explanation.title}** · `{explanation.detector_id}`\n\n"
                    f"{explanation.evidence_summary}\n\n"
                    f"**Claims:** {explanation.claims}\n\n"
                    f"**Does not claim:**\n{limits}\n"
                ),
            }
        }
    return None


__all__ = ["SOURCE", "diagnostic", "diagnostics_by_file", "hover", "publish_payloads"]
