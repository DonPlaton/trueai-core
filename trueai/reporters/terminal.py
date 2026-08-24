"""Premium-oriented, restrained terminal presentation."""

from __future__ import annotations

from collections import Counter

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from trueai.core.confidence import confidence_explanation
from trueai.core.models import (
    ConfidenceType,
    Finding,
    IntegrityStatus,
    ProvenanceClass,
    ProvenanceVerification,
    ProvenanceVerificationStatus,
    RemediationPlan,
    RemediationResult,
    ScanReport,
    Severity,
    ValidationOutcome,
)

_VERIFICATION_STYLE = {
    ProvenanceVerificationStatus.TRUSTED: "bold green",
    ProvenanceVerificationStatus.VALID: "yellow",
    ProvenanceVerificationStatus.INVALID: "bold red",
    ProvenanceVerificationStatus.NO_MANIFEST: "dim",
    ProvenanceVerificationStatus.UNSUPPORTED_CONTAINER: "dim",
    ProvenanceVerificationStatus.VERIFIER_UNAVAILABLE: "dim",
}

_SEVERITY_STYLE = {
    Severity.INFO: "dim cyan",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "bold red",
    Severity.CRITICAL: "bold white on red",
}


def _safe(value: object) -> str:
    """Return artifact-derived text that the markup parser will not interpret.

    Rich treats square brackets as markup. A file name, metadata value, or signed
    manifest field containing one is data, never formatting, so it is escaped
    before interpolation.
    """

    return escape(str(value))


class TerminalReporter:
    """Render findings without sensational authorship language."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def render(self, report: ScanReport, *, verbose: bool = False) -> None:
        """Print a scan report."""

        self.console.print(Text("TRUEAI", style="bold bright_cyan"))
        self.console.print(Text("Artifact Forensics", style="dim"))
        self.console.print()
        self.console.print(f"Scanning: [bold]{_safe(report.artifact.path)}[/bold]")
        self.console.print(
            f"{report.summary.finding_count} findings across "
            f"{report.summary.artifact_count} artifact(s)"
        )
        self.console.print()
        summary = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        summary.add_column("Evidence class")
        summary.add_column("Count", justify="right")
        confidence_counts = Counter(item.confidence_type for item in report.findings)
        for confidence_type in ConfidenceType:
            count = confidence_counts[confidence_type]
            if count:
                summary.add_row(confidence_type.value.upper(), str(count))
        provenance_count = sum(
            1 for item in report.findings if item.provenance_class != ProvenanceClass.NONE
        )
        if provenance_count:
            summary.add_row("PROVENANCE", str(provenance_count))
        self.console.print(summary)
        for finding in report.findings:
            self._finding(finding, verbose=verbose)
        if report.diagnostics:
            self.console.print("\n[bold]Diagnostics[/bold]")
            for diagnostic in report.diagnostics:
                self.console.print(
                    f"[{_SEVERITY_STYLE[diagnostic.severity]}]"
                    f"{diagnostic.severity.value.upper()}[/] {_safe(diagnostic.message)}"
                )
        if report.provenance_verifications:
            verification = Table(
                title="Authenticated provenance verification",
                show_lines=False,
            )
            verification.add_column("Artifact")
            verification.add_column("Status")
            verification.add_column("Signer")
            verification.add_column("Explanation")
            for result in report.provenance_verifications:
                signer = (
                    result.signer.common_name
                    if result.signer is not None and result.signer.common_name
                    else "-"
                )
                verification.add_row(
                    _safe(result.artifact_path),
                    Text(
                        result.status.value.upper(),
                        style=_VERIFICATION_STYLE[result.status],
                    ),
                    _safe(signer),
                    _safe(result.explanation),
                )
            self.console.print()
            self.console.print(verification)
        integrity_style = {
            IntegrityStatus.PASS: "green",
            IntegrityStatus.FAIL: "red",
            IntegrityStatus.NOT_VERIFIABLE: "yellow",
            IntegrityStatus.NOT_MODIFIED: "dim",
        }[report.integrity.status]
        self.console.print("\n[bold]Integrity[/bold]")
        self.console.print(
            f"[{integrity_style}]{report.integrity.status.value.replace('_', ' ').title()}[/] — "
            f"{_safe(report.integrity.explanation)}"
        )

    def render_plan(self, plan: RemediationPlan) -> None:
        """Print a remediation preview."""

        table = Table(title=f"Remediation preview — {plan.policy}", show_lines=False)
        table.add_column("Safety")
        table.add_column("Artifact")
        table.add_column("Operation")
        table.add_column("Findings", justify="right")
        for remediation in plan.remediations:
            table.add_row(
                remediation.safety.value,
                _safe(remediation.artifact_path),
                _safe(remediation.remediation_id),
                str(len(remediation.finding_ids)),
            )
        self.console.print(table)
        if plan.preserved_findings:
            self.console.print(f"Preserved findings: {len(plan.preserved_findings)}")
        if plan.blocked_findings:
            self.console.print(f"Blocked from automatic remediation: {len(plan.blocked_findings)}")
        if plan.review_findings:
            self.console.print(f"Manual review: {len(plan.review_findings)}")

    def render_result(self, result: RemediationResult) -> None:
        """Print an applied or dry-run result."""

        title = "Dry run" if result.dry_run else "Clean result"
        lines = [
            f"Output: {_safe(result.output_path or 'not created')}",
            f"Changed fields: {len(result.changed_fields)}",
            f"Integrity: {result.integrity.status.value.upper()}",
            _safe(result.integrity.explanation),
        ]
        if result.backup_path:
            lines.insert(1, f"Backup: {_safe(result.backup_path)}")
        self.console.print(Panel("\n".join(lines), title=title, border_style="bright_cyan"))

    def render_verification(self, result: ProvenanceVerification) -> None:
        """Print an authenticated provenance result without overstating it."""

        style = _VERIFICATION_STYLE[result.status]
        lines = [
            f"[{style}]{result.status.value.replace('_', ' ').upper()}[/]",
            _safe(result.explanation),
            "",
            f"Artifact: {_safe(result.artifact_path)}",
            f"Verifier: {_safe(result.verifier)}",
            f"Trust anchors configured: {'yes' if result.trust_anchors_configured else 'no'}",
        ]
        if result.claim_generator:
            lines.append(f"Claim generator: {_safe(result.claim_generator)}")
        if result.title:
            lines.append(f"Manifest title: {_safe(result.title)}")
        if result.signer is not None:
            signer = result.signer
            lines.append(
                "Signer: "
                + " · ".join(
                    _safe(part)
                    for part in (
                        signer.common_name,
                        signer.issuer,
                        signer.algorithm,
                        signer.signed_at,
                    )
                    if part
                )
            )
        if result.remote_manifest_url:
            fetched = "fetched" if result.remote_manifests_allowed else "not fetched"
            lines.append(f"Remote manifest: {_safe(result.remote_manifest_url)} ({fetched})")
        self.console.print(
            Panel("\n".join(lines), title="Provenance verification", border_style="bright_cyan")
        )
        if result.assertions:
            table = Table(title="Assertions", show_lines=False)
            table.add_column("Label")
            table.add_column("Data")
            for assertion in result.assertions:
                table.add_row(_safe(assertion.label), _safe(assertion.summary))
            self.console.print(table)
        failures = result.failures()
        if failures:
            table = Table(title="Failed checks", show_lines=False)
            table.add_column("Code")
            table.add_column("Explanation")
            for entry in failures:
                table.add_row(_safe(entry.code), _safe(entry.explanation))
            self.console.print(table)
        elif result.validation:
            passed = sum(
                1 for entry in result.validation if entry.outcome == ValidationOutcome.SUCCESS
            )
            self.console.print(f"[dim]{passed} validation check(s) passed.[/dim]")

    def _finding(self, finding: Finding, *, verbose: bool) -> None:
        style = _SEVERITY_STYLE[finding.severity]
        location = ""
        if finding.location and finding.location.line:
            location = f" · {_safe(finding.artifact_path)}:{finding.location.line}"
        provider = f" · {_safe(finding.provider)}" if finding.provider else ""
        self.console.print()
        self.console.print(
            f"[{style}]{finding.severity.value.upper()}[/] "
            f"[bold]{_safe(finding.title)}[/bold]{provider}{location}"
        )
        self.console.print(_safe(finding.description))
        self.console.print(
            f"[dim]{finding.confidence_type.value.upper()} {finding.confidence:.2f} · "
            f"{finding.category.value} · {finding.id}[/dim]"
        )
        if verbose:
            self.console.print(
                f"[dim]{confidence_explanation(finding.confidence, finding.confidence_type)}[/dim]"
            )
            self.console.print(f"Evidence: {_safe(finding.evidence)}")
