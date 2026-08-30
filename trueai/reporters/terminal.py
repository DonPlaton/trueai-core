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
    RemediationPlan,
    RemediationResult,
    ScanReport,
    Severity,
    ValidationOutcome,
)
from trueai.core.provenance_view import (
    FacetRow,
    MarkerPresence,
    ProvenanceFacets,
    ProviderVerification,
    SignatureState,
    SignerTrust,
    facets_for_report,
    facets_from_verification,
)

#: A settled negative and an unanswered question must not look alike. Dim reads
#: as "nothing to see"; an unanswered question is something to see, so it is
#: yellow. Anything not listed falls back to yellow rather than to dim, because
#: an unrecognised answer is by definition not a result.
_FACET_STYLE = {
    MarkerPresence.PRESENT.value: "bold cyan",
    MarkerPresence.ABSENT.value: "dim",
    SignatureState.VALID.value: "bold green",
    SignatureState.INVALID.value: "bold red",
    SignatureState.NO_SIGNATURE.value: "dim",
    SignerTrust.TRUSTED.value: "bold green",
    SignerTrust.NOT_TRUSTED.value: "yellow",
    SignerTrust.NOT_APPLICABLE.value: "dim",
    ProviderVerification.VERIFIED.value: "bold green",
    ProviderVerification.NOT_VERIFIED.value: "dim",
    ProviderVerification.NOT_SUPPORTED.value: "dim",
}


def _facet_style(row: FacetRow) -> str:
    """Return the style for one answer, defaulting an unknown one to yellow."""

    return "yellow" if row.unknown else _FACET_STYLE.get(row.answer, "yellow")


def _facet_text(row: FacetRow) -> Text:
    """Render one facet answer in a style that matches what it actually says."""

    return Text(row.answer.replace("_", " ").upper(), style=_facet_style(row))


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


def _count(total: int, noun: str) -> str:
    """Render a count with its noun agreeing.

    "1 findings across 9 artifact(s)" is the first line of the first report a
    buyer reads. Every noun here is regular, so a plural `s` is the whole rule
    and a table of exceptions would be more code than the problem.
    """

    return f"{total} {noun}" if total == 1 else f"{total} {noun}s"


#: Past this many names the list stops being readable and the count is what is
#: left to say. The names are in the JSON report either way.
_MAX_NAMED = 12


def _operation_names(result: RemediationResult, plan: RemediationPlan | None) -> tuple[str, ...]:
    """Turn applied remediation identifiers into the operations they name."""

    if plan is None:
        return result.applied_remediation_ids
    named = {item.id: item.remediation_id for item in plan.remediations}
    return tuple(named.get(identifier, identifier) for identifier in result.applied_remediation_ids)


def _listed(label: str, names: tuple[str, ...]) -> str:
    """Return ``label``, the count, and the names -- or why there are none."""

    if not names:
        return f"{label}: none"
    if len(names) <= _MAX_NAMED:
        return f"{label} ({len(names)}): {_safe(', '.join(names))}"
    shown = ", ".join(names[:_MAX_NAMED])
    return f"{label} ({len(names)}): {_safe(shown)}, and {len(names) - _MAX_NAMED} more"


class TerminalReporter:
    """Render findings without sensational authorship language."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def render(self, report: ScanReport, *, verbose: bool = False) -> None:
        """Print a scan report."""

        self.console.print(Text("TRUEAI", style="bold bright_cyan"))
        self.console.print(Text("Artifact Forensics", style="dim"))
        self.console.print()
        # "Target", not "Scanning": this renders a finished report, and `explain`
        # renders one it loaded from a file without scanning anything at all.
        self.console.print(f"Target: [bold]{_safe(report.artifact.path)}[/bold]")
        self.console.print(
            f"{_count(report.summary.finding_count, 'finding')} across "
            f"{_count(report.summary.artifact_count, 'artifact')}"
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
        self.console.print(summary)
        # Printed under the table rather than as a row in it. Evidence class is a
        # partition -- every finding has exactly one -- and provenance is an
        # attribute a finding of any class may also carry. As a row it read as a
        # fifth class, and the column stopped adding up to the finding count.
        provenance_count = sum(
            1 for item in report.findings if item.provenance_class != ProvenanceClass.NONE
        )
        if provenance_count:
            noun = "finding" if provenance_count == 1 else "findings"
            verb = "carries" if provenance_count == 1 else "carry"
            self.console.print(
                f"  {provenance_count} {noun} above also {verb} a provenance class, "
                "which is an attribute rather than a fifth evidence class."
            )
        for finding in report.findings:
            self._finding(finding, verbose=verbose)
        if report.diagnostics:
            self.console.print("\n[bold]Diagnostics[/bold]")
            for diagnostic in report.diagnostics:
                # A diagnostic is about a file the scan could not fully read, and
                # a HIGH one decides the exit code. Printing it without the path
                # gave an operator a failed build and nothing to open. The path
                # is optional on the model, so it is appended only when present
                # rather than rendered as an em dash the way the table does it.
                where = f" · {_safe(diagnostic.artifact_path)}" if diagnostic.artifact_path else ""
                self.console.print(
                    f"[{_SEVERITY_STYLE[diagnostic.severity]}]"
                    f"{diagnostic.severity.value.upper()}[/] "
                    f"{_safe(diagnostic.message)}{where}"
                )
        if report.provenance_verifications:
            # Four columns rather than one status, because a marker existing, its
            # signature verifying, its signer being trusted, and a provider
            # adapter confirming a watermark are four separate findings. One
            # column forces a reader to guess which of them a green badge means.
            verification = Table(title="Provenance", show_lines=False)
            verification.add_column("Artifact")
            verification.add_column("Marker")
            verification.add_column("Signature")
            verification.add_column("Signer trust")
            verification.add_column("Provider")
            faceted = facets_for_report(report)
            for facets in faceted:
                verification.add_row(
                    _safe(facets.artifact_path),
                    *(_facet_text(row) for row in facets.rows()),
                )
            self.console.print()
            self.console.print(verification)
            self._render_unknowns(faceted)
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

    def render_result(self, result: RemediationResult, plan: RemediationPlan | None = None) -> None:
        """Print an applied or dry-run result, naming what changed.

        A count cannot tell an operator that `Software` went and `Author`
        stayed, and that is the question somebody sanitizing a client deliverable
        is asking.

        ``plan`` is optional and only used to name the operations. The result
        records them by content-addressed identifier -- `rem_5f3c1dcf` -- which
        is the right thing to keep in an audit trail and the wrong thing to show
        a person; the plan is where those identifiers have names.
        """

        title = "Dry run" if result.dry_run else "Clean result"
        # "Output" beside a path nothing was written to reads as a file that
        # exists. In a dry run the path is where it would go.
        destination = "Would write" if result.dry_run else "Output"
        lines = [
            f"{destination}: {_safe(result.output_path or 'not created')}",
            _listed("Changed fields", result.changed_fields),
            _listed("Operations applied", _operation_names(result, plan)),
            f"Integrity: {result.integrity.status.value.upper()}",
            _safe(result.integrity.explanation),
        ]
        if result.backup_path:
            lines.insert(1, f"Backup: {_safe(result.backup_path)}")
        self.console.print(Panel("\n".join(lines), title=title, border_style="bright_cyan"))

    def _render_unknowns(self, faceted: tuple[ProvenanceFacets, ...]) -> None:
        """Name what was not determined, so silence is not read as absence."""

        undetermined = [(item, item.unknowns()) for item in faceted]
        if not any(rows for _, rows in undetermined):
            return
        self.console.print("\n[bold]Not determined[/bold]")
        for facets, rows in undetermined:
            for row in rows:
                self.console.print(
                    f"[yellow]{_safe(facets.artifact_path)}[/] — "
                    f"{_safe(row.question)} {_safe(row.detail)}"
                )

    def render_verification(self, result: ProvenanceVerification) -> None:
        """Print an authenticated provenance result without overstating it."""

        facets = facets_from_verification(result)
        lines = [_safe(facets.headline()), ""]
        for row in facets.rows():
            answer = row.answer.replace("_", " ").upper()
            lines.append(
                f"{_safe(row.question)} [{_facet_style(row)}]{answer}[/] — {_safe(row.detail)}"
            )
        lines += [
            "",
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
        for caveat in facets.caveats():
            lines += ["", _safe(caveat)]
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

    def render_attestation_verification(
        self,
        result: object,
        attestation: object = None,
    ) -> None:
        """Print each verification property on its own line.

        There is no summary verdict here on purpose. A reader who wants one has
        to decide which properties matter for their situation, which is the
        decision this record exists to support rather than to make for them.
        """

        from trueai.core.attestation import AttestationVerification, ProcessAttestation

        assert isinstance(result, AttestationVerification)
        table = Table(title="Process attestation verification", show_lines=False)
        table.add_column("Property")
        table.add_column("Result")

        def mark(value: bool | None, yes: str = "yes", no: str = "no") -> str:
            if value is None:
                return "[dim]not checked[/dim]"
            return f"[green]{yes}[/green]" if value else f"[red]{no}[/red]"

        def signature(status: str) -> str:
            styles = {
                "valid": "[green]valid[/green]",
                "invalid": "[red]invalid[/red]",
                "unverified": "[yellow]unverified (no key supplied)[/yellow]",
                "error": "[red]could not be checked[/red]",
                "absent": "[dim]absent[/dim]",
            }
            return styles.get(status, _safe(status))

        table.add_row("Record", _safe(result.attestation_id))
        table.add_row("Schema valid", mark(result.schema_valid))
        table.add_row("Content identifier", mark(result.content_id_valid))
        table.add_row("Artifact binding", mark(result.subject_bound))
        table.add_row("Evidence references resolve", mark(result.evidence_binding_complete))
        table.add_row("Claimant signature", signature(result.claimant_signature))
        table.add_row("Reviewer signature", signature(result.reviewer_signature))
        table.add_row("Organization signature", signature(result.organization_signature))
        table.add_row("Assessor signature", signature(result.assessor_signature))
        table.add_row("Within validity window", mark(not result.expired))
        table.add_row("Evaluation profile supported", mark(result.evaluation_profile_supported))
        table.add_row("Disclosed evidence consistent", mark(result.disclosed_evidence_consistent))
        table.add_row("Unresolved dissent", mark(not result.unresolved_dissent))
        table.add_row("Limitations acknowledged", mark(result.limitations_acknowledged))
        if result.strongest_evidence_status is not None:
            table.add_row(
                "Strongest evidence anywhere",
                _safe(result.strongest_evidence_status.value),
            )
        self.console.print(table)

        if result.authenticated_declaration:
            # The wording is the point. An identified person signed this; that is
            # not the same as anyone having checked whether it is true.
            self.console.print(
                "\n[bold green]Authenticated declaration[/bold green] — an identified claimant "
                "signed this record over these exact bytes."
            )
            self.console.print(
                "[dim]This is not a verified human-contribution claim. Only an applicable "
                "assessor can evaluate whether a claim is true.[/dim]"
            )
        else:
            self.console.print(
                "\n[yellow]Not an authenticated declaration[/yellow] — see the properties above "
                "for which check did not pass."
            )

        for problem in result.problems:
            self.console.print(f"[red]•[/red] {_safe(problem)}")

        if isinstance(attestation, ProcessAttestation):
            self.console.print("\n[bold]Limitations[/bold]")
            for limitation in attestation.limitations:
                self.console.print(f"  [dim]- {_safe(limitation.statement)}[/dim]")

    def render_profile_result(
        self,
        result: object,
        attestation: object = None,
    ) -> None:
        """Print one profile's outcome as stages, weights, and unmet requirements.

        The stage summary says "human-originated, AI-executed, human-validated"
        and stops there. Nothing here renders as an authorship verdict: the
        profile result is a policy answer about review requirements, the
        assurance level is about evidence strength, and neither is presented as
        the other.
        """

        from trueai.core.attestation import ProcessAttestation
        from trueai.core.evaluation import ProfileResult, stage_summary

        assert isinstance(result, ProfileResult)
        table = Table(
            title=f"Profile {result.profile_id} {result.profile_version}",
            show_lines=False,
        )
        table.add_column("Dimension")
        table.add_column("Weight", justify="right")
        table.add_column("Claimed as")
        table.add_column("Evidence")
        table.add_column("AI role")
        table.add_column("Meets profile")

        for outcome in result.outcomes:
            met = "[green]yes[/green]" if outcome.satisfied else "[red]no[/red]"
            table.add_row(
                _safe(outcome.dimension.value.replace("_", " ")),
                f"{outcome.weight:.2f}",
                _safe(outcome.level.value) if outcome.level else "[dim]not claimed[/dim]",
                _safe(outcome.evidence_status.value) if outcome.evidence_status else "[dim]—[/dim]",
                _safe(outcome.ai_autonomy.value) if outcome.ai_autonomy else "[dim]—[/dim]",
                met,
            )
        self.console.print(table)

        if isinstance(attestation, ProcessAttestation):
            self.console.print(
                f"\n[bold]Process summary[/bold] {_safe(stage_summary(attestation))}"
            )
            self.console.print(
                "[dim]Each part names a stage and who carried it. No combination of stage "
                "claims establishes authorship or originality.[/dim]"
            )

        assurance = result.assurance
        self.console.print(
            f"\n[bold]Process Assurance Level[/bold] {_safe(assurance.level.value)} — "
            f"{_safe(assurance.meaning)}"
        )
        for reason in assurance.reasons:
            self.console.print(f"  [dim]· {_safe(reason)}[/dim]")
        if assurance.next_level_requires:
            self.console.print("[bold]For the next level[/bold]")
            for requirement in assurance.next_level_requires:
                self.console.print(f"  [dim]- {_safe(requirement)}[/dim]")

        if result.meets_review_requirements:
            self.console.print(f"\n[green]{_safe(result.statement)}[/green]")
        else:
            self.console.print(f"\n[yellow]{_safe(result.statement)}[/yellow]")
            for unmet in result.unmet_requirements:
                self.console.print(f"[red]•[/red] {_safe(unmet)}")

        if isinstance(attestation, ProcessAttestation):
            self.console.print("\n[bold]Limitations[/bold]")
            for limitation in attestation.limitations:
                self.console.print(f"  [dim]- {_safe(limitation.statement)}[/dim]")

    def render_distribution_verification(
        self,
        result: object,
        distribution: object = None,
    ) -> None:
        """Print each distribution property on its own line.

        Integrity, identity, currency, and compatibility are four questions. A
        single verdict would let "signed by someone unknown" and "signed by a
        known publisher and revoked yesterday" render identically.
        """

        from trueai.plugins.distribution import DistributionVerification, PluginDistribution

        assert isinstance(result, DistributionVerification)
        table = Table(title="Plugin distribution verification")
        table.add_column("Property")
        table.add_column("Result")

        def mark(value: bool | None, yes: str = "yes", no: str = "no") -> str:
            if value is None:
                return "[dim]not checked[/dim]"
            return f"[green]{yes}[/green]" if value else f"[red]{no}[/red]"

        table.add_row("Distribution", _safe(result.distribution_id))
        if isinstance(distribution, PluginDistribution):
            table.add_row("Detector", _safe(distribution.detector_id))
            table.add_row("Publisher", _safe(distribution.publisher))
            table.add_row("Files signed", str(len(distribution.files)))
        table.add_row("Content identifier", mark(result.content_id_valid))
        table.add_row("Files match what was signed", mark(result.files_match))
        table.add_row("Publisher signature", _safe(result.signature))
        table.add_row("Within validity window", mark(not result.expired))
        table.add_row("Withdrawn by publisher", mark(not result.revoked, "no", "yes"))
        table.add_row("On the organization allowlist", mark(result.allowlisted))
        table.add_row("Core version compatible", mark(result.core_compatible))
        table.add_row("Report schema compatible", mark(result.schema_compatible))
        if result.publisher_identity is not None:
            table.add_row("Publisher identity", _safe(result.publisher_identity.assurance.value))
        self.console.print(table)

        for path in result.unlisted_files:
            self.console.print(f"[red]•[/red] not covered by the signature: {_safe(path)}")
        for path in result.missing_files:
            self.console.print(f"[red]•[/red] signed but missing: {_safe(path)}")
        for problem in result.problems:
            self.console.print(f"[red]•[/red] {_safe(problem)}")

        if result.may_load():
            self.console.print(
                "\n[green]This plugin may be loaded[/green] — every check the host requires "
                "before import came back clean."
            )
        else:
            self.console.print(
                "\n[yellow]This plugin will not be loaded[/yellow] — see the properties above."
            )

    def _finding(self, finding: Finding, *, verbose: bool) -> None:
        style = _SEVERITY_STYLE[finding.severity]
        # The path is printed whether or not there is a line to go with it. Most
        # findings are about a whole file — a container box, a document
        # property, an editor namespace — and printing the path only when a line
        # existed meant a directory scan reported "SVG generator comment" with no
        # way to tell which of the files it came from.
        location = f" · {_safe(finding.artifact_path)}"
        if finding.location and finding.location.line:
            location += f":{finding.location.line}"
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
