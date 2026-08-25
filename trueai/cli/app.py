"""Typer CLI for local scans, inspection, planning, and verified cleanup."""

from __future__ import annotations

import importlib.util
import json
import os
import signal
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from enum import IntEnum, StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from trueai import __version__
from trueai.core.engine import TrueAIEngine
from trueai.core.errors import (
    ArtifactNotFoundError,
    AttestationError,
    OptionalDependencyError,
    PolicyValidationError,
    RemediationError,
    TrueAIError,
)
from trueai.core.models import ScanOptions, Severity
from trueai.core.policy import PolicyProfile, PolicyStore
from trueai.core.policy_bundle import (
    EnterprisePolicyBundle,
    PolicyBundleControls,
    apply_policy_bundle,
    issue_policy_bundle,
    load_policy_bundle,
    policy_bundle_json,
    policy_bundle_schema_json,
    verify_policy_bundle,
)
from trueai.core.progress import (
    CancellationToken,
    ProgressEvent,
    ProgressObserver,
    ScanCancelled,
)
from trueai.core.remediation import RemediationPlanner, RemediationService
from trueai.plugins.confinement import ConfinementLevel
from trueai.plugins.host import PluginIsolation
from trueai.reporters import HTMLReporter, JSONReporter, SARIFReporter, TerminalReporter


class AttestationPresentation(StrEnum):
    """Presentation forms for a process attestation.

    ``sarif-properties`` emits the property bag a CI job merges into a SARIF
    run, so process facts reach a dashboard as named properties rather than as
    an invented severity.
    """

    TERMINAL = "terminal"
    JSON = "json"
    SUMMARY = "summary"
    SARIF_PROPERTIES = "sarif-properties"


class InteropTarget(StrEnum):
    """Interoperable provenance vocabularies a record can be exported to."""

    PROV = "prov"
    DSSE = "dsse"
    C2PA = "c2pa"


class ExitCode(IntEnum):
    """Stable process exit codes."""

    SUCCESS = 0
    REVIEW_REQUIRED = 1
    POLICY_VIOLATION = 2
    UNSUPPORTED_OR_CORRUPT = 3
    INTERNAL_ERROR = 4


class OutputFormat(StrEnum):
    """Supported report formats."""

    TERMINAL = "terminal"
    JSON = "json"
    SARIF = "sarif"
    HTML = "html"
    #: GitHub-style workflow annotations plus a Markdown job summary.
    CI = "ci"
    #: LSP-shaped diagnostics keyed by file, for an editor extension.
    IDE = "ide"
    #: Every desktop view in one versioned bundle.
    DESKTOP = "desktop"


console = Console()
error_console = Console(stderr=True)
app = typer.Typer(
    name="trueai",
    no_args_is_help=True,
    help="Local-first artifact forensics and predictable sanitization.",
    rich_markup_mode="rich",
)
detectors_app = typer.Typer(
    help="List and inspect detector registrations.", invoke_without_command=True
)
policies_app = typer.Typer(help="List and inspect policy profiles.", invoke_without_command=True)
app.add_typer(detectors_app, name="detectors")
app.add_typer(policies_app, name="policies")


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"TrueAI Core {__version__} (schema 0.1)")
        raise typer.Exit()


@app.callback()
def root(
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True, help="Show version."),
    ] = False,
) -> None:
    """Inspect evidence, preserve provenance, and clean only predictable residue."""

    del version


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="File, directory, or Git repository to scan.")],
    output_format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            help="terminal, json, sarif, html, ci, ide, or desktop",
        ),
    ] = OutputFormat.TERMINAL,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Explicit report path.")
    ] = None,
    policy_name: Annotated[
        str, typer.Option("--policy", help="Built-in name or YAML path.")
    ] = "audit",
    policy_bundle: Annotated[
        Path | None,
        typer.Option(
            "--policy-bundle",
            exists=True,
            dir_okay=False,
            help="Signed enterprise policy bundle; its embedded profile replaces --policy.",
        ),
    ] = None,
    policy_key: Annotated[
        Path | None,
        typer.Option(
            "--policy-key",
            exists=True,
            dir_okay=False,
            help="Ed25519 public key required to authenticate --policy-bundle.",
        ),
    ] = None,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show detailed evidence.")
    ] = False,
    experimental: Annotated[
        bool, typer.Option("--experimental", help="Enable experimental heuristic detectors.")
    ] = False,
    max_file_size_mb: Annotated[
        int, typer.Option("--max-file-size-mb", min=1, help="Per-file read limit.")
    ] = 25,
    jobs: Annotated[
        int,
        typer.Option(
            "--jobs",
            "-j",
            min=1,
            max=64,
            help="Artifacts to inspect concurrently. Results stay in artifact order.",
        ),
    ] = 1,
    cache: Annotated[
        bool,
        typer.Option("--cache/--no-cache", help="Reuse detector output for unchanged content."),
    ] = False,
    progress: Annotated[
        bool,
        typer.Option(
            "--progress/--no-progress",
            help="Show scan progress on a terminal. Off when output is redirected.",
        ),
    ] = True,
    cache_dir: Annotated[
        Path | None,
        typer.Option("--cache-dir", help="Cache location. Implies --cache."),
    ] = None,
    plugins: Annotated[
        PluginIsolation,
        typer.Option(
            "--plugins",
            help="How to run third-party detectors: in_process, subprocess, or disabled.",
        ),
    ] = PluginIsolation.SUBPROCESS,
    verify_authenticated_provenance: Annotated[
        bool,
        typer.Option(
            "--verify-provenance",
            help="Explicitly run official C2PA verification and attach results to the report.",
        ),
    ] = False,
    trust_anchors: Annotated[
        Path | None,
        typer.Option(
            "--trust-anchors",
            exists=True,
            dir_okay=False,
            help="PEM trust anchors for --verify-provenance.",
        ),
    ] = None,
    allow_remote_manifests: Annotated[
        bool,
        typer.Option(
            "--allow-remote-manifests",
            help="Permit remote C2PA manifest fetching during explicit verification.",
        ),
    ] = False,
    plugin_confinement: Annotated[
        ConfinementLevel,
        typer.Option(
            "--plugin-confinement",
            help=(
                "none, best_effort, or required. `required` refuses to run a plugin when "
                "operating-system confinement cannot be established."
            ),
        ),
    ] = ConfinementLevel.BEST_EFFORT,
    attestation: Annotated[
        Path | None,
        typer.Option(
            "--attestation",
            exists=True,
            dir_okay=False,
            help=(
                "Process attestation whose verified facts are added to the SARIF run's "
                "property bag. Detection results are unaffected."
            ),
        ),
    ] = None,
) -> None:
    """Scan an artifact without modifying it."""

    try:
        if output is not None and path.exists() and output.resolve() == path.resolve():
            raise RemediationError("Report output must not overwrite the scanned artifact")
        if (trust_anchors is not None or allow_remote_manifests) and not (
            verify_authenticated_provenance
        ):
            raise PolicyValidationError(
                "--trust-anchors and --allow-remote-manifests require --verify-provenance"
            )
        policy, bundle = _resolve_policy(policy_name, policy_bundle, policy_key)
        options = ScanOptions(
            max_file_size=max_file_size_mb * 1024 * 1024,
            include_experimental=experimental,
            max_workers=jobs,
            cache_directory=_resolve_cache_directory(path, cache, cache_dir),
        )
        engine = TrueAIEngine.default(
            include_experimental=experimental,
            plugin_isolation=plugins,
            plugin_confinement=plugin_confinement,
        )
        with _scan_progress(progress) as (observer, token):
            try:
                report = engine.scan(
                    path,
                    options=options,
                    policy=policy,
                    progress=observer,
                    cancellation=token,
                )
            except ScanCancelled as cancelled:
                # A cancelled scan produces no report on purpose: a shorter one
                # reads exactly like a clean one to whoever opens it next.
                error_console.print(f"[yellow]{escape(str(cancelled))}[/yellow]")
                raise typer.Exit(code=130) from None
        if bundle is not None:
            assert policy_key is not None
            report = apply_policy_bundle(report, bundle, public_key=policy_key)
        if verify_authenticated_provenance and not _has_blocking_diagnostics(report):
            from trueai.detectors.provenance.verification import (
                attach_provenance_verifications,
            )

            report = attach_provenance_verifications(
                report,
                path,
                trust_anchors=trust_anchors,
                allow_remote_manifests=allow_remote_manifests,
            )
        # A record travels alongside the scan; it never changes what was detected.
        # Its facts land in the SARIF property bag with the verification result
        # attached, so an unauthenticated record reads as one.
        attestation_properties = (
            _attestation_properties(attestation, path) if attestation is not None else None
        )
        rendered = _render_report(
            report,
            output_format,
            verbose,
            emit=output is None or output_format == OutputFormat.TERMINAL,
            attestation_properties=attestation_properties,
        )
        if output is not None:
            if rendered is None:
                rendered = JSONReporter().render(report)
            output.write_text(rendered + "\n", encoding="utf-8")
            if output_format != OutputFormat.TERMINAL:
                error_console.print(f"Report written: {output}")
        raise typer.Exit(_exit_code(report))
    except typer.Exit:
        raise
    except (ArtifactNotFoundError, PolicyValidationError, TrueAIError) as exc:
        error_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc
    except Exception as exc:
        error_console.print(f"[red]Internal error: {type(exc).__name__}: {exc}[/red]")
        raise typer.Exit(ExitCode.INTERNAL_ERROR) from exc


@app.command()
def clean(
    path: Annotated[Path, typer.Argument(help="Single artifact to sanitize.")],
    policy_name: Annotated[
        str, typer.Option("--policy", help="Built-in name or YAML path.")
    ] = "safe-clean",
    policy_bundle: Annotated[
        Path | None,
        typer.Option(
            "--policy-bundle",
            exists=True,
            dir_okay=False,
            help="Signed enterprise policy bundle; its embedded profile replaces --policy.",
        ),
    ] = None,
    policy_key: Annotated[
        Path | None,
        typer.Option(
            "--policy-key",
            exists=True,
            dir_okay=False,
            help="Ed25519 public key required to authenticate --policy-bundle.",
        ),
    ] = None,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Explicit cleaned path.")
    ] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Preview without writing.")] = False,
    in_place: Annotated[
        bool,
        typer.Option(
            "--in-place", help="Overwrite only after verified temp output; create backup."
        ),
    ] = False,
    experimental: Annotated[
        bool,
        typer.Option(
            "--experimental",
            help="Include heuristic style detectors in scan and post-clean verification.",
        ),
    ] = False,
    verify_residue: Annotated[
        bool,
        typer.Option(
            "--verify-residue/--no-verify-residue",
            help="Rescan output and report any remaining machine/tool indicators.",
        ),
    ] = True,
    certificate_output: Annotated[
        Path | None,
        typer.Option(
            "--certificate",
            help="Write a content-bound post-clean audit certificate as JSON.",
        ),
    ] = None,
    signing_key: Annotated[
        Path | None,
        typer.Option(
            "--signing-key",
            exists=True,
            dir_okay=False,
            help="Optional Ed25519 private key for the certificate.",
        ),
    ] = None,
) -> None:
    """Plan, preview, apply, verify, and report predictable remediation."""

    try:
        policy, bundle = _resolve_policy(policy_name, policy_bundle, policy_key)
        # The cleaner re-reads the artifact, so it must use the boundaries the
        # scan applied rather than a fresh set of defaults.
        if certificate_output is not None and not verify_residue:
            raise RemediationError("--certificate requires post-clean residue verification")
        if signing_key is not None and certificate_output is None:
            raise RemediationError("--signing-key requires --certificate")
        options = ScanOptions(include_experimental=experimental)
        engine = TrueAIEngine.default(include_experimental=experimental)
        report = engine.scan(path, options=options, policy=policy)
        if bundle is not None:
            assert policy_key is not None
            report = apply_policy_bundle(report, bundle, public_key=policy_key)
        if _has_blocking_diagnostics(report):
            TerminalReporter(console).render(report, verbose=True)
            raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT)
        plan = RemediationPlanner().plan(report, policy)
        terminal = TerminalReporter(console)
        terminal.render_plan(plan)
        result = RemediationService().apply(
            path,
            report,
            plan,
            output_path=output,
            in_place=in_place,
            dry_run=dry_run,
            options=options,
        )
        terminal.render_result(result)
        delivery = None
        if not dry_run and verify_residue:
            from trueai.core.delivery import DeliveryStatus, verify_clean_delivery

            verified_target = Path(result.output_path) if result.output_path is not None else path
            delivery = verify_clean_delivery(verified_target, options=options, engine=engine)
            color = {
                DeliveryStatus.CLEAR: "green",
                DeliveryStatus.INDICATORS_REMAIN: "yellow",
                DeliveryStatus.INCOMPLETE: "red",
            }[delivery.status]
            console.print()
            console.print(
                f"Post-clean residue verification: [{color}]{delivery.status.value.upper()}[/{color}]"
            )
            console.print(escape(delivery.explanation))
            if delivery.indicator_finding_ids:
                console.print(
                    f"Remaining indicator findings: {len(delivery.indicator_finding_ids)}"
                )
            if certificate_output is not None:
                from trueai.core.certificates import certificate_json, issue_certificate

                certificate = issue_certificate(
                    delivery.report,
                    options,
                    signing_key=signing_key,
                )
                _write_new_certificate(
                    certificate_output, certificate_json(certificate), verified_target
                )
                console.print(f"Certificate: {certificate.certificate_id}")
                console.print(f"Certificate written: {certificate_output}")
        if delivery is not None and delivery.status.value == "incomplete":
            code = ExitCode.UNSUPPORTED_OR_CORRUPT
        elif report.summary.violation_count:
            code = ExitCode.POLICY_VIOLATION
        elif (
            plan.review_findings
            or plan.blocked_findings
            or (delivery is not None and delivery.status.value == "indicators_remain")
        ):
            code = ExitCode.REVIEW_REQUIRED
        else:
            code = ExitCode.SUCCESS
        raise typer.Exit(code)
    except typer.Exit:
        raise
    except (PolicyValidationError, RemediationError, TrueAIError, ValueError) as exc:
        error_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc
    except Exception as exc:
        error_console.print(f"[red]Internal error: {type(exc).__name__}: {exc}[/red]")
        raise typer.Exit(ExitCode.INTERNAL_ERROR) from exc


@app.command()
def inspect(
    path: Annotated[Path, typer.Argument(help="Artifact to inspect in detail.")],
    experimental: Annotated[bool, typer.Option("--experimental")] = False,
) -> None:
    """Show detailed evidence for every finding without mutation."""

    try:
        report = TrueAIEngine.default(include_experimental=experimental).scan(
            path,
            options=ScanOptions(include_experimental=experimental),
            policy=PolicyStore.get("audit"),
        )
        TerminalReporter(console).render(report, verbose=True)
        raise typer.Exit(_exit_code(report))
    except typer.Exit:
        raise
    except TrueAIError as exc:
        error_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc


@app.command()
def explain(
    finding_id: Annotated[str, typer.Argument(help="Stable finding ID from a JSON report.")],
    report_path: Annotated[
        Path,
        typer.Option("--report", exists=True, dir_okay=False, help="TrueAI JSON report."),
    ] = Path("trueai-report.json"),
) -> None:
    """Explain one finding from a validated JSON report."""

    try:
        report = JSONReporter.load(report_path)
        finding = next((item for item in report.findings if item.id == finding_id), None)
        if finding is None:
            error_console.print(f"[red]Finding not present in report: {finding_id}[/red]")
            raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT)
        single_report = report.model_copy(
            update={
                "findings": (finding,),
                "summary": report.summary.model_copy(update={"finding_count": 1}),
            }
        )
        TerminalReporter(console).render(single_report, verbose=True)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        error_console.print(f"[red]Invalid report: {exc}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc


@app.command()
def verify(
    path: Annotated[Path, typer.Argument(help="Artifact whose provenance should be verified.")],
    trust_anchors: Annotated[
        Path | None,
        typer.Option(
            "--trust-anchors",
            help="PEM bundle of trusted roots. Without it a valid signature is not trusted.",
        ),
    ] = None,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="terminal or json")
    ] = OutputFormat.TERMINAL,
    allow_remote_manifests: Annotated[
        bool,
        typer.Option(
            "--allow-remote-manifests",
            help="Permit fetching a manifest stored off the machine. Off by default.",
        ),
    ] = False,
) -> None:
    """Verify authenticated C2PA provenance, separately from scanning."""

    from trueai.detectors.provenance.verification import verify_provenance

    try:
        result = verify_provenance(
            path,
            trust_anchors=trust_anchors,
            allow_remote_manifests=allow_remote_manifests,
        )
        if output_format == OutputFormat.JSON:
            typer.echo(
                json.dumps(
                    result.model_dump(mode="json", exclude_none=True),
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            TerminalReporter(console).render_verification(result)
        raise typer.Exit(_verification_exit_code(result.status))
    except typer.Exit:
        raise
    except (ArtifactNotFoundError, TrueAIError, OSError) as exc:
        error_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc


def _verification_exit_code(status: object) -> ExitCode:
    """Map a verification status onto the documented exit codes."""

    from trueai.core.models import ProvenanceVerificationStatus

    if status == ProvenanceVerificationStatus.TRUSTED:
        return ExitCode.SUCCESS
    if status == ProvenanceVerificationStatus.INVALID:
        return ExitCode.POLICY_VIOLATION
    if status in {
        ProvenanceVerificationStatus.VALID,
        ProvenanceVerificationStatus.NO_MANIFEST,
    }:
        return ExitCode.REVIEW_REQUIRED
    return ExitCode.UNSUPPORTED_OR_CORRUPT


plugins_app = typer.Typer(
    help="Review third-party detector manifests and host decisions.",
    invoke_without_command=True,
)
app.add_typer(plugins_app, name="plugins")


@plugins_app.callback(invoke_without_command=True)
def plugins_callback(ctx: typer.Context) -> None:
    """Show plugins when no plugin subcommand is supplied."""

    if ctx.invoked_subcommand is None:
        _print_plugins()


@plugins_app.command("sign")
def plugins_sign(
    root: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=False, help="Directory the plugin was built in."),
    ],
    detector_id: Annotated[str, typer.Option("--detector-id", help="Detector this publishes.")],
    version: Annotated[str, typer.Option("--version", help="Distribution version.")],
    entry_point: Annotated[
        str, typer.Option("--entry-point", help="module:attribute the host will load.")
    ],
    publisher: Annotated[str, typer.Option("--publisher", help="Publishing organization.")],
    signing_key: Annotated[
        Path,
        typer.Option("--signing-key", exists=True, dir_okay=False, help="Ed25519 private key."),
    ],
    capability: Annotated[
        list[str] | None,
        typer.Option("--capability", help="Capability the plugin needs, repeatable."),
    ] = None,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Where to write the distribution.")
    ] = None,
    publisher_id: Annotated[
        str | None, typer.Option("--publisher-id", help="Directory identifier for the publisher.")
    ] = None,
    minimum_core: Annotated[
        str | None, typer.Option("--minimum-core", help="Lowest TrueAI core this supports.")
    ] = None,
    maximum_core: Annotated[
        str | None, typer.Option("--maximum-core", help="Highest TrueAI core this supports.")
    ] = None,
) -> None:
    """Sign every file of a plugin along with the capabilities it declares.

    The manifest travels inside the signature, so a host can decide what the
    plugin may do without importing it — and the module's bytes are covered by
    the same signature, so a declared capability set cannot be contradicted by
    what module-level code actually does.
    """

    from trueai.plugins.distribution import (
        DISTRIBUTION_FILENAME,
        DistributionError,
        build_distribution,
        distribution_json,
        sign_distribution,
    )
    from trueai.plugins.manifest import PluginCapability, PluginManifest

    try:
        capabilities = frozenset(PluginCapability(item) for item in capability or [])
        manifest = PluginManifest(
            detector_id=detector_id,
            name=detector_id,
            version=version,
            vendor=publisher,
            capabilities=capabilities or PluginManifest.model_fields["capabilities"].default,
        )
        published = build_distribution(
            detector_id=detector_id,
            version=version,
            entry_point=entry_point,
            manifest=manifest,
            publisher=publisher,
            publisher_id=publisher_id,
            root=root,
            minimum_core_version=minimum_core,
            maximum_core_version=maximum_core,
        )
        published = sign_distribution(published, signing_key=signing_key)
        destination = output or root / DISTRIBUTION_FILENAME
        destination.write_text(distribution_json(published) + chr(10), encoding="utf-8")
        console.print(
            f"{published.distribution_id} covers {len(published.files)} file(s), "
            f"written to {destination}"
        )
    except (DistributionError, ValueError, OSError) as exc:
        error_console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc


@plugins_app.command("verify")
def plugins_verify(
    distribution_path: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, help="Distribution document.")
    ],
    root: Annotated[
        Path | None,
        typer.Option(
            "--root",
            exists=True,
            file_okay=False,
            help="Installed plugin directory. Without it, file digests are not checked.",
        ),
    ] = None,
    public_key: Annotated[
        Path | None,
        typer.Option("--public-key", exists=True, dir_okay=False, help="Publisher public key."),
    ] = None,
    allowlist_path: Annotated[
        Path | None,
        typer.Option("--allowlist", exists=True, dir_okay=False, help="Organization allowlist."),
    ] = None,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="terminal or json")
    ] = OutputFormat.TERMINAL,
) -> None:
    """Report every property separately: integrity, identity, currency, compatibility."""

    from trueai.plugins.distribution import (
        DistributionError,
        load_allowlist,
        load_distribution,
        verify_distribution,
    )

    try:
        published = load_distribution(distribution_path)
        allowlist = load_allowlist(allowlist_path) if allowlist_path else None
        result = verify_distribution(
            published, root=root, public_key=public_key, allowlist=allowlist
        )
        if output_format == OutputFormat.JSON:
            typer.echo(
                json.dumps(
                    result.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True
                )
            )
        else:
            TerminalReporter(console).render_distribution_verification(result, published)
        raise typer.Exit(ExitCode.SUCCESS if result.may_load() else ExitCode.REVIEW_REQUIRED)
    except typer.Exit:
        raise
    except (DistributionError, ValueError, OSError) as exc:
        error_console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc


@plugins_app.command("allowlist")
def plugins_allowlist(
    output: Annotated[Path, typer.Argument(help="Where to write the signed allowlist.")],
    organization: Annotated[str, typer.Option("--organization", help="Whose decision this is.")],
    signing_key: Annotated[
        Path,
        typer.Option("--signing-key", exists=True, dir_okay=False, help="Ed25519 private key."),
    ],
    sequence: Annotated[
        int,
        typer.Option("--sequence", min=1, help="Monotonic sequence; a lower one is a rollback."),
    ],
    days: Annotated[int, typer.Option("--days", min=1, help="Validity window in days.")] = 90,
    allow_distribution: Annotated[
        list[str] | None,
        typer.Option("--allow-distribution", help="TAIPKG1- identifier, repeatable."),
    ] = None,
    allow_publisher_key: Annotated[
        list[str] | None,
        typer.Option("--allow-publisher-key", help="sha256:… publisher key id, repeatable."),
    ] = None,
) -> None:
    """Publish an organization's decision about which plugins may be installed.

    Finite-lifetime and sequenced, because an allowlist that can be replaced with
    an older copy allows whatever the older copy allowed.
    """

    from datetime import UTC, datetime, timedelta

    from trueai.core.trust import public_key_id
    from trueai.plugins.distribution import (
        DistributionError,
        PluginAllowlist,
        allowlist_json,
        sign_allowlist,
    )

    try:
        issued = datetime.now(UTC)
        public = signing_key.with_suffix(".pub")
        if not public.is_file():
            raise DistributionError(
                f"Expected the matching public key at {public}, so the allowlist can record "
                "which key issued it."
            )
        allowlist = PluginAllowlist(
            organization=organization,
            issuer_key_id=public_key_id(public),
            sequence=sequence,
            issued_at=issued,
            expires_at=issued + timedelta(days=days),
            allowed_distribution_ids=frozenset(allow_distribution or []),
            allowed_publisher_key_ids=frozenset(allow_publisher_key or []),
        )
        allowlist = sign_allowlist(allowlist, signing_key=signing_key)
        output.write_text(allowlist_json(allowlist) + chr(10), encoding="utf-8")
        console.print(
            f"{organization} allowlist sequence {sequence} written to {output}; "
            f"{len(allowlist.allowed_distribution_ids)} distribution(s), "
            f"{len(allowlist.allowed_publisher_key_ids)} publisher key(s)"
        )
    except (DistributionError, ValueError, OSError) as exc:
        error_console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc


@plugins_app.command("list")
def list_plugins() -> None:
    """List installed third-party detectors, what they ask for, and the verdict."""

    _print_plugins()


cache_app = typer.Typer(help="Inspect and clear the incremental scan cache.")
app.add_typer(cache_app, name="cache")

attestations_app = typer.Typer(
    help="Create, sign, and verify Human Contribution Records (process attestations)."
)
app.add_typer(attestations_app, name="attestations")


@attestations_app.command("init")
def attestations_init(
    output: Annotated[Path, typer.Argument(help="Manifest path to create.")] = Path(
        "attestation.yaml"
    ),
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing manifest.")] = False,
) -> None:
    """Write a starter manifest that claims nothing it cannot support."""

    from trueai.core.attestation_manifest import template_manifest

    try:
        if output.exists() and not force:
            raise RemediationError(f"Refusing to overwrite {output}; pass --force")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(template_manifest(), encoding="utf-8")
        console.print(f"Wrote {output}")
        console.print(
            "[dim]Fill in only what you can support. A dimension you leave out stays "
            "not_claimed, which is an honest answer.[/dim]"
        )
    except (OSError, RemediationError) as exc:
        error_console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc


@attestations_app.command("validate")
def attestations_validate(
    manifest: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, help="Manifest to check.")
    ],
    artifact: Annotated[
        Path | None,
        typer.Option(
            "--artifact",
            exists=True,
            dir_okay=True,
            help="Subject file or directory inventory root.",
        ),
    ] = None,
) -> None:
    """Check a manifest without writing anything."""

    from trueai.core.attestation_manifest import build_attestation, load_manifest

    try:
        record = build_attestation(
            load_manifest(manifest),
            artifact=artifact,
            base_directory=manifest.parent,
        )
        console.print(
            f"Manifest is valid: {len(record.claims)} claim(s), "
            f"{len(record.actors)} actor(s), {len(record.evidence)} evidence reference(s)."
        )
    except (AttestationError, ValueError) as exc:
        error_console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc


@attestations_app.command("issue")
def attestations_issue(
    manifest: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, help="Manifest describing the work.")
    ],
    artifact: Annotated[
        Path | None,
        typer.Option(
            "--artifact",
            exists=True,
            dir_okay=True,
            help="Subject file or directory inventory root.",
        ),
    ] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Record path.")] = None,
    signing_key: Annotated[
        Path | None,
        typer.Option(
            "--signing-key",
            exists=True,
            dir_okay=False,
            help="Ed25519 key that signs the record as the claimant.",
        ),
    ] = None,
    claimant: Annotated[
        str | None,
        typer.Option("--claimant", help="Actor id that the signing key belongs to."),
    ] = None,
    valid_for_days: Annotated[
        int | None, typer.Option("--valid-for-days", min=1, help="Finite validity period.")
    ] = None,
) -> None:
    """Build a content-bound record from a manifest, optionally signing it."""

    from trueai.core.attestation import SignatureRole, attestation_json, sign_attestation
    from trueai.core.attestation_manifest import build_attestation, load_manifest

    try:
        record = build_attestation(
            load_manifest(manifest),
            artifact=artifact,
            base_directory=manifest.parent,
            valid_for_days=valid_for_days,
        )
        if signing_key is not None:
            if claimant is None:
                raise AttestationError("--signing-key requires --claimant")
            record = sign_attestation(
                record,
                role=SignatureRole.CLAIMANT,
                actor_id=claimant,
                signing_key=signing_key,
            )
        destination = output or manifest.with_suffix(".process.json")
        destination.write_text(attestation_json(record) + "\n", encoding="utf-8")
        console.print(f"{record.attestation_id} written to {destination}")
        if signing_key is None:
            console.print(
                "[dim]Unsigned: the record is content-addressed and tamper evident, but "
                "nobody has stood behind it yet.[/dim]"
            )
    except (AttestationError, ValueError, OSError) as exc:
        error_console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc


@attestations_app.command("sign")
def attestations_sign(
    record_path: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, help="Record to countersign.")
    ],
    signing_key: Annotated[
        Path, typer.Option("--signing-key", exists=True, dir_okay=False, help="Ed25519 key.")
    ],
    actor: Annotated[str, typer.Option("--actor", help="Actor id doing the signing.")],
    role: Annotated[
        str,
        typer.Option("--role", help="claimant, reviewer, organization, or assessor."),
    ] = "reviewer",
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Where to write the signed record.")
    ] = None,
) -> None:
    """Add one signed statement without invalidating the existing ones."""

    from trueai.core.attestation import (
        SignatureRole,
        attestation_json,
        load_attestation,
        sign_attestation,
    )

    try:
        try:
            signature_role = SignatureRole(role)
        except ValueError as exc:
            allowed = ", ".join(item.value for item in SignatureRole)
            raise AttestationError(f"Unknown role {role!r}; expected one of {allowed}") from exc
        record = sign_attestation(
            load_attestation(record_path),
            role=signature_role,
            actor_id=actor,
            signing_key=signing_key,
        )
        destination = output or record_path
        destination.write_text(attestation_json(record) + "\n", encoding="utf-8")
        console.print(f"{actor} signed {record.attestation_id} as {signature_role.value}")
    except (AttestationError, ValueError, OSError) as exc:
        error_console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc


@attestations_app.command("verify")
def attestations_verify(
    record_path: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, help="Record to verify.")
    ],
    artifact: Annotated[
        Path | None,
        typer.Option(
            "--artifact",
            exists=True,
            dir_okay=True,
            help="Subject file or directory inventory; required to establish binding.",
        ),
    ] = None,
    public_key: Annotated[
        list[str] | None,
        typer.Option(
            "--public-key",
            help="actor=path, repeatable. Without a key a signature is unverified, not invalid.",
        ),
    ] = None,
    profile: Annotated[
        list[str] | None,
        typer.Option("--profile", help="Evaluation profile this verifier supports."),
    ] = None,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="terminal or json")
    ] = OutputFormat.TERMINAL,
) -> None:
    """Report every verification property separately, never as one badge."""

    from trueai.core.attestation import load_attestation, verify_attestation

    try:
        keys: dict[str, str | Path] = {}
        for entry in public_key or []:
            actor_id, separator, key_path = entry.partition("=")
            if not separator:
                raise AttestationError(f"--public-key expects actor=path, got {entry!r}")
            keys[actor_id] = key_path
        record = load_attestation(record_path)
        result = verify_attestation(
            record,
            artifact=artifact,
            public_keys=keys or None,
            supported_profiles=frozenset(profile) if profile else None,
        )
        if output_format == OutputFormat.JSON:
            typer.echo(
                json.dumps(
                    result.model_dump(mode="json"),
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            TerminalReporter(console).render_attestation_verification(result, record)
        raise typer.Exit(_attestation_exit_code(result))
    except typer.Exit:
        raise
    except (AttestationError, ValueError, OSError) as exc:
        error_console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc


@attestations_app.command("summarize")
def attestations_summarize(
    record_path: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, help="Record to summarize.")
    ],
) -> None:
    """Print a stage-by-stage summary that repeats its own limitations."""

    from trueai.core.attestation import load_attestation
    from trueai.core.attestation_manifest import summarize

    try:
        typer.echo(summarize(load_attestation(record_path)))
    except (AttestationError, OSError) as exc:
        error_console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc


@attestations_app.command("evaluate")
def attestations_evaluate(
    record_path: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, help="Record to evaluate.")
    ],
    profile_id: Annotated[
        str,
        typer.Option("--profile", help="Evaluation profile to apply."),
    ] = "software-delivery",
    artifact: Annotated[
        Path | None,
        typer.Option(
            "--artifact",
            exists=True,
            dir_okay=True,
            help="Subject file or directory inventory; without it assurance remains PAL-0.",
        ),
    ] = None,
    public_key: Annotated[
        list[str] | None,
        typer.Option("--public-key", help="actor=path, repeatable."),
    ] = None,
    output_format: Annotated[
        AttestationPresentation,
        typer.Option("--format", "-f", help="terminal, json, summary, or sarif-properties"),
    ] = AttestationPresentation.TERMINAL,
) -> None:
    """Apply one versioned profile and present the result without upgrading it.

    A profile answers whether a record meets a stated set of review
    requirements. It does not answer who authored the work, and no output here
    converts a stage claim into an authorship or originality proof.
    """

    from trueai.core.attestation import load_attestation, verify_attestation
    from trueai.core.evaluation import (
        evaluate_with_profile,
        get_profile,
        portable_summary,
        sarif_properties,
    )

    try:
        keys: dict[str, str | Path] = {}
        for entry in public_key or []:
            actor_id, separator, key_path = entry.partition("=")
            if not separator:
                raise AttestationError(f"--public-key expects actor=path, got {entry!r}")
            keys[actor_id] = key_path
        profile = get_profile(profile_id)
        record = load_attestation(record_path)
        verification = verify_attestation(
            record,
            artifact=artifact,
            public_keys=keys or None,
            supported_profiles=frozenset({profile_id}),
        )
        result = evaluate_with_profile(record, verification, profile)

        if output_format == AttestationPresentation.JSON:
            typer.echo(
                json.dumps(
                    result.model_dump(mode="json"),
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
            )
        elif output_format == AttestationPresentation.SARIF_PROPERTIES:
            typer.echo(
                json.dumps(
                    sarif_properties(record, verification),
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
            )
        elif output_format == AttestationPresentation.SUMMARY:
            typer.echo(portable_summary(record, verification, profile))
        else:
            TerminalReporter(console).render_profile_result(result, record)
        raise typer.Exit(
            ExitCode.SUCCESS if result.meets_review_requirements else ExitCode.REVIEW_REQUIRED
        )
    except typer.Exit:
        raise
    except KeyError as exc:
        error_console.print(f"[red]{escape(str(exc.args[0]))}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc
    except (AttestationError, ValueError, OSError) as exc:
        error_console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc


@attestations_app.command("profiles")
def attestations_profiles() -> None:
    """List the built-in evaluation profiles and what each one weighs."""

    from trueai.core.evaluation import BUILT_IN_PROFILES

    for profile_id, profile in sorted(BUILT_IN_PROFILES.items()):
        console.print(f"[bold]{escape(profile_id)}[/bold] {escape(profile.version)}")
        console.print(f"  {escape(profile.description)}")
        weights = ", ".join(
            f"{requirement.dimension.value}={requirement.weight:.2f}"
            + ("*" if requirement.required else "")
            for requirement in profile.requirements
        )
        console.print(f"  [dim]weights: {escape(weights)}[/dim]")
        console.print(f"  [dim]minimum assurance: {escape(profile.minimum_assurance.value)}[/dim]")


@attestations_app.command("export")
def attestations_export(
    record_path: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, help="Record to export.")
    ],
    target: Annotated[
        InteropTarget,
        typer.Option("--to", help="prov (W3C PROV-JSON), dsse (in-toto), or c2pa (assertions)."),
    ] = InteropTarget.PROV,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Where to write the export.")
    ] = None,
    signing_key: Annotated[
        Path | None,
        typer.Option(
            "--signing-key",
            exists=True,
            dir_okay=False,
            help=(
                "Sign the DSSE envelope. The record's own signatures cannot be reused: "
                "they cover different bytes."
            ),
        ),
    ] = None,
) -> None:
    """Export a record to an interoperable vocabulary, stating what was left behind.

    Each export carries a list of the concepts its target cannot express. A
    consumer who reads only the mapped half will read the record as stronger than
    it is, so the unmapped half travels with it.
    """

    from trueai.core.attestation import load_attestation
    from trueai.core.interop import (
        to_c2pa_assertions,
        to_dsse_envelope,
        to_prov,
        unmapped_concepts,
    )
    from trueai.core.trust import LocalKeySigningProvider

    try:
        if signing_key is not None and target != InteropTarget.DSSE:
            raise AttestationError("--signing-key applies only to --to dsse")
        record = load_attestation(record_path)
        payload: object
        if target == InteropTarget.PROV:
            payload = to_prov(record)
        elif target == InteropTarget.DSSE:
            providers = (LocalKeySigningProvider(signing_key),) if signing_key else ()
            payload = to_dsse_envelope(record, providers=providers).model_dump(mode="json")
        else:
            payload = {
                "assertions": to_c2pa_assertions(record),
                "note": (
                    "TrueAI produces assertion data. It does not sign, embed, or produce "
                    "C2PA manifests."
                ),
            }
        rendered = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
        if output is not None:
            output.write_text(rendered + "\n", encoding="utf-8")
            console.print(f"{target.value} export written to {output}")
        else:
            typer.echo(rendered)
        for item in unmapped_concepts(target.value):
            error_console.print(f"[dim]not exported: {escape(item.concept)}[/dim]")
    except (AttestationError, ValueError, OSError) as exc:
        error_console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc


@attestations_app.command("interop")
def attestations_interop(
    record_path: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, help="Record to describe.")
    ],
) -> None:
    """Say what each interoperable export would carry, and what it would drop."""

    from trueai.core.attestation import load_attestation
    from trueai.core.interop import interop_summary

    try:
        typer.echo(interop_summary(load_attestation(record_path)))
    except (AttestationError, OSError) as exc:
        error_console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc


@attestations_app.command("redact")
def attestations_redact(
    record_path: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, help="Record to redact.")
    ],
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Where to write the public variant.")
    ] = None,
) -> None:
    """Write a public variant carrying no withheld material.

    The redacted record gets a new identifier because it makes a narrower set of
    statements, and signatures are dropped because they covered the full bytes.
    """

    from trueai.core.attestation import attestation_json, load_attestation
    from trueai.core.attestation_manifest import redact_for_public

    try:
        record = load_attestation(record_path)
        public = redact_for_public(record)
        destination = output or record_path.with_suffix(".public.json")
        destination.write_text(attestation_json(public) + "\n", encoding="utf-8")
        console.print(f"{public.attestation_id} written to {destination}")
        if record.signatures:
            console.print(
                "[dim]Signatures were dropped: they cover the unredacted bytes. Sign the "
                "public variant separately if it needs to be authenticated.[/dim]"
            )
    except (AttestationError, ValueError, OSError) as exc:
        error_console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc


@attestations_app.command("keygen")
def attestations_keygen(
    private_key: Annotated[Path, typer.Argument(help="Where to write the private key.")],
    public_key: Annotated[Path, typer.Argument(help="Where to write the public key.")],
) -> None:
    """Generate an Ed25519 key pair for signing records."""

    from trueai.core.certificates import generate_ed25519_keypair

    try:
        identifier = generate_ed25519_keypair(private_key, public_key)
        console.print(f"Key {identifier} written to {private_key} and {public_key}")
    except (AttestationError, OptionalDependencyError, OSError) as exc:
        error_console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc


@attestations_app.command("schema")
def attestations_schema(
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the schema to a file.")
    ] = None,
) -> None:
    """Emit the process-attestation JSON Schema."""

    from trueai.core.attestation import attestation_schema_json

    rendered = attestation_schema_json()
    if output is None:
        typer.echo(rendered.rstrip("\n"))
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    error_console.print(f"Schema written: {output}")


def _attestation_exit_code(result: object) -> ExitCode:
    """Map verification results onto the documented exit codes.

    A record whose content identifier or artifact binding fails is corrupt. A
    record that is merely unsigned or self-declared needs review, not rejection:
    that is a normal, honest state.
    """

    from trueai.core.attestation import AttestationVerification

    assert isinstance(result, AttestationVerification)
    if not result.content_id_valid or result.subject_bound is False:
        return ExitCode.POLICY_VIOLATION
    if "invalid" in {
        result.claimant_signature,
        result.reviewer_signature,
        result.organization_signature,
        result.assessor_signature,
    }:
        return ExitCode.POLICY_VIOLATION
    if result.authenticated_declaration and not result.problems:
        return ExitCode.SUCCESS
    return ExitCode.REVIEW_REQUIRED


certificates_app = typer.Typer(help="Issue and verify content-bound TrueAI audit certificates.")
app.add_typer(certificates_app, name="certificates")


@certificates_app.command("issue")
def certificates_issue(
    path: Annotated[Path, typer.Argument(help="Artifact to scan and bind to the certificate.")],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="New certificate JSON path."),
    ] = None,
    policy_name: Annotated[
        str, typer.Option("--policy", help="Built-in name or YAML path.")
    ] = "audit",
    experimental: Annotated[
        bool,
        typer.Option("--experimental", help="Include heuristic style detectors in scope."),
    ] = False,
    signing_key: Annotated[
        Path | None,
        typer.Option(
            "--signing-key",
            exists=True,
            dir_okay=False,
            help="Optional Ed25519 private key used to authenticate the issuer.",
        ),
    ] = None,
    valid_for_days: Annotated[
        int | None,
        typer.Option(
            "--valid-for-days",
            min=1,
            help="Optional finite certificate validity period.",
        ),
    ] = None,
) -> None:
    """Scan exact bytes and write an honest, independently verifiable audit record."""

    from trueai.core.certificates import CertificateStatus, certificate_json, issue_certificate

    try:
        policy = PolicyStore.get(policy_name)
        options = ScanOptions(include_experimental=experimental)
        report = TrueAIEngine.default(include_experimental=experimental).scan(
            path, options=options, policy=policy
        )
        certificate = issue_certificate(
            report,
            options,
            signing_key=signing_key,
            valid_for=(timedelta(days=valid_for_days) if valid_for_days is not None else None),
        )
        target = output or _default_certificate_path(path)
        _write_new_certificate(target, certificate_json(certificate), path)
        color = {
            CertificateStatus.CLEAR: "green",
            CertificateStatus.INDICATORS_DETECTED: "yellow",
            CertificateStatus.INCOMPLETE: "red",
        }[certificate.status]
        console.print(f"Certificate: [bold]{certificate.certificate_id}[/bold]")
        console.print(f"Status: [{color}]{certificate.status.value.upper()}[/{color}]")
        console.print(escape(certificate.statement))
        console.print(f"Written: {target}")
        if certificate.status == CertificateStatus.CLEAR:
            code = ExitCode.SUCCESS
        elif certificate.status == CertificateStatus.INDICATORS_DETECTED:
            code = ExitCode.REVIEW_REQUIRED
        else:
            code = ExitCode.UNSUPPORTED_OR_CORRUPT
        raise typer.Exit(code)
    except typer.Exit:
        raise
    except (OSError, TrueAIError, ValueError) as exc:
        error_console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc


@certificates_app.command("verify")
def certificates_verify(
    certificate_path: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, help="Certificate JSON to verify.")
    ],
    artifact: Annotated[
        Path | None,
        typer.Option("--artifact", help="Optional file/directory whose bytes must match."),
    ] = None,
    public_key: Annotated[
        Path | None,
        typer.Option(
            "--public-key",
            exists=True,
            dir_okay=False,
            help="Issuer Ed25519 public key for signature verification.",
        ),
    ] = None,
    revocation_list_path: Annotated[
        Path | None,
        typer.Option(
            "--revocation-list",
            exists=True,
            dir_okay=False,
            help="Optional issuer-signed revocation list.",
        ),
    ] = None,
    require_revocation_check: Annotated[
        bool,
        typer.Option(
            "--require-revocation-check",
            help="Fail unless a current authenticated revocation list was checked.",
        ),
    ] = False,
    require_full_verification: Annotated[
        bool,
        typer.Option(
            "--require-full-verification",
            help="Fail unless the signature, the artifact bytes, and revocation were all checked.",
        ),
    ] = False,
) -> None:
    """Verify content ID, optional issuer signature, and optional artifact binding."""

    from trueai.core.certificates import (
        load_certificate,
        load_revocation_list,
        verify_certificate,
    )

    try:
        certificate = load_certificate(certificate_path)
        revocation_list = (
            load_revocation_list(revocation_list_path) if revocation_list_path is not None else None
        )
        result = verify_certificate(
            certificate,
            public_key=public_key,
            artifact=artifact,
            revocation_list=revocation_list,
            require_revocation_check=require_revocation_check,
        )
        console.print(f"Certificate: [bold]{certificate.certificate_id}[/bold]")
        # Three states, not two. "Nothing that was checked came back false" and
        # "everything was checked and held" are different results, and a green
        # VALID on an unsigned certificate nobody compared to a file says the
        # second while meaning the first.
        unchecked = result.unchecked()
        if not result.valid:
            verdict, colour = "INVALID", "red"
        elif result.authenticated:
            verdict, colour = "VALID", "green"
        else:
            verdict, colour = "VALID, NOT FULLY CHECKED", "yellow"
        console.print(f"Verification: [{colour}]{verdict}[/]")
        for explanation in result.explanations:
            console.print(f"- {escape(explanation)}")
        for clause in unchecked:
            console.print(f"[yellow]not checked:[/yellow] {escape(clause)}")
        if not result.valid or (require_full_verification and unchecked):
            raise typer.Exit(ExitCode.POLICY_VIOLATION)
        raise typer.Exit(ExitCode.SUCCESS)
    except typer.Exit:
        raise
    except (OSError, TrueAIError, ValueError) as exc:
        error_console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc


@certificates_app.command("revoke")
def certificates_revoke(
    certificate_path: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, help="Signed certificate to revoke.")
    ],
    revocation_list_path: Annotated[
        Path,
        typer.Option(
            "--revocation-list",
            help="Revocation-list JSON to create or advance atomically.",
        ),
    ],
    signing_key: Annotated[
        Path,
        typer.Option(
            "--signing-key",
            exists=True,
            dir_okay=False,
            help="Issuer Ed25519 private key that signed the certificate.",
        ),
    ],
    reason: Annotated[
        str,
        typer.Option(
            "--reason",
            help="unspecified, key_compromise, artifact_withdrawn, superseded, or issued_in_error",
        ),
    ] = "unspecified",
    explanation: Annotated[
        str | None,
        typer.Option("--explanation", help="Optional operator explanation (maximum 500 chars)."),
    ] = None,
    replacement_certificate_id: Annotated[
        str | None,
        typer.Option("--replacement", help="Optional replacement TAI1 certificate ID."),
    ] = None,
    valid_for_days: Annotated[
        int,
        typer.Option(
            "--valid-for-days",
            min=1,
            help="Freshness period for the newly signed list.",
        ),
    ] = 30,
) -> None:
    """Withdraw one signed certificate through an authenticated finite-lifetime list."""

    from trueai.core.certificates import (
        RevocationReason,
        load_certificate,
        load_revocation_list,
        revocation_list_json,
        revoke_certificate,
    )

    try:
        certificate = load_certificate(certificate_path)
        existing = (
            load_revocation_list(revocation_list_path) if revocation_list_path.exists() else None
        )
        updated = revoke_certificate(
            certificate,
            signing_key=signing_key,
            reason=RevocationReason(reason),
            explanation=explanation,
            replacement_certificate_id=replacement_certificate_id,
            existing=existing,
            valid_for=timedelta(days=valid_for_days),
        )
        _replace_revocation_list(revocation_list_path, revocation_list_json(updated))
        console.print(f"Revoked: [bold]{certificate.certificate_id}[/bold]")
        console.print(f"Revocation list sequence: {updated.sequence}")
        console.print(f"Written: {revocation_list_path}")
    except (OSError, TrueAIError, ValueError) as exc:
        error_console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc


@certificates_app.command("keygen")
def certificates_keygen(
    private_key: Annotated[
        Path, typer.Option("--private-key", help="New private PEM path.")
    ] = Path("trueai-ed25519-private.pem"),
    public_key: Annotated[Path, typer.Option("--public-key", help="New public PEM path.")] = Path(
        "trueai-ed25519-public.pem"
    ),
) -> None:
    """Generate an Ed25519 issuer keypair without overwriting existing keys."""

    from trueai.core.certificates import generate_ed25519_keypair

    try:
        key_id = generate_ed25519_keypair(private_key, public_key)
        console.print(f"Key ID: [bold]{key_id}[/bold]")
        console.print(f"Private key: {private_key}")
        console.print(f"Public key: {public_key}")
    except (OSError, TrueAIError, ValueError) as exc:
        error_console.print(f"[red]{escape(str(exc))}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc


@certificates_app.command("schema")
def certificates_schema(
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write schema to a new file instead of stdout."),
    ] = None,
) -> None:
    """Emit JSON Schema for audit-certificate version 0.1."""

    from trueai.core.certificates import certificate_schema_json

    rendered = certificate_schema_json()
    if output is None:
        typer.echo(rendered.rstrip("\n"))
        return
    if output.exists():
        error_console.print(f"[red]Refusing to overwrite existing schema: {output}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(rendered)


@certificates_app.command("revocation-schema")
def certificates_revocation_schema(
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write schema to a new file instead of stdout."),
    ] = None,
) -> None:
    """Emit JSON Schema for signed revocation-list version 0.1."""

    from trueai.core.certificates import revocation_list_schema_json

    rendered = revocation_list_schema_json()
    if output is None:
        typer.echo(rendered.rstrip("\n"))
        return
    if output.exists():
        error_console.print(f"[red]Refusing to overwrite existing schema: {output}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(rendered)


@cache_app.command("path")
def cache_path(
    target: Annotated[Path, typer.Argument(help="Scanned file, directory, or repository.")] = Path(
        "."
    ),
) -> None:
    """Show where the incremental cache for a target lives."""

    console.print(str(_default_cache_directory(target)))


@cache_app.command("inspect")
def cache_inspect(
    target: Annotated[Path, typer.Argument(help="Scanned file, directory, or repository.")] = Path(
        "."
    ),
    show_entries: Annotated[
        int,
        typer.Option("--entries", help="List this many entries, oldest generation first."),
    ] = 0,
) -> None:
    """Report what the incremental cache holds, including what it should not."""

    from trueai.core.cache import ScanCache

    directory = _default_cache_directory(target)
    cache = ScanCache(directory)
    inventory = cache.inspect()
    console.print(f"[bold]{escape(str(directory))}[/bold]")
    console.print(escape(inventory.explain()))
    console.print(
        f"Budget: {cache.max_bytes / (1024 * 1024):.0f} MB; "
        f"used {inventory.total_bytes / (1024 * 1024):.1f} MB"
    )
    if inventory.generations():
        generations = inventory.generations()
        console.print(f"Generations present: {generations[0]}–{generations[-1]}")
    for name in inventory.damaged:
        console.print(f"[yellow]damaged[/yellow] {escape(name)}")
    for name in inventory.foreign:
        # Named, never deleted: a cache directory is not a place to be confident
        # about what is safe to remove.
        console.print(f"[yellow]not written by TrueAI, left in place[/yellow] {escape(name)}")
    if show_entries:
        table = Table(title="Eviction order", show_lines=False)
        table.add_column("Key")
        table.add_column("Generation", justify="right")
        table.add_column("Bytes", justify="right")
        table.add_column("Reachable")
        for entry in cache.eviction_order(inventory)[:show_entries]:
            table.add_row(
                entry.key[:16],
                str(entry.generation),
                str(entry.size_bytes),
                "yes" if entry.reachable() else "no (older build)",
            )
        console.print(table)


@cache_app.command("prune")
def cache_prune(
    target: Annotated[Path, typer.Argument(help="Scanned file, directory, or repository.")] = Path(
        "."
    ),
    unreachable: Annotated[
        bool,
        typer.Option("--unreachable", help="Remove entries written by another build."),
    ] = False,
    older_than: Annotated[
        int | None,
        typer.Option("--older-than", help="Remove entries below this generation."),
    ] = None,
    to_fit: Annotated[
        int | None,
        typer.Option("--to-fit", help="Evict in order until the cache is at most this many bytes."),
    ] = None,
    yes: Annotated[
        bool,
        typer.Option("--yes", help="Required: pruning deletes cached results."),
    ] = False,
) -> None:
    """Remove cache entries under an explicit rule."""

    from trueai.core.cache import ScanCache

    if not (unreachable or older_than is not None or to_fit is not None):
        # No rule removes nothing. A prune that defaulted to deleting everything
        # would make a mistyped command destructive, and this is the one place a
        # wrong deletion is silent: the next scan is merely slower.
        console.print(
            "[red]Nothing selected.[/red] Pass --unreachable, --older-than, or --to-fit. "
            "To delete everything, use `trueai cache clear`."
        )
        raise typer.Exit(code=2)
    if not yes:
        console.print("[red]Refusing to prune without --yes.[/red] Pruning deletes stored results.")
        raise typer.Exit(code=2)

    directory = _default_cache_directory(target)
    result = ScanCache(directory).prune(
        unreachable_only=unreachable,
        older_than_generation=older_than,
        to_fit=to_fit,
    )
    console.print(escape(result.explain()))
    for name, reason in result.refused:
        console.print(f"[yellow]refused[/yellow] {escape(name)}: {escape(reason)}")


@cache_app.command("clear")
def cache_clear(
    target: Annotated[Path, typer.Argument(help="Scanned file, directory, or repository.")] = Path(
        "."
    ),
) -> None:
    """Delete every cached artifact result for a target."""

    from trueai.core.cache import ScanCache

    directory = _default_cache_directory(target)
    removed = ScanCache(directory).clear()
    console.print(f"Removed {removed} cached result(s) from {directory}")


@app.command()
def schema(
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the schema to a file instead of stdout."),
    ] = None,
) -> None:
    """Emit the JSON Schema of the public report for downstream consumers."""

    from trueai.schema import canonical_schema_json, report_schema

    rendered = canonical_schema_json(report_schema())
    if output is None:
        typer.echo(rendered.rstrip("\n"))
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    error_console.print(f"Schema written: {output}")


@detectors_app.callback(invoke_without_command=True)
def detectors_callback(ctx: typer.Context) -> None:
    """Show detectors when no detector subcommand is supplied."""

    if ctx.invoked_subcommand is None:
        _print_detectors()


@detectors_app.command("list")
def list_detectors() -> None:
    """List stable IDs, types, categories, and enabled state."""

    _print_detectors()


@policies_app.callback(invoke_without_command=True)
def policies_callback(ctx: typer.Context) -> None:
    """Show policies when no policy subcommand is supplied."""

    if ctx.invoked_subcommand is None:
        _print_policies()


@policies_app.command("list")
def list_policies() -> None:
    """List built-in policy profiles."""

    _print_policies()


@policies_app.command("bundle-create")
def policy_bundle_create(
    policy_name: Annotated[str, typer.Argument(help="Built-in policy name or YAML path.")],
    output: Annotated[Path, typer.Option("--output", "-o", help="New bundle JSON path.")],
    signing_key: Annotated[
        Path,
        typer.Option(
            "--signing-key",
            exists=True,
            dir_okay=False,
            help="Ed25519 private key used to authenticate the bundle.",
        ),
    ],
    issuer: Annotated[str, typer.Option("--issuer", help="Human-readable issuer identity.")],
    expires_days: Annotated[
        int,
        typer.Option("--expires-days", min=1, max=366, help="Finite bundle validity."),
    ] = 90,
    controls_file: Annotated[
        Path | None,
        typer.Option(
            "--controls",
            exists=True,
            dir_okay=False,
            help="Optional YAML suppressions and exceptions.",
        ),
    ] = None,
    baseline_report: Annotated[
        Path | None,
        typer.Option(
            "--baseline-report",
            exists=True,
            dir_okay=False,
            help="Optional complete JSON report whose exact finding IDs form the baseline.",
        ),
    ] = None,
) -> None:
    """Create a content-addressed, finite-lifetime signed policy bundle."""

    try:
        profile = PolicyStore.get(policy_name)
        controls = (
            PolicyBundleControls.from_yaml(controls_file)
            if controls_file is not None
            else PolicyBundleControls()
        )
        baseline_ids: tuple[str, ...] = ()
        if baseline_report is not None:
            report = JSONReporter.load(baseline_report)
            if _has_blocking_diagnostics(report):
                raise PolicyValidationError("An incomplete report cannot become a baseline")
            baseline_ids = tuple(sorted(finding.id for finding in report.findings))
        bundle = issue_policy_bundle(
            profile,
            issuer=issuer,
            signing_key=signing_key,
            expires_in=timedelta(days=expires_days),
            baseline_finding_ids=baseline_ids,
            controls=controls,
        )
        _write_new_policy_bundle(output, policy_bundle_json(bundle))
        console.print(f"Policy bundle: {bundle.bundle_id}")
        console.print(f"Policy: {bundle.profile.policy}")
        console.print(f"Baseline findings: {len(bundle.baseline_finding_ids)}")
        console.print(f"Bundle written: {output}")
    except (OSError, ValueError, TrueAIError) as exc:
        error_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc


@policies_app.command("bundle-verify")
def policy_bundle_verify(
    bundle_path: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False, help="Policy bundle JSON."),
    ],
    public_key: Annotated[
        Path,
        typer.Option(
            "--public-key",
            exists=True,
            dir_okay=False,
            help="Trusted Ed25519 issuer public key.",
        ),
    ],
) -> None:
    """Verify a policy bundle before deployment."""

    try:
        bundle = load_policy_bundle(bundle_path)
        verification = verify_policy_bundle(bundle, public_key=public_key)
        status = "VALID" if verification.valid else "INVALID"
        color = "green" if verification.valid else "red"
        console.print(f"[{color}]{status}[/{color}] {bundle.bundle_id}")
        for explanation in verification.explanations:
            console.print(escape(explanation))
        raise typer.Exit(ExitCode.SUCCESS if verification.valid else ExitCode.POLICY_VIOLATION)
    except typer.Exit:
        raise
    except (OSError, ValueError, TrueAIError) as exc:
        error_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(ExitCode.UNSUPPORTED_OR_CORRUPT) from exc


@policies_app.command("bundle-schema")
def policy_bundle_schema_command(
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write schema to a file instead of stdout."),
    ] = None,
) -> None:
    """Print the stable policy-bundle JSON Schema."""

    rendered = policy_bundle_schema_json()
    if output is None:
        typer.echo(rendered, nl=False)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    error_console.print(f"Schema written: {output}")


@app.command()
def doctor() -> None:
    """Check runtime, core parsers, optional PDF cleanup, and privacy defaults."""

    checks = Table(title="TrueAI Doctor")
    checks.add_column("Check")
    checks.add_column("Status")
    # The Detail column carries the only actionable text in this table: which
    # extra to install. Rich elides an overlong cell, and the widest row sets the
    # width the narrower ones are cut to, so on an 80-column terminal
    # `install trueai-core[pdf]` rendered as a horizontal ellipsis -- the check
    # said something was missing and withheld what to do about it. Fold wraps.
    checks.add_column("Detail", overflow="fold")
    checks.add_row(
        "Python", "PASS" if sys.version_info >= (3, 12) else "FAIL", sys.version.split()[0]
    )
    for dependency in ("pydantic", "typer", "rich", "PIL", "defusedxml", "pathspec", "yaml"):
        available = importlib.util.find_spec(dependency) is not None
        checks.add_row(
            dependency, "PASS" if available else "FAIL", "installed" if available else "missing"
        )
    pikepdf_available = importlib.util.find_spec("pikepdf") is not None
    checks.add_row(
        "PDF cleanup",
        "PASS" if pikepdf_available else "OPTIONAL",
        "pikepdf installed" if pikepdf_available else escape("install trueai-core[pdf]"),
    )
    from trueai.detectors.provenance.verification import C2PAVerifier, c2pa_available

    checks.add_row(
        "C2PA verification",
        "PASS" if c2pa_available() else "OPTIONAL",
        C2PAVerifier().verifier_name() if c2pa_available() else escape("install trueai-core[c2pa]"),
    )
    cryptography_available = importlib.util.find_spec("cryptography") is not None
    checks.add_row(
        "Signed certificates",
        "PASS" if cryptography_available else "OPTIONAL",
        (
            "Ed25519 available"
            if cryptography_available
            else escape("install trueai-core[attestation]")
        ),
    )
    checks.add_row("Network policy", "PASS", "offline; no telemetry or scan-time requests")
    console.print(checks)


@contextmanager
def _scan_progress(
    enabled: bool,
) -> Iterator[tuple[ProgressObserver | None, CancellationToken]]:
    """Yield a progress observer and a token wired to Ctrl-C.

    Rich lives here and nowhere near the engine: the core emits frozen events
    and polls a one-method predicate, so a CI run, a desktop client, and this
    terminal each render them their own way.

    The bar is suppressed when output is redirected, because progress written to
    a pipe is noise in a log and breaks anything parsing the stream.
    """

    token = CancellationToken()
    previous = None
    try:
        previous = signal.signal(
            signal.SIGINT,
            lambda *_: token.cancel("interrupted at the keyboard"),
        )
    except ValueError:
        # Not the main thread: the scan simply cannot be cancelled that way.
        previous = None

    if not (enabled and error_console.is_terminal):
        try:
            yield None, token
        finally:
            if previous is not None:
                signal.signal(signal.SIGINT, previous)
        return

    from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn

    bar = Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=error_console,
        transient=True,
    )
    task = bar.add_task("scanning", total=None)

    def observe(event: ProgressEvent) -> None:
        bar.update(
            task,
            completed=event.completed,
            total=event.total,
            description=event.phase.value,
        )

    try:
        with bar:
            yield observe, token
    finally:
        if previous is not None:
            signal.signal(signal.SIGINT, previous)


def _default_cache_directory(target: Path) -> Path:
    """Return the per-target cache location.

    The cache lives beside what it describes so that deleting a checkout deletes
    its cache with it, and so a scan never writes outside the tree the user
    pointed at. Discovery already ignores .trueai/, so the cache can never become
    an artifact of the next scan.
    """

    resolved = target.expanduser()
    base = resolved.parent if resolved.is_file() else resolved
    return base / ".trueai" / "cache"


def _resolve_policy(
    policy_name: str,
    bundle_path: Path | None,
    public_key: Path | None,
) -> tuple[PolicyProfile, EnterprisePolicyBundle | None]:
    """Resolve either a local profile or an authenticated enterprise bundle."""

    if (bundle_path is None) != (public_key is None):
        raise PolicyValidationError("--policy-bundle and --policy-key must be supplied together")
    if bundle_path is None:
        return PolicyStore.get(policy_name), None
    bundle = load_policy_bundle(bundle_path)
    assert public_key is not None
    verification = verify_policy_bundle(bundle, public_key=public_key)
    if not verification.valid:
        raise PolicyValidationError(
            "Policy bundle verification failed: " + " ".join(verification.explanations)
        )
    return bundle.profile, bundle


def _resolve_cache_directory(
    target: Path,
    enabled: bool,
    explicit: Path | None,
) -> Path | None:
    """Resolve the cache directory from the two mutually reinforcing flags."""

    if explicit is not None:
        return explicit.expanduser()
    if enabled:
        return _default_cache_directory(target)
    return None


def _default_certificate_path(target: Path) -> Path:
    """Place a certificate beside, never inside, the artifact it binds."""

    source = target.resolve(strict=True)
    return source.parent / f"{source.name}.trueai-certificate.json"


def _write_new_certificate(target: Path, payload: str, artifact: Path) -> None:
    """Write a certificate once without changing the inventory it certifies."""

    source = artifact.resolve(strict=True)
    destination = target.resolve()
    if source.is_file() and destination == source:
        raise RemediationError("Certificate output must not overwrite the certified artifact")
    if source.is_dir():
        try:
            destination.relative_to(source)
        except ValueError:
            pass
        else:
            raise RemediationError(
                "Certificate output must be outside the certified directory inventory"
            )
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with destination.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.write("\n")
    except FileExistsError as exc:
        raise RemediationError(
            f"Refusing to overwrite existing certificate: {destination}"
        ) from exc


def _write_new_policy_bundle(target: Path, payload: str) -> None:
    """Write an authenticated control-plane document without overwriting one."""

    destination = target.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with destination.open("x", encoding="utf-8") as handle:
            handle.write(payload)
            handle.write(chr(10))
    except FileExistsError as exc:
        raise PolicyValidationError(
            f"Refusing to overwrite existing policy bundle: {destination}"
        ) from exc


def _replace_revocation_list(target: Path, payload: str) -> None:
    """Publish a signed list atomically after preserving the previous file on failure."""

    destination = target.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
            delete=False,
        ) as handle:
            handle.write(payload)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
            temporary = Path(handle.name)
        os.replace(temporary, destination)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _attestation_properties(record_path: Path, artifact: Path) -> dict[str, object]:
    """Return the SARIF property bag for a record travelling with a scan.

    The record is verified against the scanned artifact, with no public keys: a
    scan is not the place to decide whom to trust. Every property says what was
    established, including that signatures were not checked.
    """

    from trueai.core.attestation import load_attestation, verify_attestation
    from trueai.core.evaluation import sarif_properties

    record = load_attestation(record_path)
    subject = artifact if artifact.is_file() else None
    return sarif_properties(record, verify_attestation(record, artifact=subject))


def _render_report(
    report: object,
    output_format: OutputFormat,
    verbose: bool,
    *,
    emit: bool = True,
    attestation_properties: dict[str, object] | None = None,
) -> str | None:
    from trueai.core.models import ScanReport

    assert isinstance(report, ScanReport)
    if output_format == OutputFormat.JSON:
        rendered = JSONReporter().render(report)
        if emit:
            if sys.stdout.isatty():
                console.print(rendered)
            else:
                typer.echo(rendered)
        return rendered
    if output_format == OutputFormat.SARIF:
        rendered = SARIFReporter().render(report, attestation_properties=attestation_properties)
        if emit:
            typer.echo(rendered)
        return rendered
    if output_format == OutputFormat.HTML:
        rendered = HTMLReporter().render(report)
        if emit:
            typer.echo(rendered)
        return rendered
    if output_format in {OutputFormat.CI, OutputFormat.IDE, OutputFormat.DESKTOP}:
        rendered = _render_adapter(report, output_format)
        if emit:
            typer.echo(rendered)
        return rendered
    TerminalReporter(console).render(report, verbose=verbose)
    return None


def _render_adapter(report: object, output_format: OutputFormat) -> str:
    """Render one of the interface adapters, all built on the public schema."""

    from trueai.adapters import desktop_bundle, diagnostics_by_file, job_summary
    from trueai.adapters import workflow_annotations as annotations
    from trueai.core.models import ScanReport

    assert isinstance(report, ScanReport)
    if output_format == OutputFormat.CI:
        # Annotations first so a runner picks them up as it streams, then the
        # summary a person reads afterwards.
        return "\n".join([*annotations(report), "", job_summary(report)])
    if output_format == OutputFormat.IDE:
        return json.dumps(diagnostics_by_file(report), ensure_ascii=False, indent=2, sort_keys=True)
    return json.dumps(desktop_bundle(report), ensure_ascii=False, indent=2, sort_keys=True)


def _exit_code(report: object) -> ExitCode:
    from trueai.core.models import ProvenanceVerificationStatus, ScanReport

    assert isinstance(report, ScanReport)
    if _has_blocking_diagnostics(report):
        return ExitCode.UNSUPPORTED_OR_CORRUPT
    verification_statuses = {item.status for item in report.provenance_verifications}
    if verification_statuses & {
        ProvenanceVerificationStatus.VERIFIER_UNAVAILABLE,
        ProvenanceVerificationStatus.UNSUPPORTED_CONTAINER,
    }:
        return ExitCode.UNSUPPORTED_OR_CORRUPT
    if ProvenanceVerificationStatus.INVALID in verification_statuses:
        return ExitCode.POLICY_VIOLATION
    if report.summary.violation_count:
        return ExitCode.POLICY_VIOLATION
    if verification_statuses & {
        ProvenanceVerificationStatus.VALID,
        ProvenanceVerificationStatus.NO_MANIFEST,
    }:
        return ExitCode.REVIEW_REQUIRED
    if report.summary.review_count:
        return ExitCode.REVIEW_REQUIRED
    return ExitCode.SUCCESS


def _has_blocking_diagnostics(report: object) -> bool:
    from trueai.core.models import ScanReport

    assert isinstance(report, ScanReport)
    return any(
        diagnostic.severity in {Severity.HIGH, Severity.CRITICAL}
        for diagnostic in report.diagnostics
    )


def _print_detectors() -> None:
    registry = TrueAIEngine.default(include_experimental=False).registry
    all_registry = TrueAIEngine.default(include_experimental=True).registry
    table = Table(title="TrueAI Detectors")
    table.add_column("ID")
    table.add_column("Enabled")
    table.add_column("Types")
    table.add_column("Categories")
    for detector in all_registry.detectors(include_disabled=True):
        table.add_row(
            detector.id,
            "yes" if registry.is_enabled(detector.id) else "experimental",
            ", ".join(sorted(item.value for item in detector.supported_types)),
            ", ".join(sorted(item.value for item in detector.categories)),
        )
    console.print(table)


def _print_plugins() -> None:
    from trueai.plugins.host import PluginHost

    result = PluginHost().discover()
    table = Table(title="TrueAI Plugins")
    table.add_column("Detector")
    table.add_column("Version")
    table.add_column("Manifest")
    table.add_column("Requests", overflow="fold")
    table.add_column("Verdict", overflow="fold")
    table.add_column("Confined")
    decisions = {decision.detector_id: decision for decision in result.decisions}
    containment = {item.detector_id: item for item in result.containment}
    for manifest in result.manifests:
        decision = decisions.get(manifest.detector_id)
        limits = containment.get(manifest.detector_id)
        table.add_row(
            manifest.detector_id,
            manifest.version,
            "declared" if manifest.declared else "synthesized",
            ", ".join(sorted(item.value for item in manifest.capabilities)),
            "allowed" if decision is None or decision.allowed else "refused",
            _containment_cell(limits),
        )
    for rejection in result.rejections:
        table.add_row(rejection.detector_id, "-", "-", "-", f"refused: {rejection.reason}", "-")
    if not result.manifests and not result.rejections:
        console.print("No third-party detectors are installed.")
        return
    console.print(table)
    # Printed in full below the table rather than squeezed into a cell: an
    # operator who sees "partial" needs the sentence, and a column that elides it
    # reports a problem while withholding what the problem is.
    for item in result.containment:
        for line in item.not_enforced:
            console.print(f"[yellow]not enforced[/yellow] {item.detector_id}: {line}")


def _containment_cell(limits: object) -> str:
    """Summarize what the operating system granted one plugin's helper process."""

    if limits is None:
        # No helper ran, because the manifest arrived signed. That is not the
        # same as "nothing was enforced", and must not read as either verdict.
        return "not measured"
    not_enforced = getattr(limits, "not_enforced", ())
    established = getattr(limits, "established", ())
    if not_enforced:
        return f"partial ({len(established)}/{len(established) + len(not_enforced)})"
    return f"full ({len(established)})"


def _print_policies() -> None:
    table = Table(title="TrueAI Policies")
    table.add_column("Policy")
    table.add_column("Default")
    table.add_column("Explicit rules", justify="right")
    for policy in PolicyStore.list():
        table.add_row(policy.policy, policy.default_action.value, str(len(policy.rules)))
    console.print(table)


def main() -> None:
    """Console-script entry point."""

    app()


if __name__ == "__main__":
    main()
