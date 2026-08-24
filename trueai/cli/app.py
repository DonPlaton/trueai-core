"""Typer CLI for local scans, inspection, planning, and verified cleanup."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
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
from trueai.core.remediation import RemediationPlanner, RemediationService
from trueai.plugins.host import PluginIsolation
from trueai.reporters import JSONReporter, SARIFReporter, TerminalReporter


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
        typer.Option("--format", "-f", help="terminal, json, or sarif"),
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
        report = TrueAIEngine.default(
            include_experimental=experimental,
            plugin_isolation=plugins,
        ).scan(
            path,
            options=options,
            policy=policy,
        )
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
        rendered = _render_report(
            report,
            output_format,
            verbose,
            emit=output is None or output_format == OutputFormat.TERMINAL,
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


@plugins_app.command("list")
def list_plugins() -> None:
    """List installed third-party detectors, what they ask for, and the verdict."""

    _print_plugins()


cache_app = typer.Typer(help="Inspect and clear the incremental scan cache.")
app.add_typer(cache_app, name="cache")

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
        console.print(
            f"Verification: [{'green' if result.valid else 'red'}]{'VALID' if result.valid else 'INVALID'}[/]"
        )
        for explanation in result.explanations:
            console.print(f"- {escape(explanation)}")
        raise typer.Exit(ExitCode.SUCCESS if result.valid else ExitCode.POLICY_VIOLATION)
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
    checks.add_column("Detail")
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


def _render_report(
    report: object,
    output_format: OutputFormat,
    verbose: bool,
    *,
    emit: bool = True,
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
        rendered = SARIFReporter().render(report)
        if emit:
            typer.echo(rendered)
        return rendered
    TerminalReporter(console).render(report, verbose=verbose)
    return None


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
    table.add_column("Requests")
    table.add_column("Verdict")
    decisions = {decision.detector_id: decision for decision in result.decisions}
    for manifest in result.manifests:
        decision = decisions.get(manifest.detector_id)
        table.add_row(
            manifest.detector_id,
            manifest.version,
            "declared" if manifest.declared else "synthesized",
            ", ".join(sorted(item.value for item in manifest.capabilities)),
            "allowed" if decision is None or decision.allowed else "refused",
        )
    for rejection in result.rejections:
        table.add_row(rejection.detector_id, "-", "-", "-", f"refused: {rejection.reason}")
    if not result.manifests and not result.rejections:
        console.print("No third-party detectors are installed.")
        return
    console.print(table)


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
