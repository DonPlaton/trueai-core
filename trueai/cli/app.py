"""Typer CLI for local scans, inspection, planning, and verified cleanup."""

from __future__ import annotations

import importlib.util
import json
import sys
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
from trueai.core.policy import PolicyStore
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
    ] = PluginIsolation.IN_PROCESS,
) -> None:
    """Scan an artifact without modifying it."""

    try:
        if output is not None and path.exists() and output.resolve() == path.resolve():
            raise RemediationError("Report output must not overwrite the scanned artifact")
        policy = PolicyStore.get(policy_name)
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
) -> None:
    """Plan, preview, apply, verify, and report predictable remediation."""

    try:
        policy = PolicyStore.get(policy_name)
        report = TrueAIEngine.default().scan(path, policy=policy)
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
        )
        terminal.render_result(result)
        if report.summary.violation_count:
            code = ExitCode.POLICY_VIOLATION
        elif plan.review_findings or plan.blocked_findings:
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
    from trueai.core.models import ScanReport

    assert isinstance(report, ScanReport)
    if _has_blocking_diagnostics(report):
        return ExitCode.UNSUPPORTED_OR_CORRUPT
    if report.summary.violation_count:
        return ExitCode.POLICY_VIOLATION
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
