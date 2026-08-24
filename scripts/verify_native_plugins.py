"""Run hostile *native* plugins through the real host and check what stops them.

``scripts/verify_linux_confinement.py`` checks the confinement function. This
checks the whole path: entry point, manifest review, worker spawn, confinement,
guards, and the host's deadline — against plugins that reach the kernel through
``ctypes`` and therefore ignore every Python-level guard.

Run inside a container, where the kernel is real:

    docker run --rm --security-opt seccomp=unconfined -v "$PWD:/work" -w /work \
        python:3.12-slim sh -c "pip install -q pydantic pathspec typer rich pyyaml \
        && python scripts/verify_native_plugins.py"

``seccomp=unconfined`` is needed because Docker's own filter blocks the
``unshare`` this confinement depends on — the host it protects is a developer
machine, not a container.

Checks that assert a **gap** matter as much as the ones asserting a control. A
documented gap that quietly closed means the documentation is now wrong in the
other direction, and the point of this file is that neither kind of drift goes
unnoticed.
"""

from __future__ import annotations

import sys
from importlib.metadata import EntryPoint
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY))

import trueai.plugins.host as host_module  # noqa: E402
from trueai import TrueAIEngine  # noqa: E402
from trueai.core.models import ScanDiagnostic, ScanReport  # noqa: E402
from trueai.core.registry import DetectorRegistry  # noqa: E402
from trueai.plugins import (  # noqa: E402
    DEFAULT_GRANTED_CAPABILITIES,
    CapabilityPolicy,
    ConfinementLevel,
    PluginCapability,
    PluginIsolation,
)

EXAMPLES = "tests.plugin_examples"


def run(
    attribute: str,
    artifact: Path,
    *,
    timeout: float = 60.0,
    extra: frozenset[PluginCapability] = frozenset(),
    confinement: ConfinementLevel = ConfinementLevel.BEST_EFFORT,
) -> ScanReport:
    """Scan one artifact with exactly one hostile plugin installed."""

    point = EntryPoint(
        name="hostile", value=f"{EXAMPLES}:{attribute}", group=host_module.ENTRY_POINT_GROUP
    )
    host_module.entry_points = lambda *, group: [point]  # type: ignore[assignment]
    registry = DetectorRegistry()
    registry.discover(
        isolation=PluginIsolation.SUBPROCESS,
        timeout=timeout,
        search_path=(str(REPOSITORY),),
        confinement=confinement,
        policy=CapabilityPolicy(granted=frozenset(DEFAULT_GRANTED_CAPABILITIES) | extra),
    )
    return TrueAIEngine(registry).scan(artifact)


def messages(report: ScanReport) -> str:
    return " | ".join(f"{item.code}: {item.message}" for item in report.diagnostics)


def diagnostic(report: ScanReport, code: str) -> ScanDiagnostic | None:
    return next((item for item in report.diagnostics if item.code == code), None)


def main() -> int:
    import tempfile

    workspace = Path(tempfile.mkdtemp(prefix="native-verify-"))
    artifact = workspace / "notes.txt"
    artifact.write_text("Ordinary content.\n", encoding="utf-8")

    failures = 0

    def check(name: str, condition: bool, detail: str = "") -> None:
        nonlocal failures
        if condition:
            print(f"  ok   {name}")
        else:
            print(f"  FAIL {name}: {detail}")
            failures += 1

    print("[1] a hostile native plugin cannot write outside its grant")
    report = run("NATIVE_WRITER_REGISTRATION", artifact)
    escaped = artifact.parent / "written-by-native-code.txt"
    check(
        "no file appeared beside the artifact",
        not escaped.exists(),
        f"{escaped} was created despite the read-only mount namespace",
    )
    check(
        "the attempt is reported, not swallowed",
        "NATIVE-WRITE-SUCCEEDED" not in messages(report) and bool(report.diagnostics),
        messages(report),
    )

    print("[2] a granted native write into the scratch directory still works")
    report = run(
        "NATIVE_SCRATCH_REGISTRATION",
        artifact,
        extra=frozenset({PluginCapability.WRITE_TEMPORARY}),
    )
    check(
        "the write reached the scratch grant",
        "NATIVE-SCRATCH-WRITE-SUCCEEDED" in messages(report),
        f"confinement blocked a granted write: {messages(report)}",
    )

    print("[3] a hostile native plugin cannot open a socket")
    report = run("NATIVE_SOCKET_REGISTRATION", artifact)
    check(
        "the worker did not report a socket",
        "NATIVE-SOCKET-SUCCEEDED" not in messages(report),
        messages(report),
    )
    check(
        "the failure is visible to the operator",
        bool(report.diagnostics),
        "the plugin failed silently",
    )

    print("[4] a hostile native plugin cannot start another program")
    report = run("NATIVE_EXEC_REGISTRATION", artifact)
    check(
        "execve did not run /bin/true",
        "NATIVE-EXEC-RETURNED" not in messages(report),
        messages(report),
    )
    check("the failure is visible", bool(report.diagnostics), "the plugin failed silently")

    print("[5] a hostile native plugin cannot outlive its deadline")
    report = run("NATIVE_SPINNER_REGISTRATION", artifact, timeout=3.0)
    timed_out = diagnostic(report, "plugin_timeout")
    check(
        "the host killed a worker spinning inside libc",
        timed_out is not None,
        messages(report),
    )

    print("[6] reading outside the grants is still possible, exactly as documented")
    report = run("NATIVE_READER_REGISTRATION", artifact)
    check(
        "the documented read gap behaves as documented",
        "NATIVE-READ-SUCCEEDED" in messages(report),
        "reads outside the grant were refused — docs now understate the confinement: "
        + messages(report),
    )

    print("[7] negative control: without confinement the same plugin does escape")
    control = workspace / "control"
    control.mkdir()
    control_artifact = control / "notes.txt"
    control_artifact.write_text("Ordinary content.\n", encoding="utf-8")
    run("NATIVE_WRITER_REGISTRATION", control_artifact, confinement=ConfinementLevel.NONE)
    check(
        "the write lands when confinement is off",
        (control / "written-by-native-code.txt").exists(),
        "check [1] proves nothing if the write would have failed anyway",
    )

    print("[8] negative control: without confinement the native socket opens")
    report = run("NATIVE_SOCKET_REGISTRATION", artifact, confinement=ConfinementLevel.NONE)
    check(
        "the socket opens when confinement is off",
        "NATIVE-SOCKET-SUCCEEDED" in messages(report),
        "check [3] proves nothing if the socket would have failed anyway: " + messages(report),
    )

    print(f"\n{'FAILED' if failures else 'PASSED'}: {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
