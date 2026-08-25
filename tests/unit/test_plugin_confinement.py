"""Operating-system confinement for plugin workers.

Confinement is the one place where a security feature is easiest to fake: an
"applied" flag with nothing behind it looks identical, in a report, to a kernel
that actually refused something. These tests check the parts that are true on
every platform — the levels, the honesty of the reports, the refusal path — and
delegate the platform-specific proof to the checks that need a real kernel:

* Linux: ``scripts/verify_linux_confinement.py``, run in a container, where a
  denied syscall must kill the child rather than return an error.
* Windows: the restricted-token spawn below, which compares a privilege count.
"""

from __future__ import annotations

import os
import sys
from importlib.metadata import EntryPoint
from pathlib import Path

import pytest

import trueai.plugins.host as host_module
from tests.support import confinement_report
from trueai import TrueAIEngine
from trueai.core.registry import DetectorRegistry
from trueai.plugins import (
    BrokerGrants,
    ConfinementLevel,
    ConfinementReport,
    ConfinementUnavailableError,
    NetworkGrant,
    PluginIsolation,
    describe_platform,
)
from trueai.plugins.confinement import windows_confinement_report

REPOSITORY_ROOT = str(Path(__file__).resolve().parents[2])
EXAMPLES = "tests.plugin_examples"


def entry_point(name: str, attribute: str) -> EntryPoint:
    return EntryPoint(
        name=name, value=f"{EXAMPLES}:{attribute}", group=host_module.ENTRY_POINT_GROUP
    )


@pytest.fixture
def install_plugins(monkeypatch: pytest.MonkeyPatch):
    def install(*points: EntryPoint) -> None:
        monkeypatch.setattr(host_module, "entry_points", lambda *, group: list(points))

    return install


@pytest.fixture
def artifact(tmp_path: Path) -> Path:
    path = tmp_path / "notes.txt"
    path.write_text("Ordinary content.\n", encoding="utf-8")
    return path


# -- what the platform offers --------------------------------------------------------


def test_the_platform_is_probed_rather_than_assumed_from_its_name() -> None:
    """Availability is a property of the machine, not of the platform string."""

    available = describe_platform()

    assert available.mechanism
    if not available.available:
        assert available.reason, "an unavailable mechanism must say why"


def test_windows_confinement_is_marked_as_belonging_to_process_creation() -> None:
    """A process cannot narrow its own token, and the model has to say so."""

    available = describe_platform()
    if available.platform != "windows":
        pytest.skip("Windows-specific property")

    assert available.spawn_time_only is True


def test_linux_confinement_is_applied_by_the_process_to_itself() -> None:
    available = describe_platform()
    if available.platform != "linux":
        pytest.skip("Linux-specific property")

    assert available.spawn_time_only is False


# -- reports are honest about their gaps ---------------------------------------------


def test_level_none_says_that_nothing_is_enforced() -> None:
    report = confinement_report(ConfinementLevel.NONE)

    assert report.applied is False
    assert report.not_enforced
    assert "Only the Python guards apply" in report.not_enforced[0]


def test_an_applied_report_still_lists_what_it_does_not_cover() -> None:
    """A confinement claiming to cover everything is describing something else."""

    report = confinement_report(ConfinementLevel.BEST_EFFORT)

    assert report.not_enforced, report
    assert report.summary()


def test_best_effort_records_a_gap_instead_of_raising() -> None:
    """On a platform without a self-confinement backend, work continues."""

    report = confinement_report(ConfinementLevel.BEST_EFFORT)

    if not report.applied:
        assert report.reason
        assert "not established" in " ".join(report.not_enforced)


def test_required_refuses_where_best_effort_would_have_degraded() -> None:
    """Silently degrading is indistinguishable, in a report, from having succeeded."""

    degraded = confinement_report(ConfinementLevel.BEST_EFFORT)
    if degraded.applied:
        pytest.skip("This machine can establish confinement, so there is nothing to refuse")

    with pytest.raises(ConfinementUnavailableError):
        confinement_report(ConfinementLevel.REQUIRED)


def test_the_windows_report_does_not_claim_to_be_appcontainer() -> None:
    report = windows_confinement_report(ConfinementLevel.BEST_EFFORT)

    gaps = " ".join(report.not_enforced)
    assert "Filesystem isolation" in gaps
    assert "AppContainer" in gaps
    assert "Network isolation" in gaps


def test_a_report_round_trips_through_the_worker_protocol() -> None:
    """The host reports the confinement that happened, not the one it asked for."""

    from trueai.plugins.protocol import WorkerResponse

    response = WorkerResponse(
        detector_id="example.v1",
        ok=True,
        confinement=ConfinementReport(
            mechanism="seccomp+namespaces",
            applied=True,
            established=("no_new_privs",),
            not_enforced=("filesystem",),
        ),
    )

    parsed = WorkerResponse.model_validate_json(response.model_dump_json())

    assert parsed.confinement is not None
    assert parsed.confinement.mechanism == "seccomp+namespaces"
    assert parsed.confinement.not_enforced == ("filesystem",)


# -- the Linux backend's shape (verified for real by the container script) ------------


def test_the_seccomp_filter_denies_more_when_less_is_granted() -> None:
    """The filter is derived from the grants, not from a fixed list."""

    from trueai.plugins.confinement import _EXEC_SYSCALLS, _NETWORK_SYSCALLS
    from trueai.plugins.manifest import PluginCapability

    granted = BrokerGrants(network=NetworkGrant(endpoints=(("a.test", 1),))).capabilities()

    assert PluginCapability.NETWORK in granted
    assert PluginCapability.RUN_SUBPROCESS not in granted
    # Both lists exist and are disjoint, so a network grant cannot accidentally
    # re-enable exec.
    assert not set(_NETWORK_SYSCALLS) & set(_EXEC_SYSCALLS)


def test_fork_is_deliberately_absent_from_the_denied_syscalls() -> None:
    """glibc routes os.fork() through clone, which threading also uses.

    Denying fork by number would have looked like a control and been none. The
    gap is recorded in the report instead.
    """

    from trueai.plugins.confinement import _EXEC_SYSCALLS

    assert "fork" not in _EXEC_SYSCALLS
    assert "clone" not in _EXEC_SYSCALLS
    assert set(_EXEC_SYSCALLS) == {"execve", "execveat"}


def test_the_syscall_table_only_covers_architectures_it_pinned() -> None:
    """A filter built from guessed numbers denies the wrong calls."""

    from trueai.plugins.confinement import _AUDIT_ARCH, _LINUX_SYSCALLS

    assert set(_LINUX_SYSCALLS) == set(_AUDIT_ARCH)
    for architecture, table in _LINUX_SYSCALLS.items():
        assert "execve" in table, architecture
        assert "socket" in table, architecture
        assert "ptrace" in table, architecture


def test_the_macos_profile_denies_by_default(tmp_path: Path) -> None:
    from trueai.plugins.broker import TemporaryOutputGrant
    from trueai.plugins.confinement import _sandbox_profile

    profile = _sandbox_profile(
        BrokerGrants(temporary_output=TemporaryOutputGrant(directory=tmp_path))
    )

    assert "(deny default)" in profile
    assert str(tmp_path) in profile
    assert "network-outbound" not in profile


def test_the_macos_profile_opens_only_what_a_grant_covers(tmp_path: Path) -> None:
    from trueai.plugins.confinement import _sandbox_profile

    profile = _sandbox_profile(BrokerGrants(network=NetworkGrant(endpoints=(("a.test", 1),))))

    assert "(allow network-outbound)" in profile
    assert "file-write*" not in profile


# -- the Windows backend (verified here, on a real Windows kernel) --------------------


@pytest.mark.skipif(os.name != "nt", reason="Restricted tokens are a Windows mechanism")
def test_a_restricted_token_actually_drops_privileges(tmp_path: Path) -> None:
    """An "applied" flag proves nothing. A privilege count does."""

    from trueai.plugins.windows_token import restricted_spawning_available, spawn_restricted

    if not restricted_spawning_available():
        pytest.skip("This machine cannot create a restricted token")

    probe = tmp_path / "probe.py"
    probe.write_text(
        "\n".join(
            [
                "import ctypes, sys",
                "from ctypes import wintypes",
                "k = ctypes.WinDLL('kernel32', use_last_error=True)",
                "a = ctypes.WinDLL('advapi32', use_last_error=True)",
                "k.GetCurrentProcess.argtypes = []",
                "k.GetCurrentProcess.restype = wintypes.HANDLE",
                "a.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,"
                " ctypes.POINTER(wintypes.HANDLE)]",
                "a.OpenProcessToken.restype = wintypes.BOOL",
                "a.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int,"
                " ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]",
                "a.GetTokenInformation.restype = wintypes.BOOL",
                "t = wintypes.HANDLE()",
                "a.OpenProcessToken(k.GetCurrentProcess(), 0x0008, ctypes.byref(t))",
                "n = wintypes.DWORD()",
                "a.GetTokenInformation(t, 3, None, 0, ctypes.byref(n))",
                "b = ctypes.create_string_buffer(n.value)",
                "a.GetTokenInformation(t, 3, b, n.value, ctypes.byref(n))",
                "open(sys.argv[1], 'w').write(str(int.from_bytes(b.raw[:4], 'little')))",
            ]
        ),
        encoding="utf-8",
    )

    import subprocess

    plain_out = tmp_path / "plain.txt"
    subprocess.run([sys.executable, str(probe), str(plain_out)], check=True, timeout=120)

    restricted_out = tmp_path / "restricted.txt"
    code = spawn_restricted(
        [sys.executable, str(probe), str(restricted_out)],
        environment=dict(os.environ),
        timeout=120.0,
    )

    assert code == 0
    assert restricted_out.is_file(), "the restricted worker did not run"
    assert int(restricted_out.read_text()) < int(plain_out.read_text())


@pytest.mark.skipif(os.name != "nt", reason="Restricted tokens are a Windows mechanism")
def test_a_restricted_worker_that_overruns_its_deadline_is_terminated(tmp_path: Path) -> None:
    from trueai.plugins.windows_token import restricted_spawning_available, spawn_restricted

    if not restricted_spawning_available():
        pytest.skip("This machine cannot create a restricted token")

    with pytest.raises(TimeoutError):
        spawn_restricted(
            [sys.executable, "-c", "import time; time.sleep(600)"],
            environment=dict(os.environ),
            timeout=2.0,
        )


# -- end to end ----------------------------------------------------------------------


def test_plugins_still_run_with_confinement_requested(install_plugins, artifact: Path) -> None:
    """Confinement must not become a plugin outage on a supported platform."""

    install_plugins(entry_point("declared", "DECLARED_REGISTRATION"))
    registry = DetectorRegistry()
    registry.discover(
        isolation=PluginIsolation.SUBPROCESS,
        timeout=120.0,
        search_path=(REPOSITORY_ROOT,),
        confinement=ConfinementLevel.BEST_EFFORT,
    )

    report = TrueAIEngine(registry).scan(artifact)

    findings = [
        finding for finding in report.findings if finding.detector_id == "example.well-behaved.v1"
    ]
    assert findings, report.diagnostics


def test_confinement_none_leaves_the_previous_behaviour_intact(
    install_plugins, artifact: Path
) -> None:
    install_plugins(entry_point("declared", "DECLARED_REGISTRATION"))
    registry = DetectorRegistry()
    registry.discover(
        isolation=PluginIsolation.SUBPROCESS,
        timeout=120.0,
        search_path=(REPOSITORY_ROOT,),
        confinement=ConfinementLevel.NONE,
    )

    report = TrueAIEngine(registry).scan(artifact)

    assert [
        finding for finding in report.findings if finding.detector_id == "example.well-behaved.v1"
    ], report.diagnostics


def test_required_confinement_reports_rather_than_silently_running(
    install_plugins, artifact: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A plugin the host could not confine must not quietly run unconfined."""

    from trueai.plugins import confinement as confinement_module
    from trueai.plugins.confinement import PlatformConfinement

    monkeypatch.setattr(
        confinement_module,
        "describe_platform",
        lambda: PlatformConfinement(
            platform="imaginary",
            mechanism="none",
            available=False,
            reason="No confinement backend for this platform.",
        ),
    )
    install_plugins(entry_point("declared", "DECLARED_REGISTRATION"))
    registry = DetectorRegistry()
    registry.discover(
        isolation=PluginIsolation.SUBPROCESS,
        timeout=120.0,
        search_path=(REPOSITORY_ROOT,),
        confinement=ConfinementLevel.REQUIRED,
    )

    report = TrueAIEngine(registry).scan(artifact)

    unconfined = [
        diagnostic
        for diagnostic in report.diagnostics
        if diagnostic.code == "plugin_confinement_unavailable"
    ]
    findings = [
        finding for finding in report.findings if finding.detector_id == "example.well-behaved.v1"
    ]
    assert unconfined, report.diagnostics
    assert not findings, "a plugin the host could not confine must not have run"
    assert "not imported" in unconfined[0].message


def test_the_windows_token_module_states_the_platform_it_needs() -> None:
    """It fails on import off Windows, and says which module is the problem.

    `from ctypes import wintypes` already fails on POSIX, but with an ImportError
    that names ctypes. The guard also carries a second job: a type checker
    narrows on `sys.platform` and on nothing else, so it is what lets a Linux
    mypy run skip a module written entirely against the Win32 API instead of
    reporting every WinDLL reference in it.
    """

    source = (
        Path(__file__).resolve().parents[2] / "trueai" / "plugins" / "windows_token.py"
    ).read_text(encoding="utf-8")

    assert 'if sys.platform != "win32":' in source
    assert "raise ImportError" in source
    assert source.index("import sys") < source.index("from ctypes import wintypes")


def test_the_windows_job_limits_are_guarded_by_a_check_mypy_understands() -> None:
    """`os.name == "nt"` reads as a platform guard and narrows nothing."""

    source = (
        Path(__file__).resolve().parents[2] / "trueai" / "plugins" / "resources.py"
    ).read_text(encoding="utf-8")
    body = source[source.index("def _apply_windows_job_limits") :]

    assert 'if sys.platform != "win32":' in body
    assert body.index('if sys.platform != "win32":') < body.index("ctypes.WinDLL")


def test_no_test_module_confines_the_test_runner() -> None:
    """The guard for the defect that hid every other defect.

    apply_confinement is one-way on purpose. A test that calls it in-process
    leaves the runner with a read-only root and an empty grant set, so every
    later test dies in its own tmp_path fixture. The first Linux run of this
    suite reported fourteen hundred errors that way: one real failure, and the
    rest collateral from a process that could no longer write anything.

    The controls are still measured against a real kernel -- in a child, through
    tests.support.confinement_report, which is allowed to be destroyed by them.
    """

    tests_root = Path(__file__).resolve().parents[1]
    # Assembled, so the check does not report the file it is written in.
    needle = "apply_confinement" + "("
    offenders = [
        path.relative_to(tests_root).as_posix()
        for path in tests_root.rglob("test_*.py")
        if needle in path.read_text(encoding="utf-8")
    ]

    assert offenders == [], (
        "these modules confine the process running them; "
        f"use tests.support.confinement_report instead: {offenders}"
    )
