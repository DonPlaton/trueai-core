"""Hostile *native* plugins against the confinement that is supposed to stop them.

The Python guards replace functions; native code goes around them. These tests
therefore reach the kernel through ``ctypes``, and they measure two things:

* what the platform actually stops, and
* what it does not — because a documented gap that quietly closed means the
  documentation is now wrong in the other direction.

Coverage is split by what a platform can prove:

* **Linux** confines writes, the network, and process execution. Proving that
  needs a real kernel, so it lives in ``scripts/verify_native_plugins.py``, run
  in a container with both positive checks and negative controls.
* **Windows** confines the *deadline* and nothing else natively: a restricted
  token drops privileges, it does not isolate the filesystem or the network. The
  deadline is proven here, and the gaps are asserted here rather than being left
  implicit.
"""

from __future__ import annotations

import os
import sys
from importlib.metadata import EntryPoint
from pathlib import Path

import pytest

import trueai.plugins.host as host_module
from trueai import TrueAIEngine
from trueai.core.models import ScanReport
from trueai.core.registry import DetectorRegistry
from trueai.plugins import (
    DEFAULT_GRANTED_CAPABILITIES,
    CapabilityPolicy,
    ConfinementLevel,
    PluginCapability,
    PluginIsolation,
    describe_platform,
)

REPOSITORY_ROOT = str(Path(__file__).resolve().parents[2])
EXAMPLES = "tests.plugin_examples"

pytestmark = pytest.mark.filterwarnings("ignore::ResourceWarning")


@pytest.fixture
def artifact(tmp_path: Path) -> Path:
    path = tmp_path / "notes.txt"
    path.write_text("Ordinary content.\n", encoding="utf-8")
    return path


def scan_with(
    attribute: str,
    artifact: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    timeout: float = 60.0,
    extra: frozenset[PluginCapability] = frozenset(),
    confinement: ConfinementLevel = ConfinementLevel.BEST_EFFORT,
) -> ScanReport:
    """Scan one artifact with exactly one hostile plugin installed."""

    point = EntryPoint(
        name="hostile", value=f"{EXAMPLES}:{attribute}", group=host_module.ENTRY_POINT_GROUP
    )
    monkeypatch.setattr(host_module, "entry_points", lambda *, group: [point])
    registry = DetectorRegistry()
    registry.discover(
        isolation=PluginIsolation.SUBPROCESS,
        timeout=timeout,
        search_path=(REPOSITORY_ROOT,),
        confinement=confinement,
        policy=CapabilityPolicy(granted=frozenset(DEFAULT_GRANTED_CAPABILITIES) | extra),
    )
    return TrueAIEngine(registry).scan(artifact)


def messages(report: ScanReport) -> str:
    return " | ".join(f"{item.code}: {item.message}" for item in report.diagnostics)


# -- the deadline: the one control every platform provides ---------------------------


def test_a_plugin_spinning_in_native_code_does_not_outlive_its_deadline(
    artifact: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``libc.sleep`` holds no GIL and answers no Python signal handler.

    Only the host terminating the process ends it, which is why the deadline is
    enforced by the parent rather than by anything inside the worker.
    """

    report = scan_with("NATIVE_SPINNER_REGISTRATION", artifact, monkeypatch, timeout=3.0)

    timed_out = [item for item in report.diagnostics if item.code == "plugin_timeout"]
    assert timed_out, messages(report)
    assert "terminated" in timed_out[0].message


def test_a_killed_worker_does_not_take_the_scan_with_it(
    artifact: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The scan still completes and still reports the built-in findings."""

    report = scan_with("NATIVE_SPINNER_REGISTRATION", artifact, monkeypatch, timeout=3.0)

    assert report.integrity is not None
    assert "example.native-spinner.v1" not in report.detectors_run or report.diagnostics


# -- what each platform actually claims ----------------------------------------------


def test_the_platform_report_matches_what_this_platform_can_enforce() -> None:
    """The report is the contract. It has to say what the machine really does."""

    from tests.support import confinement_report
    from trueai.plugins.confinement import windows_confinement_report

    available = describe_platform()
    if available.platform == "windows":
        report = windows_confinement_report(ConfinementLevel.BEST_EFFORT)
        gaps = " ".join(report.not_enforced)
        # Everything a hostile native plugin could do on Windows is named as a gap.
        assert "Filesystem isolation" in gaps
        assert "Network isolation" in gaps
        assert "Syscall filtering" in gaps
        return

    # In a child. Applying it here would confine the test runner, and there is
    # no way back from a seccomp filter or a read-only mount namespace.
    report = confinement_report(ConfinementLevel.BEST_EFFORT)
    if not report.applied:
        return
    established = " ".join(report.established)
    # Named per platform rather than as one list, because a report that
    # accepted any wording would accept the wrong one. The Darwin branch used to
    # pass this assertion only because no macOS worker ever reached it.
    if available.platform == "linux":
        assert "seccomp" in established or "namespace" in established
    elif available.platform == "darwin":
        assert report.mechanism == "sandbox_init"
        assert "deny by default" in established
    else:  # pragma: no cover - a platform with a backend nobody has written yet
        raise AssertionError(f"{available.platform} reports confinement with no stated mechanism")


@pytest.mark.skipif(os.name != "nt", reason="Windows-specific gap")
def test_windows_does_not_stop_a_native_write_and_says_so(
    artifact: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A restricted token is not AppContainer, and the test says the same thing.

    If Windows filesystem confinement is ever implemented this test fails, which
    is the point: the claim in the docs and the behaviour move together.
    """

    from trueai.plugins.confinement import windows_confinement_report

    report = scan_with("NATIVE_WRITER_REGISTRATION", artifact, monkeypatch)
    escaped = artifact.parent / "written-by-native-code.txt"

    assert escaped.exists() or "NATIVE-WRITE-SUCCEEDED" in messages(report), (
        "Windows now confines native writes; update windows_confinement_report and docs"
    )
    assert "Filesystem isolation" in " ".join(
        windows_confinement_report(ConfinementLevel.BEST_EFFORT).not_enforced
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows-specific gap")
def test_windows_does_not_stop_a_native_socket_and_says_so(
    artifact: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from trueai.plugins.confinement import windows_confinement_report

    # The socket call itself goes through ws2_32 on Windows rather than libc, so
    # what is asserted here is the claim rather than the call: no mechanism on
    # this platform would have stopped it.
    gaps = " ".join(windows_confinement_report(ConfinementLevel.BEST_EFFORT).not_enforced)

    assert "Network isolation" in gaps
    assert "not implemented" in gaps


# -- the hostile plugins themselves --------------------------------------------------


def test_every_hostile_plugin_declares_a_narrow_manifest() -> None:
    """A hostile plugin that asks for everything would be refused for the wrong reason."""

    from tests import plugin_examples

    registrations = [
        plugin_examples.NATIVE_WRITER_REGISTRATION,
        plugin_examples.NATIVE_READER_REGISTRATION,
        plugin_examples.NATIVE_SOCKET_REGISTRATION,
        plugin_examples.NATIVE_EXEC_REGISTRATION,
        plugin_examples.NATIVE_SPINNER_REGISTRATION,
    ]

    for registration in registrations:
        assert registration.manifest.capabilities == frozenset({PluginCapability.READ_ARTIFACT}), (
            registration.manifest.detector_id
        )


def test_the_hostile_plugins_are_refused_by_a_stricter_policy(
    artifact: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Policy is the first boundary, before any confinement is needed at all."""

    point = EntryPoint(
        name="hostile",
        value=f"{EXAMPLES}:NATIVE_SOCKET_REGISTRATION",
        group=host_module.ENTRY_POINT_GROUP,
    )
    monkeypatch.setattr(host_module, "entry_points", lambda *, group: [point])
    registry = DetectorRegistry()
    registry.discover(
        isolation=PluginIsolation.SUBPROCESS,
        timeout=60.0,
        search_path=(REPOSITORY_ROOT,),
        policy=CapabilityPolicy(allowed_detector_ids=frozenset({"acme.trusted.v1"})),
    )

    assert "example.native-socket.v1" not in [
        getattr(detector, "id", "") for detector in registry.detectors()
    ]


def test_a_hostile_plugin_never_reaches_the_scanner_process(
    artifact: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Whatever the plugin does, it does it somewhere the host is not."""

    before = set(sys.modules)
    scan_with("NATIVE_SOCKET_REGISTRATION", artifact, monkeypatch)
    after = set(sys.modules)

    hostile = {name for name in after - before if "native" in name.lower()}
    assert not hostile, hostile
