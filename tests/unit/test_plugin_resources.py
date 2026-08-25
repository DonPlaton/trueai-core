"""Process limits, and the three states a platform can leave them in.

The reason this file exists: `setrlimit(RLIMIT_AS, 512MB)` is refused on hosted
macOS, both limits were installed inside one `try`, and the single failure threw
away the CPU ceiling that would have been granted. `apply_process_resource_limits`
raised, every plugin was rejected at discovery, and TrueAI silently did not
support plugins on macOS at all.

The distinction the code has to keep is between:

* a limit that is in force,
* a limit this platform refuses, and
* a helper process that could not be limited at all.

Collapsing the first two overstates the protection. Collapsing the last two
throws away protection that was available. Both are worse than saying which.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from trueai.plugins.resources import (
    PluginResourceLimits,
    ResourceLimitReport,
    ResourceLimitsUnavailableError,
    _apply_posix_limits,
    apply_process_resource_limits,
)

LIMITS = PluginResourceLimits(max_memory_bytes=256 * 1024 * 1024, max_cpu_seconds=5)

RLIM_INFINITY = -1


def fake_resource(
    *,
    refuse: frozenset[str] = frozenset(),
    hard: dict[str, int] | None = None,
) -> SimpleNamespace:
    """A stand-in for the `resource` module that records what was asked of it."""

    applied: dict[str, tuple[int, int]] = {}
    names = {1: "RLIMIT_AS", 2: "RLIMIT_CPU"}
    hard_limits = hard or {}

    def getrlimit(key: int) -> tuple[int, int]:
        name = names[key]
        return (RLIM_INFINITY, hard_limits.get(name, RLIM_INFINITY))

    def setrlimit(key: int, values: tuple[int, int]) -> None:
        name = names[key]
        if name in refuse:
            raise ValueError("current limit exceeds maximum limit")
        applied[name] = values

    return SimpleNamespace(
        RLIMIT_AS=1,
        RLIMIT_CPU=2,
        RLIM_INFINITY=RLIM_INFINITY,
        getrlimit=getrlimit,
        setrlimit=setrlimit,
        applied=applied,
    )


def install(monkeypatch: pytest.MonkeyPatch, module: SimpleNamespace) -> None:
    import importlib

    monkeypatch.setattr(
        importlib, "import_module", lambda name: module if name == "resource" else None
    )


# -- the three states ------------------------------------------------------------------


def test_every_accepted_limit_is_reported_as_established(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = fake_resource()
    install(monkeypatch, module)

    report = _apply_posix_limits(LIMITS)

    assert report.not_enforced == ()
    assert report.memory_capped
    assert module.applied["RLIMIT_AS"] == (LIMITS.max_memory_bytes, LIMITS.max_memory_bytes)
    assert module.applied["RLIMIT_CPU"] == (5, 5)


def test_one_refused_limit_does_not_discard_the_other(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The macOS failure, exactly. The CPU ceiling was available and thrown away."""

    module = fake_resource(refuse=frozenset({"RLIMIT_AS"}))
    install(monkeypatch, module)

    report = _apply_posix_limits(LIMITS)

    assert "RLIMIT_CPU" in module.applied
    assert not report.memory_capped
    assert any("address space" in line for line in report.not_enforced)
    assert any("CPU time" in line for line in report.established)


def test_the_refusal_says_which_limit_and_what_the_kernel_answered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ "Unable to install POSIX plugin resource limits" named neither."""

    install(monkeypatch, fake_resource(refuse=frozenset({"RLIMIT_AS"})))

    report = _apply_posix_limits(LIMITS)

    assert report.not_enforced == (
        "address space: setrlimit(RLIMIT_AS) was refused (current limit exceeds maximum limit)",
    )


def test_a_process_that_cannot_be_limited_at_all_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Partial containment is a fact to report. No containment is a refusal."""

    install(monkeypatch, fake_resource(refuse=frozenset({"RLIMIT_AS", "RLIMIT_CPU"})))

    with pytest.raises(ResourceLimitsUnavailableError, match="No process limit"):
        _apply_posix_limits(LIMITS)


# -- clamping --------------------------------------------------------------------------


def test_the_request_never_exceeds_the_hard_limit_already_in_place(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Asking above the hard limit is itself an EINVAL, and needs privilege.

    A worker that raised its own ceiling would be a worker that could remove it,
    so the request is clamped downward instead of attempted and lost.
    """

    module = fake_resource(hard={"RLIMIT_AS": 100 * 1024 * 1024})
    install(monkeypatch, module)

    report = _apply_posix_limits(LIMITS)

    assert module.applied["RLIMIT_AS"] == (100 * 1024 * 1024, 100 * 1024 * 1024)
    assert report.memory_capped


def test_the_hard_limit_comes_down_with_the_soft_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Otherwise the plugin raises the soft limit back and the ceiling was theatre."""

    module = fake_resource()
    install(monkeypatch, module)

    _apply_posix_limits(LIMITS)

    for soft, hard in module.applied.values():
        assert soft == hard


# -- the caller that must not proceed --------------------------------------------------


PARTIAL = ResourceLimitReport(
    mechanism="test",
    established=("CPU time capped at 5 seconds",),
    not_enforced=("address space: setrlimit(RLIMIT_AS) was refused (EINVAL)",),
)


def whatever_this_platform_does(
    monkeypatch: pytest.MonkeyPatch, report: ResourceLimitReport
) -> None:
    """Pin both platform appliers, so `require_all` is tested and not the OS."""

    from trueai.plugins import resources

    monkeypatch.setattr(resources, "_apply_posix_limits", lambda limits: report)
    monkeypatch.setattr(resources, "_apply_windows_job_limits", lambda limits: report)


def test_require_all_refuses_when_any_limit_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`required` confinement means every control, not the ones that were easy."""

    whatever_this_platform_does(monkeypatch, PARTIAL)

    with pytest.raises(ResourceLimitsUnavailableError, match="address space"):
        apply_process_resource_limits(LIMITS, require_all=True)


def test_the_default_caller_proceeds_with_what_it_got(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Refusing to scan is a worse answer than scanning and saying what is missing."""

    whatever_this_platform_does(monkeypatch, PARTIAL)

    report = apply_process_resource_limits(LIMITS)

    assert report.established
    assert report.not_enforced


def test_require_all_accepts_a_platform_that_granted_everything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    complete = ResourceLimitReport(mechanism="test", established=("everything",))
    whatever_this_platform_does(monkeypatch, complete)

    assert apply_process_resource_limits(LIMITS, require_all=True) is complete


# -- the report itself -----------------------------------------------------------------


def test_an_empty_not_enforced_means_complete_not_unmeasured() -> None:
    """Two readings of an empty tuple, and only one of them is the right one."""

    report = ResourceLimitReport(
        mechanism="posix-rlimit", established=("address space capped at 1 bytes",)
    )

    assert report.not_enforced == ()
    assert report.memory_capped


def test_a_report_is_frozen() -> None:
    report = ResourceLimitReport(mechanism="posix-rlimit")

    with pytest.raises(ValidationError):
        report.mechanism = "something else"  # type: ignore[misc]


def test_the_real_platform_installs_at_least_one_limit() -> None:
    """Run against the actual kernel in a child, since the limits are one-way.

    In a child on every platform, not only POSIX: the Windows path assigns the
    *calling* process to a job object with a memory ceiling, so measuring it in
    the test runner would put the test runner under it.
    """

    import json
    import subprocess

    probe = (
        "import json,sys;"
        "from trueai.plugins.resources import PluginResourceLimits,"
        "apply_process_resource_limits as apply;"
        "r=apply(PluginResourceLimits());"
        "sys.stdout.write(json.dumps(r.model_dump(mode='json')))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, timeout=60
    )

    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["established"], report
