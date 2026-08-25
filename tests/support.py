"""Shared helpers for capability-dependent security tests.

Several security boundaries can only be exercised where the runner is allowed to
create symlinks. Skipping those cases silently would let the suite report green
while the security policy claims coverage it does not have, so CI sets
``TRUEAI_REQUIRE_PRIVILEGED_TESTS=1`` on platforms where the capability must
exist, and the skip becomes a failure there.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from typing import NoReturn

import pytest

ENFORCEMENT_VARIABLE = "TRUEAI_REQUIRE_PRIVILEGED_TESTS"
OPTIONAL_DEPENDENCY_VARIABLE = "TRUEAI_REQUIRE_OPTIONAL_DEPENDENCIES"
BUILT_DISTRIBUTION_VARIABLE = "TRUEAI_REQUIRE_BUILT_DISTRIBUTIONS"
#: Shared with ``scripts/verify_native_plugins.py`` so that "where is this
#: actually checked" has one answer rather than one per platform.
CONFINEMENT_VARIABLE = "TRUEAI_REQUIRE_CONFINEMENT"


def privileged_tests_required() -> bool:
    """Return whether missing OS capabilities must fail instead of skip."""

    return os.environ.get(ENFORCEMENT_VARIABLE, "").strip().lower() in {"1", "true", "yes"}


def unavailable_capability(capability: str, reason: object) -> NoReturn:
    """Skip, or fail when the platform is expected to provide the capability."""

    message = f"{capability} is unavailable on this platform: {reason}"
    if privileged_tests_required():
        pytest.fail(
            f"{message}\n{ENFORCEMENT_VARIABLE} is set, so this security case must run here."
        )
    pytest.skip(message)


def create_symlink(link: Path, target: Path, *, target_is_directory: bool = False) -> None:
    """Create ``link`` pointing at ``target``, or skip/fail where the OS forbids it.

    ``FileExistsError`` is deliberately not caught. It does not mean the platform
    refuses symlinks; it means the caller asked for a link where something
    already is, which is a mistake in the test. Folding it into the skip is how a
    security case swapped its two arguments and then reported for months as an
    unavailable platform capability rather than as a test that never ran.
    """

    if link.exists() or link.is_symlink():
        raise FileExistsError(
            f"{link} already exists, so it cannot become a symlink to {target}. "
            "create_symlink takes the link first and its target second."
        )
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except FileExistsError:
        raise
    except (OSError, NotImplementedError) as exc:
        unavailable_capability("Symlink creation", exc)


def optional_dependencies_required() -> bool:
    """Return whether missing optional dependencies must fail instead of skip."""

    return os.environ.get(OPTIONAL_DEPENDENCY_VARIABLE, "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def missing_modules(*names: str) -> list[str]:
    """Return which of the named modules are not importable."""

    return [name for name in names if importlib.util.find_spec(name) is None]


def assert_optional_dependencies(*names: str) -> None:
    """Fail when a job that promised to cover optional features cannot run them.

    A suite that quietly skips its only coverage of an optional integration
    reports green while proving nothing, so at least one CI job sets
    ``TRUEAI_REQUIRE_OPTIONAL_DEPENDENCIES=1`` and turns that skip into a failure.
    """

    if not optional_dependencies_required():
        return
    missing = missing_modules(*names)
    if missing:
        pytest.fail(
            f"{OPTIONAL_DEPENDENCY_VARIABLE} is set but these modules are missing: "
            + ", ".join(missing)
        )


def unavailable_confinement(control: str, reason: object) -> NoReturn:
    """Skip, or fail where the operating-system control is expected to work.

    Not the same as a failure. A restricted Windows token cannot attach to the
    window station of a hosted runner's non-interactive session, and a Linux
    runner refuses the unshare an unprivileged mount namespace needs. Reporting
    either as a broken control says the confinement is broken, when the truth is
    that this machine will not offer it -- and only one of those should wake
    somebody up.
    """

    message = f"{control} is unavailable on this machine: {reason}"
    if os.environ.get(CONFINEMENT_VARIABLE, "").strip().lower() in {"1", "true", "yes"}:
        pytest.fail(f"{message}\n{CONFINEMENT_VARIABLE} is set, so this control must hold here.")
    pytest.skip(message)


# -- prerequisites the test matrix deliberately does not provide -----------------------


def release_closure_problem() -> str | None:
    """Return why the full runtime closure cannot be walked, or ``None``.

    The license, SBOM, and advisory gates each traverse the installed dependency
    graph for every runtime extra. The test matrix installs ``.[dev,pdf]`` on
    purpose, because that is the shape a user gets and the shape the graceful
    degradation tests need. Widening it to keep these seven tests happy would
    delete that coverage.
    """

    import sys

    repository = Path(__file__).resolve().parents[1]
    if str(repository) not in sys.path:
        sys.path.insert(0, str(repository))
    from scripts.check_licenses import runtime_distribution_names

    try:
        runtime_distribution_names()
    except RuntimeError as exc:
        return str(exc)
    return None


def require_release_closure() -> None:
    """Skip unless every runtime extra is installed, or fail where it must be."""

    problem = release_closure_problem()
    if problem is None:
        return
    message = f"The full runtime closure is not installed: {problem}"
    if optional_dependencies_required():
        pytest.fail(
            f"{message}\n{OPTIONAL_DEPENDENCY_VARIABLE} is set, so this gate must run here."
        )
    pytest.skip(message)


def built_distributions_required() -> bool:
    """Return whether an unbuilt ``dist/`` must fail instead of skip."""

    return os.environ.get(BUILT_DISTRIBUTION_VARIABLE, "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def require_built_distributions() -> None:
    """Skip unless ``dist/`` holds a wheel and an sdist, or fail where it must.

    The manifest gate reads the archives themselves; there is nothing to inspect
    in a tree that has not been built. That is a missing prerequisite, not a
    passing check, and the two must not report the same.
    """

    dist = Path(__file__).resolve().parents[1] / "dist"
    wheels = list(dist.glob("*.whl")) if dist.is_dir() else []
    sources = list(dist.glob("*.tar.gz")) if dist.is_dir() else []
    if wheels and sources:
        return
    message = (
        f"No built distributions in {dist}: the manifest gate inspects the archives, "
        "so there is nothing for it to answer about."
    )
    if built_distributions_required():
        pytest.fail(f"{message}\n{BUILT_DISTRIBUTION_VARIABLE} is set, so this gate must run here.")
    pytest.skip(message)


# -- confinement has to be applied somewhere it is allowed to win ----------------------

#: Applied in a child, printed as JSON, read back by the parent. Confinement is
#: one-way by design, so the process that applies it is spent afterwards.
_CONFINEMENT_PROBE = """
import json, sys
from trueai.plugins import confinement as module
from trueai.plugins.broker import BrokerGrants
from trueai.plugins.confinement import (
    ConfinementLevel,
    ConfinementUnavailableError,
    PlatformConfinement,
    apply_confinement,
)

level = ConfinementLevel(sys.argv[1])
spawn_time = sys.argv[2] == "1"
pretend = json.loads(sys.argv[3])
if pretend:
    # Patched here, in the process that reads it. A monkeypatch in the test
    # runner reaches the test runner, and the decision under test is made two
    # processes away.
    module.describe_platform = lambda: PlatformConfinement(**pretend)
try:
    report = apply_confinement(BrokerGrants(), level, spawn_time_applied=spawn_time)
except ConfinementUnavailableError as exc:
    payload = {"refused": str(exc)}
else:
    payload = {"report": report.model_dump(mode="json")}
# Written to an already-open descriptor: the filter denies sockets and exec, and
# a read-only root does not close a pipe.
sys.stdout.write(json.dumps(payload))
"""


def confinement_report(
    level: object,
    *,
    spawn_time_applied: bool = False,
    pretend_platform: dict[str, object] | None = None,
) -> object:
    """Apply confinement in a child process and return the report it produced.

    Calling ``apply_confinement`` in the test runner confines the test runner.
    There is no way back from it -- that is the point of the mechanism -- so on
    Linux the runner is left with a read-only root and an empty grant set, and
    every later test fails inside its own ``tmp_path`` fixture. The control is
    still measured against a real kernel here; only the casualty changes.

    Raises ``ConfinementUnavailableError`` when the child refused, so a caller
    can still assert that ``REQUIRED`` refuses where ``BEST_EFFORT`` degrades.
    """

    import json
    import subprocess
    import sys

    from trueai.plugins.confinement import ConfinementReport, ConfinementUnavailableError

    repository = Path(__file__).resolve().parents[1]
    environment = dict(os.environ)
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        f"{repository}{os.pathsep}{existing}" if existing else str(repository)
    )

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            _CONFINEMENT_PROBE,
            str(getattr(level, "value", level)),
            "1" if spawn_time_applied else "0",
            json.dumps(pretend_platform or {}),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        env=environment,
    )
    if completed.returncode != 0:
        pytest.fail(
            "The confinement probe did not survive its own confinement "
            f"(exit {completed.returncode}): {completed.stderr.strip()}"
        )
    payload = json.loads(completed.stdout)
    if "refused" in payload:
        raise ConfinementUnavailableError(payload["refused"])
    return ConfinementReport.model_validate(payload["report"])
