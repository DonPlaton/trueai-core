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
    """Create a symlink, or skip/fail when the platform forbids it."""

    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
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
