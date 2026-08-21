"""Verify that built distributions contain exactly the intended files.

A source distribution must be able to rebuild and re-test the project, and the
wheel must not ship tests, fixtures, or developer tooling. Reviewing this by eye
before every release does not scale, so the manifest is asserted in CI.
"""

from __future__ import annotations

import sys
import tarfile
import zipfile
from collections.abc import Iterable
from pathlib import Path

DIST = Path("dist")

WHEEL_REQUIRED = (
    "trueai/__init__.py",
    "trueai/py.typed",
    "trueai/cli/app.py",
    "trueai/core/engine.py",
    "trueai/policies/audit.yaml",
    "trueai/policies/safe-clean.yaml",
    "trueai/policies/privacy.yaml",
    "trueai/policies/client-delivery.yaml",
    "trueai/policies/strict.yaml",
)
WHEEL_FORBIDDEN_PREFIXES = ("tests/", "docs/", "scripts/", "skills/", ".github/")

SDIST_REQUIRED = (
    "pyproject.toml",
    "README.md",
    "LICENSE",
    "SECURITY.md",
    "CHANGELOG.md",
    "tests/conftest.py",
    "docs/architecture.md",
    "schema/trueai-report-0.1.schema.json",
    "trueai/policies/audit.yaml",
)
SDIST_FORBIDDEN_SUBSTRINGS = (
    "/.venv/",
    "/.git/",
    "/.mypy_cache/",
    "/.ruff_cache/",
    "/.pytest_cache/",
    "/dist/",
)


def wheel_names(path: Path) -> list[str]:
    """Return archive member names inside a wheel."""

    with zipfile.ZipFile(path) as archive:
        return archive.namelist()


def sdist_names(path: Path) -> list[str]:
    """Return archive member names inside a source distribution, without its root prefix."""

    with tarfile.open(path) as archive:
        members = archive.getnames()
    stripped: list[str] = []
    for name in members:
        _, separator, remainder = name.partition("/")
        stripped.append(remainder if separator else name)
    return stripped


def report(problems: Iterable[str]) -> int:
    """Print problems and return a process exit code."""

    collected = list(problems)
    if not collected:
        print("Distribution manifests are correct.")
        return 0
    for problem in collected:
        print(f"error: {problem}", file=sys.stderr)
    return 1


def main() -> int:
    """Check every built distribution in ``dist/``."""

    problems: list[str] = []
    wheels = sorted(DIST.glob("*.whl"))
    sdists = sorted(DIST.glob("*.tar.gz"))
    if not wheels:
        problems.append("no wheel found in dist/")
    if not sdists:
        problems.append("no source distribution found in dist/")

    for wheel in wheels:
        names = wheel_names(wheel)
        for required in WHEEL_REQUIRED:
            if required not in names:
                problems.append(f"{wheel.name} is missing {required}")
        for name in names:
            if name.startswith(WHEEL_FORBIDDEN_PREFIXES):
                problems.append(f"{wheel.name} ships development-only path {name}")

    for sdist in sdists:
        names = sdist_names(sdist)
        for required in SDIST_REQUIRED:
            if required not in names:
                problems.append(f"{sdist.name} is missing {required}")
        for name in names:
            if any(marker in f"/{name}" for marker in SDIST_FORBIDDEN_SUBSTRINGS):
                problems.append(f"{sdist.name} ships environment path {name}")

    return report(problems)


if __name__ == "__main__":
    raise SystemExit(main())
