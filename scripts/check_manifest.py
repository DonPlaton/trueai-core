"""Verify that built distributions contain exactly the intended files.

A source distribution must be able to rebuild and re-test the project, and the
wheel must not ship tests, fixtures, or developer tooling. Reviewing this by eye
before every release does not scale, so the manifest is asserted in CI.
"""

from __future__ import annotations

import sys
import tarfile
import tomllib
import zipfile
from collections.abc import Iterable
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
DIST = Path("dist")

WHEEL_REQUIRED = (
    "trueai/__init__.py",
    "trueai/py.typed",
    "trueai/cli/app.py",
    "trueai/core/engine.py",
    "trueai/core/certificates.py",
    "trueai/core/policy_bundle.py",
    "trueai/cleaners/media.py",
    "trueai/detectors/media/containers.py",
    "trueai/detectors/media/metadata.py",
    "trueai/plugins/inspector.py",
    "trueai/plugins/resources.py",
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
    "docs/reproducible-builds.md",
    # An auditor must be able to rebuild from the sdist alone, which needs the
    # dependency lock and the container definition that pins the environment.
    "uv.lock",
    "Dockerfile",
    "docs/certificates.md",
    "schema/trueai-certificate-0.1.schema.json",
    "schema/trueai-policy-bundle-0.1.schema.json",
    "schema/trueai-revocation-list-0.1.schema.json",
    "schema/trueai-report-0.1.schema.json",
    "tests/unit/test_policy_bundles.py",
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


def packaged_version(distribution: Path) -> str:
    """Return the version a distribution's filename declares.

    Both `name-version-py3-none-any.whl` and `name-version.tar.gz` put the
    version in the second hyphen-separated field of the stem, and the packaging
    specification requires it to be there.
    """

    stem = distribution.name
    for suffix in (".tar.gz", ".whl"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    parts = stem.split("-")
    return parts[1] if len(parts) > 1 else ""


def stale(distributions: list[Path], expected: str) -> list[str]:
    """Name any distribution that was not built from the version in the tree.

    Without this the gate reads whatever is in `dist/` and certifies it. In CI
    that directory is empty until the build step, so the mistake is loud. On a
    maintainer's machine `dist/` holds the last build, which may be from another
    commit, and the gate returns a pass having examined the wrong bytes. A tool
    whose subject is documents that claim more than was checked cannot ship a
    gate that does it.

    A matching version is not proof the bytes match, and this does not pretend
    otherwise: it catches the stale build, and only rebuilding proves the rest.
    """

    return [
        f"{item.name} was built from version {packaged_version(item) or 'an unreadable name'}, "
        f"and the working tree is at {expected}; rebuild dist/ before checking it"
        for item in distributions
        if packaged_version(item) != expected
    ]


def main() -> int:
    """Check every built distribution in ``dist/``."""

    # `pyproject.toml` is what the builder reads, and it is what
    # `check_release_tag.py` compares a tag against. Reading the same field here
    # keeps the three of them from disagreeing.
    pyproject = tomllib.loads((REPOSITORY / "pyproject.toml").read_text(encoding="utf-8"))
    expected = str(pyproject["project"]["version"])

    problems: list[str] = []
    wheels = sorted(DIST.glob("*.whl"))
    sdists = sorted(DIST.glob("*.tar.gz"))
    if not wheels:
        problems.append("no wheel found in dist/")
    if not sdists:
        problems.append("no source distribution found in dist/")
    problems.extend(stale([*wheels, *sdists], expected))

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
