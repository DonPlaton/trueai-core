"""Fail the build when a runtime dependency uses a license outside the allowlist.

TrueAI Core is Apache-2.0 and is intended for commercial and enterprise use, so a
copyleft dependency arriving through a transitive upgrade must be a build failure
rather than a discovery made after distribution.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

_REPOSITORY = Path(__file__).resolve().parent.parent
if str(_REPOSITORY) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY))

#: One license, several spellings. The list carries all of them because two
#: readers disagree about which field to believe: pip-licenses prefers the
#: trove classifier ("ISC License (ISCL)") and installed metadata prefers the
#: `License:` field ("ISC License"). Same license, and a gate that failed on the
#: spelling would teach a maintainer to widen the list rather than read it.
ALLOWED_LICENSES = frozenset(
    {
        "Apache Software License",
        "Apache License",
        "Apache-2.0",
        "BSD License",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "HPND",
        "ISC License (ISCL)",
        "ISC License",
        "ISC",
        "MIT",
        "MIT-0",
        "MIT License",
        "MIT-CMU",
        "MPL-2.0",
        "Mozilla Public License 2.0 (MPL 2.0)",
        "Python Software Foundation License",
        "PSF-2.0",
        "PSFL",
        "The Unlicense (Unlicense)",
    }
)

# Distributions whose classifiers are missing or ambiguous, reviewed manually.
REVIEWED_EXCEPTIONS = {
    "trueai-core": "Apache-2.0 (this project)",
}
RUNTIME_EXTRAS = frozenset({"attestation", "c2pa", "pdf"})


def license_is_allowed(license_expression: str) -> bool:
    """Validate every atom in a simple SPDX OR/AND or pip-licenses list.

    Dependency metadata commonly reports dual licenses as ``MIT OR Apache-2.0``.
    Treating that whole expression as one unknown label creates false release
    failures. Requiring every named atom to be allowlisted stays conservative for
    both OR and AND expressions without adding a runtime SPDX parser.
    """

    if license_expression.strip() in ALLOWED_LICENSES:
        return True
    atoms = [
        atom.strip().strip("()")
        for atom in re.split(r"\s+(?:OR|AND)\s+|;", license_expression)
        if atom.strip()
    ]
    return bool(atoms) and all(atom in ALLOWED_LICENSES for atom in atoms)


def runtime_distribution_names(
    root: str = "trueai-core",
    *,
    extras: frozenset[str] = RUNTIME_EXTRAS,
) -> tuple[str, ...]:
    """Return the installed runtime dependency closure for the selected extras.

    Release environments also contain pytest, pip-audit, CycloneDX, and this
    script's own license reader. Including those tools would make the runtime
    license gate depend on whichever transitive packages the CI tooling happened
    to install that day, despite none of them shipping in the TrueAI wheel.
    """

    pending: list[tuple[str, frozenset[str]]] = [(canonicalize_name(root), extras)]
    evaluated_extras: dict[str, frozenset[str]] = {}
    display_names: dict[str, str] = {}
    marker_environment = default_environment()
    while pending:
        name, requested_extras = pending.pop()
        previous = evaluated_extras.get(name)
        if previous is not None and requested_extras <= previous:
            continue
        active_extras = requested_extras | (previous or frozenset())
        try:
            package = distribution(name)
        except PackageNotFoundError as exc:
            raise RuntimeError(
                f"Runtime distribution {name!r} is not installed; install all release extras"
            ) from exc
        evaluated_extras[name] = active_extras
        display_names[name] = package.metadata.get("Name", name)
        for requirement_text in package.requires or ():
            requirement = Requirement(requirement_text)
            if requirement.marker is not None:
                contexts = active_extras | frozenset({""})
                if not any(
                    requirement.marker.evaluate(
                        {**marker_environment, "extra": extra},
                        context="metadata",
                    )
                    for extra in contexts
                ):
                    continue
            dependency_name = canonicalize_name(requirement.name)
            pending.append((dependency_name, frozenset(requirement.extras)))
    return tuple(sorted(display_names.values(), key=str.casefold))


def read_licenses_directly(names: tuple[str, ...]) -> list[dict[str, str]]:
    """Read licenses from installed metadata, in pip-licenses' output shape.

    The same source pip-licenses reads. Having it here means the gate runs from a
    working tree without an extra install, which is the difference between
    finding a licensing problem before pushing and finding it in CI.
    """

    from scripts.generate_sbom import _license_of

    packages: list[dict[str, str]] = []
    for name in sorted(names):
        try:
            package = distribution(name)
        except PackageNotFoundError:
            continue
        packages.append(
            {
                "Name": package.metadata.get("Name", name),
                "Version": package.version or "",
                "License": _license_of(package.metadata) or "UNKNOWN",
            }
        )
    return packages


def main() -> int:
    """Compare installed distribution licenses against the allowlist."""

    try:
        runtime_packages = runtime_distribution_names()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "piplicenses",
            "--format=json",
            "--packages",
            *runtime_packages,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        if "No module named piplicenses" in completed.stderr:
            # Fall back rather than skip. A gate that quietly does nothing when a
            # tool is missing is worse than one that fails, because it reports
            # success either way.
            packages = read_licenses_directly(runtime_packages)
            print("pip-licenses is not installed; reading licenses from installed metadata.")
        else:
            print(completed.stderr, file=sys.stderr)
            return completed.returncode
    else:
        packages = json.loads(completed.stdout)

    problems: list[str] = []
    for package in packages:
        name = package["Name"]
        license_name = package["License"]
        version = package["Version"]
        if name in REVIEWED_EXCEPTIONS:
            continue
        if license_is_allowed(license_name):
            continue
        problems.append(f"{name} {version} declares license {license_name!r}")

    if problems:
        print("Dependency licenses outside the allowlist:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            "Review the dependency, then either replace it or extend ALLOWED_LICENSES "
            "with an explicit justification.",
            file=sys.stderr,
        )
        return 1
    print(f"All {len(packages)} runtime distributions use allowlisted licenses.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
