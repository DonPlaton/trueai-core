"""Fail the build when a runtime dependency uses a license outside the allowlist.

TrueAI Core is Apache-2.0 and is intended for commercial and enterprise use, so a
copyleft dependency arriving through a transitive upgrade must be a build failure
rather than a discovery made after distribution.
"""

from __future__ import annotations

import json
import subprocess
import sys

ALLOWED_LICENSES = frozenset(
    {
        "Apache Software License",
        "Apache-2.0",
        "BSD License",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "HPND",
        "ISC License (ISCL)",
        "MIT",
        "MIT License",
        "MIT-CMU",
        "MPL-2.0",
        "Mozilla Public License 2.0 (MPL 2.0)",
        "Python Software Foundation License",
        "The Unlicense (Unlicense)",
    }
)

# Distributions whose classifiers are missing or ambiguous, reviewed manually.
REVIEWED_EXCEPTIONS = {
    "trueai-core": "Apache-2.0 (this project)",
}


def main() -> int:
    """Compare installed distribution licenses against the allowlist."""

    completed = subprocess.run(
        [sys.executable, "-m", "piplicenses", "--format=json", "--with-system"],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        print(completed.stderr, file=sys.stderr)
        return completed.returncode
    packages = json.loads(completed.stdout)

    problems: list[str] = []
    for package in packages:
        name = package["Name"]
        license_name = package["License"]
        version = package["Version"]
        if name in REVIEWED_EXCEPTIONS:
            continue
        declared = {part.strip() for part in license_name.split(";") if part.strip()}
        if declared & ALLOWED_LICENSES:
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
    print(f"All {len(packages)} installed distributions use allowlisted licenses.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
