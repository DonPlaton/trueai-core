"""Confirm that the pushed Git tag matches the packaged version."""

from __future__ import annotations

import os
import sys
import tomllib
from pathlib import Path


def main() -> int:
    """Compare ``refs/tags/vX.Y.Z`` against the project version."""

    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    version = str(pyproject["project"]["version"])

    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with Path(output_path).open("a", encoding="utf-8") as handle:
            handle.write(f"version={version}\n")

    reference = os.environ.get("GITHUB_REF", "")
    if not reference.startswith("refs/tags/"):
        print(f"No tag in GITHUB_REF; packaging version {version}.")
        return 0

    tag = reference.removeprefix("refs/tags/")
    expected = f"v{version}"
    if tag != expected:
        print(
            f"error: tag {tag!r} does not match the packaged version {version!r}. "
            f"Expected {expected!r}.",
            file=sys.stderr,
        )
        return 1
    print(f"Tag {tag} matches the packaged version.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
