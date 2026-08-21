"""Compare two build outputs byte for byte to prove reproducibility."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path


def digest(path: Path) -> str:
    """Return the SHA-256 digest of a file."""

    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: list[str]) -> int:
    """Compare every artifact in the first directory against the second."""

    if len(argv) != 2:
        print("usage: compare_builds.py <first-dist> <second-dist>", file=sys.stderr)
        return 2
    first, second = Path(argv[0]), Path(argv[1])
    artifacts = sorted(path for path in first.iterdir() if path.is_file())
    if not artifacts:
        print(f"error: {first} contains no artifacts", file=sys.stderr)
        return 1

    mismatched: list[str] = []
    for artifact in artifacts:
        counterpart = second / artifact.name
        if not counterpart.is_file():
            mismatched.append(f"{artifact.name} is missing from {second}")
            continue
        if digest(artifact) != digest(counterpart):
            mismatched.append(f"{artifact.name} differs between builds")

    if mismatched:
        print("Builds are not reproducible:", file=sys.stderr)
        for problem in mismatched:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print(f"All {len(artifacts)} artifacts are byte-identical across rebuilds.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
