"""Record every input a build depended on, so it can be reproduced or disputed.

A reproducible build is only useful if a third party knows what to reproduce.
This writes the inputs an auditor needs — source commit, build timestamp,
interpreter, build backend, dependency lock digest, base image, and the digests
of the artifacts produced — as one JSON document that travels with the release.

The document deliberately records digests rather than contents: it is evidence
about a build, not a copy of it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = Path("dist") / "build-inputs.json"

#: Kept in step with the digest pinned in the Dockerfile, which is the base an
#: auditor is expected to rebuild in.
BASE_IMAGE_MARKER = "FROM python@"


def digest_file(path: Path) -> str:
    """Return the SHA-256 of a file."""

    reader = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            reader.update(chunk)
    return reader.hexdigest()


def git(*arguments: str) -> str | None:
    """Run a read-only git command, returning None outside a repository."""

    try:
        completed = subprocess.run(
            ["git", "-C", str(REPOSITORY_ROOT), *arguments],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None


def base_image() -> str | None:
    """Return the container base image the Dockerfile pins."""

    dockerfile = REPOSITORY_ROOT / "Dockerfile"
    if not dockerfile.is_file():
        return None
    for line in dockerfile.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith(BASE_IMAGE_MARKER):
            return stripped.removeprefix("FROM ").split(" ")[0]
    return None


def tool_versions() -> dict[str, str]:
    """Return the versions of the tools that shape the artifacts."""

    from importlib.metadata import PackageNotFoundError, version

    versions: dict[str, str] = {}
    for name in ("hatchling", "build", "uv", "pip"):
        try:
            versions[name] = version(name)
        except PackageNotFoundError:
            continue
    return versions


def collect(distribution_directory: Path, source_date_epoch: str | None) -> dict[str, Any]:
    """Gather the full input record for one build."""

    lock = REPOSITORY_ROOT / "uv.lock"
    artifacts = sorted(
        path
        for path in distribution_directory.glob("*")
        if path.is_file() and path.suffix in {".whl", ".gz"}
    )
    return {
        "schema": "trueai-build-inputs/1",
        "source": {
            "commit": git("rev-parse", "HEAD"),
            "commit_date": git("log", "-1", "--pretty=%cI"),
            "describe": git("describe", "--tags", "--always", "--dirty"),
            "dirty": bool(git("status", "--porcelain")),
        },
        "build": {
            "source_date_epoch": source_date_epoch,
            "python_version": platform.python_version(),
            "python_implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "tool_versions": tool_versions(),
        },
        "dependencies": {
            "lock_file": lock.name if lock.is_file() else None,
            "lock_sha256": digest_file(lock) if lock.is_file() else None,
            "base_image": base_image(),
        },
        "artifacts": [
            {"name": path.name, "size": path.stat().st_size, "sha256": digest_file(path)}
            for path in artifacts
        ],
    }


def main(argv: list[str]) -> int:
    """Write the build-input record next to the artifacts it describes."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dist", type=Path, default=Path("dist"), help="Directory holding the built artifacts."
    )
    parser.add_argument("--output", type=Path, default=None, help="Where to write the record.")
    parser.add_argument(
        "--source-date-epoch",
        default=None,
        help="The SOURCE_DATE_EPOCH the build used, for the record.",
    )
    arguments = parser.parse_args(argv)

    distribution_directory = arguments.dist
    if not distribution_directory.is_dir():
        print(f"error: {distribution_directory} is not a directory", file=sys.stderr)
        return 1

    import os

    epoch = arguments.source_date_epoch or os.environ.get("SOURCE_DATE_EPOCH")
    record = collect(distribution_directory, epoch)
    if not record["artifacts"]:
        print(f"error: {distribution_directory} contains no distributions", file=sys.stderr)
        return 1

    output = arguments.output or (distribution_directory / "build-inputs.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Recorded {len(record['artifacts'])} artifact(s) in {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
