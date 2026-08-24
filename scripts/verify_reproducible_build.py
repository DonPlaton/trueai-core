"""Prove that the pinned container rebuilds the same bytes twice.

Reproducibility that is asserted in a document and never executed decays quietly.
This builds the auditor image twice with caching disabled, extracts both sets of
artifacts, and compares them byte for byte, so the claim in
``docs/reproducible-builds.md`` is checked rather than trusted.

Requires Docker. Skips with a clear message when Docker is unavailable, because
a missing tool is not evidence that the build is irreproducible.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
EXIT_SKIPPED = 0


def run(*arguments: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    """Run a command, returning its completed process."""

    return subprocess.run(
        list(arguments),
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        check=False,
    )


def docker_available() -> bool:
    """Return whether a usable Docker daemon is reachable."""

    if shutil.which("docker") is None:
        return False
    return run("docker", "info").returncode == 0


def source_date_epoch() -> str:
    """Return the commit timestamp, which pins the build clock."""

    completed = run("git", "-C", str(REPOSITORY_ROOT), "log", "-1", "--pretty=%ct")
    if completed.returncode == 0 and completed.stdout.strip():
        return completed.stdout.strip()
    # A source tree without history still builds deterministically; it just has
    # no commit to take the timestamp from.
    return "1735689600"


def build_and_extract(tag: str, epoch: str, destination: Path) -> None:
    """Build the auditor image from scratch and copy its artifacts out."""

    build = run(
        "docker",
        "build",
        "--no-cache",
        "--build-arg",
        f"SOURCE_DATE_EPOCH={epoch}",
        "-t",
        tag,
        ".",
        cwd=REPOSITORY_ROOT,
    )
    if build.returncode != 0:
        raise RuntimeError(f"docker build failed for {tag}:\n{build.stderr[-4000:]}")
    container = run("docker", "create", "--name", f"{tag}-extract", tag)
    if container.returncode != 0:
        raise RuntimeError(f"docker create failed for {tag}:\n{container.stderr[-2000:]}")
    try:
        destination.mkdir(parents=True, exist_ok=True)
        copy = run("docker", "cp", f"{tag}-extract:/dist/.", str(destination))
        if copy.returncode != 0:
            raise RuntimeError(f"docker cp failed for {tag}:\n{copy.stderr[-2000:]}")
    finally:
        run("docker", "rm", "-f", f"{tag}-extract")


def main(argv: list[str]) -> int:
    """Build twice and compare."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--keep",
        type=Path,
        default=None,
        help="Directory to keep the first build's artifacts in.",
    )
    arguments = parser.parse_args(argv)

    if not docker_available():
        print(
            "Docker is unavailable, so container reproducibility was not checked. "
            "This is a skip, not a pass.",
            file=sys.stderr,
        )
        return EXIT_SKIPPED

    epoch = source_date_epoch()
    print(f"Building twice with SOURCE_DATE_EPOCH={epoch}")
    workspace = Path(tempfile.mkdtemp(prefix="trueai-reproduce-"))
    first = arguments.keep or (workspace / "first")
    second = workspace / "second"
    try:
        build_and_extract("trueai-reproduce-a", epoch, first)
        build_and_extract("trueai-reproduce-b", epoch, second)
        comparison = run(
            sys.executable,
            str(REPOSITORY_ROOT / "scripts" / "compare_builds.py"),
            str(first),
            str(second),
        )
        print(comparison.stdout, end="")
        if comparison.returncode != 0:
            print(comparison.stderr, end="", file=sys.stderr)
            return 1
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        for tag in ("trueai-reproduce-a", "trueai-reproduce-b"):
            run("docker", "image", "rm", "-f", tag)
        if arguments.keep is None:
            shutil.rmtree(workspace, ignore_errors=True)
        else:
            shutil.rmtree(second, ignore_errors=True)
    print("The pinned container build is byte-for-byte reproducible.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
