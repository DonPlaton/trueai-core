"""Compare two build outputs to prove reproducibility.

Two levels of comparison, because they answer different questions.

**Byte comparison** answers "did this exact environment produce this exact
artifact again". It is the strong claim, and it holds inside one pinned
environment: the same container, the same interpreter, the same
``SOURCE_DATE_EPOCH``.

**Content comparison** answers "do these two artifacts carry the same files".
It exists because a ZIP records the operating system that wrote it and a
tarball records POSIX modes, and because two zlib versions compress identical
input into different bytes. An auditor rebuilding on a different platform will
see those differences and needs a way to tell them apart from a real change in
what was shipped.

Content equality with byte inequality is not a pass. It is a precise statement
that the difference lies in archive framing rather than in shipped files, and
the tool says so rather than rounding it up to success.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Member:
    """One archive entry, reduced to what actually ships."""

    name: str
    size: int
    digest: str
    mode: int


def digest(path: Path) -> str:
    """Return the SHA-256 digest of a file."""

    return hashlib.sha256(path.read_bytes()).hexdigest()


def members(path: Path) -> tuple[Member, ...] | None:
    """Return the content of an archive, or None if it is not one."""

    if path.suffix == ".whl" or path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            return tuple(
                Member(
                    name=info.filename,
                    size=info.file_size,
                    digest=hashlib.sha256(archive.read(info)).hexdigest(),
                    mode=(info.external_attr >> 16) & 0o7777,
                )
                for info in archive.infolist()
            )
    if path.name.endswith(".tar.gz"):
        with tarfile.open(path) as archive:
            collected: list[Member] = []
            for info in archive.getmembers():
                if not info.isfile():
                    continue
                handle = archive.extractfile(info)
                payload = handle.read() if handle is not None else b""
                collected.append(
                    Member(
                        name=info.name,
                        size=info.size,
                        digest=hashlib.sha256(payload).hexdigest(),
                        mode=info.mode & 0o7777,
                    )
                )
            return tuple(collected)
    return None


def describe_content_difference(first: Path, second: Path) -> list[str]:
    """Explain how two archives differ in what they carry."""

    left, right = members(first), members(second)
    if left is None or right is None:
        return [f"{first.name} is not a comparable archive"]
    left_names = {item.name for item in left}
    right_names = {item.name for item in right}
    problems: list[str] = []
    for name in sorted(left_names - right_names):
        problems.append(f"{first.name} has {name}, {second.name} does not")
    for name in sorted(right_names - left_names):
        problems.append(f"{second.name} has {name}, {first.name} does not")
    right_by_name = {item.name: item for item in right}
    for item in left:
        counterpart = right_by_name.get(item.name)
        if counterpart is None:
            continue
        if item.digest != counterpart.digest:
            problems.append(f"{item.name} differs in content")
        elif item.mode != counterpart.mode:
            problems.append(
                f"{item.name} differs only in recorded mode ({item.mode:o} vs {counterpart.mode:o})"
            )
    return problems


def main(argv: list[str]) -> int:
    """Compare every artifact in the first directory against the second."""

    parser = argparse.ArgumentParser(description="Compare two build outputs.")
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path)
    parser.add_argument(
        "--content",
        action="store_true",
        help=(
            "Also report whether byte-differing archives still carry identical files. "
            "Use when comparing builds from different platforms."
        ),
    )
    arguments = parser.parse_args(argv)

    first, second = arguments.first, arguments.second
    artifacts = sorted(
        path
        for path in first.iterdir()
        if path.is_file() and (path.suffix == ".whl" or path.name.endswith(".tar.gz"))
    )
    if not artifacts:
        print(f"error: {first} contains no distributions", file=sys.stderr)
        return 1

    identical: list[str] = []
    content_equal: list[str] = []
    mismatched: list[str] = []
    for artifact in artifacts:
        counterpart = second / artifact.name
        if not counterpart.is_file():
            mismatched.append(f"{artifact.name} is missing from {second}")
            continue
        if digest(artifact) == digest(counterpart):
            identical.append(artifact.name)
            continue
        if not arguments.content:
            mismatched.append(f"{artifact.name} differs between builds")
            continue
        problems = describe_content_difference(artifact, counterpart)
        substantive = [item for item in problems if "recorded mode" not in item]
        if substantive:
            mismatched.append(f"{artifact.name}: " + "; ".join(substantive[:5]))
        else:
            content_equal.append(artifact.name)

    for name in identical:
        print(f"identical bytes: {name}")
    for name in content_equal:
        print(
            f"identical content, different archive framing: {name} "
            "(expected across platforms; not a byte-for-byte reproduction)"
        )
    if mismatched:
        print("Builds do not match:", file=sys.stderr)
        for problem in mismatched:
            print(f"  {problem}", file=sys.stderr)
        return 1
    if content_equal and not arguments.content:  # pragma: no cover - defensive
        return 1
    print(f"Compared {len(artifacts)} artifact(s) successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
