"""Scope-validated, byte-bounded read-only Git command execution."""

from __future__ import annotations

import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from trueai.core.errors import CorruptArtifactError, ScanLimitExceededError, UnsafeArtifactError

_GIT_REPOSITORY_ENVIRONMENT = frozenset(
    {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_NAMESPACE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_REPLACE_REF_BASE",
        "GIT_WORK_TREE",
    }
)
_MAX_ALTERNATE_DATABASES = 128


@dataclass(frozen=True, slots=True)
class GitCommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def run_git_bounded(
    repository: Path,
    arguments: tuple[str, ...],
    *,
    max_output_bytes: int,
    timeout: float = 30.0,
) -> GitCommandResult:
    """Run Git without hooks or locks while draining output into bounded buffers."""

    root = repository.resolve(strict=True)
    command = [
        "git",
        "-c",
        f"safe.directory={root.as_posix()}",
        "-C",
        str(root),
        *arguments,
    ]
    environment = os.environ.copy()
    for name in tuple(environment):
        if name in _GIT_REPOSITORY_ENVIRONMENT or name.startswith("GIT_CONFIG_"):
            environment.pop(name, None)
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_NO_LAZY_FETCH"] = "1"
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    environment["GIT_TERMINAL_PROMPT"] = "0"
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
    except OSError as exc:
        raise CorruptArtifactError(f"Unable to execute Git: {exc}") from exc
    assert process.stdout is not None
    assert process.stderr is not None
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="trueai-git-output") as executor:
        stdout_future = executor.submit(_read_bounded, process.stdout, max_output_bytes)
        stderr_future = executor.submit(
            _read_bounded,
            process.stderr,
            min(max_output_bytes, 1024 * 1024),
        )
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait()
            raise ScanLimitExceededError(f"Git command exceeded {timeout:.0f} seconds") from exc
        stdout, stdout_truncated = stdout_future.result()
        stderr, stderr_truncated = stderr_future.result()
    if stdout_truncated or stderr_truncated:
        raise ScanLimitExceededError(
            f"Git command output exceeded the {max_output_bytes} byte limit"
        )
    return GitCommandResult(returncode=returncode, stdout=stdout, stderr=stderr)


def validate_repository_scope(repository: Path, max_output_bytes: int) -> Path:
    """Reject Git metadata or object databases that escape the selected root."""

    root = repository.resolve(strict=True)
    result = run_git_bounded(
        root,
        ("rev-parse", "--absolute-git-dir"),
        max_output_bytes=min(max_output_bytes, 64 * 1024),
    )
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise CorruptArtifactError(
            f"Git repository validation failed: {message or 'unknown error'}"
        )
    try:
        raw_gitdir = result.stdout.decode("utf-8", errors="strict").strip()
        gitdir = Path(raw_gitdir).resolve(strict=True)
        gitdir.relative_to(root)
    except (OSError, UnicodeError, ValueError) as exc:
        raise UnsafeArtifactError(
            "Git metadata resolves outside the selected repository root"
        ) from exc
    objects = _resolve_git_path(root, "objects", max_output_bytes)
    try:
        objects.relative_to(root)
    except ValueError as exc:
        raise UnsafeArtifactError(
            "Git object database resolves outside the selected repository root"
        ) from exc
    _validate_alternates(objects, root, max_output_bytes)
    return root


def _resolve_git_path(repository: Path, name: str, max_output_bytes: int) -> Path:
    result = run_git_bounded(
        repository,
        ("rev-parse", "--git-path", name),
        max_output_bytes=min(max_output_bytes, 64 * 1024),
    )
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise CorruptArtifactError(
            f"Unable to resolve Git {name} path: {message or 'unknown error'}"
        )
    try:
        raw_path = result.stdout.decode("utf-8", errors="strict").strip()
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = repository / candidate
        return candidate.resolve(strict=True)
    except (OSError, UnicodeError) as exc:
        raise CorruptArtifactError(f"Git {name} path is missing or invalid") from exc


def _validate_alternates(objects: Path, root: Path, max_output_bytes: int) -> None:
    pending = [objects]
    visited: set[Path] = set()
    byte_limit = min(max_output_bytes, 1024 * 1024)
    while pending:
        database = pending.pop()
        if database in visited:
            continue
        visited.add(database)
        if len(visited) > _MAX_ALTERNATE_DATABASES:
            raise ScanLimitExceededError(
                f"Git alternate object database count exceeds {_MAX_ALTERNATE_DATABASES}"
            )
        alternates_file = database / "info" / "alternates"
        if not alternates_file.exists():
            continue
        try:
            resolved_file = alternates_file.resolve(strict=True)
        except OSError as exc:
            raise CorruptArtifactError("Unable to resolve Git alternates file") from exc
        try:
            resolved_file.relative_to(root)
        except ValueError as exc:
            raise UnsafeArtifactError(
                "Git alternates file resolves outside the selected repository root"
            ) from exc
        try:
            if not resolved_file.is_file():
                raise CorruptArtifactError("Git alternates path is not a regular file")
            with resolved_file.open("rb") as handle:
                data = handle.read(byte_limit + 1)
            if len(data) > byte_limit:
                raise ScanLimitExceededError(
                    f"Git alternates file exceeds the {byte_limit} byte safety limit"
                )
            lines = data.splitlines()
        except (CorruptArtifactError, ScanLimitExceededError):
            raise
        except OSError as exc:
            raise CorruptArtifactError("Unable to inspect Git alternate object databases") from exc
        for raw_line in lines:
            if not raw_line:
                continue
            line = os.fsdecode(raw_line)
            candidate = Path(line)
            if not candidate.is_absolute():
                candidate = database / candidate
            try:
                alternate = candidate.resolve(strict=True)
                alternate.relative_to(root)
            except (OSError, ValueError) as exc:
                raise UnsafeArtifactError(
                    "Git alternate object database resolves outside the selected repository root"
                ) from exc
            pending.append(alternate)


def _read_bounded(stream: IO[bytes], limit: int) -> tuple[bytes, bool]:
    output = bytearray()
    truncated = False
    while chunk := stream.read(64 * 1024):
        remaining = limit - len(output)
        if remaining > 0:
            output.extend(chunk[:remaining])
        if len(chunk) > remaining:
            truncated = True
    return bytes(output), truncated
