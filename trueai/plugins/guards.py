"""Best-effort in-worker restrictions matching a plugin's granted capabilities.

These guards are defence in depth, not a sandbox. They stop an ordinary Python
plugin from opening a socket, spawning a process, or writing to disk when the
host did not grant that capability, and they turn an attempt to do so into a
visible failure rather than a silent success. Every documented way to write a
file from Python is covered — ``open``, ``io.open``, ``Path.open``, ``os.open``,
and the ``os``/``shutil``/``Path`` mutators — because guarding one spelling and
leaving the others is not a boundary. They do not stop native code, ctypes, or a
plugin that deliberately restores the replaced functions.

The boundary that holds regardless of these guards is the worker process itself:
a plugin cannot corrupt the host's memory, cannot outlive its timeout, and cannot
return a finding the host did not independently re-derive and validate.
"""

from __future__ import annotations

import builtins
import io
import os
import shutil
import socket
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from trueai.plugins.manifest import PluginCapability


class CapabilityDeniedError(RuntimeError):
    """Raised inside a worker when a plugin attempts an ungranted operation."""


_WRITE_MODE_CHARACTERS = frozenset({"w", "a", "x", "+"})

#: Descriptor flags that request write access. os.open takes flags rather than a
#: mode string, so the same decision is made against these instead.
_WRITE_FLAGS = (
    os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC | getattr(os, "O_EXCL", 0)
)

_NETWORK_TARGETS = ((socket, ("socket", "create_connection", "create_server", "socketpair")),)
_SUBPROCESS_TARGETS = (
    (subprocess, ("Popen", "run", "call", "check_call", "check_output", "getoutput")),
    (os, ("system", "popen", "execv", "execve", "execvp", "spawnv", "posix_spawn", "fork")),
)
_WRITE_TARGETS: tuple[tuple[Any, tuple[str, ...]], ...] = (
    (
        os,
        (
            "remove",
            "unlink",
            "rename",
            "renames",
            "replace",
            "rmdir",
            "mkdir",
            "makedirs",
            "removedirs",
            "truncate",
            "chmod",
            "symlink",
            "link",
        ),
    ),
    (shutil, ("rmtree", "copy", "copy2", "copyfile", "copytree", "move")),
    (
        Path,
        (
            "write_text",
            "write_bytes",
            "unlink",
            "mkdir",
            "rmdir",
            "rename",
            "replace",
            "touch",
            "chmod",
            "symlink_to",
            "hardlink_to",
        ),
    ),
)


def apply_guards(granted: frozenset[PluginCapability]) -> None:
    """Install the guards implied by the capabilities a plugin was not granted."""

    if PluginCapability.NETWORK not in granted:
        _deny(_NETWORK_TARGETS, PluginCapability.NETWORK)
    if PluginCapability.RUN_SUBPROCESS not in granted:
        _deny(_SUBPROCESS_TARGETS, PluginCapability.RUN_SUBPROCESS)
    if PluginCapability.WRITE_FILESYSTEM not in granted:
        _deny(_WRITE_TARGETS, PluginCapability.WRITE_FILESYSTEM)
        _guard_open_functions()


def _denied(operation: str, capability: PluginCapability) -> Callable[..., Any]:
    def guard(*args: object, **kwargs: object) -> Any:
        del args, kwargs
        raise CapabilityDeniedError(
            f"{operation} requires the {capability.value} capability, which the host did not grant."
        )

    return guard


def _install(module: Any, name: str, replacement: Any) -> None:
    """Rebind one stdlib entry point.

    Monkeypatching is the point of this module, so the rebinding is funnelled
    through a single helper instead of scattered attribute assignments.
    """

    setattr(module, name, replacement)


def _deny(
    targets: tuple[tuple[Any, tuple[str, ...]], ...],
    capability: PluginCapability,
) -> None:
    for module, names in targets:
        label = getattr(module, "__name__", type(module).__name__)
        for name in names:
            if hasattr(module, name):
                _install(module, name, _denied(f"{label}.{name}", capability))


def _guard_open_functions() -> None:
    """Allow reads through every open() spelling and deny writes through all of them.

    ``builtins.open``, ``io.open``, and ``Path.open`` are separate references, and
    ``os.open`` takes flags instead of a mode string. Guarding one of them leaves
    the rest as ordinary, fully supported ways to write a file.
    """

    capability = PluginCapability.WRITE_FILESYSTEM

    def deny(target: object) -> None:
        raise CapabilityDeniedError(
            f"Opening {target!r} for writing requires the {capability.value} capability, "
            "which the host did not grant."
        )

    original_builtin_open = builtins.open
    original_io_open = io.open
    original_path_open = Path.open
    original_os_open = os.open

    def guarded_builtin_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if _WRITE_MODE_CHARACTERS & set(mode):
            deny(file)
        return original_builtin_open(file, mode, *args, **kwargs)

    def guarded_io_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if _WRITE_MODE_CHARACTERS & set(mode):
            deny(file)
        return original_io_open(file, mode, *args, **kwargs)

    def guarded_path_open(self: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if _WRITE_MODE_CHARACTERS & set(mode):
            deny(self)
        return original_path_open(self, mode, *args, **kwargs)

    def guarded_os_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if flags & _WRITE_FLAGS:
            deny(path)
        return original_os_open(path, flags, *args, **kwargs)

    for module, name, replacement in (
        (builtins, "open", guarded_builtin_open),
        (io, "open", guarded_io_open),
        (Path, "open", guarded_path_open),
        (os, "open", guarded_os_open),
    ):
        _install(module, name, replacement)
