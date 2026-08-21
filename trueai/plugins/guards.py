"""Best-effort in-worker restrictions matching a plugin's granted capabilities.

These guards are defence in depth, not a sandbox. They stop an ordinary Python
plugin from opening a socket, spawning a process, or writing to disk when the
host did not grant that capability, and they turn an attempt to do so into a
visible failure rather than a silent success. They do not stop native code,
ctypes, or a plugin that deliberately restores the replaced functions.

The boundary that holds regardless of these guards is the worker process itself:
a plugin cannot corrupt the host's memory, cannot outlive its timeout, and cannot
return a finding the host did not independently re-derive and validate.
"""

from __future__ import annotations

import builtins
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
        _guard_open()


def _denied(operation: str, capability: PluginCapability) -> Callable[..., Any]:
    def guard(*args: object, **kwargs: object) -> Any:
        del args, kwargs
        raise CapabilityDeniedError(
            f"{operation} requires the {capability.value} capability, which the host did not grant."
        )

    return guard


def _deny(
    targets: tuple[tuple[Any, tuple[str, ...]], ...],
    capability: PluginCapability,
) -> None:
    for module, names in targets:
        label = getattr(module, "__name__", type(module).__name__)
        for name in names:
            if hasattr(module, name):
                setattr(module, name, _denied(f"{label}.{name}", capability))


def _guard_open() -> None:
    capability = PluginCapability.WRITE_FILESYSTEM
    original_open = builtins.open

    def guarded_open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        if _WRITE_MODE_CHARACTERS & set(mode):
            raise CapabilityDeniedError(
                f"Opening {file!r} for writing requires the {capability.value} capability, "
                "which the host did not grant."
            )
        return original_open(file, mode, *args, **kwargs)

    builtins.open = guarded_open
