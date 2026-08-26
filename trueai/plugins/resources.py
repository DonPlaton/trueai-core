"""Operating-system resource limits for untrusted plugin helper processes.

Every limit here is installed on its own and reported on its own. Bundling them
made one platform's refusal of one limit look like a total failure to confine,
which is how macOS ended up rejecting every plugin at discovery rather than
running them with a CPU ceiling and no address-space ceiling.

That distinction is the whole design: a control that is in place, a control the
platform refuses, and a helper that could not be limited at all are three
different states, and collapsing them either lies about the protection or throws
away protection that was available.
"""

from __future__ import annotations

import importlib
import os
import sys
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class PluginResourceLimits(BaseModel):
    """Portable resource budget passed to plugin helper processes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_memory_bytes: int = Field(default=512 * 1024 * 1024, ge=64 * 1024 * 1024)
    max_cpu_seconds: int = Field(default=30, ge=1, le=3600)
    #: Whether a helper process must refuse to start when the platform declines
    #: one of these. Off by default, because a platform that cannot cap address
    #: space -- macOS declines `RLIMIT_AS` outright -- would otherwise be a
    #: platform with no plugins rather than one with a reported gap. Kept here
    #: rather than derived from `ConfinementLevel` because they are different
    #: mechanisms: the Linux confinement report says so itself, listing "memory
    #: and CPU" among the things it does not cover.
    required: bool = False


class ResourceLimitReport(BaseModel):
    """Which limits a helper process actually got, and which it did not.

    Shaped like :class:`~trueai.plugins.confinement.ConfinementReport` on purpose:
    the two answer the same question about different mechanisms, and an operator
    reading a scan report should not have to learn two vocabularies for "this
    control is not in place here".
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    mechanism: str
    #: Limits the kernel accepted, one line each.
    established: tuple[str, ...] = ()
    #: Limits this platform refused, with the reason it gave. An empty tuple
    #: means every requested limit is in place, not that none were requested.
    not_enforced: tuple[str, ...] = ()

    @property
    def memory_capped(self) -> bool:
        """Whether an address-space ceiling is actually in force."""

        return any(line.startswith("address space") for line in self.established)


class ResourceLimitsUnavailableError(RuntimeError):
    """Raised when a helper process could not be limited at all."""


_WINDOWS_JOB_HANDLE: Any | None = None


def apply_process_resource_limits(limits: PluginResourceLimits) -> ResourceLimitReport:
    """Install CPU and memory limits before importing a plugin.

    Returns what was installed. Raises :class:`ResourceLimitsUnavailableError`
    when nothing could be, or when ``limits.required`` is set and the platform
    refused any of it.
    """

    report = _apply_windows_job_limits(limits) if os.name == "nt" else _apply_posix_limits(limits)
    if limits.required and report.not_enforced:
        raise ResourceLimitsUnavailableError(
            "These process limits could not be installed: " + "; ".join(report.not_enforced)
        )
    return report


#: Requested limit, the ``resource`` constant, and how to say it in a report.
_POSIX_LIMITS = (
    ("address space", "RLIMIT_AS", "max_memory_bytes", "bytes"),
    ("CPU time", "RLIMIT_CPU", "max_cpu_seconds", "seconds"),
)


def _apply_posix_limits(limits: PluginResourceLimits) -> ResourceLimitReport:
    """Install each rlimit independently and report which of them held."""

    try:
        resource: Any = importlib.import_module("resource")
    except ImportError as exc:  # pragma: no cover - POSIX always has it
        raise ResourceLimitsUnavailableError(
            f"The `resource` module is unavailable, so no limit could be installed: {exc}"
        ) from exc

    established: list[str] = []
    not_enforced: list[str] = []
    for label, constant, attribute, unit in _POSIX_LIMITS:
        key = getattr(resource, constant, None)
        if key is None:  # pragma: no cover - both exist on every supported POSIX
            not_enforced.append(f"{label}: this platform has no {constant}")
            continue
        requested = int(getattr(limits, attribute))
        try:
            _, hard = resource.getrlimit(key)
            # Never ask for more than the hard limit already allows. Raising one
            # needs privilege the worker must not have, and asking is itself an
            # EINVAL -- a second, unrelated way to earn the error that made macOS
            # look like it could not limit anything.
            target = requested if hard == resource.RLIM_INFINITY else min(requested, hard)
            # The hard limit comes down with the soft one, so a plugin cannot
            # raise it back: lowering a hard limit is always permitted, raising
            # it is not.
            resource.setrlimit(key, (target, target))
        except (OSError, ValueError) as exc:
            not_enforced.append(f"{label}: setrlimit({constant}) was refused ({exc})")
        else:
            established.append(f"{label} capped at {target} {unit}")

    if not established:
        raise ResourceLimitsUnavailableError(
            "No process limit could be installed: " + "; ".join(not_enforced)
        )
    return ResourceLimitReport(
        mechanism="posix-rlimit",
        established=tuple(established),
        not_enforced=tuple(not_enforced),
    )


def _apply_windows_job_limits(limits: PluginResourceLimits) -> ResourceLimitReport:
    """Assign the worker to a Job Object with hard per-process limits."""

    if sys.platform != "win32":  # pragma: no cover - the caller checks first
        # Not defensive programming: this is the check that lets a type checker
        # narrow the body below to Windows. `os.name == "nt"` at the call site
        # reads the same to a human and means nothing to mypy, which is how the
        # Windows branch went unchecked on one platform and misread on the other.
        raise ResourceLimitsUnavailableError("Windows job objects need Windows.")

    import ctypes
    from ctypes import wintypes

    class _IOCounters(ctypes.Structure):
        _fields_ = [
            ("read_ops", ctypes.c_ulonglong),
            ("write_ops", ctypes.c_ulonglong),
            ("other_ops", ctypes.c_ulonglong),
            ("read_bytes", ctypes.c_ulonglong),
            ("write_bytes", ctypes.c_ulonglong),
            ("other_bytes", ctypes.c_ulonglong),
        ]

    class _BasicLimits(ctypes.Structure):
        _fields_ = [
            ("process_time", ctypes.c_longlong),
            ("job_time", ctypes.c_longlong),
            ("flags", wintypes.DWORD),
            ("minimum_working_set", ctypes.c_size_t),
            ("maximum_working_set", ctypes.c_size_t),
            ("active_processes", wintypes.DWORD),
            ("affinity", ctypes.c_size_t),
            ("priority", wintypes.DWORD),
            ("scheduling", wintypes.DWORD),
        ]

    class _ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("basic", _BasicLimits),
            ("io", _IOCounters),
            ("process_memory", ctypes.c_size_t),
            ("job_memory", ctypes.c_size_t),
            ("peak_process_memory", ctypes.c_size_t),
            ("peak_job_memory", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise ResourceLimitsUnavailableError(
            f"CreateJobObject failed: {ctypes.WinError(ctypes.get_last_error())}"
        )
    information = _ExtendedLimits()
    information.basic.process_time = limits.max_cpu_seconds * 10_000_000
    information.basic.flags = 0x00000002 | 0x00000100 | 0x00002000
    information.process_memory = limits.max_memory_bytes
    try:
        if not kernel32.SetInformationJobObject(
            job, 9, ctypes.byref(information), ctypes.sizeof(information)
        ):
            raise ResourceLimitsUnavailableError(
                f"SetInformationJobObject failed: {ctypes.WinError(ctypes.get_last_error())}"
            )
        if not kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess()):
            raise ResourceLimitsUnavailableError(
                f"AssignProcessToJobObject failed: {ctypes.WinError(ctypes.get_last_error())}"
            )
    except Exception:
        kernel32.CloseHandle(job)
        raise

    global _WINDOWS_JOB_HANDLE
    _WINDOWS_JOB_HANDLE = job
    return ResourceLimitReport(
        mechanism="windows-job-object",
        established=(
            f"address space capped at {limits.max_memory_bytes} bytes",
            f"CPU time capped at {limits.max_cpu_seconds} seconds",
        ),
    )
