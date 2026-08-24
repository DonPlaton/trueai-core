"""Operating-system resource limits for untrusted plugin helper processes."""

from __future__ import annotations

import importlib
import os
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class PluginResourceLimits(BaseModel):
    """Portable resource budget passed to plugin helper processes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_memory_bytes: int = Field(default=512 * 1024 * 1024, ge=64 * 1024 * 1024)
    max_cpu_seconds: int = Field(default=30, ge=1, le=3600)


_WINDOWS_JOB_HANDLE: Any | None = None


def apply_process_resource_limits(limits: PluginResourceLimits) -> None:
    """Install hard CPU and memory limits before importing a plugin."""

    if os.name == "nt":
        _apply_windows_job_limits(limits)
    else:
        _apply_posix_limits(limits)


def _apply_posix_limits(limits: PluginResourceLimits) -> None:
    try:
        resource: Any = importlib.import_module("resource")

        resource.setrlimit(
            resource.RLIMIT_AS,
            (limits.max_memory_bytes, limits.max_memory_bytes),
        )
        resource.setrlimit(
            resource.RLIMIT_CPU,
            (limits.max_cpu_seconds, limits.max_cpu_seconds),
        )
    except (ImportError, OSError, ValueError) as exc:
        raise RuntimeError(f"Unable to install POSIX plugin resource limits: {exc}") from exc


def _apply_windows_job_limits(limits: PluginResourceLimits) -> None:
    """Assign the worker to a Job Object with hard per-process limits."""

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
        raise ctypes.WinError(ctypes.get_last_error())
    information = _ExtendedLimits()
    information.basic.process_time = limits.max_cpu_seconds * 10_000_000
    information.basic.flags = 0x00000002 | 0x00000100 | 0x00002000
    information.process_memory = limits.max_memory_bytes
    try:
        if not kernel32.SetInformationJobObject(
            job, 9, ctypes.byref(information), ctypes.sizeof(information)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess()):
            raise ctypes.WinError(ctypes.get_last_error())
    except Exception:
        kernel32.CloseHandle(job)
        raise

    global _WINDOWS_JOB_HANDLE
    _WINDOWS_JOB_HANDLE = job
