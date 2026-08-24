"""Spawn a plugin worker under a restricted Windows token.

Windows has no equivalent of ``seccomp``: a process cannot narrow its own token
once it is running. The restriction has to be chosen at ``CreateProcessAsUser``
time, which is why this lives apart from :mod:`trueai.plugins.confinement` and is
called by the host rather than by the worker.

What a restricted token buys is narrow and worth stating exactly. Privileges are
dropped, and the administrators group is turned deny-only, so a plugin cannot use
a privilege the operator happens to hold. It is **not** AppContainer: there is no
filesystem isolation and no network isolation, and a restricted token does not
stop a plugin reading anything the user can read.

``subprocess`` cannot pass a token, so the process is created through the Win32
API directly. That is affordable here only because the protocol is already
file-based: the host writes a request file and reads a response file, and the
worker's stdout and stderr are discarded. There are no pipes to plumb.
"""

from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from pathlib import Path

_TOKEN_DUPLICATE = 0x0002
_TOKEN_QUERY = 0x0008
_TOKEN_ASSIGN_PRIMARY = 0x0001
_TOKEN_ADJUST_DEFAULT = 0x0080
_TOKEN_ADJUST_SESSIONID = 0x0100

_DISABLE_MAX_PRIVILEGE = 0x1

_CREATE_NO_WINDOW = 0x08000000
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_CREATE_UNICODE_ENVIRONMENT = 0x00000400

_STARTF_USESTDHANDLES = 0x00000100

_WAIT_TIMEOUT = 0x00000102
_WAIT_FAILED = 0xFFFFFFFF
_INFINITE = 0xFFFFFFFF

_SECURITY_BUILTIN_DOMAIN_RID = 0x00000020
_DOMAIN_ALIAS_RID_ADMINS = 0x00000220
_SECURITY_NT_AUTHORITY = (0, 0, 0, 0, 0, 5)


class RestrictedSpawnError(RuntimeError):
    """Raised when a worker could not be started under a restricted token."""


class _StartupInfo(ctypes.Structure):
    _fields_ = (
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    )


class _ProcessInformation(ctypes.Structure):
    _fields_ = (
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    )


class _SidIdentifierAuthority(ctypes.Structure):
    _fields_ = (("Value", ctypes.c_byte * 6),)


class _SidAndAttributes(ctypes.Structure):
    _fields_ = (("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD))


def _kernel32() -> ctypes.WinDLL:
    return ctypes.WinDLL("kernel32", use_last_error=True)


def _advapi32() -> ctypes.WinDLL:
    return ctypes.WinDLL("advapi32", use_last_error=True)


def _declare(kernel32: ctypes.WinDLL, advapi32: ctypes.WinDLL) -> None:
    """Pin argument and return types before any call.

    ``GetCurrentProcess`` returns the pseudo-handle ``-1``. Left undeclared,
    ctypes infers an integer type from the value and the next call overflows, so
    every signature used here is stated rather than guessed.
    """

    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateProcess.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL

    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.CreateRestrictedToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.CreateRestrictedToken.restype = wintypes.BOOL
    advapi32.FreeSid.argtypes = [ctypes.c_void_p]
    advapi32.FreeSid.restype = ctypes.c_void_p
    advapi32.CreateProcessAsUserW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(_StartupInfo),
        ctypes.POINTER(_ProcessInformation),
    ]
    advapi32.CreateProcessAsUserW.restype = wintypes.BOOL


def _administrators_sid(advapi32: ctypes.WinDLL) -> ctypes.c_void_p:
    """Return the BUILTIN\\Administrators SID, to be denied in the new token.

    Deny-only is stronger than absent: an absent group can be re-added by a token
    that already holds it, while a deny-only entry stays deny-only.
    """

    advapi32.AllocateAndInitializeSid.restype = wintypes.BOOL
    advapi32.AllocateAndInitializeSid.argtypes = [
        ctypes.POINTER(_SidIdentifierAuthority),
        ctypes.c_byte,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    authority = _SidIdentifierAuthority()
    for index, value in enumerate(_SECURITY_NT_AUTHORITY):
        authority.Value[index] = value
    sid = ctypes.c_void_p()
    ok = advapi32.AllocateAndInitializeSid(
        ctypes.byref(authority),
        2,
        _SECURITY_BUILTIN_DOMAIN_RID,
        _DOMAIN_ALIAS_RID_ADMINS,
        0,
        0,
        0,
        0,
        0,
        0,
        ctypes.byref(sid),
    )
    if not ok:
        raise RestrictedSpawnError(
            f"AllocateAndInitializeSid failed: {ctypes.WinError(ctypes.get_last_error())}"
        )
    return sid


def _environment_block(environment: dict[str, str]) -> ctypes.Array[ctypes.c_wchar]:
    """Build the doubly-null-terminated Unicode environment block CreateProcess wants."""

    entries = "".join(f"{key}={value}\0" for key, value in sorted(environment.items()))
    return ctypes.create_unicode_buffer(entries + "\0")


def spawn_restricted(
    argv: list[str],
    *,
    environment: dict[str, str],
    timeout: float,
    working_directory: Path | None = None,
) -> int:
    """Run one worker under a restricted token and return its exit code.

    Raises :class:`TimeoutError` when the deadline passes, after terminating the
    process: a worker that outlives its deadline is a hang the host reports, not
    something to wait longer for.
    """

    if os.name != "nt":
        raise RestrictedSpawnError("Restricted-token spawning is a Windows mechanism")

    kernel32, advapi32 = _kernel32(), _advapi32()
    _declare(kernel32, advapi32)

    process_token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        _TOKEN_DUPLICATE
        | _TOKEN_QUERY
        | _TOKEN_ASSIGN_PRIMARY
        | _TOKEN_ADJUST_DEFAULT
        | _TOKEN_ADJUST_SESSIONID,
        ctypes.byref(process_token),
    ):
        raise RestrictedSpawnError(
            f"OpenProcessToken failed: {ctypes.WinError(ctypes.get_last_error())}"
        )

    administrators = _administrators_sid(advapi32)
    deny = (_SidAndAttributes * 1)()
    deny[0].Sid = administrators
    deny[0].Attributes = 0

    restricted = wintypes.HANDLE()
    try:
        ok = advapi32.CreateRestrictedToken(
            process_token,
            _DISABLE_MAX_PRIVILEGE,  # every privilege the token holds is removed
            1,
            deny,  # administrators becomes deny-only
            0,
            None,
            0,
            None,
            ctypes.byref(restricted),
        )
        if not ok:
            raise RestrictedSpawnError(
                f"CreateRestrictedToken failed: {ctypes.WinError(ctypes.get_last_error())}"
            )
    finally:
        advapi32.FreeSid(administrators)
        kernel32.CloseHandle(process_token)

    startup = _StartupInfo()
    startup.cb = ctypes.sizeof(_StartupInfo)
    # The protocol is file-based and plugin output is discarded, so the worker is
    # given no standard handles at all rather than the host's.
    startup.dwFlags = _STARTF_USESTDHANDLES
    startup.hStdInput = None
    startup.hStdOutput = None
    startup.hStdError = None

    information = _ProcessInformation()
    command = " ".join(_quote(item) for item in argv)
    block = _environment_block(environment)

    created = advapi32.CreateProcessAsUserW(
        restricted,
        None,
        ctypes.create_unicode_buffer(command),
        None,
        None,
        False,
        _CREATE_NO_WINDOW | _CREATE_NEW_PROCESS_GROUP | _CREATE_UNICODE_ENVIRONMENT,
        block,
        str(working_directory) if working_directory else None,
        ctypes.byref(startup),
        ctypes.byref(information),
    )
    if not created:
        error = ctypes.WinError(ctypes.get_last_error())
        kernel32.CloseHandle(restricted)
        raise RestrictedSpawnError(f"CreateProcessAsUserW failed: {error}")

    try:
        milliseconds = _INFINITE if timeout <= 0 else int(timeout * 1000)
        outcome = kernel32.WaitForSingleObject(information.hProcess, milliseconds)
        if outcome == _WAIT_TIMEOUT:
            kernel32.TerminateProcess(information.hProcess, 1)
            kernel32.WaitForSingleObject(information.hProcess, 5000)
            raise TimeoutError(f"The worker exceeded {timeout:g} seconds")
        if outcome == _WAIT_FAILED:
            raise RestrictedSpawnError(
                f"WaitForSingleObject failed: {ctypes.WinError(ctypes.get_last_error())}"
            )
        code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(information.hProcess, ctypes.byref(code)):
            raise RestrictedSpawnError(
                f"GetExitCodeProcess failed: {ctypes.WinError(ctypes.get_last_error())}"
            )
        return int(code.value)
    finally:
        for handle in (information.hThread, information.hProcess, restricted):
            if handle:
                kernel32.CloseHandle(handle)


def _quote(argument: str) -> str:
    """Quote one command-line argument the way the Windows C runtime parses it."""

    if argument and not any(character in argument for character in ' \t"'):
        return argument
    escaped = argument.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def restricted_spawning_available() -> bool:
    """Return whether a restricted token can actually be created on this machine.

    Probed rather than assumed: creating the token is cheap, and discovering at
    scan time that the mechanism is unavailable would turn a security posture into
    a plugin outage.
    """

    if os.name != "nt":
        return False
    try:
        kernel32, advapi32 = _kernel32(), _advapi32()
        _declare(kernel32, advapi32)
        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            _TOKEN_DUPLICATE | _TOKEN_QUERY | _TOKEN_ASSIGN_PRIMARY,
            ctypes.byref(token),
        ):
            return False
        restricted = wintypes.HANDLE()
        try:
            ok = advapi32.CreateRestrictedToken(
                token, _DISABLE_MAX_PRIVILEGE, 0, None, 0, None, 0, None, ctypes.byref(restricted)
            )
        finally:
            kernel32.CloseHandle(token)
        if ok:
            kernel32.CloseHandle(restricted)
        return bool(ok)
    except OSError:
        return False


__all__ = ["RestrictedSpawnError", "restricted_spawning_available", "spawn_restricted"]
