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

The worker also gets its own window station and desktop. That is not decoration.
A child created with ``lpDesktop = NULL`` inherits the creator's station and must
pass an access check against it using its own token; a token with
``BUILTIN\\Administrators`` deny-only fails that check wherever the station's DACL
grants through the administrators group, and Windows kills the process during
DLL initialization with ``STATUS_DLL_INIT_FAILED`` -- before Python starts, with
no output, which is indistinguishable from a plugin that crashed. It happens in
exactly the non-interactive sessions a service or a scheduled task runs in. A
private station also removes the clipboard, window enumeration, and window
messages to the operator's desktop from what a plugin can reach.
"""

from __future__ import annotations

import sys

if sys.platform != "win32":  # pragma: no cover - the module is Windows-only
    raise ImportError(
        "trueai.plugins.windows_token requires Windows; the host imports it only there."
    )

# ``WinDLL`` is a ``CDLL`` subclass. Handles below are annotated as ``CDLL``
# because an annotation is resolved even inside the branch the guard above makes
# unreachable, and ``ctypes.WinDLL`` does not exist in POSIX typeshed. The values
# are still WinDLL, built by the two loaders; only the static type is wider.
import ctypes
import os
import secrets
import threading
from ctypes import wintypes
from pathlib import Path
from typing import NamedTuple

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

_TOKEN_USER = 1
_TOKEN_GROUPS = 2
_TOKEN_PRIVILEGES = 3
_SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010
_DESKTOP_ALL_ACCESS = 0x000F01FF
_WINSTA_ALL_ACCESS = 0x0000037F
_SDDL_REVISION_1 = 1
_UOI_NAME = 2

#: Windows kills a process during DLL initialisation with this status when a
#: statically linked DLL's ``DllMain`` returns FALSE. For ``user32``/``gdi32``
#: that means it could not attach to a window station and desktop, which is what
#: happens to a restricted token on a station whose DACL grants through a group
#: the token holds deny-only. The process never ran a single instruction, so this
#: is a spawn failure and not the worker's exit code.
STATUS_DLL_INIT_FAILED = 0xC0000142

_STARTF_USESHOWWINDOW = 0x00000001
_SW_HIDE = 0


class RestrictedSpawnError(RuntimeError):
    """Raised when a worker could not be started under a restricted token."""


class _SecurityAttributes(ctypes.Structure):
    _fields_ = (
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", wintypes.BOOL),
    )


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


class _TokenUserInformation(ctypes.Structure):
    _fields_ = (("User", _SidAndAttributes),)


def _kernel32() -> ctypes.CDLL:
    return ctypes.WinDLL("kernel32", use_last_error=True)


def _advapi32() -> ctypes.CDLL:
    return ctypes.WinDLL("advapi32", use_last_error=True)


def _user32() -> ctypes.CDLL:
    return ctypes.WinDLL("user32", use_last_error=True)


def _declare(kernel32: ctypes.CDLL, advapi32: ctypes.CDLL) -> None:
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
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.LPWSTR),
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL


def _declare_station(user32: ctypes.CDLL, kernel32: ctypes.CDLL) -> None:
    """Pin the window-station and desktop signatures."""

    user32.GetProcessWindowStation.argtypes = []
    user32.GetProcessWindowStation.restype = wintypes.HANDLE
    user32.SetProcessWindowStation.argtypes = [wintypes.HANDLE]
    user32.SetProcessWindowStation.restype = wintypes.BOOL
    user32.CreateWindowStationW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    user32.CreateWindowStationW.restype = wintypes.HANDLE
    user32.CloseWindowStation.argtypes = [wintypes.HANDLE]
    user32.CloseWindowStation.restype = wintypes.BOOL
    user32.GetUserObjectInformationW.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    user32.GetUserObjectInformationW.restype = wintypes.BOOL
    user32.CreateDesktopW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    user32.CreateDesktopW.restype = wintypes.HANDLE
    user32.CloseDesktop.argtypes = [wintypes.HANDLE]
    user32.CloseDesktop.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p


def _administrators_sid(advapi32: ctypes.CDLL) -> ctypes.c_void_p:
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


def _token_user_sid(advapi32: ctypes.CDLL, token: wintypes.HANDLE) -> str:
    """Return the token's user SID in string form, for use in an SDDL DACL.

    The user SID rather than a group: the private station should be reachable by
    exactly the account the worker runs as, and by nothing else. Groups are what
    made the shared station reachable through ``BUILTIN\\Administrators`` in the
    first place, which is the access the restricted token deliberately gives up.
    """

    size = wintypes.DWORD()
    advapi32.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(size))
    if not size.value:
        raise RestrictedSpawnError(
            f"GetTokenInformation(TokenUser) failed: {ctypes.WinError(ctypes.get_last_error())}"
        )
    buffer = ctypes.create_string_buffer(size.value)
    if not advapi32.GetTokenInformation(token, _TOKEN_USER, buffer, size.value, ctypes.byref(size)):
        raise RestrictedSpawnError(
            f"GetTokenInformation(TokenUser) failed: {ctypes.WinError(ctypes.get_last_error())}"
        )
    information = ctypes.cast(buffer, ctypes.POINTER(_TokenUserInformation)).contents
    text = wintypes.LPWSTR()
    if not advapi32.ConvertSidToStringSidW(information.User.Sid, ctypes.byref(text)):
        raise RestrictedSpawnError(
            f"ConvertSidToStringSid failed: {ctypes.WinError(ctypes.get_last_error())}"
        )
    try:
        return str(text.value)
    finally:
        _kernel32().LocalFree(text)


def _security_attributes(
    advapi32: ctypes.CDLL, sid: str
) -> tuple[_SecurityAttributes, ctypes.c_void_p]:
    """Build a SECURITY_ATTRIBUTES granting only ``sid`` full access.

    ``D:`` with a single ACE and no inheritance: nothing else on the machine gets
    a handle to the desktop, including another session of the same account.

    The descriptor is returned alongside because Windows allocated it and Windows
    has to free it. The kernel copies it into the object being created, so the
    caller frees it once that call returns.
    """

    descriptor = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        f"D:(A;;GA;;;{sid})", _SDDL_REVISION_1, ctypes.byref(descriptor), None
    ):
        raise RestrictedSpawnError(
            "ConvertStringSecurityDescriptorToSecurityDescriptor failed: "
            f"{ctypes.WinError(ctypes.get_last_error())}"
        )
    attributes = _SecurityAttributes()
    attributes.nLength = ctypes.sizeof(_SecurityAttributes)
    attributes.lpSecurityDescriptor = descriptor
    attributes.bInheritHandle = False
    return attributes, descriptor


#: One alternate desktop per host process, created on first use. Per worker would
#: leak a kernel object per artifact scanned, and the desktop is not what
#: separates two workers from each other -- the token and the guards are.
_DESKTOP_LOCK = threading.Lock()
_DESKTOP: tuple[str | None, str | None] = (None, None)
#: Held for the life of the process. A desktop with no open handle and nothing
#: running on it is destroyed, which would take the next worker's with it.
_DESKTOP_HANDLES: list[wintypes.HANDLE] = []


def _current_station_name(user32: ctypes.CDLL) -> str:
    """Return the name of the window station this process is attached to."""

    handle = user32.GetProcessWindowStation()
    if not handle:
        raise RestrictedSpawnError(
            f"GetProcessWindowStation failed: {ctypes.WinError(ctypes.get_last_error())}"
        )
    size = wintypes.DWORD()
    user32.GetUserObjectInformationW(handle, _UOI_NAME, None, 0, ctypes.byref(size))
    buffer = ctypes.create_unicode_buffer(max(size.value // 2 + 1, 64))
    if not user32.GetUserObjectInformationW(
        handle, _UOI_NAME, buffer, ctypes.sizeof(buffer), ctypes.byref(size)
    ):
        raise RestrictedSpawnError(
            f"GetUserObjectInformation failed: {ctypes.WinError(ctypes.get_last_error())}"
        )
    return buffer.value


def _private_desktop(advapi32: ctypes.CDLL, token: wintypes.HANDLE) -> str:
    """Return ``station\\desktop`` for an isolated desktop, creating it once.

    Two rungs, strongest first.

    A window station of the worker's own is the real isolation: the child has to
    pass an access check against the station with its own token, and a station
    this process created carries a DACL naming the account rather than a group
    the restricted token holds deny-only. That is the failure a hosted runner
    hits -- the token is refused the station, and Windows destroys the process
    during DLL initialisation before it runs an instruction. Creating a station
    needs rights an ordinary interactive account does not have, so it is
    attempted and not required.

    Failing that, a desktop on the current station. An unprivileged process may
    create one, and it removes window enumeration, window messages, and hooks
    between the worker and everything the operator is running -- but it cannot
    help a token that is refused the station itself.

    Raises :class:`RestrictedSpawnError` when neither can be created, so the
    caller decides whether to fall back or refuse. Falling back silently would
    put the worker on the operator's own desktop while the report still said the
    plugin was confined.
    """

    global _DESKTOP
    with _DESKTOP_LOCK:
        name, error = _DESKTOP
        if name is not None:
            return name
        if error is not None:
            raise RestrictedSpawnError(error)
        user32, kernel32 = _user32(), _kernel32()
        _declare_station(user32, kernel32)
        try:
            attributes, descriptor = _security_attributes(
                advapi32, _token_user_sid(advapi32, token)
            )
        except RestrictedSpawnError as exc:
            _DESKTOP = (None, str(exc))
            raise
        suffix = f"{os.getpid()}-{secrets.token_hex(4)}"
        resolved: str | RestrictedSpawnError
        try:
            own = _own_station_and_desktop(user32, attributes, suffix)
            resolved = own if own is not None else _alternate_desktop(user32, attributes, suffix)
        finally:
            kernel32.LocalFree(descriptor)
        if isinstance(resolved, RestrictedSpawnError):
            _DESKTOP = (None, str(resolved))
            raise resolved
        _DESKTOP = (resolved, None)
        return resolved


def _own_station_and_desktop(
    user32: ctypes.CDLL, attributes: _SecurityAttributes, suffix: str
) -> str | None:
    """Create a window station and a desktop on it, or return None if refused.

    ``CreateDesktop`` always creates on the *calling process's* station, so the
    host stands on the new one for the length of one call and is put back in the
    ``finally``. The module lock is what keeps another thread from observing the
    host on the wrong station in between.
    """

    station_name = f"trueai-{suffix}"
    station = user32.CreateWindowStationW(
        station_name, 0, _WINSTA_ALL_ACCESS, ctypes.byref(attributes)
    )
    if not station:
        # Ordinary rather than exceptional: an interactive account is refused
        # this, on every access mask, with and without a security descriptor.
        return None
    previous = user32.GetProcessWindowStation()
    if not user32.SetProcessWindowStation(station):
        user32.CloseWindowStation(station)
        return None
    try:
        desktop = user32.CreateDesktopW(
            "Default", None, None, 0, _DESKTOP_ALL_ACCESS, ctypes.byref(attributes)
        )
    finally:
        user32.SetProcessWindowStation(previous)
    if not desktop:
        user32.CloseWindowStation(station)
        return None
    # Both handles are held for the life of the process: a station or desktop
    # with no open handle and nothing running on it is destroyed by the kernel,
    # which would take the next worker's with it.
    _DESKTOP_HANDLES.extend([station, desktop])
    return f"{station_name}\\Default"


def _alternate_desktop(
    user32: ctypes.CDLL, attributes: _SecurityAttributes, suffix: str
) -> str | RestrictedSpawnError:
    """Create a desktop on the station this process is already attached to."""

    try:
        station = _current_station_name(user32)
    except RestrictedSpawnError as exc:
        return exc
    desktop_name = f"trueai-{suffix}"
    desktop = user32.CreateDesktopW(
        desktop_name, None, None, 0, _DESKTOP_ALL_ACCESS, ctypes.byref(attributes)
    )
    if not desktop:
        return RestrictedSpawnError(
            f"CreateDesktop failed: {ctypes.WinError(ctypes.get_last_error())}"
        )
    _DESKTOP_HANDLES.append(desktop)
    return f"{station}\\{desktop_name}"


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
    isolate_desktop: bool = True,
) -> int:
    """Run one worker under a restricted token and return its exit code.

    Raises :class:`TimeoutError` when the deadline passes, after terminating the
    process: a worker that outlives its deadline is a hang the host reports, not
    something to wait longer for.

    ``isolate_desktop`` puts the worker on a window station of its own. Leave it
    on. Turning it off is only for a caller that has decided a shared station is
    acceptable and has said so somewhere an operator can read.
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
    startup.dwFlags = _STARTF_USESTDHANDLES | _STARTF_USESHOWWINDOW
    startup.wShowWindow = _SW_HIDE
    startup.hStdInput = None
    startup.hStdOutput = None
    startup.hStdError = None
    if isolate_desktop:
        try:
            startup.lpDesktop = _private_desktop(advapi32, restricted)
        except RestrictedSpawnError:
            kernel32.CloseHandle(restricted)
            raise

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
        if int(code.value) == STATUS_DLL_INIT_FAILED:
            # Reported as a spawn failure rather than returned as an exit code.
            # Windows destroyed the process during initialisation, so nothing the
            # worker was asked to do happened, and calling that "the plugin
            # crashed" blames the plugin for the host being unable to confine it.
            raise RestrictedSpawnError(
                "Windows refused to start the worker under a restricted token "
                f"(STATUS_DLL_INIT_FAILED, {STATUS_DLL_INIT_FAILED:#x}). The token could not "
                "attach to a window station or desktop; this happens in non-interactive "
                "sessions, which is how a service or a scheduled task runs."
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


class TokenRestriction(NamedTuple):
    """What this process's own token and desktop actually are, measured.

    Every field is read from the running process. Nothing here is inferred from
    the fact that a restricted token was requested, because the interesting case
    is precisely the one where it was requested and something else happened.
    """

    privileges: int
    administrators_present: bool
    administrators_deny_only: bool
    in_job_object: bool
    desktop: str | None


def describe_restriction() -> TokenRestriction:
    """Inspect the current process's token, job membership, and desktop."""

    kernel32, advapi32 = _kernel32(), _advapi32()
    _declare(kernel32, advapi32)
    user32 = _user32()
    _declare_station(user32, kernel32)
    kernel32.IsProcessInJob.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.BOOL),
    ]
    kernel32.IsProcessInJob.restype = wintypes.BOOL
    user32.GetThreadDesktop.argtypes = [wintypes.DWORD]
    user32.GetThreadDesktop.restype = wintypes.HANDLE
    kernel32.GetCurrentThreadId.argtypes = []
    kernel32.GetCurrentThreadId.restype = wintypes.DWORD

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)
    ):
        raise RestrictedSpawnError(
            f"OpenProcessToken failed: {ctypes.WinError(ctypes.get_last_error())}"
        )
    try:
        privileges = _count_privileges(advapi32, token)
        present, deny_only = _administrators_state(advapi32, token)
    finally:
        kernel32.CloseHandle(token)

    in_job = wintypes.BOOL()
    if not kernel32.IsProcessInJob(kernel32.GetCurrentProcess(), None, ctypes.byref(in_job)):
        in_job.value = False

    desktop: str | None = None
    handle = user32.GetThreadDesktop(kernel32.GetCurrentThreadId())
    if handle:
        size = wintypes.DWORD()
        user32.GetUserObjectInformationW(handle, _UOI_NAME, None, 0, ctypes.byref(size))
        buffer = ctypes.create_unicode_buffer(max(size.value // 2 + 1, 64))
        if user32.GetUserObjectInformationW(
            handle, _UOI_NAME, buffer, ctypes.sizeof(buffer), ctypes.byref(size)
        ):
            desktop = buffer.value

    return TokenRestriction(
        privileges=privileges,
        administrators_present=present,
        administrators_deny_only=deny_only,
        in_job_object=bool(in_job.value),
        desktop=desktop,
    )


def _count_privileges(advapi32: ctypes.CDLL, token: wintypes.HANDLE) -> int:
    """Return how many privileges the token still holds.

    ``DISABLE_MAX_PRIVILEGE`` removes every one, so zero is the observable
    signature of the restriction. An ordinary interactive token has several.
    """

    size = wintypes.DWORD()
    advapi32.GetTokenInformation(token, _TOKEN_PRIVILEGES, None, 0, ctypes.byref(size))
    if not size.value:
        return 0
    buffer = ctypes.create_string_buffer(size.value)
    if not advapi32.GetTokenInformation(
        token, _TOKEN_PRIVILEGES, buffer, size.value, ctypes.byref(size)
    ):
        raise RestrictedSpawnError(
            f"GetTokenInformation(TokenPrivileges) failed: "
            f"{ctypes.WinError(ctypes.get_last_error())}"
        )
    return int(ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value)


def _administrators_state(advapi32: ctypes.CDLL, token: wintypes.HANDLE) -> tuple[bool, bool]:
    """Return whether administrators is in the token, and whether it is deny-only.

    Both matter and they are different answers. On an account that is not an
    administrator the group is absent, and reporting that as "deny-only" would
    claim a restriction that was never applied to anything.
    """

    size = wintypes.DWORD()
    advapi32.GetTokenInformation(token, _TOKEN_GROUPS, None, 0, ctypes.byref(size))
    if not size.value:
        return False, False
    buffer = ctypes.create_string_buffer(size.value)
    if not advapi32.GetTokenInformation(
        token, _TOKEN_GROUPS, buffer, size.value, ctypes.byref(size)
    ):
        raise RestrictedSpawnError(
            f"GetTokenInformation(TokenGroups) failed: {ctypes.WinError(ctypes.get_last_error())}"
        )
    advapi32.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    advapi32.EqualSid.restype = wintypes.BOOL
    count = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value
    offset = ctypes.sizeof(ctypes.c_void_p)  # DWORD plus padding to pointer alignment
    entries = ctypes.cast(
        ctypes.byref(buffer, offset), ctypes.POINTER(_SidAndAttributes * count)
    ).contents
    administrators = _administrators_sid(advapi32)
    try:
        for entry in entries:
            if advapi32.EqualSid(entry.Sid, administrators):
                return True, bool(entry.Attributes & _SE_GROUP_USE_FOR_DENY_ONLY)
    finally:
        advapi32.FreeSid(administrators)
    return False, False


#: Answered once per host process. The probe starts a real process, so repeating
#: it per plugin would cost an interpreter launch per artifact scanned.
_SPAWN_PROBE_LOCK = threading.Lock()
_SPAWN_PROBE: tuple[bool, str] | None = None


def restricted_spawning_available() -> tuple[bool, str]:
    """Return whether a *worker* can actually start under a restricted token.

    Creating the token is the easy half and was all this used to check. The half
    that fails is the child passing an access check against a window station
    using that token: Windows destroys it during DLL initialisation with
    ``STATUS_DLL_INIT_FAILED``, before Python runs, with no output and no exit
    code of its own. Reported by the host as a crashed plugin, which blames the
    plugin for something the host could not do.

    So this starts one -- an interpreter that exits immediately -- and caches the
    answer. A host asking for ``required`` confinement finds out before the scan
    rather than once per plugin.
    """

    global _SPAWN_PROBE
    if os.name != "nt":
        return False, "Restricted-token spawning is a Windows mechanism."
    with _SPAWN_PROBE_LOCK:
        if _SPAWN_PROBE is not None:
            return _SPAWN_PROBE
        _SPAWN_PROBE = _probe_restricted_spawn()
        return _SPAWN_PROBE


def _probe_restricted_spawn() -> tuple[bool, str]:
    """Start and wait for one trivial worker under the real restriction."""

    import sys

    try:
        code = spawn_restricted(
            [sys.executable, "-I", "-c", "raise SystemExit(0)"],
            environment=dict(os.environ),
            timeout=60.0,
        )
    except RestrictedSpawnError as exc:
        return False, str(exc)
    except (OSError, TimeoutError) as exc:
        return False, f"The restricted-token probe did not finish: {exc}"
    if code != 0:
        return False, f"A worker under a restricted token exited with {code}."
    return True, "A worker started, ran, and exited under a restricted token."


__all__ = [
    "STATUS_DLL_INIT_FAILED",
    "RestrictedSpawnError",
    "TokenRestriction",
    "describe_restriction",
    "restricted_spawning_available",
    "spawn_restricted",
]
