"""Operating-system confinement for plugin worker processes.

The capability broker in :mod:`trueai.plugins.broker` is a contract, and
:mod:`trueai.plugins.guards` enforces it against ordinary Python. Neither stops
native code, ``ctypes``, or a plugin that restores the functions the guards
replaced. This module asks the kernel instead.

Three things make that awkward, and pretending otherwise is how a security
feature becomes a security claim:

* **The mechanisms are not equivalent.** Linux can drop into a network namespace
  and install a syscall filter after the process has started. Windows cannot
  re-restrict a running process's token, so its confinement must be chosen when
  the worker is *spawned*. macOS has a sandbox, and it has been deprecated for
  years.
* **Some of them can be unavailable at runtime.** Unprivileged user namespaces
  are disabled on some distributions; seccomp can be blocked by a container
  policy. Availability is a property of the machine, not of the code.
* **None of them covers everything.** Every backend reports what it did *not*
  enforce, and that list is not a footnote.

:class:`ConfinementLevel` exists because of the second point. ``BEST_EFFORT``
applies what the platform offers and records the gaps. ``REQUIRED`` refuses to
run a plugin at all when confinement is unavailable, which is the only posture
that can honestly be called enforcement: silently degrading to "we tried" is
indistinguishable, from the report, from having succeeded.
"""

from __future__ import annotations

import ctypes
import os
import platform
import sys
from enum import StrEnum

from trueai.core.models import FrozenModel
from trueai.plugins.broker import BrokerGrants
from trueai.plugins.manifest import PluginCapability


class ConfinementLevel(StrEnum):
    """How much the host insists on kernel-level confinement."""

    #: Do not attempt OS confinement. The Python guards still apply.
    NONE = "none"
    #: Apply what this platform offers and record what it does not cover.
    BEST_EFFORT = "best_effort"
    #: Refuse to run a plugin when confinement is unavailable. The only posture
    #: that can be called enforcement without qualification.
    REQUIRED = "required"


class ConfinementUnavailableError(RuntimeError):
    """Raised when ``REQUIRED`` confinement cannot be established."""


class ConfinementReport(FrozenModel):
    """What confinement was actually established, and what it leaves open."""

    mechanism: str
    applied: bool
    #: Controls that were established, one line each.
    established: tuple[str, ...] = ()
    #: Controls this mechanism does not provide. Never empty for a real backend:
    #: a confinement claiming to cover everything is describing something else.
    not_enforced: tuple[str, ...] = ()
    #: Why confinement could not be applied, when it could not.
    reason: str | None = None

    def summary(self) -> str:
        """Return one line naming the mechanism and its state."""

        if not self.applied:
            return f"{self.mechanism}: not applied ({self.reason or 'unavailable'})"
        return f"{self.mechanism}: applied ({len(self.established)} controls)"


class PlatformConfinement(FrozenModel):
    """What this machine can offer, decided by probing rather than by platform name."""

    platform: str
    mechanism: str
    available: bool
    #: Whether the mechanism must be selected when the process is created, rather
    #: than applied by the process to itself. Windows tokens work this way.
    spawn_time_only: bool = False
    reason: str | None = None


_LINUX_SYSCALLS: dict[str, dict[str, int]] = {
    # Only the architectures whose syscall numbers are pinned here get a filter.
    # Guessing numbers for an unlisted architecture would install a filter that
    # denies the wrong calls, which is worse than installing none.
    "x86_64": {
        "socket": 41,
        "connect": 42,
        "accept": 43,
        "sendto": 44,
        "recvfrom": 45,
        "bind": 49,
        "listen": 50,
        "socketpair": 53,
        "fork": 57,
        "vfork": 58,
        "execve": 59,
        "ptrace": 101,
        "execveat": 322,
    },
    "aarch64": {
        "ptrace": 117,
        "socket": 198,
        "socketpair": 199,
        "bind": 200,
        "listen": 201,
        "accept": 202,
        "connect": 203,
        "sendto": 206,
        "recvfrom": 207,
        "execve": 221,
        "execveat": 281,
    },
}

_AUDIT_ARCH = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}

_NETWORK_SYSCALLS = ("socket", "connect", "accept", "sendto", "recvfrom", "bind", "listen")
# Only the syscalls that start a *different* program. fork and vfork are absent
# because glibc has routed os.fork() through clone for years, and clone is shared
# with threading: filtering it stops the interpreter rather than the plugin.
# Denying fork by number would have looked like a control and been none, which is
# worse than the honest gap recorded in `not_enforced`.
_EXEC_SYSCALLS = ("execve", "execveat")

_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ALLOW = 0x7FFF0000

_CLONE_NEWUSER = 0x10000000
_CLONE_NEWNET = 0x40000000

# BPF instruction classes and modes, spelled out because the numeric literals
# alone would make the filter unreviewable.
_BPF_LD = 0x00
_BPF_W = 0x00
_BPF_ABS = 0x20
_BPF_JMP = 0x05
_BPF_JEQ = 0x10
_BPF_K = 0x00
_BPF_RET = 0x06


class _SockFilter(ctypes.Structure):
    _fields_ = (
        ("code", ctypes.c_uint16),
        ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8),
        ("k", ctypes.c_uint32),
    )


class _SockFprog(ctypes.Structure):
    _fields_ = (
        ("len", ctypes.c_uint16),
        ("filter", ctypes.POINTER(_SockFilter)),
    )


def describe_platform() -> PlatformConfinement:
    """Return what confinement this machine offers, without applying any."""

    machine = platform.machine().lower()
    if sys.platform.startswith("linux"):
        if machine not in _LINUX_SYSCALLS:
            return PlatformConfinement(
                platform="linux",
                mechanism="seccomp+namespaces",
                available=False,
                reason=(
                    f"Syscall numbers are not pinned for {machine!r}; installing a filter "
                    "against guessed numbers would deny the wrong calls."
                ),
            )
        return PlatformConfinement(platform="linux", mechanism="seccomp+namespaces", available=True)
    if sys.platform == "darwin":
        return PlatformConfinement(
            platform="darwin",
            mechanism="sandbox_init",
            available=_darwin_sandbox_available(),
            reason=(
                None
                if _darwin_sandbox_available()
                else "libsandbox does not expose sandbox_init on this system."
            ),
        )
    if os.name == "nt":
        return PlatformConfinement(
            platform="windows",
            mechanism="restricted-token",
            available=True,
            spawn_time_only=True,
        )
    return PlatformConfinement(
        platform=sys.platform,
        mechanism="none",
        available=False,
        reason=f"No confinement backend for {sys.platform!r}.",
    )


def _darwin_sandbox_available() -> bool:
    """Return whether libsandbox exposes sandbox_init on this machine."""

    try:
        library = ctypes.CDLL("/usr/lib/libsandbox.1.dylib", use_errno=True)
    except OSError:
        return False
    return hasattr(library, "sandbox_init")


def apply_confinement(
    grants: BrokerGrants,
    level: ConfinementLevel = ConfinementLevel.BEST_EFFORT,
) -> ConfinementReport:
    """Confine the current process to what the grants allow.

    Called by the worker before the plugin is imported, because import time is
    when a hostile plugin acts. On Windows this is a no-op that says so: the
    restriction there belongs to process creation, and a process cannot re-restrict
    its own token.
    """

    if level == ConfinementLevel.NONE:
        return ConfinementReport(
            mechanism="none",
            applied=False,
            reason="The host did not request operating-system confinement.",
            not_enforced=("Everything. Only the Python guards apply.",),
        )

    available = describe_platform()
    if not available.available or available.spawn_time_only:
        reason = available.reason or (
            f"{available.mechanism} must be selected when the process is created, "
            "not applied afterwards."
        )
        if level == ConfinementLevel.REQUIRED:
            raise ConfinementUnavailableError(reason)
        return ConfinementReport(
            mechanism=available.mechanism,
            applied=False,
            reason=reason,
            not_enforced=("Kernel-level confinement was not established.",),
        )

    if available.platform == "linux":
        return _apply_linux(grants, level)
    if available.platform == "darwin":
        return _apply_darwin(grants, level)
    raise ConfinementUnavailableError(f"No self-confinement backend for {available.platform}")


# -- Linux ---------------------------------------------------------------------------


def _apply_linux(grants: BrokerGrants, level: ConfinementLevel) -> ConfinementReport:
    """Drop privileges, isolate the network, and filter syscalls.

    Order matters. ``no_new_privs`` must be set before a seccomp filter can be
    installed unprivileged, and the namespace unshare has to happen before the
    filter denies the syscalls that would perform it.
    """

    capabilities = grants.capabilities()
    established: list[str] = []
    not_enforced: list[str] = [
        "Filesystem access. Confining reads and writes needs a mount namespace, "
        "which needs privileges a scanner should not hold. The broker and the "
        "Python guards remain the filesystem boundary.",
        "Memory and CPU. Those are the resource limits, applied separately.",
        "Forking a copy of the worker itself. os.fork() goes through clone, which "
        "threading also uses, so filtering it would break the interpreter. Running "
        "a different program is blocked; duplicating this one is not.",
    ]

    libc = ctypes.CDLL(None, use_errno=True)

    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        message = f"prctl(PR_SET_NO_NEW_PRIVS) failed: {os.strerror(ctypes.get_errno())}"
        if level == ConfinementLevel.REQUIRED:
            raise ConfinementUnavailableError(message)
        return ConfinementReport(
            mechanism="seccomp+namespaces",
            applied=False,
            reason=message,
            not_enforced=tuple(not_enforced),
        )
    established.append("no_new_privs: a child can never gain privileges through setuid.")

    if PluginCapability.NETWORK not in capabilities:
        # An empty network namespace is a stronger statement than filtering the
        # socket syscalls: there is no route to filter against.
        if libc.unshare(_CLONE_NEWUSER | _CLONE_NEWNET) == 0:
            established.append("network namespace: the process has no network interfaces.")
        else:
            detail = os.strerror(ctypes.get_errno())
            if level == ConfinementLevel.REQUIRED:
                raise ConfinementUnavailableError(
                    f"unshare(CLONE_NEWUSER|CLONE_NEWNET) failed: {detail}. Unprivileged user "
                    "namespaces may be disabled on this system."
                )
            not_enforced.append(
                f"Network namespace isolation: unshare failed ({detail}). The seccomp filter "
                "below still denies the socket syscalls."
            )

    denied: list[str] = ["ptrace"]
    if PluginCapability.NETWORK not in capabilities:
        denied.extend(_NETWORK_SYSCALLS)
    if PluginCapability.RUN_SUBPROCESS not in capabilities:
        denied.extend(_EXEC_SYSCALLS)

    try:
        _install_seccomp_filter(libc, denied)
    except OSError as exc:
        if level == ConfinementLevel.REQUIRED:
            raise ConfinementUnavailableError(f"seccomp filter rejected: {exc}") from exc
        not_enforced.append(f"Syscall filtering: seccomp was rejected ({exc}).")
    else:
        established.append(
            "seccomp filter: "
            + ", ".join(sorted(set(denied)))
            + " kill the process rather than returning an error."
        )

    return ConfinementReport(
        mechanism="seccomp+namespaces",
        applied=True,
        established=tuple(established),
        not_enforced=tuple(not_enforced),
    )


def _install_seccomp_filter(libc: ctypes.CDLL, denied: list[str]) -> None:
    """Install a BPF filter that kills the process on any denied syscall.

    Killing rather than returning ``EPERM`` is deliberate: a plugin that is
    refused a syscall and continues can retry through another spelling, and a
    dead worker is a diagnostic the host already knows how to report.
    """

    machine = platform.machine().lower()
    table = _LINUX_SYSCALLS[machine]
    numbers = sorted({table[name] for name in denied if name in table})
    if not numbers:
        return

    instructions: list[_SockFilter] = [
        # A filter written for one architecture must not run under another: the
        # same number is a different syscall.
        _SockFilter(code=_BPF_LD | _BPF_W | _BPF_ABS, jt=0, jf=0, k=4),
        _SockFilter(code=_BPF_JMP | _BPF_JEQ | _BPF_K, jt=1, jf=0, k=_AUDIT_ARCH[machine]),
        _SockFilter(code=_BPF_RET | _BPF_K, jt=0, jf=0, k=_SECCOMP_RET_KILL_PROCESS),
        _SockFilter(code=_BPF_LD | _BPF_W | _BPF_ABS, jt=0, jf=0, k=0),
    ]
    total = len(numbers)
    for index, number in enumerate(numbers):
        # Jump forward over the remaining comparisons and the ALLOW, landing on
        # the KILL that terminates the list.
        instructions.append(
            _SockFilter(code=_BPF_JMP | _BPF_JEQ | _BPF_K, jt=total - index, jf=0, k=number)
        )
    instructions.append(_SockFilter(code=_BPF_RET | _BPF_K, jt=0, jf=0, k=_SECCOMP_RET_ALLOW))
    instructions.append(
        _SockFilter(code=_BPF_RET | _BPF_K, jt=0, jf=0, k=_SECCOMP_RET_KILL_PROCESS)
    )

    program = (_SockFilter * len(instructions))(*instructions)
    fprog = _SockFprog(len=len(instructions), filter=program)
    if libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(fprog), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))


# -- macOS ---------------------------------------------------------------------------


def _sandbox_profile(grants: BrokerGrants) -> str:
    """Build an SBPL profile from the grants.

    Deny by default, then re-allow exactly what a grant covers. The scratch
    directory is the only writable location, and it is named rather than implied.
    """

    capabilities = grants.capabilities()
    lines = [
        "(version 1)",
        "(deny default)",
        # A worker that cannot read the interpreter and its own modules cannot
        # start, so process-level essentials are allowed explicitly.
        "(allow process-info-pidinfo)",
        "(allow sysctl-read)",
        "(allow file-read* file-read-metadata)",
    ]
    if grants.temporary_output is not None:
        directory = str(grants.temporary_output.directory).replace('"', '\\"')
        lines.append(f'(allow file-write* (subpath "{directory}"))')
    if PluginCapability.NETWORK in capabilities:
        lines.append("(allow network-outbound)")
    if PluginCapability.RUN_SUBPROCESS in capabilities:
        lines.append("(allow process-exec)")
    return "\n".join(lines)


def _apply_darwin(grants: BrokerGrants, level: ConfinementLevel) -> ConfinementReport:
    """Apply an SBPL sandbox profile to this process.

    ``sandbox_init`` has been deprecated by Apple for years while remaining the
    only interface a process has to sandbox itself. That is stated here rather
    than discovered later.
    """

    not_enforced = [
        "Read access is allowed broadly: a worker that cannot read the interpreter "
        "and its dependencies cannot start, and enumerating them is not something "
        "a scanner can do reliably.",
        "sandbox_init is deprecated by Apple. It works today and may not tomorrow.",
    ]
    try:
        library = ctypes.CDLL("/usr/lib/libsandbox.1.dylib", use_errno=True)
        error = ctypes.c_char_p()
        library.sandbox_init.argtypes = [
            ctypes.c_char_p,
            ctypes.c_uint64,
            ctypes.POINTER(ctypes.c_char_p),
        ]
        result = library.sandbox_init(
            _sandbox_profile(grants).encode("utf-8"), 0, ctypes.byref(error)
        )
    except OSError as exc:
        if level == ConfinementLevel.REQUIRED:
            raise ConfinementUnavailableError(f"libsandbox unavailable: {exc}") from exc
        return ConfinementReport(
            mechanism="sandbox_init",
            applied=False,
            reason=f"libsandbox unavailable: {exc}",
            not_enforced=tuple(not_enforced),
        )
    if result != 0:
        detail = error.value.decode("utf-8", "replace") if error.value else "unknown error"
        if level == ConfinementLevel.REQUIRED:
            raise ConfinementUnavailableError(f"sandbox_init refused the profile: {detail}")
        return ConfinementReport(
            mechanism="sandbox_init",
            applied=False,
            reason=f"sandbox_init refused the profile: {detail}",
            not_enforced=tuple(not_enforced),
        )
    return ConfinementReport(
        mechanism="sandbox_init",
        applied=True,
        established=(
            "deny by default, with writes limited to the scratch grant and network "
            "and exec allowed only where granted.",
        ),
        not_enforced=tuple(not_enforced),
    )


# -- Windows -------------------------------------------------------------------------


def windows_creation_flags(level: ConfinementLevel) -> int:
    """Return the process-creation flags a confined Windows worker is spawned with.

    ``CREATE_BREAKAWAY_FROM_JOB`` is deliberately *not* among them: the worker is
    assigned to a Job Object for its CPU and memory limits, and letting it escape
    that job would trade one control for another.
    """

    if level == ConfinementLevel.NONE:
        return 0
    # CREATE_NO_WINDOW keeps a plugin from putting a console in front of a user,
    # and CREATE_NEW_PROCESS_GROUP keeps Ctrl-C in the host's hands.
    return 0x08000000 | 0x00000200


def windows_confinement_report(level: ConfinementLevel) -> ConfinementReport:
    """Describe what the Windows spawn-time restriction achieves.

    A restricted token strips privileges and denies the administrators group. It
    is not AppContainer: there is no filesystem or network isolation, and saying
    so is the difference between a control and a claim.
    """

    if level == ConfinementLevel.NONE:
        return ConfinementReport(
            mechanism="none",
            applied=False,
            reason="The host did not request operating-system confinement.",
            not_enforced=("Everything. Only the Python guards apply.",),
        )
    return ConfinementReport(
        mechanism="restricted-token",
        applied=True,
        established=(
            "The worker runs with a token whose privileges are dropped and whose "
            "administrators membership is deny-only.",
            "The worker is assigned to a Job Object carrying its CPU and memory limits.",
        ),
        not_enforced=(
            "Filesystem isolation. A restricted token does not stop a plugin reading "
            "or writing anything the user can. AppContainer would; it needs a profile, "
            "a SID, and ACLs on the artifact and the scratch directory, and it is not "
            "implemented.",
            "Network isolation. Windows Firewall rules per AppContainer SID would be the "
            "mechanism, and they are not implemented either.",
            "Syscall filtering. There is no Windows equivalent of seccomp available to an "
            "unprivileged process.",
        ),
    )


__all__ = [
    "ConfinementLevel",
    "ConfinementReport",
    "ConfinementUnavailableError",
    "PlatformConfinement",
    "apply_confinement",
    "describe_platform",
    "windows_confinement_report",
    "windows_creation_flags",
]
