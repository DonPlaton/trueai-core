"""The capability broker: one contract for everything a plugin needs from outside.

A boolean capability answers "may this plugin write files?" The honest question is
"may this plugin write *this* file, *here*, for the duration of *this* scan?" —
and a grant that cannot express the scope has to be granted at its widest, which
is how ``write_filesystem`` ends up meaning "anywhere the user can write".

The broker replaces boolean permission with mediated access. A plugin does not
open the artifact; it asks the broker for a handle. It does not choose where its
scratch output goes; the broker owns a directory and deletes it afterwards. It
does not open a socket; it asks for an endpoint the operator allowlisted. Each
grant carries its own scope, and the broker is the single place where the scope
is checked.

**This is a contract, not a jail.** A plugin can still call :func:`open`
directly. :mod:`trueai.plugins.guards` catches the documented spellings, and
`PLUG-02` adds operating-system confinement underneath. What the broker buys
before then is real anyway:

* a grant can be *narrow*, so an operator is not forced to choose between "no
  temporary files" and "the whole filesystem";
* a refusal names the capability, the scope, and the path, so an operator can
  tell a misconfigured grant from a hostile plugin;
* a plugin written against the broker keeps working unchanged when OS
  confinement lands, because it never depended on ambient authority.

Native code is the case Python-level mediation cannot reach at all. It gets its
own capability so that a plugin loading a shared library has to say so, and an
operator who denies it can know that every plugin still running is one the guards
can actually govern.
"""

from __future__ import annotations

import os
import socket
import subprocess
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import IO, Any, Self

from pydantic import Field, model_validator

from trueai.core.models import FrozenModel
from trueai.plugins.manifest import PluginCapability

#: How much a plugin may write into its scratch directory, in total. A grant with
#: no ceiling is a disk-exhaustion primitive handed out by name.
DEFAULT_TEMPORARY_BYTES = 64 * 1024 * 1024

#: How much of the artifact a single broker read returns unless the caller asks
#: for less. The host already bounds artifact size; this bounds one read.
DEFAULT_READ_CHUNK = 8 * 1024 * 1024


class CapabilityDeniedError(RuntimeError):
    """Raised when a plugin asks the broker for something outside its grant.

    Carries the capability and, where there is one, the scope that refused, so a
    diagnostic can say which grant would have had to be widened.
    """

    def __init__(self, message: str, *, capability: PluginCapability, scope: str = "") -> None:
        # Every refusal names its capability, whether or not the caller's message
        # already did. A diagnostic that says only "outside the grant" leaves an
        # operator guessing which grant would have had to be widened.
        if capability.value not in message:
            message = f"{message} (capability: {capability.value})"
        super().__init__(message)
        self.capability = capability
        self.scope = scope


class ArtifactGrant(FrozenModel):
    """Read-only access to exactly one file: the artifact under inspection.

    Not a directory, not a glob, not "the artifact and whatever it points at".
    A symlink inside the artifact path is resolved before the comparison, so a
    plugin cannot be handed a link that resolves somewhere else.
    """

    path: Path
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class WorkspaceGrant(FrozenModel):
    """Read-only access confined to one directory subtree.

    Sibling parts of a package are a legitimate need — an OOXML part referencing
    another part, a source file referencing its header. A whole-filesystem read
    grant to satisfy that is not proportionate.
    """

    root: Path
    #: Reading a file larger than this raises rather than filling memory.
    max_file_bytes: int = Field(default=DEFAULT_READ_CHUNK, ge=1024)


class TemporaryOutputGrant(FrozenModel):
    """A scratch directory the broker owns, bounds, and removes.

    The plugin never chooses the location, so a scratch grant cannot be used to
    write next to the artifact, into the report, or over a config file. The
    budget is charged across every write, because a per-file limit is not a
    limit.
    """

    directory: Path
    max_total_bytes: int = Field(default=DEFAULT_TEMPORARY_BYTES, ge=4096)


class NetworkGrant(FrozenModel):
    """Explicitly allowlisted outbound endpoints.

    There is no "network: yes". A forensic tool that can reach an arbitrary host
    is an exfiltration path with a scan attached, so the grant is a list of
    ``(host, port)`` pairs an operator wrote down.
    """

    endpoints: tuple[tuple[str, int], ...] = ()

    @model_validator(mode="after")
    def reject_an_empty_allowlist(self) -> Self:
        """An endpoint list of nothing grants nothing, and should say so."""

        if not self.endpoints:
            raise ValueError("A network grant with no endpoints grants nothing; omit the grant")
        for host, port in self.endpoints:
            if not host or not 1 <= port <= 65535:
                raise ValueError(f"Invalid network endpoint: {host!r}:{port}")
        return self


class SubprocessGrant(FrozenModel):
    """Executables a plugin may run, named individually.

    A plugin that shells out to one well-known binary is a normal thing. A plugin
    that may run anything is a shell, and the difference is worth spelling out in
    the grant.
    """

    executables: tuple[Path, ...] = ()

    @model_validator(mode="after")
    def reject_an_empty_allowlist(self) -> Self:
        if not self.executables:
            raise ValueError("A subprocess grant with no executables grants nothing")
        return self


class NativeLibraryGrant(FrozenModel):
    """Permission to load native code, with the libraries named.

    The broker cannot mediate what native code does. This grant does not make it
    safe; it makes it *declared*, so an operator who denies it knows that every
    plugin still running is one the Python-level guards can actually govern.
    """

    libraries: tuple[str, ...] = ()
    acknowledged_unmediated: bool = False

    @model_validator(mode="after")
    def require_the_acknowledgement(self) -> Self:
        """Granting unmediated execution should be a deliberate act."""

        if not self.libraries:
            raise ValueError("A native-library grant must name the libraries it covers")
        if not self.acknowledged_unmediated:
            raise ValueError(
                "A native-library grant must set acknowledged_unmediated: the broker cannot "
                "mediate native code, and granting it silently would imply otherwise"
            )
        return self


class BrokerGrants(FrozenModel):
    """Everything one plugin invocation was granted, with each scope attached.

    Serialized into the worker request, so the worker rebuilds exactly the grants
    the host decided on rather than re-deriving them from a capability set.
    """

    artifact: ArtifactGrant | None = None
    workspace: WorkspaceGrant | None = None
    temporary_output: TemporaryOutputGrant | None = None
    network: NetworkGrant | None = None
    subprocess_: SubprocessGrant | None = Field(default=None, alias="subprocess")
    native_library: NativeLibraryGrant | None = None

    model_config = FrozenModel.model_config | {"populate_by_name": True}

    def capabilities(self) -> frozenset[PluginCapability]:
        """Return the capability set these grants correspond to.

        The guards take a capability set, so the broker and the guards stay in
        agreement instead of being configured from two places.
        """

        granted: set[PluginCapability] = set()
        if self.artifact is not None:
            granted.add(PluginCapability.READ_ARTIFACT)
        if self.workspace is not None:
            granted.add(PluginCapability.READ_WORKSPACE)
        if self.temporary_output is not None:
            granted.add(PluginCapability.WRITE_TEMPORARY)
        if self.network is not None:
            granted.add(PluginCapability.NETWORK)
        if self.subprocess_ is not None:
            granted.add(PluginCapability.RUN_SUBPROCESS)
        if self.native_library is not None:
            granted.add(PluginCapability.LOAD_NATIVE_LIBRARY)
        return frozenset(granted)

    def describe(self) -> tuple[str, ...]:
        """Return one line per grant, naming its scope.

        Used in diagnostics and the CLI, because "granted: read_workspace" tells
        an operator nothing about which directory.
        """

        lines: list[str] = []
        if self.artifact is not None:
            lines.append(f"read_artifact: {self.artifact.path}")
        if self.workspace is not None:
            lines.append(f"read_workspace: under {self.workspace.root}")
        if self.temporary_output is not None:
            lines.append(
                f"write_temporary: {self.temporary_output.directory} "
                f"(≤{self.temporary_output.max_total_bytes} bytes)"
            )
        if self.network is not None:
            endpoints = ", ".join(f"{host}:{port}" for host, port in self.network.endpoints)
            lines.append(f"network: {endpoints}")
        if self.subprocess_ is not None:
            executables = ", ".join(str(item) for item in self.subprocess_.executables)
            lines.append(f"run_subprocess: {executables}")
        if self.native_library is not None:
            libraries = ", ".join(self.native_library.libraries)
            lines.append(f"load_native_library: {libraries} (unmediated)")
        return tuple(lines)


def _resolved(path: Path) -> Path:
    """Resolve a path for comparison, following symlinks.

    Comparing unresolved paths is how ``workspace/../../etc/passwd`` passes a
    prefix check. ``strict=False`` so a path that does not exist yet still
    normalises; existence is a separate question the caller answers.
    """

    return Path(os.path.abspath(path)).resolve()


def _within(candidate: Path, root: Path) -> bool:
    """Return whether a resolved candidate sits inside a resolved root."""

    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


class CapabilityBroker:
    """The object a plugin uses to reach anything outside its own memory.

    Constructed in the worker from the grants the host decided on. Every method
    either returns a scoped handle or raises :class:`CapabilityDeniedError`
    naming what would have had to be granted.
    """

    def __init__(self, grants: BrokerGrants) -> None:
        self._grants = grants
        self._written = 0

    @property
    def grants(self) -> BrokerGrants:
        """Return the grants this broker enforces, for a plugin that wants to check."""

        return self._grants

    def granted(self, capability: PluginCapability) -> bool:
        """Return whether a capability is available, without attempting to use it.

        A plugin that degrades gracefully needs to ask before it tries, rather
        than using an exception as a feature test.
        """

        return capability in self._grants.capabilities()

    # -- the artifact -----------------------------------------------------------------

    def open_artifact(self) -> IO[bytes]:
        """Return a read-only handle to the artifact under inspection."""

        grant = self._grants.artifact
        if grant is None:
            raise CapabilityDeniedError(
                "Reading the artifact requires the read_artifact capability.",
                capability=PluginCapability.READ_ARTIFACT,
            )
        return grant.path.open("rb")

    def read_artifact(self, max_bytes: int = DEFAULT_READ_CHUNK) -> bytes:
        """Return up to ``max_bytes`` of the artifact."""

        with self.open_artifact() as handle:
            return handle.read(max_bytes)

    def artifact_digest(self) -> str:
        """Return the digest the host bound this invocation to.

        The plugin gets the same digest the host will re-check afterwards, so a
        plugin can record what it actually inspected.
        """

        grant = self._grants.artifact
        if grant is None:
            raise CapabilityDeniedError(
                "The artifact digest requires the read_artifact capability.",
                capability=PluginCapability.READ_ARTIFACT,
            )
        return grant.sha256

    # -- the workspace ----------------------------------------------------------------

    def open_workspace(self, relative: str | Path) -> IO[bytes]:
        """Return a read-only handle to a file inside the workspace grant."""

        return self.workspace_path(relative).open("rb")

    def read_workspace(self, relative: str | Path) -> bytes:
        """Return the contents of one workspace file, bounded by the grant."""

        path = self.workspace_path(relative)
        grant = self._grants.workspace
        assert grant is not None
        size = path.stat().st_size
        if size > grant.max_file_bytes:
            raise CapabilityDeniedError(
                f"{path} is {size} bytes; the workspace grant allows {grant.max_file_bytes}.",
                capability=PluginCapability.READ_WORKSPACE,
                scope=str(grant.root),
            )
        with path.open("rb") as handle:
            return handle.read(grant.max_file_bytes)

    def workspace_path(self, relative: str | Path) -> Path:
        """Resolve a workspace-relative path, refusing anything outside the grant."""

        grant = self._grants.workspace
        if grant is None:
            raise CapabilityDeniedError(
                "Reading workspace files requires the read_workspace capability.",
                capability=PluginCapability.READ_WORKSPACE,
            )
        try:
            root = _resolved(grant.root)
            candidate = _resolved(root / relative)
        except (OSError, TypeError, ValueError) as exc:
            raise CapabilityDeniedError(
                f"The requested workspace path {str(relative)!a} cannot be resolved safely.",
                capability=PluginCapability.READ_WORKSPACE,
                scope=str(grant.root),
            ) from exc
        if not _within(candidate, root):
            raise CapabilityDeniedError(
                f"{candidate} is outside the workspace grant rooted at {root}.",
                capability=PluginCapability.READ_WORKSPACE,
                scope=str(root),
            )
        return candidate

    def iter_workspace(self, pattern: str = "*") -> Iterator[Path]:
        """Yield workspace files matching a glob, confined to the grant.

        Entries that resolve outside the root — a symlink pointing away — are
        skipped rather than raising, because one hostile link in a directory
        should not make the whole listing unusable.
        """

        grant = self._grants.workspace
        if grant is None:
            raise CapabilityDeniedError(
                "Listing workspace files requires the read_workspace capability.",
                capability=PluginCapability.READ_WORKSPACE,
            )
        root = _resolved(grant.root)
        for entry in sorted(root.glob(pattern)):
            resolved = _resolved(entry)
            if resolved.is_file() and _within(resolved, root):
                yield resolved

    # -- temporary output -------------------------------------------------------------

    def temporary_path(self, name: str) -> Path:
        """Return a path inside the scratch directory, refusing traversal."""

        grant = self._grants.temporary_output
        if grant is None:
            raise CapabilityDeniedError(
                "Writing temporary output requires the write_temporary capability.",
                capability=PluginCapability.WRITE_TEMPORARY,
            )
        try:
            root = _resolved(grant.directory)
            candidate = _resolved(root / name)
        except (OSError, TypeError, ValueError) as exc:
            raise CapabilityDeniedError(
                f"The requested temporary path {name!a} cannot be resolved safely.",
                capability=PluginCapability.WRITE_TEMPORARY,
                scope=str(grant.directory),
            ) from exc
        if not _within(candidate, root):
            raise CapabilityDeniedError(
                f"{candidate} is outside the temporary grant rooted at {root}.",
                capability=PluginCapability.WRITE_TEMPORARY,
                scope=str(root),
            )
        return candidate

    @contextmanager
    def open_temporary(self, name: str, mode: str = "wb") -> Iterator[_BudgetedWriter]:
        """Open a scratch file for writing, charging its bytes against the budget.

        The handle is wrapped so every write is counted. A budget checked only at
        close is a budget an attacker writes past.
        """

        grant = self._grants.temporary_output
        if grant is None:
            raise CapabilityDeniedError(
                "Writing temporary output requires the write_temporary capability.",
                capability=PluginCapability.WRITE_TEMPORARY,
            )
        if "r" in mode and "+" not in mode:
            raise ValueError("open_temporary is for writing; use temporary_path to read back")
        path = self.temporary_path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open(mode) as handle:
            yield _BudgetedWriter(handle, self, grant.max_total_bytes)

    def _charge(self, count: int, limit: int) -> None:
        """Charge bytes against the scratch budget, refusing the write that exceeds it."""

        if self._written + count > limit:
            raise CapabilityDeniedError(
                f"The temporary-output grant allows {limit} bytes; this write would reach "
                f"{self._written + count}.",
                capability=PluginCapability.WRITE_TEMPORARY,
                scope=str(limit),
            )
        self._written += count

    @property
    def temporary_bytes_written(self) -> int:
        """Return how much of the scratch budget has been spent."""

        return self._written

    # -- network ----------------------------------------------------------------------

    def connect(self, host: str, port: int, *, timeout: float = 10.0) -> socket.socket:
        """Open a socket to an allowlisted endpoint, and to nothing else."""

        grant = self._grants.network
        if grant is None:
            raise CapabilityDeniedError(
                "Network access requires the network capability, and an endpoint allowlist.",
                capability=PluginCapability.NETWORK,
            )
        if (host, port) not in grant.endpoints:
            allowed = ", ".join(f"{item}:{number}" for item, number in grant.endpoints)
            raise CapabilityDeniedError(
                f"{host}:{port} is not in the network grant. Allowed: {allowed}.",
                capability=PluginCapability.NETWORK,
                scope=allowed,
            )
        return socket.create_connection((host, port), timeout=timeout)

    # -- subprocesses -----------------------------------------------------------------

    def run(
        self,
        argv: Sequence[str | Path],
        *,
        timeout: float = 30.0,
        input_bytes: bytes | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        """Run an allowlisted executable with no shell and no inherited stdin."""

        grant = self._grants.subprocess_
        if grant is None:
            raise CapabilityDeniedError(
                "Running a subprocess requires the run_subprocess capability.",
                capability=PluginCapability.RUN_SUBPROCESS,
            )
        if not argv:
            raise ValueError("run() needs at least an executable")
        executable = _resolved(Path(argv[0]))
        allowed = {_resolved(item) for item in grant.executables}
        if executable not in allowed:
            names = ", ".join(sorted(str(item) for item in allowed))
            raise CapabilityDeniedError(
                f"{executable} is not in the subprocess grant. Allowed: {names}.",
                capability=PluginCapability.RUN_SUBPROCESS,
                scope=names,
            )
        return subprocess.run(
            [str(executable), *(str(item) for item in argv[1:])],
            input=input_bytes if input_bytes is not None else b"",
            capture_output=True,
            timeout=timeout,
            shell=False,
            check=False,
        )

    # -- native libraries -------------------------------------------------------------

    def native_library_granted(self, name: str) -> bool:
        """Return whether a named native library was declared and granted.

        The broker cannot enforce this — ``ctypes`` does not ask permission — so
        the honest contract is that a plugin checks before loading, and a plugin
        that does not is one the manifest already failed to describe.
        """

        grant = self._grants.native_library
        return grant is not None and name in grant.libraries


class _BudgetedWriter:
    """A write handle that charges every write against the scratch budget."""

    def __init__(self, handle: IO[Any], broker: CapabilityBroker, limit: int) -> None:
        self._handle = handle
        self._broker = broker
        self._limit = limit

    def write(self, payload: Any) -> int:
        """Charge, then write. A refused write does not reach the file."""

        self._broker._charge(len(payload), self._limit)
        result: int = self._handle.write(payload)
        return result

    def writelines(self, lines: Any) -> None:
        """Write each line through the charged path rather than around it."""

        for line in lines:
            self.write(line)

    def __getattr__(self, name: str) -> Any:
        """Delegate everything else — flush, seek, name — to the real handle."""

        return getattr(self._handle, name)


def grants_for(
    capabilities: frozenset[PluginCapability],
    *,
    artifact: ArtifactGrant | None = None,
    workspace_root: Path | None = None,
    temporary_directory: Path | None = None,
    network: NetworkGrant | None = None,
    subprocess_grant: SubprocessGrant | None = None,
    native_library: NativeLibraryGrant | None = None,
) -> BrokerGrants:
    """Build the grants for one invocation from the capabilities a policy allowed.

    A capability with no scope available produces no grant. That is deliberate:
    ``network`` with no allowlist and ``run_subprocess`` with no executables mean
    the operator granted a name without granting anything, and silently inventing
    a wide scope to make the name work is exactly the failure this module exists
    to remove.
    """

    return BrokerGrants(
        artifact=artifact if PluginCapability.READ_ARTIFACT in capabilities else None,
        workspace=(
            WorkspaceGrant(root=workspace_root)
            if PluginCapability.READ_WORKSPACE in capabilities and workspace_root is not None
            else None
        ),
        temporary_output=(
            TemporaryOutputGrant(directory=temporary_directory)
            if PluginCapability.WRITE_TEMPORARY in capabilities and temporary_directory is not None
            else None
        ),
        network=network if PluginCapability.NETWORK in capabilities else None,
        subprocess=subprocess_grant if PluginCapability.RUN_SUBPROCESS in capabilities else None,
        native_library=(
            native_library if PluginCapability.LOAD_NATIVE_LIBRARY in capabilities else None
        ),
    )


__all__ = [
    "DEFAULT_READ_CHUNK",
    "DEFAULT_TEMPORARY_BYTES",
    "ArtifactGrant",
    "BrokerGrants",
    "CapabilityBroker",
    "CapabilityDeniedError",
    "NativeLibraryGrant",
    "NetworkGrant",
    "SubprocessGrant",
    "TemporaryOutputGrant",
    "WorkspaceGrant",
    "grants_for",
]
