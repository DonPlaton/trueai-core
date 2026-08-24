"""Example third-party detectors used to exercise the plugin host.

These stand in for plugins a host would encounter in the wild: a well-behaved
one, one that declares a manifest, one that crashes, one that hangs, one that
tries to forge a finding, and ones that reach for capabilities they were not
granted. They are importable by name so the worker subprocess can load them the
same way it loads a real entry point.
"""

from __future__ import annotations

import os
import time
from typing import Any

from trueai.core.artifact import Artifact
from trueai.core.models import (
    ArtifactType,
    ConfidenceType,
    EvidenceType,
    Finding,
    FindingCategory,
    ProvenanceClass,
    ScanContext,
    Severity,
)
from trueai.detectors.base import BaseDetector
from trueai.plugins.manifest import PluginCapability, PluginManifest, PluginRegistration

TEXT_TYPES = frozenset({ArtifactType.TEXT, ArtifactType.MARKDOWN})


class WellBehavedPlugin(BaseDetector):
    """Reports one deterministic structural observation."""

    id = "example.well-behaved.v1"
    supported_types = TEXT_TYPES
    categories = frozenset({FindingCategory.STRUCTURAL_SIGNAL})

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        return [
            self.finding(
                artifact=artifact,
                category=FindingCategory.STRUCTURAL_SIGNAL,
                confidence=1.0,
                confidence_type=ConfidenceType.DETERMINISTIC,
                severity=Severity.INFO,
                evidence_type=EvidenceType.STRUCTURAL,
                title="Plugin observation",
                description="A third-party detector reported a structural observation.",
                evidence={"bytes": artifact.size},
                provenance_class=ProvenanceClass.NONE,
                tags=("plugin",),
            )
        ]


class CrashingPlugin(BaseDetector):
    """Raises instead of returning findings."""

    id = "example.crashing.v1"
    supported_types = TEXT_TYPES
    categories = frozenset({FindingCategory.STRUCTURAL_SIGNAL})

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        raise RuntimeError("this plugin is broken")


class HangingPlugin(BaseDetector):
    """Never returns, so the host has to enforce its own deadline."""

    id = "example.hanging.v1"
    supported_types = TEXT_TYPES
    categories = frozenset({FindingCategory.STRUCTURAL_SIGNAL})

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        time.sleep(600)
        return []


class ForgingPlugin(BaseDetector):
    """Returns a finding whose identity does not match its own evidence."""

    id = "example.forging.v1"
    supported_types = TEXT_TYPES
    categories = frozenset({FindingCategory.STRUCTURAL_SIGNAL})

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        honest = self.finding(
            artifact=artifact,
            category=FindingCategory.STRUCTURAL_SIGNAL,
            confidence=1.0,
            confidence_type=ConfidenceType.DETERMINISTIC,
            severity=Severity.INFO,
            evidence_type=EvidenceType.STRUCTURAL,
            title="Forged",
            description="Evidence is rewritten after the identity was computed.",
            evidence={"claimed": "innocent"},
        )
        return [honest.model_copy(update={"evidence": {"claimed": "tampered"}})]


class ImpersonatingPlugin(BaseDetector):
    """Returns a finding attributed to a different detector."""

    id = "example.impersonating.v1"
    supported_types = TEXT_TYPES
    categories = frozenset({FindingCategory.STRUCTURAL_SIGNAL})

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        finding = self.finding(
            artifact=artifact,
            category=FindingCategory.STRUCTURAL_SIGNAL,
            confidence=1.0,
            confidence_type=ConfidenceType.DETERMINISTIC,
            severity=Severity.CRITICAL,
            evidence_type=EvidenceType.STRUCTURAL,
            title="Impersonation",
            description="Claims to be a built-in detector.",
            evidence={"claim": "builtin"},
        )
        return [finding.model_copy(update={"detector_id": "text.unicode-forensics.v1"})]


class LoudPlugin(BaseDetector):
    """Reports a critical finding without declaring a manifest."""

    id = "example.loud.v1"
    supported_types = TEXT_TYPES
    categories = frozenset({FindingCategory.SECURITY_ISSUE})

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        return [
            self.finding(
                artifact=artifact,
                category=FindingCategory.SECURITY_ISSUE,
                confidence=1.0,
                confidence_type=ConfidenceType.DETERMINISTIC,
                severity=Severity.CRITICAL,
                evidence_type=EvidenceType.SECURITY,
                title="Critical plugin observation",
                description="A third-party detector reported a critical observation.",
                evidence={"scope": "artifact"},
            )
        ]


#: Set when ConstructionRecordingPlugin is instantiated, so a test can assert
#: that a refused plugin never had its constructor run.
CONSTRUCTIONS: list[str] = []


class ConstructionRecordingPlugin(BaseDetector):
    """Records the fact that it was constructed."""

    id = "example.constructed.v1"
    supported_types = TEXT_TYPES
    categories = frozenset({FindingCategory.STRUCTURAL_SIGNAL})

    def __init__(self) -> None:
        CONSTRUCTIONS.append(self.id)

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        return []


class PathOpenWriterPlugin(BaseDetector):
    """Attempts to write through Path.open rather than the builtin."""

    id = "example.path-writer.v1"
    supported_types = TEXT_TYPES
    categories = frozenset({FindingCategory.SECURITY_ISSUE})

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        assert artifact.path is not None
        with (artifact.path.parent / "written-via-path-open.txt").open("w") as handle:
            handle.write("here")
        return []


class NetworkPlugin(BaseDetector):
    """Attempts to open a socket."""

    id = "example.network.v1"
    supported_types = TEXT_TYPES
    categories = frozenset({FindingCategory.SECURITY_ISSUE})

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        import socket

        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return []


class WritingPlugin(BaseDetector):
    """Attempts to write a file next to the artifact."""

    id = "example.writing.v1"
    supported_types = TEXT_TYPES
    categories = frozenset({FindingCategory.SECURITY_ISSUE})

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        assert artifact.path is not None
        (artifact.path.parent / "written-by-plugin.txt").write_text("here", encoding="utf-8")
        return []


class SubprocessPlugin(BaseDetector):
    """Attempts to start another process."""

    id = "example.subprocess.v1"
    supported_types = TEXT_TYPES
    categories = frozenset({FindingCategory.SECURITY_ISSUE})

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        import subprocess
        import sys

        subprocess.run([sys.executable, "-c", "pass"], check=False)
        return []


DECLARED_MANIFEST = PluginManifest(
    detector_id=WellBehavedPlugin.id,
    name="Well-behaved example plugin",
    version="1.2.3",
    description="Reports one structural observation per text artifact.",
    vendor="example",
    capabilities=frozenset({PluginCapability.READ_ARTIFACT}),
    supported_types=TEXT_TYPES,
    categories=frozenset({FindingCategory.STRUCTURAL_SIGNAL}),
)

DECLARED_REGISTRATION = PluginRegistration(
    manifest=DECLARED_MANIFEST,
    factory=WellBehavedPlugin,
)

GREEDY_REGISTRATION = PluginRegistration(
    manifest=DECLARED_MANIFEST.model_copy(
        update={
            "detector_id": NetworkPlugin.id,
            "name": "Greedy example plugin",
            "capabilities": frozenset({PluginCapability.READ_ARTIFACT, PluginCapability.NETWORK}),
        }
    ),
    factory=NetworkPlugin,
)

FUTURE_SCHEMA_REGISTRATION = PluginRegistration(
    manifest=DECLARED_MANIFEST.model_copy(
        update={"compatible_schema_versions": frozenset({"9.9"})}
    ),
    factory=WellBehavedPlugin,
)


def broken_factory() -> Any:
    """Raise while the host is still deciding whether to trust this plugin."""

    raise ImportError("the plugin package is not installed correctly")


# -- broker-aware plugins ------------------------------------------------------------


class BrokerReadingPlugin(BaseDetector):
    """Reads the artifact through the broker rather than through the filesystem.

    A plugin written this way never touches ambient authority, so it keeps
    working unchanged when the host tightens what ambient authority means.
    """

    id = "example.broker-reader.v1"
    supported_types = TEXT_TYPES
    categories = frozenset({FindingCategory.STRUCTURAL_SIGNAL})

    def __init__(self) -> None:
        self.broker: Any = None

    def bind_broker(self, broker: Any) -> None:
        self.broker = broker

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        payload = self.broker.read_artifact()
        return [
            self.finding(
                artifact=artifact,
                category=FindingCategory.STRUCTURAL_SIGNAL,
                confidence=1.0,
                confidence_type=ConfidenceType.DETERMINISTIC,
                severity=Severity.INFO,
                evidence_type=EvidenceType.STRUCTURAL,
                title="Broker read",
                description="The plugin read the artifact through the capability broker.",
                evidence={"bytes": len(payload), "digest": self.broker.artifact_digest()},
                provenance_class=ProvenanceClass.NONE,
                tags=("plugin", "broker"),
            )
        ]


class BrokerEscapePlugin(BaseDetector):
    """Asks the broker for a path outside its workspace grant."""

    id = "example.broker-escape.v1"
    supported_types = TEXT_TYPES
    categories = frozenset({FindingCategory.SECURITY_ISSUE})

    def __init__(self) -> None:
        self.broker: Any = None

    def bind_broker(self, broker: Any) -> None:
        self.broker = broker

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        self.broker.workspace_path("../../etc/passwd")
        return []


class BrokerScratchPlugin(BaseDetector):
    """Writes to its scratch directory, which is the only place it may write."""

    id = "example.broker-scratch.v1"
    supported_types = TEXT_TYPES
    categories = frozenset({FindingCategory.STRUCTURAL_SIGNAL})

    def __init__(self) -> None:
        self.broker: Any = None

    def bind_broker(self, broker: Any) -> None:
        self.broker = broker

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        with self.broker.open_temporary("work.bin") as handle:
            handle.write(b"scratch")
        return [
            self.finding(
                artifact=artifact,
                category=FindingCategory.STRUCTURAL_SIGNAL,
                confidence=1.0,
                confidence_type=ConfidenceType.DETERMINISTIC,
                severity=Severity.INFO,
                evidence_type=EvidenceType.STRUCTURAL,
                title="Scratch write",
                description="The plugin used its scratch grant.",
                evidence={"written": self.broker.temporary_bytes_written},
                provenance_class=ProvenanceClass.NONE,
            )
        ]


class BrokerRejectingPlugin(BaseDetector):
    """Refuses the broker it is handed."""

    id = "example.broker-rejecting.v1"
    supported_types = TEXT_TYPES
    categories = frozenset({FindingCategory.STRUCTURAL_SIGNAL})

    def bind_broker(self, broker: Any) -> None:
        raise RuntimeError("this plugin will not accept a broker")

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        return []


BROKER_READER_REGISTRATION = PluginRegistration(
    manifest=DECLARED_MANIFEST.model_copy(
        update={
            "detector_id": BrokerReadingPlugin.id,
            "name": "Broker-aware example plugin",
        }
    ),
    factory=BrokerReadingPlugin,
)

BROKER_SCRATCH_REGISTRATION = PluginRegistration(
    manifest=DECLARED_MANIFEST.model_copy(
        update={
            "detector_id": BrokerScratchPlugin.id,
            "name": "Scratch-writing example plugin",
            "capabilities": frozenset(
                {PluginCapability.READ_ARTIFACT, PluginCapability.WRITE_TEMPORARY}
            ),
        }
    ),
    factory=BrokerScratchPlugin,
)

BROKER_ESCAPE_REGISTRATION = PluginRegistration(
    manifest=DECLARED_MANIFEST.model_copy(
        update={
            "detector_id": BrokerEscapePlugin.id,
            "name": "Escaping example plugin",
            "capabilities": frozenset(
                {PluginCapability.READ_ARTIFACT, PluginCapability.READ_WORKSPACE}
            ),
        }
    ),
    factory=BrokerEscapePlugin,
)


# -- hostile native plugins ----------------------------------------------------------
#
# These reach the operating system through ctypes, which is exactly what the
# Python guards cannot intercept. They exist so the confinement tests measure the
# kernel boundary rather than the guard sitting in front of it.
#
# Each one is written for both POSIX and Windows, because a "native" plugin that
# only works on one of them would test the confinement of one platform and quietly
# skip the other.

WINDOWS = os.name == "nt"
WINDOWS_READ_TARGET = chr(67) + ":" + chr(92) + "Windows" + chr(92) + "win.ini"


def _native() -> Any:
    """Return the C runtime for this platform."""

    import ctypes

    return ctypes.CDLL("msvcrt") if WINDOWS else ctypes.CDLL(None, use_errno=True)


def _native_open_for_write(path: str) -> int:
    """Create a file through the platform's native open, bypassing Python's."""

    import ctypes
    import os as _os

    if WINDOWS:
        # _wopen: _O_WRONLY | _O_CREAT | _O_BINARY, permissions _S_IREAD|_S_IWRITE.
        runtime = _native()
        runtime._wopen.argtypes = [ctypes.c_wchar_p, ctypes.c_int, ctypes.c_int]
        return int(runtime._wopen(path, 0x0001 | 0x0100 | 0x8000, 0o600))
    return int(_native().open(path.encode("utf-8"), _os.O_WRONLY | _os.O_CREAT, 0o600))


def _native_close(descriptor: int) -> None:
    import os as _os

    if WINDOWS:
        _native()._close(descriptor)
        return
    _os.close(descriptor)


class NativeWriterPlugin(BaseDetector):
    """Writes beside the artifact through the native open call."""

    id = "example.native-writer.v1"
    supported_types = TEXT_TYPES
    categories = frozenset({FindingCategory.SECURITY_ISSUE})

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        assert artifact.path is not None
        target = str(artifact.path.parent / "written-by-native-code.txt")
        descriptor = _native_open_for_write(target)
        if descriptor < 0:
            raise OSError(f"native write refused: {target}")
        _native_close(descriptor)
        raise RuntimeError("NATIVE-WRITE-SUCCEEDED")


class NativeReaderPlugin(BaseDetector):
    """Reads a file outside every grant through the native open call."""

    id = "example.native-reader.v1"
    supported_types = TEXT_TYPES
    categories = frozenset({FindingCategory.SECURITY_ISSUE})

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        import ctypes
        import os as _os

        if WINDOWS:
            runtime = _native()
            runtime._wopen.argtypes = [ctypes.c_wchar_p, ctypes.c_int, ctypes.c_int]
            descriptor = int(runtime._wopen(WINDOWS_READ_TARGET, 0x8000, 0))
        else:
            descriptor = int(_native().open(b"/etc/hostname", _os.O_RDONLY))
        if descriptor < 0:
            raise OSError("native read refused")
        _native_close(descriptor)
        raise RuntimeError("NATIVE-READ-SUCCEEDED")


class NativeSocketPlugin(BaseDetector):
    """Opens a socket through the native call, bypassing the socket-module guard."""

    id = "example.native-socket.v1"
    supported_types = TEXT_TYPES
    categories = frozenset({FindingCategory.SECURITY_ISSUE})

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        import ctypes

        if WINDOWS:
            winsock = ctypes.WinDLL("ws2_32", use_last_error=True)
            data = ctypes.create_string_buffer(408)
            winsock.WSAStartup(0x0202, data)
            result = winsock.socket(2, 1, 0)
        else:
            # AF_INET, SOCK_STREAM. If the process is still alive after this line
            # the kernel did not stop it.
            result = _native().socket(2, 1, 0)
        raise RuntimeError(f"NATIVE-SOCKET-SUCCEEDED:{result}")


class NativeExecPlugin(BaseDetector):
    """Starts another program through the native call."""

    id = "example.native-exec.v1"
    supported_types = TEXT_TYPES
    categories = frozenset({FindingCategory.SECURITY_ISSUE})

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        import ctypes

        if WINDOWS:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            result = kernel32.WinExec(b"cmd.exe /c exit", 0)
            raise RuntimeError(f"NATIVE-EXEC-RETURNED:{result}")
        argv = (ctypes.c_char_p * 2)(b"/bin/true", None)
        environment = (ctypes.c_char_p * 1)(None)
        _native().execve(b"/bin/true", argv, environment)
        raise RuntimeError("NATIVE-EXEC-RETURNED")


class NativeSpinnerPlugin(BaseDetector):
    """Blocks inside native code, where no Python-level deadline can interrupt it."""

    id = "example.native-spinner.v1"
    supported_types = TEXT_TYPES
    categories = frozenset({FindingCategory.SECURITY_ISSUE})

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        import ctypes

        # A native sleep holds no GIL and answers no signal handler Python
        # installed. Only the host killing the process ends this.
        if WINDOWS:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.Sleep.argtypes = [ctypes.c_uint32]
            kernel32.Sleep(600_000)
        else:
            runtime = _native()
            runtime.sleep.argtypes = [ctypes.c_uint]
            runtime.sleep(600)
        return []


class ScratchWritingNativePlugin(BaseDetector):
    """Writes into the scratch grant through the native open call.

    The positive case: confinement that blocks a granted write is breakage, not
    security.
    """

    id = "example.native-scratch.v1"
    supported_types = TEXT_TYPES
    categories = frozenset({FindingCategory.STRUCTURAL_SIGNAL})

    def __init__(self) -> None:
        self.broker: Any = None

    def bind_broker(self, broker: Any) -> None:
        self.broker = broker

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        import os as _os

        target = str(self.broker.temporary_path("native.bin"))
        descriptor = _native_open_for_write(target)
        if descriptor < 0:
            raise OSError(f"native scratch write refused: {target}")
        _os.write(descriptor, b"native")
        _native_close(descriptor)
        raise RuntimeError("NATIVE-SCRATCH-WRITE-SUCCEEDED")


def _hostile(detector: type[BaseDetector], *capabilities: PluginCapability) -> PluginRegistration:
    return PluginRegistration(
        manifest=DECLARED_MANIFEST.model_copy(
            update={
                "detector_id": detector.id,
                "name": f"Hostile native plugin {detector.id}",
                "capabilities": frozenset({PluginCapability.READ_ARTIFACT, *capabilities}),
            }
        ),
        factory=detector,
    )


NATIVE_WRITER_REGISTRATION = _hostile(NativeWriterPlugin)
NATIVE_READER_REGISTRATION = _hostile(NativeReaderPlugin)
NATIVE_SOCKET_REGISTRATION = _hostile(NativeSocketPlugin)
NATIVE_EXEC_REGISTRATION = _hostile(NativeExecPlugin)
NATIVE_SPINNER_REGISTRATION = _hostile(NativeSpinnerPlugin)
NATIVE_SCRATCH_REGISTRATION = _hostile(ScratchWritingNativePlugin, PluginCapability.WRITE_TEMPORARY)
