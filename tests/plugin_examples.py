"""Example third-party detectors used to exercise the plugin host.

These stand in for plugins a host would encounter in the wild: a well-behaved
one, one that declares a manifest, one that crashes, one that hangs, one that
tries to forge a finding, and ones that reach for capabilities they were not
granted. They are importable by name so the worker subprocess can load them the
same way it loads a real entry point.
"""

from __future__ import annotations

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
