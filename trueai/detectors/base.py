"""Common detector protocol and deterministic finding construction."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Collection, Iterable, Mapping
from typing import Protocol, cast, runtime_checkable

from pydantic import JsonValue

from trueai.core.artifact import Artifact
from trueai.core.errors import ScanLimitExceededError
from trueai.core.finding_id import build_finding_id
from trueai.core.models import (
    ArtifactType,
    ConfidenceType,
    EvidenceType,
    Finding,
    FindingCategory,
    FindingLocation,
    ProvenanceClass,
    ScanContext,
    Severity,
)


@runtime_checkable
class Detector(Protocol):
    """Non-mutating detector contract for built-ins and third parties."""

    id: str
    supported_types: frozenset[ArtifactType]
    provider: str | None
    categories: frozenset[FindingCategory]
    experimental: bool

    def supports(self, artifact: Artifact) -> bool:
        """Return whether the detector can safely scan an artifact."""

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        """Inspect an artifact without mutating it."""


class BaseDetector(ABC):
    """Convenience base class that preserves the public detector contract."""

    id = "base"
    supported_types: frozenset[ArtifactType] = frozenset()
    provider: str | None = None
    categories: frozenset[FindingCategory] = frozenset()
    experimental = False

    def supports(self, artifact: Artifact) -> bool:
        return artifact.artifact_type in self.supported_types

    @abstractmethod
    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        """Inspect an artifact and return independent findings."""

    def finding(
        self,
        *,
        artifact: Artifact,
        category: FindingCategory,
        confidence: float,
        confidence_type: ConfidenceType,
        severity: Severity,
        evidence_type: EvidenceType,
        title: str,
        description: str,
        evidence: Mapping[str, object] | None = None,
        location: FindingLocation | None = None,
        provider: str | None = None,
        removable: bool = False,
        remediation_id: str | None = None,
        provenance_class: ProvenanceClass = ProvenanceClass.NONE,
        tags: Collection[str] = (),
    ) -> Finding:
        """Build a stable finding ID from evidence and location."""

        finding_evidence = cast(dict[str, JsonValue], dict(evidence or {}))
        return Finding(
            id=build_finding_id(
                artifact_path=artifact.display_path,
                category=category,
                detector_id=self.id,
                evidence=finding_evidence,
                location=location,
                provider=provider,
            ),
            detector_id=self.id,
            category=category,
            artifact_path=artifact.display_path,
            provider=provider,
            confidence=confidence,
            confidence_type=confidence_type,
            severity=severity,
            evidence_type=evidence_type,
            title=title,
            description=description,
            evidence=finding_evidence,
            location=location,
            removable=removable,
            remediation_id=remediation_id,
            provenance_class=provenance_class,
            tags=tuple(sorted(set(tags))),
        )


class FindingBuffer(list[Finding]):
    """A bounded detector-local result buffer that fails closed on excessive evidence."""

    def __init__(self, limit: int, detector_id: str) -> None:
        super().__init__()
        self._limit = limit
        self._detector_id = detector_id

    def append(self, finding: Finding) -> None:
        if len(self) >= self._limit:
            raise ScanLimitExceededError(
                f"Detector {self._detector_id} exceeded the {self._limit} finding limit"
            )
        super().append(finding)

    def extend(self, findings: Iterable[Finding]) -> None:
        for finding in findings:
            self.append(finding)
