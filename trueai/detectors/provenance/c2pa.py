"""C2PA marker discovery that makes no unverified signature claim."""

from __future__ import annotations

from trueai.core.artifact import Artifact
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
from trueai.core.provenance import PROTECTED_PROVENANCE_MARKERS
from trueai.detectors.base import BaseDetector

_C2PA_TYPES = frozenset({ArtifactType.PNG, ArtifactType.JPEG, ArtifactType.PDF, ArtifactType.SVG})


class C2PAMarkerDetector(BaseDetector):
    """Report C2PA-compatible markers while preserving them by default."""

    id = "provenance.c2pa-marker.v1"
    supported_types = _C2PA_TYPES
    categories = frozenset({FindingCategory.C2PA_PROVENANCE})

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        data = artifact.read_bytes(context.options.max_file_size)
        lowered = data.lower()
        for marker in PROTECTED_PROVENANCE_MARKERS:
            offset = lowered.find(marker)
            if offset == -1:
                continue
            return [
                self.finding(
                    artifact=artifact,
                    category=FindingCategory.C2PA_PROVENANCE,
                    confidence=1.0,
                    confidence_type=ConfidenceType.DETERMINISTIC,
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.PROVENANCE,
                    title="C2PA-compatible provenance marker detected",
                    description=(
                        "A literal C2PA/Content Credentials marker is present. Scanning does not "
                        "verify signatures, so this is marker discovery and not authenticated "
                        "provenance. Run 'trueai verify' to validate the manifest, its signature "
                        "chain, and its trust anchors. The marker is preserved by all built-in "
                        "policies."
                    ),
                    evidence={
                        "marker": marker.decode("ascii"),
                        "verification": "not_attempted",
                        "verification_command": "trueai verify",
                        "authenticated": False,
                    },
                    location=FindingLocation(byte_offset=offset),
                    removable=False,
                    provenance_class=ProvenanceClass.PROVENANCE_METADATA,
                    tags=("c2pa", "provenance", "preserve", "unverified-marker"),
                )
            ]
        return []
