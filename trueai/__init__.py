"""Public API for TrueAI Core."""

from trueai._version import PACKAGE_VERSION, SCHEMA_VERSION
from trueai.core.artifact import Artifact, ArtifactDiscovery, DiscoveryOptions
from trueai.core.engine import TrueAIEngine
from trueai.core.models import (
    ArtifactType,
    ConfidenceType,
    Finding,
    FindingCategory,
    IntegrityStatus,
    ProvenanceVerification,
    ProvenanceVerificationStatus,
    ScanOptions,
    ScanReport,
    Severity,
)
from trueai.core.policy import PolicyProfile, PolicyStore
from trueai.detectors.provenance.verification import C2PAVerifier, verify_provenance

__version__ = PACKAGE_VERSION
__schema_version__ = SCHEMA_VERSION

__all__ = [
    "Artifact",
    "ArtifactDiscovery",
    "ArtifactType",
    "C2PAVerifier",
    "ConfidenceType",
    "DiscoveryOptions",
    "Finding",
    "FindingCategory",
    "IntegrityStatus",
    "PolicyProfile",
    "PolicyStore",
    "ProvenanceVerification",
    "ProvenanceVerificationStatus",
    "ScanOptions",
    "ScanReport",
    "Severity",
    "TrueAIEngine",
    "__schema_version__",
    "__version__",
    "verify_provenance",
]
