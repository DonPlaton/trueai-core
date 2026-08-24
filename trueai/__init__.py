"""Public API for TrueAI Core."""

from trueai._version import PACKAGE_VERSION, SCHEMA_VERSION
from trueai.core.artifact import Artifact, ArtifactDiscovery, DiscoveryOptions
from trueai.core.certificates import (
    AuditCertificate,
    CertificateRevocationList,
    CertificateStatus,
    CertificateVerification,
    RevocationEntry,
    RevocationListVerification,
    RevocationReason,
    issue_certificate,
    revoke_certificate,
    verify_certificate,
    verify_revocation_list,
)
from trueai.core.delivery import DeliveryStatus, DeliveryVerification, verify_clean_delivery
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
from trueai.core.policy_bundle import (
    EnterprisePolicyBundle,
    FindingSelector,
    PolicyBundleControls,
    PolicyBundleVerification,
    PolicyException,
    PolicySuppression,
    apply_policy_bundle,
    issue_policy_bundle,
    load_policy_bundle,
    verify_policy_bundle,
)
from trueai.detectors.provenance.verification import (
    C2PAVerifier,
    attach_provenance_verifications,
    verify_provenance,
)

__version__ = PACKAGE_VERSION
__schema_version__ = SCHEMA_VERSION

__all__ = [
    "Artifact",
    "ArtifactDiscovery",
    "ArtifactType",
    "AuditCertificate",
    "C2PAVerifier",
    "CertificateRevocationList",
    "CertificateStatus",
    "CertificateVerification",
    "ConfidenceType",
    "DeliveryStatus",
    "DeliveryVerification",
    "DiscoveryOptions",
    "EnterprisePolicyBundle",
    "Finding",
    "FindingCategory",
    "FindingSelector",
    "IntegrityStatus",
    "PolicyBundleControls",
    "PolicyBundleVerification",
    "PolicyException",
    "PolicyProfile",
    "PolicyStore",
    "PolicySuppression",
    "ProvenanceVerification",
    "ProvenanceVerificationStatus",
    "RevocationEntry",
    "RevocationListVerification",
    "RevocationReason",
    "ScanOptions",
    "ScanReport",
    "Severity",
    "TrueAIEngine",
    "__schema_version__",
    "__version__",
    "apply_policy_bundle",
    "attach_provenance_verifications",
    "issue_certificate",
    "issue_policy_bundle",
    "load_policy_bundle",
    "revoke_certificate",
    "verify_certificate",
    "verify_clean_delivery",
    "verify_policy_bundle",
    "verify_provenance",
    "verify_revocation_list",
]
