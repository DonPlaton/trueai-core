"""Domain exceptions with stable error codes."""


class TrueAIError(Exception):
    """Base class for expected TrueAI failures."""

    code = "trueai_error"


class ArtifactNotFoundError(TrueAIError):
    """Raised when a requested artifact does not exist."""

    code = "artifact_not_found"


class UnsupportedArtifactError(TrueAIError):
    """Raised when no safe parser exists for an artifact."""

    code = "unsupported_artifact"


class ArtifactTooLargeError(TrueAIError):
    """Raised when a configured resource boundary is exceeded."""

    code = "artifact_too_large"


class ScanLimitExceededError(TrueAIError):
    """Raised when a scan cannot complete inside an explicit resource budget."""

    code = "scan_limit_exceeded"


class CorruptArtifactError(TrueAIError):
    """Raised when an artifact cannot be parsed safely."""

    code = "corrupt_artifact"


class UnsafeArtifactError(TrueAIError):
    """Raised when an archive or path violates a security boundary."""

    code = "unsafe_artifact"


class DetectorRegistrationError(TrueAIError):
    """Raised for invalid or duplicate detector registrations."""

    code = "detector_registration_error"


class PolicyValidationError(TrueAIError):
    """Raised when a policy violates the public or safety schema."""

    code = "policy_validation_error"


class RemediationError(TrueAIError):
    """Raised when a remediation cannot be planned or applied safely."""

    code = "remediation_error"


class OptionalDependencyError(TrueAIError):
    """Raised when a requested capability needs an optional dependency."""

    code = "optional_dependency_missing"


class ProvenanceConfigurationError(TrueAIError):
    """Raised when requested provenance trust settings cannot be enforced."""

    code = "provenance_configuration_error"


class AttestationError(TrueAIError):
    """Raised when an audit certificate cannot be issued or verified safely."""

    code = "attestation_error"
