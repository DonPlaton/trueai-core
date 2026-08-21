"""Stable public data models for scanning, policy, and remediation."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, Self
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from trueai._version import PACKAGE_VERSION
from trueai._version import SCHEMA_VERSION as PUBLIC_SCHEMA_VERSION
from trueai.core.frozen import deep_freeze

SCHEMA_VERSION: Literal["0.1"] = PUBLIC_SCHEMA_VERSION


class ArtifactType(StrEnum):
    """Artifact types understood by the engine."""

    TEXT = "text"
    MARKDOWN = "markdown"
    SOURCE_CODE = "source_code"
    HTML = "html"
    CSS = "css"
    SVG = "svg"
    DOCX = "docx"
    PPTX = "pptx"
    XLSX = "xlsx"
    PDF = "pdf"
    PNG = "png"
    JPEG = "jpeg"
    GIT_REPOSITORY = "git_repository"
    DIRECTORY = "directory"
    BINARY = "binary"
    UNKNOWN = "unknown"


class FindingCategory(StrEnum):
    """Stable taxonomy used by findings and policy rules."""

    INVISIBLE_UNICODE = "invisible_unicode"
    SUSPICIOUS_UNICODE = "suspicious_unicode"
    EXPLICIT_AI_ATTRIBUTION = "explicit_ai_attribution"
    GENERATOR_METADATA = "generator_metadata"
    GIT_ATTRIBUTION = "git_attribution"
    TOOLING_RESIDUE = "tooling_residue"
    DOCUMENT_METADATA = "document_metadata"
    PERSONAL_METADATA = "personal_metadata"
    IMAGE_METADATA = "image_metadata"
    C2PA_PROVENANCE = "c2pa_provenance"
    PROVIDER_WATERMARK = "provider_watermark"
    STYLISTIC_SIGNAL = "stylistic_signal"
    DESIGN_STYLE_SIGNAL = "design_style_signal"
    HIDDEN_ELEMENT = "hidden_element"
    GENERATED_COMMENT = "generated_comment"
    STRUCTURAL_SIGNAL = "structural_signal"
    SECURITY_ISSUE = "security_issue"


class ConfidenceType(StrEnum):
    """Nature of the evidence, independent of its numeric strength."""

    DETERMINISTIC = "deterministic"
    VERIFIED = "verified"
    PROBABILISTIC = "probabilistic"
    HEURISTIC = "heuristic"


class Severity(StrEnum):
    """Operational importance, not a claim about authorship."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EvidenceType(StrEnum):
    """Primary source of a finding."""

    TEXT = "text"
    METADATA = "metadata"
    GIT = "git"
    STRUCTURAL = "structural"
    STATISTICAL = "statistical"
    PROVENANCE = "provenance"
    SECURITY = "security"


class ProvenanceClass(StrEnum):
    """Relationship of a finding to provenance."""

    NONE = "none"
    ATTRIBUTION = "attribution"
    METADATA = "metadata"
    PROVENANCE_METADATA = "provenance_metadata"
    AUTHENTICATED_PROVENANCE = "authenticated_provenance"
    PROVIDER_WATERMARK = "provider_watermark"
    HEURISTIC = "heuristic"


class UnicodeSafetyClass(StrEnum):
    """Context-sensitive Unicode classification."""

    SAFE = "safe"
    TYPOGRAPHIC = "typographic"
    LANGUAGE_DEPENDENT = "language_dependent"
    SUSPICIOUS = "suspicious"
    INVISIBLE = "invisible"
    CONTROL = "control"


class PolicyAction(StrEnum):
    """Actions a policy can assign to a finding."""

    IGNORE = "ignore"
    REPORT = "report"
    REVIEW = "review"
    REMOVE = "remove"
    PRESERVE = "preserve"
    ERROR = "error"


class IntegrityStatus(StrEnum):
    """Outcome of post-remediation content verification."""

    PASS = "pass"
    FAIL = "fail"
    NOT_VERIFIABLE = "not_verifiable"
    NOT_MODIFIED = "not_modified"


class NetworkPolicy(StrEnum):
    """Explicit network boundary for future verification adapters."""

    OFFLINE = "offline"
    EXPLICIT_ONLY = "explicit_only"


class RemediationSafety(StrEnum):
    """Mutation risk classification."""

    SAFE_METADATA = "safe_metadata"
    PREDICTABLE_CONTENT = "predictable_content"
    DESTRUCTIVE = "destructive"
    PROVENANCE_PROTECTED = "provenance_protected"


class ProvenanceVerificationStatus(StrEnum):
    """Outcome of authenticated C2PA verification, distinct from marker discovery."""

    TRUSTED = "trusted"
    VALID = "valid"
    INVALID = "invalid"
    NO_MANIFEST = "no_manifest"
    UNSUPPORTED_CONTAINER = "unsupported_container"
    VERIFIER_UNAVAILABLE = "verifier_unavailable"


class ValidationOutcome(StrEnum):
    """Category a verifier assigned to one validation entry."""

    SUCCESS = "success"
    INFORMATIONAL = "informational"
    FAILURE = "failure"


class WatermarkSupportStatus(StrEnum):
    """Status returned by provider verification adapters."""

    SUPPORTED = "supported"
    NOT_SUPPORTED = "not_supported"
    VERIFICATION_UNAVAILABLE = "verification_unavailable"


class FrozenModel(BaseModel):
    """Strict immutable base for public report objects."""

    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=False)

    @model_validator(mode="after")
    def freeze_nested_containers(self) -> Self:
        """Make nested mappings/lists immutable instead of only freezing attributes."""

        for field_name in type(self).model_fields:
            current = getattr(self, field_name)
            frozen = deep_freeze(current)
            if frozen is not current:
                object.__setattr__(self, field_name, frozen)
        return self


class FindingLocation(FrozenModel):
    """Optional source location in text, bytes, XML, or package parts."""

    line: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)
    offset: int | None = Field(default=None, ge=0)
    end_offset: int | None = Field(default=None, ge=0)
    byte_offset: int | None = Field(default=None, ge=0)
    package_part: str | None = None
    json_pointer: str | None = None


class Finding(FrozenModel):
    """A single explainable observation emitted by one detector."""

    id: str = Field(min_length=12, max_length=80)
    detector_id: str = Field(min_length=3, max_length=120)
    category: FindingCategory
    artifact_path: str
    provider: str | None = None
    confidence: Annotated[float, Field(ge=0.0, le=1.0)]
    confidence_type: ConfidenceType
    severity: Severity
    evidence_type: EvidenceType
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1)
    evidence: dict[str, JsonValue] = Field(default_factory=dict)
    location: FindingLocation | None = None
    removable: bool = False
    remediation_id: str | None = None
    provenance_class: ProvenanceClass = ProvenanceClass.NONE
    tags: tuple[str, ...] = ()


class ArtifactDescriptor(FrozenModel):
    """Machine-readable description of an artifact included in a report."""

    path: str
    artifact_type: ArtifactType
    media_type: str | None = None
    size: int | None = Field(default=None, ge=0)
    sha256: str | None = None


class ScanOptions(FrozenModel):
    """Resource and detector boundaries for a scan."""

    max_file_size: int = Field(default=25 * 1024 * 1024, ge=1)
    max_archive_uncompressed_size: int = Field(default=100 * 1024 * 1024, ge=1)
    max_archive_entries: int = Field(default=10_000, ge=1)
    max_compression_ratio: float = Field(default=200.0, ge=1.0)
    max_files: int = Field(default=100_000, ge=1)
    max_findings: int = Field(default=10_000, ge=1, le=1_000_000)
    max_parser_events: int = Field(default=50_000, ge=1, le=5_000_000)
    git_commit_limit: int = Field(default=500, ge=1, le=100_000)
    max_git_output_bytes: int = Field(default=8 * 1024 * 1024, ge=1024)
    follow_symlinks: bool = False
    include_experimental: bool = False
    enabled_detectors: frozenset[str] | None = None
    disabled_detectors: frozenset[str] = frozenset()
    network_policy: NetworkPolicy = NetworkPolicy.OFFLINE
    # Detectors run per artifact, so more than one artifact can be inspected at a
    # time. Results are merged in artifact order, which keeps a completed scan
    # byte-identical to a sequential one. Third-party detectors must be
    # thread-safe before this is raised above 1.
    max_workers: int = Field(default=1, ge=1, le=64)
    # Content-addressed reuse of per-artifact detector output. None disables it.
    cache_directory: Path | None = None


class ScanContext(FrozenModel):
    """Read-only context passed to detectors."""

    options: ScanOptions
    root: Path | None = None


class ScanDiagnostic(FrozenModel):
    """Non-finding information about skipped or malformed inputs."""

    code: str
    message: str
    artifact_path: str | None = None
    severity: Severity = Severity.INFO


class PolicyDecision(FrozenModel):
    """Policy action assigned to a finding."""

    finding_id: str
    action: PolicyAction
    rationale: str


class ScanSummary(FrozenModel):
    """Precomputed counts for stable clients."""

    artifact_count: int = Field(ge=0)
    finding_count: int = Field(ge=0)
    by_confidence_type: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    review_count: int = Field(default=0, ge=0)
    violation_count: int = Field(default=0, ge=0)


class IntegrityReport(FrozenModel):
    """Evidence that remediation changed only approved material."""

    status: IntegrityStatus
    explanation: str
    before_sha256: str | None = None
    after_sha256: str | None = None
    logical_before_sha256: str | None = None
    logical_after_sha256: str | None = None
    intentionally_removed: tuple[str, ...] = ()


class ScanReport(FrozenModel):
    """Versioned top-level report schema."""

    schema_version: Literal["0.1"] = SCHEMA_VERSION
    package_version: str = PACKAGE_VERSION
    scan_id: UUID = Field(default_factory=uuid4)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    artifact: ArtifactDescriptor
    artifacts: tuple[ArtifactDescriptor, ...]
    summary: ScanSummary
    findings: tuple[Finding, ...]
    diagnostics: tuple[ScanDiagnostic, ...] = ()
    detectors_run: tuple[str, ...] = ()
    policy: str | None = None
    policy_decisions: tuple[PolicyDecision, ...] = ()
    integrity: IntegrityReport = Field(
        default_factory=lambda: IntegrityReport(
            status=IntegrityStatus.NOT_MODIFIED,
            explanation="Scan-only operation; the artifact was not modified.",
        )
    )


class Remediation(FrozenModel):
    """One predictable operation proposed for one artifact."""

    id: str
    remediation_id: str
    artifact_path: str
    finding_ids: tuple[str, ...]
    description: str
    safety: RemediationSafety
    payload: dict[str, JsonValue] = Field(default_factory=dict)


class RemediationPlan(FrozenModel):
    """Reviewable plan derived from findings and a policy."""

    schema_version: Literal["0.1"] = SCHEMA_VERSION
    policy: str
    remediations: tuple[Remediation, ...]
    review_findings: tuple[str, ...] = ()
    preserved_findings: tuple[str, ...] = ()
    blocked_findings: tuple[str, ...] = ()


class RemediationResult(FrozenModel):
    """Result of applying and verifying a remediation plan."""

    artifact_path: str
    output_path: str | None
    backup_path: str | None = None
    applied_remediation_ids: tuple[str, ...] = ()
    changed_fields: tuple[str, ...] = ()
    integrity: IntegrityReport
    dry_run: bool = False


class ProvenanceSigner(FrozenModel):
    """Identity the signing certificate asserts, as reported by the verifier."""

    common_name: str | None = None
    issuer: str | None = None
    algorithm: str | None = None
    certificate_serial_number: str | None = None
    signed_at: str | None = None


class ProvenanceAssertion(FrozenModel):
    """One claim carried inside a manifest."""

    label: str
    summary: str


class ProvenanceValidationEntry(FrozenModel):
    """One check the verifier performed and its outcome."""

    code: str
    outcome: ValidationOutcome
    explanation: str
    target: str | None = None


class ProvenanceVerification(FrozenModel):
    """Result of authenticated verification for one artifact.

    A trusted result is the only one that establishes provenance. ``VALID`` means
    the signature and content hashes check out but the signer is not in the trust
    store in use, which is a materially weaker statement and is reported as such.
    """

    schema_version: Literal["0.1"] = SCHEMA_VERSION
    artifact_path: str
    status: ProvenanceVerificationStatus
    verifier: str
    explanation: str
    trust_anchors_configured: bool = False
    remote_manifests_allowed: bool = False
    active_manifest_label: str | None = None
    claim_generator: str | None = None
    title: str | None = None
    embedded: bool | None = None
    remote_manifest_url: str | None = None
    signer: ProvenanceSigner | None = None
    assertions: tuple[ProvenanceAssertion, ...] = ()
    ingredients: tuple[str, ...] = ()
    validation: tuple[ProvenanceValidationEntry, ...] = ()

    @property
    def authenticated(self) -> bool:
        """Return whether the artifact carries provenance signed by a trusted anchor."""

        return self.status == ProvenanceVerificationStatus.TRUSTED

    def failures(self) -> tuple[ProvenanceValidationEntry, ...]:
        """Return only the checks that failed."""

        return tuple(
            entry for entry in self.validation if entry.outcome == ValidationOutcome.FAILURE
        )


class WatermarkVerificationResult(FrozenModel):
    """Provider adapter response without invented verification claims."""

    provider: str
    status: WatermarkSupportStatus
    verified: bool = False
    explanation: str
    findings: tuple[Finding, ...] = ()
