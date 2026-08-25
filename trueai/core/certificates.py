"""Content-bound audit certificates for completed TrueAI scans.

A certificate records what one concrete TrueAI version observed about one exact
artifact inventory. It never asserts human authorship or the universal absence of
machine assistance. Unsigned certificates are content-addressed and tamper
evident; optional Ed25519 signatures authenticate the issuer.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Self
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from trueai._version import PACKAGE_VERSION, SCHEMA_VERSION
from trueai.core.artifact import Artifact, ArtifactDiscovery, DiscoveryOptions
from trueai.core.errors import AttestationError, OptionalDependencyError
from trueai.core.models import (
    ArtifactDescriptor,
    ArtifactType,
    Finding,
    FindingCategory,
    FrozenModel,
    ScanOptions,
    ScanReport,
)

CERTIFICATE_SCHEMA_VERSION: Literal["0.1"] = "0.1"
REVOCATION_SCHEMA_VERSION: Literal["0.1"] = "0.1"
_MAX_ATTESTATION_FILE_BYTES = 2 * 1024 * 1024
_MAX_KEY_FILE_BYTES = 1024 * 1024

# These are observable AI-assistance, generator-tool, watermark, or style
# indicators. A match is still evidence of that individual trace, not proof of
# how the complete artifact was authored.
INDICATOR_CATEGORIES = frozenset(
    {
        FindingCategory.EXPLICIT_AI_ATTRIBUTION,
        FindingCategory.GENERATOR_METADATA,
        FindingCategory.GIT_ATTRIBUTION,
        FindingCategory.INVISIBLE_UNICODE,
        FindingCategory.SUSPICIOUS_UNICODE,
        FindingCategory.TOOLING_RESIDUE,
        FindingCategory.PROVIDER_WATERMARK,
        FindingCategory.STYLISTIC_SIGNAL,
        FindingCategory.DESIGN_STYLE_SIGNAL,
        FindingCategory.GENERATED_COMMENT,
    }
)

PROVENANCE_CATEGORIES = frozenset({FindingCategory.C2PA_PROVENANCE})
_CONTAINER_TYPES = frozenset({ArtifactType.DIRECTORY, ArtifactType.GIT_REPOSITORY})


class CertificateStatus(StrEnum):
    """Outcome of the scan represented by a certificate."""

    CLEAR = "clear"
    INDICATORS_DETECTED = "indicators_detected"
    INCOMPLETE = "incomplete"


class RevocationReason(StrEnum):
    """Operator-auditable reason an issuer withdrew a certificate."""

    UNSPECIFIED = "unspecified"
    KEY_COMPROMISE = "key_compromise"
    ARTIFACT_WITHDRAWN = "artifact_withdrawn"
    SUPERSEDED = "superseded"
    ISSUED_IN_ERROR = "issued_in_error"


class CertificateSignature(FrozenModel):
    """Optional issuer signature over the canonical certificate claims."""

    algorithm: Literal["ed25519"] = "ed25519"
    key_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    value: str = Field(min_length=40, max_length=200)


class AuditCertificate(FrozenModel):
    """Versioned, content-bound record of one TrueAI scan."""

    certificate_schema_version: Literal["0.1"] = CERTIFICATE_SCHEMA_VERSION
    certificate_id: str = Field(pattern=r"^TAI1-[A-Z2-7]{32}$")
    issued_at: datetime
    expires_at: datetime | None = None
    package_version: str = PACKAGE_VERSION
    report_schema_version: str = SCHEMA_VERSION
    scan_id: UUID
    status: CertificateStatus
    statement: str
    artifact: ArtifactDescriptor
    artifact_inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy: str | None = None
    scan_complete: bool
    experimental_detectors_enabled: bool
    indicator_categories: tuple[str, ...]
    indicator_finding_ids: tuple[str, ...] = ()
    protected_provenance_finding_ids: tuple[str, ...] = ()
    detectors_run: tuple[str, ...] = ()
    diagnostic_codes: tuple[str, ...] = ()
    scan_options: dict[str, object]
    limitations: tuple[str, ...]
    signature: CertificateSignature | None = None

    @field_validator("issued_at")
    @classmethod
    def require_utc_offset(cls, value: datetime) -> datetime:
        """Reject ambiguous local timestamps in an auditable record."""

        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Certificate issue time must include a UTC offset")
        return value

    @model_validator(mode="after")
    def validate_status_claim(self) -> Self:
        """Keep status from contradicting completeness or indicator evidence."""

        if self.status == CertificateStatus.CLEAR and (
            not self.scan_complete or self.indicator_finding_ids
        ):
            raise ValueError("A clear certificate requires a complete scan with no indicators")
        if self.status == CertificateStatus.INDICATORS_DETECTED and (
            not self.scan_complete or not self.indicator_finding_ids
        ):
            raise ValueError("Detected status requires a complete scan and indicator findings")
        if self.status == CertificateStatus.INCOMPLETE and self.scan_complete:
            raise ValueError("Incomplete status requires scan_complete=false")
        if self.expires_at is not None:
            if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
                raise ValueError("Certificate expiry time must include a UTC offset")
            if self.expires_at <= self.issued_at:
                raise ValueError("Certificate expiry must be later than its issue time")
        return self


class RevocationEntry(FrozenModel):
    """One immutable withdrawal record published by a certificate issuer."""

    certificate_id: str = Field(pattern=r"^TAI1-[A-Z2-7]{32}$")
    revoked_at: datetime
    reason: RevocationReason
    explanation: str | None = Field(default=None, max_length=500)
    replacement_certificate_id: str | None = Field(default=None, pattern=r"^TAI1-[A-Z2-7]{32}$")

    @model_validator(mode="after")
    def validate_entry(self) -> Self:
        if self.revoked_at.tzinfo is None or self.revoked_at.utcoffset() is None:
            raise ValueError("Revocation time must include a UTC offset")
        if self.replacement_certificate_id == self.certificate_id:
            raise ValueError("A replacement certificate must have a different ID")
        return self


class CertificateRevocationList(FrozenModel):
    """Signed, finite-lifetime list of certificates withdrawn by one issuer."""

    revocation_schema_version: Literal["0.1"] = REVOCATION_SCHEMA_VERSION
    issuer_key_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    sequence: int = Field(ge=1)
    issued_at: datetime
    expires_at: datetime
    entries: tuple[RevocationEntry, ...] = ()
    signature: CertificateSignature | None = None

    @model_validator(mode="after")
    def validate_list(self) -> Self:
        for field, value in (("issue", self.issued_at), ("expiry", self.expires_at)):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"Revocation-list {field} time must include a UTC offset")
        if self.expires_at <= self.issued_at:
            raise ValueError("Revocation-list expiry must be later than its issue time")
        identifiers = tuple(entry.certificate_id for entry in self.entries)
        if identifiers != tuple(sorted(identifiers)):
            raise ValueError("Revocation entries must be sorted by certificate ID")
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("A certificate may appear only once in a revocation list")
        if any(entry.revoked_at > self.issued_at for entry in self.entries):
            raise ValueError("A revocation entry cannot be dated after the list was issued")
        return self


class CertificateVerification(FrozenModel):
    """Result of checking a certificate's identity, signature, and artifact binding."""

    valid: bool
    certificate_id_valid: bool
    signature_present: bool
    signature_verified: bool | None
    artifact_verified: bool | None
    temporal_valid: bool = True
    revocation_checked: bool = False
    revocation_list_valid: bool | None = None
    revoked: bool | None = None
    explanations: tuple[str, ...]

    def unchecked(self) -> tuple[str, ...]:
        """Return the checks that did not run, one clause each.

        ``valid`` means nothing that was checked came back false. It does not
        mean everything was checked, and the difference is the whole point: an
        unsigned certificate verified without its artifact and without a
        revocation list is a self-consistent JSON document and nothing more.
        A reader who sees only ``valid`` is entitled to think otherwise.
        """

        missing: list[str] = []
        if not self.signature_present:
            missing.append("the issuer signature, because the certificate is unsigned")
        elif self.signature_verified is None:
            missing.append("the issuer signature, because no public key was supplied")
        if self.artifact_verified is None:
            missing.append("the artifact binding, because no artifact was supplied")
        if not self.revocation_checked:
            missing.append("revocation, because no authenticated revocation list was checked")
        return tuple(missing)

    @property
    def authenticated(self) -> bool:
        """Whether the issuer was authenticated and the artifact bytes matched.

        The predicate a reader means by "this certificate checks out". Kept apart
        from ``valid``, which is only "nothing that was checked came back false",
        and from ``unchecked()``, which lists everything nobody looked at.

        Revocation is deliberately not part of it. It answers a different
        question -- whether the issuer has since withdrawn a certificate that was
        and remains correctly signed -- and folding it in would make an
        unqualified result unreachable for any issuer who has never published a
        revocation list, which is a caveat that fires every time and is therefore
        read no times. ``require_revocation_check`` is how a caller who needs it
        asks.
        """

        return (
            self.valid
            and self.certificate_id_valid
            and self.signature_present
            and self.signature_verified is True
            and self.artifact_verified is True
        )


class RevocationListVerification(FrozenModel):
    """Signature and freshness result for an issuer revocation list."""

    valid: bool
    signature_verified: bool
    temporal_valid: bool
    issuer_key_id: str
    sequence: int
    explanations: tuple[str, ...]


def machine_indicator_findings(report: ScanReport) -> tuple[Finding, ...]:
    """Return findings in the documented machine/tool indicator scope."""

    selected: list[Finding] = []
    for finding in report.findings:
        if finding.category not in INDICATOR_CATEGORIES:
            continue
        if finding.category in {
            FindingCategory.INVISIBLE_UNICODE,
            FindingCategory.SUSPICIOUS_UNICODE,
        } and finding.evidence.get("safety_class") not in {
            "suspicious",
            "invisible",
            "control",
        }:
            # A leading BOM, typographic space, ZWJ/ZWNJ, or variation selector is
            # still reported by Unicode forensics but is not promoted into a
            # machine/tool indicator merely for existing.
            continue
        selected.append(finding)
    return tuple(selected)


def issue_certificate(
    report: ScanReport,
    options: ScanOptions,
    *,
    signing_key: str | Path | None = None,
    issued_at: datetime | None = None,
    valid_for: timedelta | None = None,
) -> AuditCertificate:
    """Create a certificate from a completed report without reinterpreting findings."""

    issue_time = _normalized_time(issued_at)
    if valid_for is not None and valid_for <= timedelta(0):
        raise AttestationError("Certificate validity duration must be positive")
    expires_at = issue_time + valid_for if valid_for is not None else None

    indicators = machine_indicator_findings(report)
    diagnostics = tuple(sorted({item.code for item in report.diagnostics}))
    inventory_digest = artifact_inventory_digest(report.artifacts)
    inventory_hashes_complete = all(
        descriptor.sha256 is not None or descriptor.artifact_type in _CONTAINER_TYPES
        for descriptor in report.artifacts
    )
    scan_complete = not diagnostics and inventory_hashes_complete
    if not scan_complete:
        status = CertificateStatus.INCOMPLETE
        statement = "The scan was incomplete; no clearance statement is issued."
    elif indicators:
        status = CertificateStatus.INDICATORS_DETECTED
        statement = (
            "TrueAI detected one or more machine-assistance, generator-tool, watermark, "
            "or heuristic style indicators in the documented scope."
        )
    else:
        status = CertificateStatus.CLEAR
        statement = (
            "TrueAI detected no machine-assistance, generator-tool, watermark, or heuristic "
            "style indicators within the documented detector scope."
        )

    limitations = [
        "This certificate records detector results for exact artifact bytes; it does not prove human authorship.",
        "Absence of a detected indicator is not proof that AI assistance was never used.",
        "Protected provenance and provider watermarks are reported, not defeated or secretly removed.",
    ]
    if not options.include_experimental:
        limitations.append(
            "Experimental stylometry and design-style detectors were not enabled for this scan."
        )

    claims = {
        "certificate_schema_version": CERTIFICATE_SCHEMA_VERSION,
        "issued_at": issue_time,
        "expires_at": expires_at,
        "package_version": report.package_version,
        "report_schema_version": report.schema_version,
        "scan_id": str(report.scan_id),
        "status": status,
        "statement": statement,
        "artifact": report.artifact,
        "artifact_inventory_sha256": inventory_digest,
        "report_sha256": _sha256_json(report.model_dump(mode="json")),
        "policy": report.policy,
        "scan_complete": scan_complete,
        "experimental_detectors_enabled": options.include_experimental,
        "indicator_categories": tuple(sorted(item.value for item in INDICATOR_CATEGORIES)),
        "indicator_finding_ids": tuple(item.id for item in indicators),
        "protected_provenance_finding_ids": tuple(
            item.id for item in report.findings if item.category in PROVENANCE_CATEGORIES
        ),
        "detectors_run": report.detectors_run,
        "diagnostic_codes": diagnostics,
        "scan_options": _portable_options(options),
        "limitations": tuple(limitations),
    }
    # Normalize datetimes, enums, nested models, and immutable mappings through
    # the public model before hashing. Issuance and later JSON verification must
    # hash the exact same representation.
    provisional = AuditCertificate(certificate_id=f"TAI1-{'A' * 32}", **claims)
    normalized_claims = _certificate_claims(provisional)
    certificate_id = _certificate_id(normalized_claims)
    certificate = provisional.model_copy(update={"certificate_id": certificate_id})
    if signing_key is None:
        return certificate
    signature = _sign(certificate, Path(signing_key))
    return certificate.model_copy(update={"signature": signature})


def verify_certificate(
    certificate: AuditCertificate,
    *,
    public_key: str | Path | None = None,
    artifact: str | Path | Artifact | None = None,
    revocation_list: CertificateRevocationList | None = None,
    require_revocation_check: bool = False,
    at_time: datetime | None = None,
) -> CertificateVerification:
    """Verify identity, signature, freshness, revocation, and optional artifact bytes."""

    explanations: list[str] = []
    claims = _certificate_claims(certificate)
    expected_id = _certificate_id(claims)
    id_valid = expected_id == certificate.certificate_id
    explanations.append(
        "Certificate content ID is valid." if id_valid else "Certificate content ID is invalid."
    )

    signature_verified: bool | None = None
    if certificate.signature is not None:
        if public_key is None:
            explanations.append("An issuer signature is present but no public key was supplied.")
        else:
            signature_verified = _verify_signature(certificate, Path(public_key))
            explanations.append(
                "Issuer signature is valid."
                if signature_verified
                else "Issuer signature is invalid or belongs to another key."
            )
    elif public_key is not None:
        signature_verified = False
        explanations.append("A public key was supplied, but the certificate is unsigned.")
    else:
        explanations.append("Certificate is unsigned; its issuer is not authenticated.")

    verification_time = _normalized_time(at_time)
    temporal_valid = certificate.issued_at <= verification_time and (
        certificate.expires_at is None or verification_time < certificate.expires_at
    )
    if certificate.issued_at > verification_time:
        explanations.append("Certificate issue time is in the future.")
    elif certificate.expires_at is not None and verification_time >= certificate.expires_at:
        explanations.append("Certificate has expired.")
    elif certificate.expires_at is None:
        explanations.append("Certificate has no recorded expiry time.")
    else:
        explanations.append("Certificate is within its recorded validity period.")

    artifact_verified: bool | None = None
    if artifact is not None:
        try:
            options = ScanOptions.model_validate(certificate.scan_options)
            descriptors = describe_artifact_inventory(artifact, options)
            actual = artifact_inventory_digest(descriptors)
            artifact_verified = actual == certificate.artifact_inventory_sha256
        except Exception as exc:
            artifact_verified = False
            explanations.append(
                f"Artifact inventory could not be verified: {type(exc).__name__}: {exc}"
            )
        else:
            explanations.append(
                "Artifact bytes match the certificate."
                if artifact_verified
                else "Artifact bytes do not match the certificate."
            )

    revocation_checked = False
    revocation_list_valid: bool | None = None
    revoked: bool | None = None
    if revocation_list is not None:
        if public_key is None:
            revocation_list_valid = False
            explanations.append(
                "A revocation list was supplied but no issuer public key was provided."
            )
        else:
            list_verification = verify_revocation_list(
                revocation_list,
                public_key=public_key,
                at_time=verification_time,
            )
            revocation_list_valid = list_verification.valid
            explanations.extend(list_verification.explanations)
            if certificate.signature is None:
                revocation_list_valid = False
                explanations.append(
                    "An unsigned certificate cannot be bound to an issuer revocation list."
                )
            elif revocation_list.issuer_key_id != certificate.signature.key_id:
                revocation_list_valid = False
                explanations.append(
                    "The revocation list belongs to a different certificate issuer."
                )
            elif list_verification.valid:
                revocation_checked = True
                revoked = any(
                    entry.certificate_id == certificate.certificate_id
                    for entry in revocation_list.entries
                )
                explanations.append(
                    "Certificate is revoked by the issuer."
                    if revoked
                    else "Certificate is not listed as revoked by the issuer."
                )
    elif require_revocation_check:
        revocation_list_valid = False
        explanations.append("Revocation status was required but no revocation list was supplied.")

    signature_ok = certificate.signature is None or signature_verified is True
    artifact_ok = artifact_verified is not False
    revocation_ok = (
        revocation_list_valid is not False
        and revoked is not True
        and (not require_revocation_check or revocation_checked)
    )
    valid = id_valid and signature_ok and artifact_ok and temporal_valid and revocation_ok
    return CertificateVerification(
        valid=valid,
        certificate_id_valid=id_valid,
        signature_present=certificate.signature is not None,
        signature_verified=signature_verified,
        artifact_verified=artifact_verified,
        temporal_valid=temporal_valid,
        revocation_checked=revocation_checked,
        revocation_list_valid=revocation_list_valid,
        revoked=revoked,
        explanations=tuple(explanations),
    )


def revoke_certificate(
    certificate: AuditCertificate,
    *,
    signing_key: str | Path,
    reason: RevocationReason = RevocationReason.UNSPECIFIED,
    explanation: str | None = None,
    replacement_certificate_id: str | None = None,
    existing: CertificateRevocationList | None = None,
    revoked_at: datetime | None = None,
    valid_for: timedelta = timedelta(days=30),
) -> CertificateRevocationList:
    """Create or advance an issuer-signed revocation list for one certificate."""

    if certificate.signature is None:
        raise AttestationError("Unsigned certificates have no authenticated issuer to revoke them")
    if _certificate_id(_certificate_claims(certificate)) != certificate.certificate_id:
        raise AttestationError("Refusing to revoke a certificate with an invalid content ID")
    if valid_for <= timedelta(0):
        raise AttestationError("Revocation-list validity duration must be positive")
    private_key = _load_private_key(Path(signing_key))
    issuer_key_id = _key_id(private_key.public_key())
    if issuer_key_id != certificate.signature.key_id or not _verify_payload_with_key(
        certificate.signature,
        _signed_payload(certificate),
        private_key.public_key(),
    ):
        raise AttestationError(
            "The signing key does not authenticate the certificate being revoked"
        )

    issue_time = _normalized_time(revoked_at)
    entries: dict[str, RevocationEntry] = {}
    sequence = 1
    if existing is not None:
        if existing.signature is None or not _verify_payload_with_key(
            existing.signature,
            _revocation_payload(existing),
            private_key.public_key(),
        ):
            raise AttestationError("Existing revocation-list signature is invalid")
        if existing.issuer_key_id != issuer_key_id:
            raise AttestationError("Existing revocation list belongs to a different issuer")
        if issue_time <= existing.issued_at:
            raise AttestationError(
                "An updated revocation list must have a later issue time than its predecessor"
            )
        entries = {entry.certificate_id: entry for entry in existing.entries}
        sequence = existing.sequence + 1
    if certificate.certificate_id in entries:
        raise AttestationError("Certificate is already present in the revocation list")
    entries[certificate.certificate_id] = RevocationEntry(
        certificate_id=certificate.certificate_id,
        revoked_at=issue_time,
        reason=reason,
        explanation=explanation,
        replacement_certificate_id=replacement_certificate_id,
    )
    provisional = CertificateRevocationList(
        issuer_key_id=issuer_key_id,
        sequence=sequence,
        issued_at=issue_time,
        expires_at=issue_time + valid_for,
        entries=tuple(entries[key] for key in sorted(entries)),
    )
    signature = _sign_payload(_revocation_payload(provisional), private_key)
    return provisional.model_copy(update={"signature": signature})


def verify_revocation_list(
    revocation_list: CertificateRevocationList,
    *,
    public_key: str | Path,
    at_time: datetime | None = None,
) -> RevocationListVerification:
    """Authenticate one revocation list and check its finite freshness window."""

    explanations: list[str] = []
    signature_verified = False
    if revocation_list.signature is None:
        explanations.append("Revocation list is unsigned.")
    else:
        signature_verified = _verify_detached_signature(
            revocation_list.signature,
            _revocation_payload(revocation_list),
            Path(public_key),
        )
        explanations.append(
            "Revocation-list signature is valid."
            if signature_verified
            else "Revocation-list signature is invalid or belongs to another key."
        )
    verification_time = _normalized_time(at_time)
    temporal_valid = revocation_list.issued_at <= verification_time < revocation_list.expires_at
    if revocation_list.issued_at > verification_time:
        explanations.append("Revocation list is not valid yet.")
    elif verification_time >= revocation_list.expires_at:
        explanations.append("Revocation list has expired and cannot establish current status.")
    else:
        explanations.append("Revocation list is within its freshness period.")
    return RevocationListVerification(
        valid=signature_verified and temporal_valid,
        signature_verified=signature_verified,
        temporal_valid=temporal_valid,
        issuer_key_id=revocation_list.issuer_key_id,
        sequence=revocation_list.sequence,
        explanations=tuple(explanations),
    )


def describe_artifact_inventory(
    target: str | Path | Artifact,
    options: ScanOptions,
) -> tuple[ArtifactDescriptor, ...]:
    """Describe exact bytes using the same discovery boundaries as scanning."""

    discovery = ArtifactDiscovery(
        DiscoveryOptions(
            max_file_size=options.max_file_size,
            max_files=options.max_files,
            follow_symlinks=options.follow_symlinks,
        )
    )
    artifacts = discovery.discover(target)
    if discovery.truncated or discovery.issues:
        raise AttestationError("Artifact inventory discovery was incomplete")
    descriptors: list[ArtifactDescriptor] = []
    for item in artifacts:
        try:
            digest = item.sha256(options.max_file_size)
        except Exception as exc:
            if item.artifact_type not in _CONTAINER_TYPES:
                raise AttestationError(f"Unable to hash {item.display_path}: {exc}") from exc
            digest = None
        descriptors.append(
            ArtifactDescriptor(
                path=item.display_path,
                artifact_type=item.artifact_type,
                media_type=item.media_type,
                size=item.size,
                sha256=digest,
            )
        )
    return tuple(descriptors)


def artifact_inventory_digest(descriptors: tuple[ArtifactDescriptor, ...]) -> str:
    """Hash a file by content, or a container by its ordered logical inventory."""

    if len(descriptors) == 1 and descriptors[0].sha256 is not None:
        return descriptors[0].sha256
    payload = [descriptor.model_dump(mode="json") for descriptor in descriptors]
    return _sha256_json(payload)


def load_certificate(path: str | Path) -> AuditCertificate:
    """Load and validate a certificate JSON file."""

    source = Path(path)
    try:
        if source.stat().st_size > _MAX_ATTESTATION_FILE_BYTES:
            raise AttestationError("Certificate exceeds the 2 MiB input limit")
        with source.open("rb") as handle:
            data = handle.read(_MAX_ATTESTATION_FILE_BYTES + 1)
        return AuditCertificate.model_validate_json(data)
    except AttestationError:
        raise
    except Exception as exc:
        raise AttestationError(f"Invalid certificate: {type(exc).__name__}: {exc}") from exc


def certificate_json(certificate: AuditCertificate) -> str:
    """Render stable, human-reviewable certificate JSON."""

    return json.dumps(
        certificate.model_dump(mode="json", exclude_none=True),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )


def load_revocation_list(path: str | Path) -> CertificateRevocationList:
    """Load a bounded signed revocation-list JSON file."""

    source = Path(path)
    try:
        if source.stat().st_size > _MAX_ATTESTATION_FILE_BYTES:
            raise AttestationError("Revocation list exceeds the 2 MiB input limit")
        with source.open("rb") as handle:
            data = handle.read(_MAX_ATTESTATION_FILE_BYTES + 1)
        result = CertificateRevocationList.model_validate_json(data)
        if result.signature is None:
            raise AttestationError("Revocation list is unsigned")
        return result
    except AttestationError:
        raise
    except Exception as exc:
        raise AttestationError(f"Invalid revocation list: {type(exc).__name__}: {exc}") from exc


def revocation_list_json(revocation_list: CertificateRevocationList) -> str:
    """Render stable, human-reviewable revocation-list JSON."""

    return json.dumps(
        revocation_list.model_dump(mode="json", exclude_none=True),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )


def certificate_schema() -> dict[str, Any]:
    """Return the JSON Schema for audit-certificate version 0.1."""

    schema = AuditCertificate.model_json_schema()
    schema["$id"] = "https://schemas.trueai.dev/certificate/0.1/schema.json"
    schema["title"] = "TrueAI Audit Certificate 0.1"
    return schema


def certificate_schema_json() -> str:
    """Render the audit-certificate schema deterministically."""

    return json.dumps(certificate_schema(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def revocation_list_schema() -> dict[str, Any]:
    """Return the JSON Schema for revocation-list version 0.1."""

    schema = CertificateRevocationList.model_json_schema()
    schema["$id"] = "https://schemas.trueai.dev/revocation-list/0.1/schema.json"
    schema["title"] = "TrueAI Certificate Revocation List 0.1"
    return schema


def revocation_list_schema_json() -> str:
    """Render the revocation-list schema deterministically."""

    return json.dumps(revocation_list_schema(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def generate_ed25519_keypair(private_path: str | Path, public_path: str | Path) -> str:
    """Generate a PEM keypair and return its stable public key identifier."""

    private_target = Path(private_path)
    public_target = Path(public_path)
    if private_target.exists() or public_target.exists():
        raise AttestationError("Refusing to overwrite an existing signing key")
    private_target.parent.mkdir(parents=True, exist_ok=True)
    public_target.parent.mkdir(parents=True, exist_ok=True)
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )
    except ImportError as exc:
        raise _attestation_dependency_error() from exc
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    public_bytes = private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    try:
        with private_target.open("xb") as handle:
            handle.write(private_bytes)
        with public_target.open("xb") as handle:
            handle.write(public_bytes)
    except Exception:
        private_target.unlink(missing_ok=True)
        public_target.unlink(missing_ok=True)
        raise
    with _suppress_os_error():
        os.chmod(private_target, 0o600)
    return _key_id(private_key.public_key())


def _portable_options(options: ScanOptions) -> dict[str, object]:
    payload = options.model_dump(mode="json", exclude={"cache_directory"})
    # Execution scheduling does not affect observations or artifact identity.
    payload["max_workers"] = 1
    return payload


def _certificate_id(claims: dict[str, object]) -> str:
    digest = hashlib.sha256(_canonical_json(claims)).digest()
    token = base64.b32encode(digest[:20]).decode("ascii").rstrip("=")
    return f"TAI1-{token}"


def _sha256_json(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


def canonical_json_bytes(value: object) -> bytes:
    """Serialize a signed TrueAI claim with the shared canonical JSON profile."""

    return _canonical_json(value)


def sign_detached_payload(
    payload: bytes,
    signing_key: str | Path,
) -> CertificateSignature:
    """Sign arbitrary bounded TrueAI control-plane bytes with Ed25519."""

    return _sign_payload(payload, _load_private_key(Path(signing_key)))


def verify_detached_payload(
    signature: CertificateSignature,
    payload: bytes,
    public_key: str | Path,
) -> bool:
    """Verify an Ed25519 signature and its key identifier."""

    return _verify_detached_signature(signature, payload, Path(public_key))


def _signed_payload(certificate: AuditCertificate) -> bytes:
    payload = certificate.model_dump(mode="json", exclude={"signature"}, exclude_none=False)
    if certificate.expires_at is None:
        payload.pop("expires_at", None)
    return _canonical_json(payload)


def _certificate_claims(certificate: AuditCertificate) -> dict[str, object]:
    """Return identity claims while retaining compatibility with pre-expiry 0.1 records."""

    payload = certificate.model_dump(
        mode="json", exclude={"certificate_id", "signature"}, exclude_none=False
    )
    if certificate.expires_at is None:
        # ``expires_at`` was introduced as an additive optional 0.1 field. Older
        # certificates did not hash a null placeholder, so omitting it preserves
        # their content IDs while finite-lifetime certificates bind the timestamp.
        payload.pop("expires_at", None)
    return payload


def _sign(certificate: AuditCertificate, private_path: Path) -> CertificateSignature:
    key = _load_private_key(private_path)
    return _sign_payload(_signed_payload(certificate), key)


def _load_private_key(private_path: Path) -> Any:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
    except ImportError as exc:
        raise _attestation_dependency_error() from exc
    try:
        key = load_pem_private_key(_read_key_file(private_path), password=None)
    except Exception as exc:
        raise AttestationError(f"Unable to load signing key: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise AttestationError("Signing key must be an Ed25519 private key")
    return key


def _sign_payload(payload: bytes, private_key: Any) -> CertificateSignature:
    signature = private_key.sign(payload)
    return CertificateSignature(
        key_id=_key_id(private_key.public_key()),
        value=base64.b64encode(signature).decode("ascii"),
    )


def _verify_signature(certificate: AuditCertificate, public_path: Path) -> bool:
    assert certificate.signature is not None
    return _verify_detached_signature(
        certificate.signature,
        _signed_payload(certificate),
        public_path,
    )


def _verify_detached_signature(
    signature: CertificateSignature,
    payload: bytes,
    public_path: Path,
) -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
    except ImportError as exc:
        raise _attestation_dependency_error() from exc

    try:
        key = load_pem_public_key(_read_key_file(public_path))
        if not isinstance(key, Ed25519PublicKey):
            return False
        return _verify_payload_with_key(signature, payload, key)
    except Exception:
        return False


def _verify_payload_with_key(signature: CertificateSignature, payload: bytes, key: Any) -> bool:
    try:
        if _key_id(key) != signature.key_id:
            return False
        key.verify(base64.b64decode(signature.value, validate=True), payload)
    except Exception:
        return False
    return True


def _revocation_payload(revocation_list: CertificateRevocationList) -> bytes:
    return _canonical_json(
        revocation_list.model_dump(mode="json", exclude={"signature"}, exclude_none=False)
    )


def _normalized_time(value: datetime | None) -> datetime:
    result = value or datetime.now(UTC)
    if result.tzinfo is None or result.utcoffset() is None:
        raise AttestationError("Verification time must include a UTC offset")
    return result.astimezone(UTC)


def _read_key_file(path: Path) -> bytes:
    try:
        size = path.stat().st_size
        if size > _MAX_KEY_FILE_BYTES:
            raise AttestationError(f"Key file exceeds {_MAX_KEY_FILE_BYTES} bytes")
        with path.open("rb") as handle:
            data = handle.read(_MAX_KEY_FILE_BYTES + 1)
    except AttestationError:
        raise
    except OSError as exc:
        raise AttestationError(f"Unable to read key file: {exc}") from exc
    if len(data) > _MAX_KEY_FILE_BYTES:
        raise AttestationError(f"Key file exceeds {_MAX_KEY_FILE_BYTES} bytes")
    return data


def _key_id(public_key: Any) -> str:
    try:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    except ImportError as exc:
        raise _attestation_dependency_error() from exc
    encoded = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _attestation_dependency_error() -> OptionalDependencyError:
    return OptionalDependencyError(
        "Signed certificates require the 'attestation' optional dependency"
    )


class _suppress_os_error:
    """Tiny local context manager that avoids importing contextlib for one chmod."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, exception_type: object, exception: object, traceback: object) -> bool:
        return isinstance(exception, OSError)
