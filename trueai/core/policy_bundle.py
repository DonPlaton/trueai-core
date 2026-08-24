"""Signed enterprise policy bundles, baselines, exceptions, and audit trails."""

from __future__ import annotations

import base64
import fnmatch
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Self

import yaml
from pydantic import Field, ValidationError, field_validator, model_validator

from trueai.core.certificates import (
    CertificateSignature,
    canonical_json_bytes,
    sign_detached_payload,
    verify_detached_payload,
)
from trueai.core.errors import PolicyValidationError
from trueai.core.models import (
    Finding,
    FindingCategory,
    FrozenModel,
    PolicyAction,
    PolicyAuditEntry,
    PolicyDecision,
    ScanReport,
)
from trueai.core.policy import PolicyProfile

POLICY_BUNDLE_SCHEMA_VERSION: Literal["0.1"] = "0.1"
_MAX_BUNDLE_BYTES = 1024 * 1024
_MAX_CONTROLS_BYTES = 512 * 1024
_MAX_LIFETIME = timedelta(days=366)
_PROTECTED = {
    FindingCategory.C2PA_PROVENANCE,
    FindingCategory.PROVIDER_WATERMARK,
}


class FindingSelector(FrozenModel):
    """Deterministic selector for policy controls; every populated field must match."""

    finding_id: str | None = None
    detector_id: str | None = None
    category: FindingCategory | None = None
    artifact_glob: str | None = Field(default=None, min_length=1, max_length=500)
    provider: str | None = None
    tags_all: tuple[str, ...] = ()

    @model_validator(mode="after")
    def require_constraint(self) -> Self:
        if not any(
            (
                self.finding_id,
                self.detector_id,
                self.category,
                self.artifact_glob,
                self.provider,
                self.tags_all,
            )
        ):
            raise ValueError("A finding selector must contain at least one constraint")
        if len(set(self.tags_all)) != len(self.tags_all):
            raise ValueError("Selector tags must be unique")
        return self

    def matches(self, finding: Finding) -> bool:
        """Return whether all declared constraints match one immutable finding."""

        path = finding.artifact_path.replace(chr(92), "/")
        return (
            (self.finding_id is None or finding.id == self.finding_id)
            and (self.detector_id is None or finding.detector_id == self.detector_id)
            and (self.category is None or finding.category == self.category)
            and (
                self.artifact_glob is None
                or fnmatch.fnmatchcase(path, self.artifact_glob.replace(chr(92), "/"))
            )
            and (self.provider is None or finding.provider == self.provider)
            and set(self.tags_all).issubset(finding.tags)
        )


class PolicySuppression(FrozenModel):
    """Finite, approved suppression that retains the underlying finding."""

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,119}$")
    selector: FindingSelector
    reason: str = Field(min_length=3, max_length=1000)
    approved_by: str = Field(min_length=1, max_length=200)
    expires_at: datetime

    @field_validator("expires_at")
    @classmethod
    def require_offset(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Suppression expiry must include a UTC offset")
        return value


class PolicyException(PolicySuppression):
    """Finite, approved action override for matching findings."""

    action: PolicyAction


class PolicyBundleControls(FrozenModel):
    """Unsigned authoring input for bundle controls."""

    suppressions: tuple[PolicySuppression, ...] = ()
    exceptions: tuple[PolicyException, ...] = ()

    @classmethod
    def from_yaml(cls, source: str | Path) -> PolicyBundleControls:
        path = Path(source)
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise PolicyValidationError(f"Unable to read policy controls: {exc}") from exc
        if len(data) > _MAX_CONTROLS_BYTES:
            raise PolicyValidationError(
                f"Policy controls exceed the {_MAX_CONTROLS_BYTES} byte limit"
            )
        try:
            raw: Any = yaml.safe_load(data.decode("utf-8"))
            return cls.model_validate(raw or {})
        except (UnicodeError, yaml.YAMLError, ValidationError, ValueError) as exc:
            raise PolicyValidationError(f"Invalid policy controls: {exc}") from exc


class EnterprisePolicyBundle(FrozenModel):
    """Content-addressed policy profile and its signed operational controls."""

    bundle_schema_version: Literal["0.1"] = POLICY_BUNDLE_SCHEMA_VERSION
    bundle_id: str = Field(pattern=r"^TPB1-[A-Z2-7]{32}$")
    issuer: str = Field(min_length=1, max_length=200)
    issued_at: datetime
    expires_at: datetime
    profile: PolicyProfile
    baseline_finding_ids: tuple[str, ...] = ()
    suppressions: tuple[PolicySuppression, ...] = ()
    exceptions: tuple[PolicyException, ...] = ()
    signature: CertificateSignature | None = None

    @model_validator(mode="after")
    def validate_bundle(self) -> Self:
        for name, value in (("issue", self.issued_at), ("expiry", self.expires_at)):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"Bundle {name} time must include a UTC offset")
        if self.expires_at <= self.issued_at:
            raise ValueError("Bundle expiry must be later than issue time")
        if self.expires_at - self.issued_at > _MAX_LIFETIME:
            raise ValueError("Bundle lifetime may not exceed 366 days")
        if self.baseline_finding_ids != tuple(sorted(set(self.baseline_finding_ids))):
            raise ValueError("Baseline finding IDs must be sorted and unique")
        control_ids = [item.id for item in (*self.suppressions, *self.exceptions)]
        if len(control_ids) != len(set(control_ids)):
            raise ValueError("Suppression and exception IDs must be unique")
        if any(
            item.expires_at <= self.issued_at for item in (*self.suppressions, *self.exceptions)
        ):
            raise ValueError("A control must remain valid after the bundle issue time")
        if any(
            item.expires_at > self.expires_at for item in (*self.suppressions, *self.exceptions)
        ):
            raise ValueError("A control cannot outlive its containing bundle")
        return self


class PolicyBundleVerification(FrozenModel):
    """Cryptographic, identity, and temporal verification of a policy bundle."""

    valid: bool
    bundle_id_valid: bool
    signature_present: bool
    signature_verified: bool
    temporal_valid: bool
    explanations: tuple[str, ...]


class EnterprisePolicyEvaluation(FrozenModel):
    """Policy decisions plus the exact override trail that produced them."""

    decisions: tuple[PolicyDecision, ...]
    audit: tuple[PolicyAuditEntry, ...]
    review_count: int = Field(ge=0)
    violation_count: int = Field(ge=0)


def issue_policy_bundle(
    profile: PolicyProfile,
    *,
    issuer: str,
    signing_key: str | Path,
    expires_in: timedelta = timedelta(days=90),
    baseline_finding_ids: tuple[str, ...] = (),
    controls: PolicyBundleControls | None = None,
    issued_at: datetime | None = None,
) -> EnterprisePolicyBundle:
    """Create and sign a finite-lifetime enterprise policy bundle."""

    issue_time = _normalized_time(issued_at)
    if expires_in <= timedelta(0) or expires_in > _MAX_LIFETIME:
        raise PolicyValidationError("Policy bundle lifetime must be between 1 second and 366 days")
    selected = controls or PolicyBundleControls()
    claims = {
        "issuer": issuer,
        "issued_at": issue_time,
        "expires_at": issue_time + expires_in,
        "profile": profile,
        "baseline_finding_ids": tuple(sorted(set(baseline_finding_ids))),
        "suppressions": selected.suppressions,
        "exceptions": selected.exceptions,
    }
    provisional = EnterprisePolicyBundle(bundle_id=f"TPB1-{'A' * 32}", **claims)
    bundle_id = _bundle_id(_bundle_claims(provisional))
    unsigned = provisional.model_copy(update={"bundle_id": bundle_id})
    signature = sign_detached_payload(_bundle_payload(unsigned), signing_key)
    return unsigned.model_copy(update={"signature": signature})


def verify_policy_bundle(
    bundle: EnterprisePolicyBundle,
    *,
    public_key: str | Path,
    at_time: datetime | None = None,
) -> PolicyBundleVerification:
    """Verify content identity, issuer signature, and finite validity."""

    explanations: list[str] = []
    expected_id = _bundle_id(_bundle_claims(bundle))
    identity_valid = expected_id == bundle.bundle_id
    if not identity_valid:
        explanations.append("The policy bundle content ID does not match its claims.")
    signature_present = bundle.signature is not None
    signature_verified = bool(
        bundle.signature is not None
        and verify_detached_payload(bundle.signature, _bundle_payload(bundle), public_key)
    )
    if not signature_present:
        explanations.append("The policy bundle is unsigned.")
    elif not signature_verified:
        explanations.append("The policy bundle signature or key identifier is invalid.")
    verification_time = _normalized_time(at_time)
    temporal_valid = bundle.issued_at <= verification_time < bundle.expires_at
    if verification_time < bundle.issued_at:
        explanations.append("The policy bundle is not valid yet.")
    elif verification_time >= bundle.expires_at:
        explanations.append("The policy bundle has expired.")
    if identity_valid and signature_verified and temporal_valid:
        explanations.append("Bundle identity, issuer signature, and validity interval verified.")
    return PolicyBundleVerification(
        valid=identity_valid and signature_verified and temporal_valid,
        bundle_id_valid=identity_valid,
        signature_present=signature_present,
        signature_verified=signature_verified,
        temporal_valid=temporal_valid,
        explanations=tuple(explanations),
    )


def policy_bundle_json(bundle: EnterprisePolicyBundle) -> str:
    """Render a policy bundle deterministically for review and distribution."""

    return json.dumps(
        bundle.model_dump(mode="json", exclude_none=True),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )


def policy_bundle_schema() -> dict[str, Any]:
    """Return the JSON Schema for enterprise policy bundle version 0.1."""

    schema = EnterprisePolicyBundle.model_json_schema(mode="serialization")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = "https://schemas.trueai.dev/policy-bundle/0.1/schema.json"
    return schema


def policy_bundle_schema_json() -> str:
    """Render the policy-bundle schema deterministically."""

    return json.dumps(
        policy_bundle_schema(),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + chr(10)


def load_policy_bundle(path: str | Path) -> EnterprisePolicyBundle:
    """Read and validate a bounded policy bundle JSON document."""

    target = Path(path)
    try:
        size = target.stat().st_size
        if size > _MAX_BUNDLE_BYTES:
            raise PolicyValidationError(f"Policy bundle exceeds the {_MAX_BUNDLE_BYTES} byte limit")
        with target.open("rb") as handle:
            data = handle.read(_MAX_BUNDLE_BYTES + 1)
    except PolicyValidationError:
        raise
    except OSError as exc:
        raise PolicyValidationError(f"Unable to read policy bundle: {exc}") from exc
    if len(data) > _MAX_BUNDLE_BYTES:
        raise PolicyValidationError(f"Policy bundle exceeds the {_MAX_BUNDLE_BYTES} byte limit")
    try:
        return EnterprisePolicyBundle.model_validate_json(data)
    except (ValidationError, ValueError) as exc:
        raise PolicyValidationError(f"Invalid policy bundle: {exc}") from exc


def apply_policy_bundle(
    report: ScanReport,
    bundle: EnterprisePolicyBundle,
    *,
    public_key: str | Path,
    at_time: datetime | None = None,
) -> ScanReport:
    """Verify a bundle, evaluate every finding, and attach its audit trail."""

    verification_time = _normalized_time(at_time)
    verification = verify_policy_bundle(
        bundle,
        public_key=public_key,
        at_time=verification_time,
    )
    if not verification.valid:
        raise PolicyValidationError(
            "Policy bundle verification failed: " + " ".join(verification.explanations)
        )
    evaluation = _evaluate(report.findings, bundle, verification_time)
    summary = report.summary.model_copy(
        update={
            "review_count": evaluation.review_count,
            "violation_count": evaluation.violation_count,
        }
    )
    return report.model_copy(
        update={
            "policy": bundle.profile.policy,
            "policy_decisions": evaluation.decisions,
            "policy_bundle_id": bundle.bundle_id,
            "policy_audit": evaluation.audit,
            "summary": summary,
        }
    )


def _evaluate(
    findings: tuple[Finding, ...],
    bundle: EnterprisePolicyBundle,
    at_time: datetime,
) -> EnterprisePolicyEvaluation:
    decisions: list[PolicyDecision] = []
    audit: list[PolicyAuditEntry] = []
    review_count = 0
    violation_count = 0
    baseline = set(bundle.baseline_finding_ids)
    for finding in findings:
        action = bundle.profile.action_for(finding)
        rationale = (
            f"Policy bundle {bundle.bundle_id} maps category "
            f"'{finding.category.value}' to '{action.value}'."
        )
        matched_exceptions = sorted(
            (item for item in bundle.exceptions if item.selector.matches(finding)),
            key=lambda item: item.id,
        )
        matched_suppressions = sorted(
            (item for item in bundle.suppressions if item.selector.matches(finding)),
            key=lambda item: item.id,
        )
        active_exceptions = [item for item in matched_exceptions if at_time < item.expires_at]
        active_suppressions = [item for item in matched_suppressions if at_time < item.expires_at]
        if finding.category in _PROTECTED:
            action = PolicyAction.PRESERVE
            matched = [*matched_exceptions, *matched_suppressions]
            if finding.id in baseline or matched:
                audit.append(
                    PolicyAuditEntry(
                        finding_id=finding.id,
                        source="protected",
                        rule_id=matched[0].id if matched else None,
                        action=action,
                        reason=(
                            "Protected provenance remains visible and preserved; enterprise "
                            "overrides cannot suppress or remove it."
                        ),
                    )
                )
            rationale = "Protected provenance is preserved independently of enterprise overrides."
        elif active_exceptions:
            actions = {item.action for item in active_exceptions}
            if len(actions) != 1:
                identifiers = ", ".join(item.id for item in active_exceptions)
                raise PolicyValidationError(
                    f"Conflicting active policy exceptions match {finding.id}: {identifiers}"
                )
            selected_exception = active_exceptions[0]
            action = selected_exception.action
            rationale = f"Approved exception '{selected_exception.id}' selects '{action.value}'."
            audit.append(_audit_entry(finding, selected_exception, "exception", action))
        elif active_suppressions:
            selected_suppression = active_suppressions[0]
            action = PolicyAction.IGNORE
            rationale = (
                f"Approved suppression '{selected_suppression.id}' acknowledges this finding."
            )
            audit.append(_audit_entry(finding, selected_suppression, "suppression", action))
        elif finding.id in baseline:
            action = PolicyAction.IGNORE
            rationale = "The exact finding ID is present in the signed baseline."
            audit.append(
                PolicyAuditEntry(
                    finding_id=finding.id,
                    source="baseline",
                    action=action,
                    reason=rationale,
                )
            )
        for expired in (*matched_exceptions, *matched_suppressions):
            if at_time >= expired.expires_at:
                audit.append(
                    PolicyAuditEntry(
                        finding_id=finding.id,
                        source=(
                            "exception" if isinstance(expired, PolicyException) else "suppression"
                        ),
                        rule_id=expired.id,
                        action=action,
                        reason=f"Expired control '{expired.id}' did not override the decision.",
                        approved_by=expired.approved_by,
                        expires_at=expired.expires_at,
                    )
                )
        if action in {PolicyAction.REVIEW, PolicyAction.REMOVE}:
            review_count += 1
        elif action == PolicyAction.ERROR:
            violation_count += 1
        decisions.append(PolicyDecision(finding_id=finding.id, action=action, rationale=rationale))
    return EnterprisePolicyEvaluation(
        decisions=tuple(decisions),
        audit=tuple(audit),
        review_count=review_count,
        violation_count=violation_count,
    )


def _audit_entry(
    finding: Finding,
    control: PolicySuppression,
    source: Literal["suppression", "exception"],
    action: PolicyAction,
) -> PolicyAuditEntry:
    return PolicyAuditEntry(
        finding_id=finding.id,
        source=source,
        rule_id=control.id,
        action=action,
        reason=control.reason,
        approved_by=control.approved_by,
        expires_at=control.expires_at,
    )


def _bundle_claims(bundle: EnterprisePolicyBundle) -> dict[str, object]:
    return bundle.model_dump(
        mode="json",
        exclude={"bundle_id", "signature"},
        exclude_none=False,
    )


def _bundle_payload(bundle: EnterprisePolicyBundle) -> bytes:
    return canonical_json_bytes(
        bundle.model_dump(mode="json", exclude={"signature"}, exclude_none=False)
    )


def _bundle_id(claims: dict[str, object]) -> str:
    digest = hashlib.sha256(canonical_json_bytes(claims)).digest()
    token = base64.b32encode(digest[:20]).decode("ascii").rstrip("=")
    return f"TPB1-{token}"


def _normalized_time(value: datetime | None) -> datetime:
    result = value or datetime.now(UTC)
    if result.tzinfo is None or result.utcoffset() is None:
        raise PolicyValidationError("Policy bundle time must include a UTC offset")
    return result.astimezone(UTC)
