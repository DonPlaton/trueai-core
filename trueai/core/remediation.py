"""Policy-driven planning, preview, safe output handling, and verified application."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from collections import defaultdict
from pathlib import Path

from trueai.cleaners import cleaner_for
from trueai.core.errors import RemediationError
from trueai.core.finding_id import finding_id_is_valid
from trueai.core.models import (
    ArtifactType,
    Finding,
    FindingCategory,
    IntegrityReport,
    IntegrityStatus,
    PolicyAction,
    ProvenanceClass,
    Remediation,
    RemediationPlan,
    RemediationResult,
    RemediationSafety,
    ScanOptions,
    ScanReport,
    Severity,
)
from trueai.core.policy import PolicyProfile

_PROTECTED_CATEGORIES = {
    FindingCategory.C2PA_PROVENANCE,
    FindingCategory.PROVIDER_WATERMARK,
}
_PROTECTED_PROVENANCE = {
    ProvenanceClass.PROVENANCE_METADATA,
    ProvenanceClass.AUTHENTICATED_PROVENANCE,
    ProvenanceClass.PROVIDER_WATERMARK,
}


class RemediationPlanner:
    """Translate policy decisions into an explicit, reviewable plan."""

    def plan(self, report: ScanReport, policy: PolicyProfile) -> RemediationPlan:
        """Create remediations without applying them."""

        recorded_actions = {
            decision.finding_id: decision.action for decision in report.policy_decisions
        }
        protected_artifacts = {
            finding.artifact_path
            for finding in report.findings
            if finding.category in _PROTECTED_CATEGORIES
            or finding.provenance_class in _PROTECTED_PROVENANCE
        }
        grouped: dict[tuple[str, str], list[Finding]] = defaultdict(list)
        review: list[str] = []
        preserved: list[str] = []
        blocked: list[str] = []
        for finding in report.findings:
            action = recorded_actions.get(finding.id, policy.action_for(finding))
            if action == PolicyAction.PRESERVE:
                preserved.append(finding.id)
                continue
            if action in {PolicyAction.REVIEW, PolicyAction.ERROR}:
                review.append(finding.id)
                continue
            if action != PolicyAction.REMOVE:
                continue
            if (
                finding.artifact_path in protected_artifacts
                or finding.category in _PROTECTED_CATEGORIES
                or finding.provenance_class in _PROTECTED_PROVENANCE
            ):
                preserved.append(finding.id)
                blocked.append(finding.id)
                review.append(finding.id)
                continue
            if not finding.removable or finding.remediation_id in {None, "git.rewrite-history"}:
                review.append(finding.id)
                blocked.append(finding.id)
                continue
            assert finding.remediation_id is not None
            grouped[(finding.artifact_path, finding.remediation_id)].append(finding)
        remediations: list[Remediation] = []
        for (artifact_path, remediation_id), findings in sorted(grouped.items()):
            safety = self._safety(remediation_id)
            finding_ids = tuple(item.id for item in findings)
            remediations.append(
                Remediation(
                    id=_remediation_identifier(artifact_path, remediation_id, finding_ids),
                    remediation_id=remediation_id,
                    artifact_path=artifact_path,
                    finding_ids=finding_ids,
                    description=f"Apply {remediation_id} to {len(findings)} selected finding(s).",
                    safety=safety,
                    payload={
                        "findings": [
                            item.model_dump(mode="json", exclude_none=True) for item in findings
                        ]
                    },
                )
            )
        return RemediationPlan(
            policy=policy.policy,
            remediations=tuple(remediations),
            review_findings=tuple(sorted(review)),
            preserved_findings=tuple(sorted(preserved)),
            blocked_findings=tuple(sorted(blocked)),
        )

    @staticmethod
    def _safety(remediation_id: str) -> RemediationSafety:
        if remediation_id.startswith(("docx.", "pptx.", "xlsx.", "pdf.", "image.", "media.")):
            return RemediationSafety.SAFE_METADATA
        if remediation_id.startswith("git."):
            return RemediationSafety.DESTRUCTIVE
        return RemediationSafety.PREDICTABLE_CONTENT


class RemediationService:
    """Apply a plan to one file through a temporary output and integrity gate."""

    def apply(
        self,
        source: str | Path,
        report: ScanReport,
        plan: RemediationPlan,
        *,
        output_path: str | Path | None = None,
        in_place: bool = False,
        dry_run: bool = False,
        options: ScanOptions | None = None,
    ) -> RemediationResult:
        """Apply planned changes; originals are preserved unless ``in_place`` is explicit.

        ``options`` should be the same boundaries the scan ran under, so a cleaner
        that re-reads the artifact applies the limits the detector applied rather
        than inventing its own.
        """

        source_path = Path(source).resolve(strict=True)
        if not source_path.is_file():
            raise RemediationError("v0.1 applies remediation to one file at a time")
        relevant = self._validate_and_bind(source_path, report, plan)
        if not relevant:
            return RemediationResult(
                artifact_path=str(source_path),
                output_path=None,
                integrity=IntegrityReport(
                    status=IntegrityStatus.NOT_MODIFIED,
                    explanation="The selected policy produced no applicable remediation.",
                ),
                dry_run=dry_run,
            )
        if dry_run:
            return RemediationResult(
                artifact_path=str(source_path),
                output_path=str(self._destination(source_path, output_path, in_place)),
                applied_remediation_ids=tuple(item.id for item in relevant),
                changed_fields=tuple(item.remediation_id for item in relevant),
                integrity=IntegrityReport(
                    status=IntegrityStatus.NOT_MODIFIED,
                    explanation="Dry run; the remediation plan was not applied.",
                ),
                dry_run=True,
            )
        artifact_type = report.artifact.artifact_type
        if artifact_type in {ArtifactType.DIRECTORY, ArtifactType.GIT_REPOSITORY}:
            raise RemediationError(
                "Directory and Git history remediation is not applied automatically"
            )
        destination = self._destination(source_path, output_path, in_place)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() and not in_place:
            raise RemediationError(f"Refusing to overwrite existing output: {destination}")
        cleaner = cleaner_for(artifact_type)
        unsupported = {
            item.remediation_id
            for item in relevant
            if item.remediation_id not in cleaner.supported_remediation_ids
        }
        if unsupported:
            raise RemediationError(
                f"Cleaner does not support planned operations: {sorted(unsupported)}"
            )
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=".trueai-",
            suffix=destination.suffix,
            dir=destination.parent,
        )
        os.close(file_descriptor)
        temporary = Path(temporary_name)
        backup_path: Path | None = None
        try:
            outcome = cleaner.apply(source_path, temporary, relevant, options)
            if outcome.integrity.status != IntegrityStatus.PASS:
                raise RemediationError(
                    f"Integrity verification failed: {outcome.integrity.explanation}"
                )
            if in_place:
                backup_path = self._backup_path(source_path)
                shutil.copy2(source_path, backup_path)
                try:
                    with temporary.open("rb") as cleaned, source_path.open("wb") as original:
                        shutil.copyfileobj(cleaned, original, length=1024 * 1024)
                        original.flush()
                        os.fsync(original.fileno())
                    shutil.copystat(backup_path, source_path, follow_symlinks=False)
                except Exception:
                    shutil.copy2(backup_path, source_path)
                    raise
            else:
                shutil.copystat(source_path, temporary, follow_symlinks=False)
                os.replace(temporary, destination)
        finally:
            if temporary.exists():
                temporary.unlink()
        return RemediationResult(
            artifact_path=str(source_path),
            output_path=str(destination),
            backup_path=str(backup_path) if backup_path else None,
            applied_remediation_ids=tuple(item.id for item in relevant),
            changed_fields=outcome.changed_fields,
            integrity=outcome.integrity,
        )

    @staticmethod
    def _validate_and_bind(
        source_path: Path,
        report: ScanReport,
        plan: RemediationPlan,
    ) -> tuple[Remediation, ...]:
        if report.policy is None or report.policy != plan.policy:
            raise RemediationError("Remediation plan is not bound to the scan policy")
        if any(
            diagnostic.severity in {Severity.HIGH, Severity.CRITICAL}
            for diagnostic in report.diagnostics
        ):
            raise RemediationError("Refusing remediation from an incomplete or failed scan")
        expected_name = Path(report.artifact.path).name
        if expected_name != source_path.name:
            raise RemediationError(
                f"Scanned artifact name {expected_name!r} does not match {source_path.name!r}"
            )
        expected_hash = report.artifact.sha256
        if expected_hash is None:
            raise RemediationError("Scan report has no source hash for remediation binding")
        actual_hash = RemediationService._sha256_file(source_path)
        if actual_hash != expected_hash:
            raise RemediationError(
                "Artifact changed after scanning; create a new scan and remediation plan"
            )

        findings = {finding.id: finding for finding in report.findings}
        decisions = {decision.finding_id: decision.action for decision in report.policy_decisions}
        protected_artifacts = {
            finding.artifact_path
            for finding in report.findings
            if finding.category in _PROTECTED_CATEGORIES
            or finding.provenance_class in _PROTECTED_PROVENANCE
        }
        sanitized: list[Remediation] = []
        seen_findings: set[str] = set()
        for remediation in plan.remediations:
            if not remediation.finding_ids:
                raise RemediationError("Remediation contains no finding IDs")
            expected_remediation_id = _remediation_identifier(
                remediation.artifact_path,
                remediation.remediation_id,
                remediation.finding_ids,
            )
            if remediation.id != expected_remediation_id:
                raise RemediationError(f"Remediation identity is invalid: {remediation.id}")
            selected: list[Finding] = []
            for finding_id in remediation.finding_ids:
                if finding_id in seen_findings:
                    raise RemediationError(
                        f"Finding appears in multiple remediations: {finding_id}"
                    )
                finding = findings.get(finding_id)
                if finding is None or not finding_id_is_valid(finding):
                    raise RemediationError(f"Unknown or mutated finding: {finding_id}")
                if decisions.get(finding_id) != PolicyAction.REMOVE:
                    raise RemediationError(f"Policy did not authorize removal: {finding_id}")
                if finding.artifact_path != remediation.artifact_path:
                    raise RemediationError(f"Remediation artifact mismatch: {finding_id}")
                if finding.remediation_id != remediation.remediation_id or not finding.removable:
                    raise RemediationError(
                        f"Finding is not removable by this operation: {finding_id}"
                    )
                if (
                    finding.artifact_path in protected_artifacts
                    or finding.category in _PROTECTED_CATEGORIES
                    or finding.provenance_class in _PROTECTED_PROVENANCE
                ):
                    raise RemediationError(
                        f"Artifact contains protected provenance; removal blocked: {finding_id}"
                    )
                selected.append(finding)
                seen_findings.add(finding_id)
            remediation_data = remediation.model_dump(mode="python")
            remediation_data["payload"] = {
                "findings": [
                    finding.model_dump(mode="json", exclude_none=True) for finding in selected
                ]
            }
            sanitized.append(Remediation.model_validate(remediation_data))
        return tuple(
            remediation
            for remediation in sanitized
            if remediation.artifact_path in {source_path.name, report.artifact.path}
        )

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _destination(
        source: Path,
        output_path: str | Path | None,
        in_place: bool,
    ) -> Path:
        if in_place and output_path is not None:
            raise RemediationError("--in-place and an explicit output path are mutually exclusive")
        if in_place:
            return source
        if output_path is not None:
            return Path(output_path).resolve()
        return source.with_name(f"{source.stem}.cleaned{source.suffix}")

    @staticmethod
    def _backup_path(source: Path) -> Path:
        base = source.with_name(f"{source.name}.trueai.bak")
        if not base.exists():
            return base
        index = 1
        while True:
            candidate = source.with_name(f"{source.name}.trueai.{index}.bak")
            if not candidate.exists():
                return candidate
            index += 1


def _remediation_identifier(
    artifact_path: str,
    remediation_id: str,
    finding_ids: tuple[str, ...],
) -> str:
    identity = f"{artifact_path}\x00{remediation_id}\x00{','.join(finding_ids)}"
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return f"rem_{digest}"
