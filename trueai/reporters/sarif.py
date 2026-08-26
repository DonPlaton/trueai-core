"""SARIF 2.1.0 adapter for CI and code-scanning consumers."""

from __future__ import annotations

import json

from trueai.core.models import (
    Finding,
    ScanDiagnostic,
    ScanReport,
    Severity,
    evidence_limits,
)

_LEVELS = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


class SARIFReporter:
    """Map findings to SARIF while retaining TrueAI evidence semantics in properties."""

    def render(
        self,
        report: ScanReport,
        *,
        indent: int | None = 2,
        attestation_properties: dict[str, object] | None = None,
    ) -> str:
        """Return a SARIF JSON document.

        ``attestation_properties`` comes from
        :func:`trueai.core.evaluation.sarif_properties`. It lands in the run's
        property bag under keys that name what was established, so a dashboard
        cannot render a process attestation as an authorship badge.
        """

        # A rule is a class of check and a result is one instance of it. Taking
        # the rule's description from whichever finding arrived first labelled
        # every alert under `design.raster-metadata.v1` "Image metadata:
        # Software", including the ones about Author -- and a code scanning
        # dashboard groups by rule and shows exactly that line.
        categories: dict[str, set[str]] = {}
        provenance: dict[str, set[str]] = {}
        limits: dict[str, list[str]] = {}
        results: list[dict[str, object]] = []
        for finding in report.findings:
            detector = finding.detector_id
            categories.setdefault(detector, set()).add(finding.category.value)
            provenance.setdefault(detector, set()).add(finding.provenance_class.value)
            for sentence in evidence_limits(finding.confidence_type, finding.provenance_class):
                if sentence not in limits.setdefault(detector, []):
                    limits[detector].append(sentence)
            results.append(self._result(finding))
        rules = {
            detector: self._rule(detector, categories[detector], provenance[detector], limits)
            for detector in categories
        }
        blocking = any(
            diagnostic.severity in {Severity.HIGH, Severity.CRITICAL}
            for diagnostic in report.diagnostics
        )
        payload = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "TrueAI Core",
                            "version": report.package_version,
                            "informationUri": "https://github.com/DonPlaton/trueai-core",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                    # An incomplete scan must not read as a clean one. A blocking
                    # diagnostic marks the invocation unsuccessful, which is how a
                    # SARIF consumer learns the run cannot be trusted even when
                    # the results array is empty.
                    "invocations": [
                        {
                            "executionSuccessful": not blocking,
                            "toolExecutionNotifications": [
                                self._notification(diagnostic) for diagnostic in report.diagnostics
                            ],
                        }
                    ],
                    "properties": {
                        "trueaiSchemaVersion": report.schema_version,
                        "trueaiIntegrityStatus": report.integrity.status.value,
                        **(attestation_properties or {}),
                    },
                }
            ],
        }
        return json.dumps(payload, ensure_ascii=False, indent=indent, sort_keys=True)

    @staticmethod
    def _rule(
        detector_id: str,
        categories: set[str],
        provenance: set[str],
        limits: dict[str, list[str]],
    ) -> dict[str, object]:
        """Describe the detector, and what a result from it does not establish.

        ``fullDescription`` is what a code scanning alert page renders as the
        explanation of a rule, which makes it the one place in this integration
        most likely to be read by somebody who has not read the documentation. It
        carries the evidence-class limits rather than nothing.
        """

        named = ", ".join(sorted(categories))
        caveats = " ".join(limits.get(detector_id, []))
        return {
            "id": detector_id,
            "name": detector_id.replace(".", "_"),
            "shortDescription": {"text": f"TrueAI {detector_id} reports {named} observations."},
            "fullDescription": {"text": caveats},
            "help": {"text": caveats},
            "properties": {
                "categories": sorted(categories),
                "provenanceClasses": sorted(provenance),
            },
        }

    @staticmethod
    def _notification(diagnostic: ScanDiagnostic) -> dict[str, object]:
        """Map one scan diagnostic onto a SARIF tool-execution notification."""

        notification: dict[str, object] = {
            "descriptor": {"id": diagnostic.code},
            "level": _LEVELS[diagnostic.severity],
            "message": {"text": diagnostic.message},
            "properties": {"trueaiSeverity": diagnostic.severity.value},
        }
        if diagnostic.artifact_path:
            notification["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": diagnostic.artifact_path.replace("\\", "/")}
                    }
                }
            ]
        return notification

    @staticmethod
    def _result(finding: Finding) -> dict[str, object]:
        physical_location: dict[str, object] = {
            "artifactLocation": {"uri": finding.artifact_path.replace("\\", "/")}
        }
        if finding.location and finding.location.line:
            physical_location["region"] = {
                "startLine": finding.location.line,
                "startColumn": finding.location.column or 1,
            }
        result: dict[str, object] = {
            "ruleId": finding.detector_id,
            "level": _LEVELS[finding.severity],
            "message": {"text": f"{finding.title}: {finding.description}"},
            "fingerprints": {"trueaiFindingId": finding.id},
            "properties": {
                "category": finding.category.value,
                "confidence": finding.confidence,
                "confidenceType": finding.confidence_type.value,
                "evidenceType": finding.evidence_type.value,
                "provider": finding.provider,
                "provenanceClass": finding.provenance_class.value,
                "removable": finding.removable,
                "tags": list(finding.tags),
                "evidence": finding.evidence,
            },
            "locations": [
                {
                    "physicalLocation": physical_location,
                }
            ],
        }
        return result
