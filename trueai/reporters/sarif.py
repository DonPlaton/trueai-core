"""SARIF 2.1.0 adapter for CI and code-scanning consumers."""

from __future__ import annotations

import json

from trueai.core.models import Finding, ScanDiagnostic, ScanReport, Severity

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

        rules: dict[str, dict[str, object]] = {}
        results: list[dict[str, object]] = []
        for finding in report.findings:
            rules.setdefault(
                finding.detector_id,
                {
                    "id": finding.detector_id,
                    "name": finding.detector_id.replace(".", "_"),
                    "shortDescription": {"text": finding.title},
                    "help": {"text": finding.description},
                    "properties": {
                        "category": finding.category.value,
                        "provenanceClass": finding.provenance_class.value,
                    },
                },
            )
            results.append(self._result(finding))
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
                            "informationUri": "https://github.com/trueai-core/trueai-core",
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
