"""Explicit AI-tool attribution detector using external provider rules."""

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
from trueai.detectors.base import BaseDetector, FindingBuffer
from trueai.providers import AttributionContext, attribution_rules, is_standalone_attribution


class ExplicitAttributionDetector(BaseDetector):
    """Detect literal attributions; it does not infer authorship from style."""

    id = "text.explicit-attribution.v1"
    supported_types = frozenset({ArtifactType.TEXT, ArtifactType.MARKDOWN})
    categories = frozenset({FindingCategory.EXPLICIT_AI_ATTRIBUTION})

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        text = artifact.read_text(context.options.max_file_size)
        findings = FindingBuffer(context.options.max_findings, self.id)
        for rule in attribution_rules():
            if AttributionContext.TEXT not in rule.contexts:
                continue
            line = 1
            previous_offset = 0
            last_newline = -1
            for match in rule.finditer(text):
                line_breaks = text.count("\n", previous_offset, match.start())
                if line_breaks:
                    last_newline = text.rfind("\n", previous_offset, match.start())
                    line += line_breaks
                previous_offset = match.start()
                line_start = last_newline + 1
                line_end_without_newline = text.find("\n", match.end())
                if line_end_without_newline == -1:
                    line_end = len(text)
                else:
                    line_end = line_end_without_newline + 1
                column = match.start() - line_start + 1
                line_text = text[line_start:line_end].rstrip("\r\n")
                relative_start = match.start() - line_start
                relative_end = relative_start + len(match.group(0))
                standalone = is_standalone_attribution(
                    line_text,
                    relative_start,
                    relative_end,
                )
                remediation_id = (
                    "text.remove-attribution-line"
                    if rule.remediation_type == "remove_line" and standalone
                    else None
                )
                findings.append(
                    self.finding(
                        artifact=artifact,
                        category=FindingCategory.EXPLICIT_AI_ATTRIBUTION,
                        confidence=rule.confidence,
                        confidence_type=ConfidenceType.DETERMINISTIC,
                        severity=Severity.MEDIUM,
                        evidence_type=EvidenceType.TEXT,
                        title="Explicit AI-tool attribution",
                        description=(
                            f"{rule.explanation} This reports literal residue, not inferred authorship."
                            + (
                                " The surrounding line contains other substantive text and "
                                "requires review."
                                if not standalone
                                else ""
                            )
                        ),
                        evidence={
                            "rule_id": rule.id,
                            "match": match.group(0),
                            "line_text": line_text,
                            "line_raw": text[line_start:line_end],
                            "line_start": line_start,
                            "line_end": line_end,
                        },
                        location=FindingLocation(
                            line=line,
                            column=column,
                            offset=match.start(),
                            end_offset=match.end(),
                        ),
                        provider=rule.provider,
                        removable=remediation_id is not None,
                        remediation_id=remediation_id,
                        provenance_class=ProvenanceClass.ATTRIBUTION,
                        tags=("attribution", "literal", rule.provider),
                    )
                )
        return findings
