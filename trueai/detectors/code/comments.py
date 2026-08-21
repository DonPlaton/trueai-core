"""Provider-rule scanning restricted to actual source comments."""

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
from trueai.detectors.code.attribution import extract_comments
from trueai.providers import AttributionContext, attribution_rules, is_standalone_attribution


class CodeCommentAttributionDetector(BaseDetector):
    """Detect explicit AI statements only inside parsed or conservative comment spans."""

    id = "code.comment-attribution.v1"
    supported_types = frozenset({ArtifactType.SOURCE_CODE})
    categories = frozenset(
        {FindingCategory.GENERATED_COMMENT, FindingCategory.EXPLICIT_AI_ATTRIBUTION}
    )

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        text = artifact.read_text(context.options.max_file_size)
        findings = FindingBuffer(context.options.max_findings, self.id)
        for comment in extract_comments(text, artifact.path, context.options.max_parser_events):
            for rule in attribution_rules():
                if AttributionContext.COMMENT not in rule.contexts:
                    continue
                for match in rule.finditer(comment.text):
                    start = comment.start + match.start()
                    end = comment.start + match.end()
                    standalone = is_standalone_attribution(
                        comment.text,
                        match.start(),
                        match.end(),
                    )
                    removable = comment.syntax_verified and standalone
                    findings.append(
                        self.finding(
                            artifact=artifact,
                            category=FindingCategory.GENERATED_COMMENT,
                            confidence=(rule.confidence if comment.syntax_verified else 0.65),
                            confidence_type=(
                                ConfidenceType.DETERMINISTIC
                                if comment.syntax_verified
                                else ConfidenceType.HEURISTIC
                            ),
                            severity=Severity.MEDIUM,
                            evidence_type=EvidenceType.TEXT,
                            title="AI attribution in source comment",
                            description=(
                                f"{rule.explanation} "
                                + (
                                    "The match is the only substantive text in a syntax-verified "
                                    "source comment."
                                    if removable
                                    else "The comment contains other substantive text or the "
                                    "language fallback cannot prove this token is outside a "
                                    "string; review only."
                                )
                            ),
                            evidence={
                                "rule_id": rule.id,
                                "match": match.group(0),
                                "comment": comment.text,
                                "comment_start": comment.start,
                                "comment_end": comment.end,
                            },
                            location=FindingLocation(
                                line=comment.line,
                                column=comment.column + match.start(),
                                offset=start,
                                end_offset=end,
                            ),
                            provider=rule.provider,
                            removable=removable,
                            remediation_id=(
                                "text.remove-attribution-comment" if removable else None
                            ),
                            provenance_class=ProvenanceClass.ATTRIBUTION,
                            tags=("code", "comment", "literal", rule.provider)
                            + (("syntax-verified",) if removable else ("review-only",)),
                        )
                    )
        return findings
