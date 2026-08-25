"""Passive CSS comment, hidden-rule, and embedded-data inspection."""

from __future__ import annotations

import re

from trueai.core.artifact import Artifact
from trueai.core.dom_features import FeatureBudget, extract_stylesheet_features
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
from trueai.detectors.code.attribution import extract_css_comments
from trueai.providers import AttributionContext, attribution_rules, is_standalone_attribution


class CSSDetector(BaseDetector):
    """Inspect CSS text without resolving imports or loading external resources."""

    id = "web.css-forensics.v1"
    supported_types = frozenset({ArtifactType.CSS})
    categories = frozenset(
        {
            FindingCategory.GENERATED_COMMENT,
            FindingCategory.HIDDEN_ELEMENT,
            FindingCategory.STRUCTURAL_SIGNAL,
        }
    )

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        text = artifact.read_text(context.options.max_file_size)
        findings = FindingBuffer(context.options.max_findings, self.id)
        features_finding = self._features_finding(artifact, text, context)
        if features_finding is not None:
            findings.append(features_finding)
        for comment in extract_css_comments(text, context.options.max_parser_events):
            for rule in attribution_rules():
                if AttributionContext.COMMENT not in rule.contexts:
                    continue
                for match in rule.finditer(comment.text):
                    offset = comment.start + match.start()
                    standalone = is_standalone_attribution(
                        comment.text,
                        match.start(),
                        match.end(),
                    )
                    findings.append(
                        self.finding(
                            artifact=artifact,
                            category=FindingCategory.GENERATED_COMMENT,
                            confidence=rule.confidence,
                            confidence_type=ConfidenceType.DETERMINISTIC,
                            severity=Severity.MEDIUM,
                            evidence_type=EvidenceType.TEXT,
                            title="AI attribution in CSS comment",
                            description=(
                                rule.explanation
                                + (
                                    " The comment contains other substantive text; review only."
                                    if not standalone
                                    else ""
                                )
                            ),
                            evidence={
                                "rule_id": rule.id,
                                "comment": comment.text,
                                "comment_start": comment.start,
                                "comment_end": comment.end,
                            },
                            location=self._location(text, offset, comment.end),
                            provider=rule.provider,
                            removable=standalone,
                            remediation_id=(
                                "text.remove-attribution-comment" if standalone else None
                            ),
                            provenance_class=ProvenanceClass.ATTRIBUTION,
                            tags=("css", "comment", "literal", rule.provider),
                        )
                    )
        for rule_match in re.finditer(
            r"(?is)([^{}]+)\{[^{}]*(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?)\s*;?[^{}]*\}",
            text,
        ):
            findings.append(
                self.finding(
                    artifact=artifact,
                    category=FindingCategory.HIDDEN_ELEMENT,
                    confidence=1.0,
                    confidence_type=ConfidenceType.DETERMINISTIC,
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.STRUCTURAL,
                    title="CSS rule can hide elements",
                    description=(
                        "A CSS rule explicitly hides matching elements. This is structural context, "
                        "not evidence of a watermark or AI provenance."
                    ),
                    evidence={
                        "selector": rule_match.group(1).strip(),
                        "declaration": rule_match.group(2),
                    },
                    location=self._location(text, rule_match.start(), rule_match.end()),
                    tags=("css", "hidden", "not-provenance"),
                )
            )
        for data_uri in re.finditer(r"(?i)url\(\s*['\"]?data:", text):
            findings.append(
                self.finding(
                    artifact=artifact,
                    category=FindingCategory.STRUCTURAL_SIGNAL,
                    confidence=1.0,
                    confidence_type=ConfidenceType.DETERMINISTIC,
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.STRUCTURAL,
                    title="Embedded CSS data URI",
                    description="A CSS declaration embeds data directly; no external resource is fetched.",
                    evidence={"token": data_uri.group(0)},
                    location=self._location(text, data_uri.start(), data_uri.end()),
                    tags=("css", "data-uri"),
                )
            )
        return findings

    @staticmethod
    def _location(text: str, start: int, end: int) -> FindingLocation:
        line = text.count("\n", 0, start) + 1
        last_newline = text.rfind("\n", 0, start)
        return FindingLocation(
            line=line,
            column=start - last_newline,
            offset=start,
            end_offset=end,
        )

    def _features_finding(
        self, artifact: Artifact, text: str, context: ScanContext
    ) -> Finding | None:
        """Report the stylesheet's shape as measurements.

        A stylesheet with a thousand `!important` declarations is a stylesheet
        with a thousand `!important` declarations. This finding says that and
        stops.
        """

        budget = FeatureBudget(max_events=context.options.max_parser_events)
        features = extract_stylesheet_features(text, budget)
        if features.rules == 0:
            return None
        return self.finding(
            artifact=artifact,
            category=FindingCategory.STRUCTURAL_SIGNAL,
            confidence=1.0,
            confidence_type=ConfidenceType.DETERMINISTIC,
            severity=Severity.INFO,
            evidence_type=EvidenceType.STRUCTURAL,
            title="Stylesheet feature summary",
            description=(
                f"The stylesheet declares {features.rules} rule(s), {features.selectors} "
                f"selector(s), and {features.declarations} declaration(s). These are "
                "measurements of stylesheet shape, not evidence of authorship."
                + ("" if features.complete else f" Measurement stopped: {features.truncated_by}.")
            ),
            evidence=features.as_evidence(),
            removable=False,
            provenance_class=ProvenanceClass.NONE,
            tags=("css", "features", "measurement"),
        )
