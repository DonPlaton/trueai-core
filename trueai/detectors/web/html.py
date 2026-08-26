"""Non-executing HTML metadata and structure inspection."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from html.parser import HTMLParser

from trueai.core.artifact import Artifact
from trueai.core.dom_features import FeatureBudget, extract_dom_topology, guard_html_parsing
from trueai.core.errors import ScanLimitExceededError
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


@dataclass(frozen=True, slots=True)
class HTMLEvent:
    """A parser event used to construct findings after safe parsing."""

    kind: str
    line: int
    column: int
    tag: str | None = None
    attributes: tuple[tuple[str, str | None], ...] = ()
    data: str | None = None
    raw: str | None = None


class _ForensicHTMLParser(HTMLParser):
    def __init__(self, max_events: int) -> None:
        super().__init__(convert_charrefs=False)
        self.events: list[HTMLEvent] = []
        self.max_events = max_events
        self.truncated = False

    def _append(self, event: HTMLEvent) -> None:
        if len(self.events) >= self.max_events:
            self.truncated = True
            return
        self.events.append(event)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        line, column = self.getpos()
        self._append(
            HTMLEvent(
                "start",
                line,
                column + 1,
                tag=tag,
                attributes=tuple(attrs),
                raw=self.get_starttag_text(),
            )
        )

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_comment(self, data: str) -> None:
        line, column = self.getpos()
        self._append(HTMLEvent("comment", line, column + 1, data=data))


class HTMLDetector(BaseDetector):
    """Inspect metadata, comments, hidden structure, scripts, and data URIs."""

    id = "web.html-forensics.v1"
    supported_types = frozenset({ArtifactType.HTML})
    categories = frozenset(
        {
            FindingCategory.GENERATOR_METADATA,
            FindingCategory.GENERATED_COMMENT,
            FindingCategory.HIDDEN_ELEMENT,
            FindingCategory.SECURITY_ISSUE,
        }
    )

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        text = artifact.read_text(context.options.max_file_size)
        guard_html_parsing(text)
        parser = _ForensicHTMLParser(context.options.max_parser_events)
        parser.feed(text)
        parser.close()
        if parser.truncated:
            raise ScanLimitExceededError(
                f"HTML event limit {context.options.max_parser_events} was exceeded"
            )
        findings = FindingBuffer(context.options.max_findings, self.id)
        topology_finding = self._topology_finding(artifact, text, context)
        if topology_finding is not None:
            findings.append(topology_finding)
        line_offsets = self._line_offsets(text, {event.line for event in parser.events})
        for event in parser.events:
            location = FindingLocation(line=event.line, column=event.column)
            start_offset = line_offsets[event.line] + event.column - 1
            if event.kind == "comment" and event.data is not None:
                findings.extend(
                    self._comment_findings(
                        artifact,
                        event,
                        location,
                        text,
                        start_offset,
                    )
                )
                continue
            attributes = {key.casefold(): (value or "") for key, value in event.attributes}
            if event.tag == "meta" and attributes.get("name", "").casefold() == "generator":
                generator = attributes.get("content", "")
                findings.append(
                    self.finding(
                        artifact=artifact,
                        category=FindingCategory.GENERATOR_METADATA,
                        confidence=1.0,
                        confidence_type=ConfidenceType.DETERMINISTIC,
                        severity=Severity.MEDIUM,
                        evidence_type=EvidenceType.METADATA,
                        title="HTML generator metadata",
                        description="A standard HTML generator meta element names the creating tool.",
                        evidence={
                            "tag": "meta",
                            "name": "generator",
                            "content": generator,
                            "tag_start": start_offset,
                            "tag_end": start_offset + len(event.raw or ""),
                            "tag_raw": event.raw or "",
                        },
                        location=location,
                        removable=True,
                        remediation_id="html.remove-generator-metadata",
                        provenance_class=ProvenanceClass.METADATA,
                        tags=("html", "metadata", "generator"),
                    )
                )
            style = attributes.get("style", "").replace(" ", "").casefold()
            hidden_reasons = []
            if "hidden" in attributes:
                hidden_reasons.append("hidden attribute")
            if "display:none" in style:
                hidden_reasons.append("display:none")
            if "visibility:hidden" in style:
                hidden_reasons.append("visibility:hidden")
            if "opacity:0" in style or "opacity:0.0" in style:
                hidden_reasons.append("zero opacity")
            if hidden_reasons:
                findings.append(
                    self.finding(
                        artifact=artifact,
                        category=FindingCategory.HIDDEN_ELEMENT,
                        confidence=1.0,
                        confidence_type=ConfidenceType.DETERMINISTIC,
                        severity=Severity.LOW,
                        evidence_type=EvidenceType.STRUCTURAL,
                        title="Hidden HTML element",
                        description=(
                            "The element is hidden by explicit markup or inline style. Hidden "
                            "elements are common and are not assumed to be watermarks."
                        ),
                        evidence={"tag": event.tag or "", "reasons": hidden_reasons},
                        location=location,
                        tags=("html", "hidden", "not-provenance"),
                    )
                )
            if event.tag == "script":
                findings.append(
                    self.finding(
                        artifact=artifact,
                        category=FindingCategory.SECURITY_ISSUE,
                        confidence=1.0,
                        confidence_type=ConfidenceType.DETERMINISTIC,
                        severity=Severity.LOW,
                        evidence_type=EvidenceType.SECURITY,
                        title="Embedded HTML script",
                        description="A script element is present. TrueAI records it and never executes it.",
                        evidence={"tag": "script", "src": attributes.get("src", "inline")},
                        location=location,
                        tags=("html", "script", "passive-scan"),
                    )
                )
            for attribute, value in attributes.items():
                if value.lstrip().casefold().startswith("data:"):
                    findings.append(
                        self.finding(
                            artifact=artifact,
                            category=FindingCategory.STRUCTURAL_SIGNAL,
                            confidence=1.0,
                            confidence_type=ConfidenceType.DETERMINISTIC,
                            severity=Severity.INFO,
                            evidence_type=EvidenceType.STRUCTURAL,
                            title="Embedded data URI",
                            description="An HTML attribute embeds data directly in the artifact.",
                            evidence={"tag": event.tag or "", "attribute": attribute},
                            location=location,
                            tags=("html", "data-uri"),
                        )
                    )
        return findings

    def _comment_findings(
        self,
        artifact: Artifact,
        event: HTMLEvent,
        location: FindingLocation,
        text: str,
        start_offset: int,
    ) -> Iterable[Finding]:
        assert event.data is not None
        end_marker = text.find("-->", start_offset)
        comment_end = len(text) if end_marker < 0 else end_marker + 3
        raw_comment = text[start_offset:comment_end]
        for rule in attribution_rules():
            if AttributionContext.HTML_COMMENT not in rule.contexts:
                continue
            for match in rule.finditer(event.data):
                standalone = is_standalone_attribution(
                    event.data,
                    match.start(),
                    match.end(),
                )
                yield self.finding(
                    artifact=artifact,
                    category=FindingCategory.GENERATED_COMMENT,
                    confidence=rule.confidence,
                    confidence_type=ConfidenceType.DETERMINISTIC,
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.TEXT,
                    title="AI attribution in HTML comment",
                    description=(
                        f"{rule.explanation} The match occurs inside an HTML comment."
                        + (
                            " Other substantive comment text requires review."
                            if not standalone
                            else ""
                        )
                    ),
                    evidence={
                        "rule_id": rule.id,
                        "match": match.group(0),
                        "comment": event.data,
                        "comment_start": start_offset,
                        "comment_end": comment_end,
                        "comment_raw": raw_comment,
                    },
                    location=location,
                    provider=rule.provider,
                    removable=standalone,
                    remediation_id="html.remove-attribution-comment" if standalone else None,
                    provenance_class=ProvenanceClass.ATTRIBUTION,
                    tags=("html", "comment", "literal", rule.provider),
                )

    def _topology_finding(
        self, artifact: Artifact, text: str, context: ScanContext
    ) -> Finding | None:
        """Report the document's shape as measurements, and only as measurements.

        Counts, not conclusions. Nesting depth and wrapper density are facts about
        a tree; what they imply about who built it is not something this project
        will pretend to know, so the finding carries no removal, no severity above
        informational, and provenance class NONE.
        """

        budget = FeatureBudget(max_events=context.options.max_parser_events)
        topology = extract_dom_topology(text, budget)
        if topology.elements == 0:
            return None
        evidence = topology.as_evidence()
        return self.finding(
            artifact=artifact,
            category=FindingCategory.STRUCTURAL_SIGNAL,
            confidence=1.0,
            # A count is observed, not estimated. Calling it heuristic would
            # understate it; calling it provenance would overstate it by far more.
            confidence_type=ConfidenceType.DETERMINISTIC,
            severity=Severity.INFO,
            evidence_type=EvidenceType.STRUCTURAL,
            title="HTML document topology",
            description=(
                f"The document contains {topology.elements} element(s) nested up to "
                f"{topology.max_depth} deep. These are measurements of document shape. "
                "They are not evidence of authorship, and no threshold here converts "
                "them into one."
                + ("" if topology.complete else f" Measurement stopped: {topology.truncated_by}.")
            ),
            evidence=evidence,
            removable=False,
            provenance_class=ProvenanceClass.NONE,
            tags=("html", "topology", "measurement"),
        )

    @staticmethod
    def _line_offsets(text: str, requested_lines: set[int]) -> dict[int, int]:
        offsets = {1: 0}
        if not requested_lines:
            return offsets
        remaining = requested_lines - {1}
        line = 1
        for index, character in enumerate(text):
            if character != "\n":
                continue
            line += 1
            if line in remaining:
                offsets[line] = index + 1
                remaining.remove(line)
                if not remaining:
                    break
        return offsets
