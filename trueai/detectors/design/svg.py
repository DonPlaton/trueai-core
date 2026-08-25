"""First-class passive SVG forensic inspection."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

from trueai.core.artifact import Artifact
from trueai.core.errors import CorruptArtifactError, ScanLimitExceededError
from trueai.core.models import (
    ArtifactType,
    ConfidenceType,
    EvidenceType,
    Finding,
    FindingCategory,
    ProvenanceClass,
    ScanContext,
    Severity,
)
from trueai.core.provenance import contains_protected_provenance_marker
from trueai.core.spans import Delimiter, scan_delimited
from trueai.detectors.base import BaseDetector, FindingBuffer
from trueai.detectors.documents.opc import local_name, parse_xml
from trueai.providers import AttributionContext, attribution_rules, is_standalone_attribution

_EDITOR_NAMESPACES = ("inkscape", "sodipodi", "adobe", "serif", "sketch")
_GEOMETRY_TAGS = {"path", "rect", "circle", "ellipse", "polygon", "polyline", "line"}


@dataclass(frozen=True, slots=True)
class SVGViewport:
    min_x: float
    min_y: float
    width: float
    height: float


class SVGDetector(BaseDetector):
    """Differentiate SVG security, metadata, residue, provenance, and heuristics."""

    id = "design.svg-forensics.v1"
    supported_types = frozenset({ArtifactType.SVG})
    categories = frozenset(
        {
            FindingCategory.GENERATOR_METADATA,
            FindingCategory.HIDDEN_ELEMENT,
            FindingCategory.SECURITY_ISSUE,
            FindingCategory.STRUCTURAL_SIGNAL,
            FindingCategory.EXPLICIT_AI_ATTRIBUTION,
        }
    )

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        data = artifact.read_bytes(context.options.max_file_size)
        if data.count(b"<") > context.options.max_parser_events:
            raise ScanLimitExceededError(
                f"SVG exceeds the {context.options.max_parser_events} parser-event limit"
            )
        root = parse_xml(data, artifact.display_path)
        if local_name(root.tag) != "svg":
            raise CorruptArtifactError("XML root is not an SVG element")
        text = data.decode("utf-8", errors="replace")
        findings = FindingBuffer(context.options.max_findings, self.id)
        findings.extend(self._comment_findings(artifact, text))
        viewport = self._viewport(root)
        geometry_counts: Counter[str] = Counter()
        defined_ids: set[str] = set()
        referenced_ids: set[str] = set()
        for element in root.iter():
            tag = local_name(element.tag)
            if tag in {"metadata", "rdf", "RDF", "xmpmeta"}:
                serialized_metadata = ElementTree.tostring(element, encoding="utf-8")
                protected = contains_protected_provenance_marker(serialized_metadata)
                findings.append(
                    self.finding(
                        artifact=artifact,
                        category=FindingCategory.GENERATOR_METADATA,
                        confidence=1.0,
                        confidence_type=ConfidenceType.DETERMINISTIC,
                        severity=Severity.MEDIUM,
                        evidence_type=EvidenceType.METADATA,
                        title="SVG metadata element",
                        description=(
                            "An SVG metadata/RDF/XMP element is present. It may describe editing "
                            "history or provenance, but its presence alone is not authenticated."
                            + (
                                " A provenance marker is present, so built-in cleanup preserves it."
                                if protected
                                else ""
                            )
                        ),
                        evidence={
                            "element": tag,
                            "text_excerpt": "".join(element.itertext())[:160],
                            "protected_provenance_marker": protected,
                        },
                        removable=not protected,
                        remediation_id=None if protected else "svg.remove-metadata-element",
                        provenance_class=(
                            ProvenanceClass.PROVENANCE_METADATA
                            if protected
                            else ProvenanceClass.METADATA
                        ),
                        tags=("svg", "metadata", "design-residue")
                        + (("preserve", "provenance-marker") if protected else ()),
                    )
                )
            editor_attributes = [
                key
                for key in element.attrib
                if any(namespace in key.casefold() for namespace in _EDITOR_NAMESPACES)
            ]
            if editor_attributes:
                editor_values = [element.attrib[key] for key in editor_attributes]
                protected = contains_protected_provenance_marker(
                    " ".join(editor_attributes + editor_values)
                )
                findings.append(
                    self.finding(
                        artifact=artifact,
                        category=FindingCategory.GENERATOR_METADATA,
                        confidence=1.0,
                        confidence_type=ConfidenceType.DETERMINISTIC,
                        severity=Severity.LOW,
                        evidence_type=EvidenceType.METADATA,
                        title="SVG editor-specific attributes",
                        description=(
                            "Editor-specific XML attributes remain in the design file."
                            + (
                                " A provenance marker occurs in this attribute set, so cleanup "
                                "preserves it."
                                if protected
                                else ""
                            )
                        ),
                        evidence={"element": tag, "attributes": sorted(editor_attributes)},
                        removable=not protected,
                        remediation_id=None if protected else "svg.remove-editor-attributes",
                        provenance_class=(
                            ProvenanceClass.PROVENANCE_METADATA
                            if protected
                            else ProvenanceClass.METADATA
                        ),
                        tags=("svg", "metadata", "editor-residue")
                        + (("preserve", "provenance-marker") if protected else ()),
                    )
                )
            hidden_reasons = self._hidden_reasons(element)
            if hidden_reasons:
                findings.append(
                    self.finding(
                        artifact=artifact,
                        category=FindingCategory.HIDDEN_ELEMENT,
                        confidence=1.0,
                        confidence_type=ConfidenceType.DETERMINISTIC,
                        severity=Severity.LOW,
                        evidence_type=EvidenceType.STRUCTURAL,
                        title="Hidden SVG element",
                        description=(
                            "The element is hidden by explicit SVG/CSS properties. Hidden elements "
                            "are not assumed to be watermarks."
                        ),
                        evidence={
                            "element": tag,
                            "id": element.attrib.get("id", ""),
                            "reasons": hidden_reasons,
                        },
                        tags=("svg", "hidden", "not-provenance"),
                    )
                )
            if tag == "script":
                findings.append(
                    self.finding(
                        artifact=artifact,
                        category=FindingCategory.SECURITY_ISSUE,
                        confidence=1.0,
                        confidence_type=ConfidenceType.DETERMINISTIC,
                        severity=Severity.HIGH,
                        evidence_type=EvidenceType.SECURITY,
                        title="Embedded SVG script",
                        description="The SVG contains a script element. TrueAI records and never executes it.",
                        evidence={"element": "script"},
                        tags=("svg", "script", "passive-scan"),
                    )
                )
            for key, value in element.attrib.items():
                if value.lstrip().casefold().startswith("data:"):
                    findings.append(
                        self.finding(
                            artifact=artifact,
                            category=FindingCategory.STRUCTURAL_SIGNAL,
                            confidence=1.0,
                            confidence_type=ConfidenceType.DETERMINISTIC,
                            severity=Severity.INFO,
                            evidence_type=EvidenceType.STRUCTURAL,
                            title="Embedded SVG data URI",
                            description="An SVG attribute embeds data directly in the document.",
                            evidence={"element": tag, "attribute": local_name(key)},
                            tags=("svg", "data-uri"),
                        )
                    )
                referenced_ids.update(re.findall(r"#([A-Za-z_][\w:.-]*)", value))
            if "id" in element.attrib:
                defined_ids.add(element.attrib["id"])
            if tag == "path" and element.attrib.get("d"):
                geometry_counts[element.attrib["d"]] += 1
            if viewport is not None and tag in _GEOMETRY_TAGS:
                off_canvas = self._is_far_off_canvas(element, viewport)
                if off_canvas:
                    findings.append(
                        self.finding(
                            artifact=artifact,
                            category=FindingCategory.STRUCTURAL_SIGNAL,
                            confidence=0.7,
                            confidence_type=ConfidenceType.HEURISTIC,
                            severity=Severity.LOW,
                            evidence_type=EvidenceType.STRUCTURAL,
                            title="Far off-canvas SVG geometry",
                            description=(
                                "Geometry coordinates are far outside the declared viewBox. This is "
                                "a structural heuristic, not provenance."
                            ),
                            evidence={"element": tag, "id": element.attrib.get("id", "")},
                            provenance_class=ProvenanceClass.HEURISTIC,
                            tags=("svg", "off-canvas", "heuristic", "not-provenance"),
                        )
                    )
        duplicates = {geometry: count for geometry, count in geometry_counts.items() if count > 1}
        if duplicates:
            findings.append(
                self.finding(
                    artifact=artifact,
                    category=FindingCategory.STRUCTURAL_SIGNAL,
                    confidence=1.0,
                    confidence_type=ConfidenceType.DETERMINISTIC,
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.STRUCTURAL,
                    title="Duplicated SVG path geometry",
                    description="Identical path data occurs more than once; this is design structure only.",
                    evidence={
                        "duplicate_groups": len(duplicates),
                        "duplicate_instances": sum(duplicates.values()),
                    },
                    tags=("svg", "geometry", "duplication", "not-provenance"),
                )
            )
        unused_ids = sorted(defined_ids - referenced_ids)
        if unused_ids and any(local_name(child.tag) == "defs" for child in root):
            findings.append(
                self.finding(
                    artifact=artifact,
                    category=FindingCategory.STRUCTURAL_SIGNAL,
                    confidence=0.7,
                    confidence_type=ConfidenceType.HEURISTIC,
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.STRUCTURAL,
                    title="Potentially unused SVG definitions",
                    description="Some IDs are not referenced by URL or fragment syntax in this SVG.",
                    evidence={"unreferenced_ids": unused_ids[:100]},
                    provenance_class=ProvenanceClass.HEURISTIC,
                    tags=("svg", "defs", "heuristic"),
                )
            )
        return findings

    def _comment_findings(self, artifact: Artifact, text: str) -> Iterable[Finding]:
        # Scanned rather than matched: the lazy regular expression this replaced
        # restarted at every `<!--` when the closing `-->` was absent. The XML
        # parser rejects that input before it reaches here, so this was defence
        # behind a working guard -- which is exactly the code that stops being
        # true first, when somebody reuses the function.
        for start, end in scan_delimited(text, (Delimiter("<!--", "-->"),)):
            content = text[start:end]
            protected = contains_protected_provenance_marker(content)
            if re.search(r"(?i)\b(?:generator|created with|exported by)\b", content):
                yield self.finding(
                    artifact=artifact,
                    category=FindingCategory.GENERATOR_METADATA,
                    confidence=0.95,
                    confidence_type=ConfidenceType.DETERMINISTIC,
                    severity=Severity.LOW,
                    evidence_type=EvidenceType.METADATA,
                    title="SVG generator comment",
                    description="An XML comment describes a generator or export tool.",
                    evidence={"comment": content[:300]},
                    removable=not protected,
                    remediation_id=None if protected else "svg.remove-generator-comment",
                    provenance_class=(
                        ProvenanceClass.PROVENANCE_METADATA
                        if protected
                        else ProvenanceClass.METADATA
                    ),
                    tags=("svg", "comment", "generator")
                    + (("preserve", "provenance-marker") if protected else ()),
                )
            for rule in attribution_rules():
                if AttributionContext.HTML_COMMENT not in rule.contexts:
                    continue
                for match in rule.finditer(content):
                    standalone = is_standalone_attribution(
                        content,
                        match.start(),
                        match.end(),
                    )
                    yield self.finding(
                        artifact=artifact,
                        category=FindingCategory.EXPLICIT_AI_ATTRIBUTION,
                        confidence=rule.confidence,
                        confidence_type=ConfidenceType.DETERMINISTIC,
                        severity=Severity.MEDIUM,
                        evidence_type=EvidenceType.TEXT,
                        title="AI attribution in SVG comment",
                        description=(
                            rule.explanation
                            + (
                                " Other substantive comment text requires review."
                                if not standalone
                                else ""
                            )
                        ),
                        evidence={"rule_id": rule.id, "match": match.group(0)},
                        provider=rule.provider,
                        removable=not protected and standalone,
                        remediation_id=(
                            "svg.remove-generator-comment" if not protected and standalone else None
                        ),
                        provenance_class=(
                            ProvenanceClass.PROVENANCE_METADATA
                            if protected
                            else ProvenanceClass.ATTRIBUTION
                        ),
                        tags=("svg", "comment", "literal", rule.provider),
                    )

    @staticmethod
    def _hidden_reasons(element: Element) -> list[str]:
        style = element.attrib.get("style", "").replace(" ", "").casefold()
        reasons = []
        if element.attrib.get("display", "").casefold() == "none" or "display:none" in style:
            reasons.append("display:none")
        if (
            element.attrib.get("visibility", "").casefold() == "hidden"
            or "visibility:hidden" in style
        ):
            reasons.append("visibility:hidden")
        opacity = element.attrib.get("opacity", "")
        if opacity in {"0", "0.0", "0.00"} or re.search(r"(?:^|;)opacity:0(?:\.0+)?(?:;|$)", style):
            reasons.append("zero opacity")
        return reasons

    @staticmethod
    def _viewport(root: Element) -> SVGViewport | None:
        view_box = root.attrib.get("viewBox", "")
        try:
            values = [float(item) for item in re.split(r"[\s,]+", view_box.strip())]
        except ValueError:
            return None
        if len(values) != 4 or values[2] <= 0 or values[3] <= 0:
            return None
        return SVGViewport(*values)

    @staticmethod
    def _is_far_off_canvas(element: Element, viewport: SVGViewport) -> bool:
        coordinates: list[float] = []
        for attribute in ("x", "y", "cx", "cy", "x1", "x2", "y1", "y2"):
            raw = element.attrib.get(attribute)
            if raw is None:
                continue
            match = re.match(r"[-+]?\d+(?:\.\d+)?", raw)
            if match:
                coordinates.append(float(match.group(0)))
        if not coordinates:
            return False
        x_limit = max(abs(viewport.min_x), viewport.width) * 10
        y_limit = max(abs(viewport.min_y), viewport.height) * 10
        limit = max(x_limit, y_limit, 1000.0)
        return any(abs(value) > limit for value in coordinates)
