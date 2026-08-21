"""Shared Office Open XML forensics for Word, PowerPoint, and Excel packages.

Word, PowerPoint, and Excel documents are the same container with different
content parts: identical `docProps` metadata, identical custom XML, identical
relationship graph, identical embedding and macro layout. Re-implementing that
inspection per format would let the three drift apart, and a security boundary
that holds for one format but not another is worse than no boundary at all.

Only the content-bearing parts differ, so each format subclass contributes its
own findings through :meth:`OfficeOpenXmlDetector.content_findings` while the
package-level evidence is collected once, here.
"""

from __future__ import annotations

import zipfile
from collections.abc import Iterable
from xml.etree.ElementTree import Element

from trueai.core.artifact import Artifact
from trueai.core.models import (
    ConfidenceType,
    EvidenceType,
    Finding,
    FindingCategory,
    FindingLocation,
    ProvenanceClass,
    ScanContext,
    Severity,
)
from trueai.core.provenance import contains_protected_provenance_marker
from trueai.detectors.base import BaseDetector, FindingBuffer
from trueai.detectors.documents.opc import (
    local_name,
    open_validated_opc,
    parse_xml,
    read_opc_xml_part,
)
from trueai.providers import AttributionContext, attribution_rules, is_standalone_attribution

CORE_PROPERTIES_PART = "docProps/core.xml"
APP_PROPERTIES_PART = "docProps/app.xml"
CUSTOM_PROPERTIES_PART = "docProps/custom.xml"

_CORE_PERSONAL_FIELDS = {"creator", "lastModifiedBy"}
_CORE_FIELDS = {
    "creator",
    "lastModifiedBy",
    "title",
    "subject",
    "keywords",
    "description",
    "category",
    "contentStatus",
    "created",
    "modified",
    "revision",
}
_APP_FIELDS = {"Application", "AppVersion", "Company", "Manager", "Template"}

OOXML_CATEGORIES = frozenset(
    {
        FindingCategory.DOCUMENT_METADATA,
        FindingCategory.PERSONAL_METADATA,
        FindingCategory.GENERATOR_METADATA,
        FindingCategory.EXPLICIT_AI_ATTRIBUTION,
        FindingCategory.C2PA_PROVENANCE,
        FindingCategory.STRUCTURAL_SIGNAL,
        FindingCategory.SECURITY_ISSUE,
    }
)


class OfficeOpenXmlDetector(BaseDetector):
    """Inspect an OPC package without invoking Office, macros, or embedded objects."""

    #: Human-facing format name used in finding titles, for example ``DOCX``.
    format_label = "OOXML"
    #: Lowercase tag and remediation namespace, for example ``docx``.
    format_tag = "ooxml"
    #: Package prefix holding the content parts, for example ``word/``.
    content_prefix = ""

    categories = OOXML_CATEGORIES

    @property
    def metadata_remediation_id(self) -> str:
        """Remediation identifier for standard document properties."""

        return f"{self.format_tag}.remove-metadata-field"

    @property
    def custom_property_remediation_id(self) -> str:
        """Remediation identifier for application-defined custom properties."""

        return f"{self.format_tag}.remove-custom-property"

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        if artifact.path is None:
            return []
        findings = FindingBuffer(context.options.max_findings, self.id)
        with open_validated_opc(artifact.path, context.options) as package:
            names = set(package.namelist())
            if CORE_PROPERTIES_PART in names:
                root = parse_xml(
                    read_opc_xml_part(package, CORE_PROPERTIES_PART, context.options),
                    CORE_PROPERTIES_PART,
                )
                findings.extend(
                    self._property_findings(artifact, root, CORE_PROPERTIES_PART, _CORE_FIELDS)
                )
            if APP_PROPERTIES_PART in names:
                root = parse_xml(
                    read_opc_xml_part(package, APP_PROPERTIES_PART, context.options),
                    APP_PROPERTIES_PART,
                )
                findings.extend(
                    self._property_findings(artifact, root, APP_PROPERTIES_PART, _APP_FIELDS)
                )
            if CUSTOM_PROPERTIES_PART in names:
                root = parse_xml(
                    read_opc_xml_part(package, CUSTOM_PROPERTIES_PART, context.options),
                    CUSTOM_PROPERTIES_PART,
                )
                findings.extend(self._custom_property_findings(artifact, root))
            findings.extend(self.content_findings(artifact, package, names, context))
            findings.extend(self._package_structure_findings(artifact, names))
            for custom_xml_name in sorted(
                name for name in names if name.startswith("customXml/") and name.endswith(".xml")
            ):
                custom_xml_data = read_opc_xml_part(package, custom_xml_name, context.options)
                parse_xml(custom_xml_data, custom_xml_name)
                findings.extend(
                    self._custom_xml_content_findings(artifact, custom_xml_name, custom_xml_data)
                )
            for relationship_name in sorted(name for name in names if name.endswith(".rels")):
                root = parse_xml(
                    read_opc_xml_part(package, relationship_name, context.options),
                    relationship_name,
                )
                findings.extend(self._relationship_findings(artifact, root, relationship_name))
        return findings

    def content_findings(
        self,
        artifact: Artifact,
        package: zipfile.ZipFile,
        names: set[str],
        context: ScanContext,
    ) -> Iterable[Finding]:
        """Return findings from the format-specific content parts."""

        del artifact, package, names, context
        return ()

    # -- shared package-level evidence -------------------------------------------------

    def _property_findings(
        self,
        artifact: Artifact,
        root: Element,
        part: str,
        included: set[str],
    ) -> Iterable[Finding]:
        for element in root.iter():
            name = local_name(element.tag)
            value = (element.text or "").strip()
            if name not in included or not value:
                continue
            if name in _CORE_PERSONAL_FIELDS or name in {"Company", "Manager"}:
                category = FindingCategory.PERSONAL_METADATA
                title = f"{self.format_label} personal metadata: {name}"
            elif name in {"Application", "AppVersion"}:
                category = FindingCategory.GENERATOR_METADATA
                title = f"{self.format_label} creating application: {name}"
            else:
                category = FindingCategory.DOCUMENT_METADATA
                title = f"{self.format_label} document property: {name}"
            protected = contains_protected_provenance_marker(value)
            yield self.finding(
                artifact=artifact,
                category=category,
                confidence=1.0,
                confidence_type=ConfidenceType.DETERMINISTIC,
                severity=(
                    Severity.MEDIUM
                    if category
                    in {FindingCategory.PERSONAL_METADATA, FindingCategory.GENERATOR_METADATA}
                    else Severity.LOW
                ),
                evidence_type=EvidenceType.METADATA,
                title=title,
                description=(
                    "A standard OPC document property is populated. It describes the file or "
                    "editing workflow and does not prove AI authorship."
                    + (
                        " A provenance marker is present, so built-in cleanup preserves it."
                        if protected
                        else ""
                    )
                ),
                evidence={"part": part, "field": name, "value": value},
                location=FindingLocation(package_part=part),
                removable=not protected,
                remediation_id=None if protected else self.metadata_remediation_id,
                provenance_class=(
                    ProvenanceClass.PROVENANCE_METADATA if protected else ProvenanceClass.METADATA
                ),
                tags=(self.format_tag, "metadata", name.casefold())
                + (("preserve", "provenance-marker") if protected else ()),
            )
            yield from self.metadata_attribution(artifact, part, name, value)

    def _custom_property_findings(self, artifact: Artifact, root: Element) -> Iterable[Finding]:
        for property_element in root.iter():
            if local_name(property_element.tag) != "property":
                continue
            name = property_element.attrib.get("name", "unnamed")
            value = " ".join(
                part.strip()
                for child in property_element
                for part in child.itertext()
                if part.strip()
            )
            protected = contains_protected_provenance_marker(value)
            yield self.finding(
                artifact=artifact,
                category=FindingCategory.DOCUMENT_METADATA,
                confidence=1.0,
                confidence_type=ConfidenceType.DETERMINISTIC,
                severity=Severity.LOW,
                evidence_type=EvidenceType.METADATA,
                title=f"{self.format_label} custom property",
                description=(
                    "The document contains an application-defined custom property."
                    + (
                        " A provenance marker is present, so built-in cleanup preserves it."
                        if protected
                        else ""
                    )
                ),
                evidence={"part": CUSTOM_PROPERTIES_PART, "field": name, "value": value},
                location=FindingLocation(package_part=CUSTOM_PROPERTIES_PART),
                removable=not protected,
                remediation_id=None if protected else self.custom_property_remediation_id,
                provenance_class=(
                    ProvenanceClass.PROVENANCE_METADATA if protected else ProvenanceClass.METADATA
                ),
                tags=(self.format_tag, "metadata", "custom-property")
                + (("preserve", "provenance-marker") if protected else ()),
            )
            yield from self.metadata_attribution(artifact, CUSTOM_PROPERTIES_PART, name, value)

    def _package_structure_findings(self, artifact: Artifact, names: set[str]) -> list[Finding]:
        findings: list[Finding] = []
        custom_xml = sorted(
            name for name in names if name.startswith("customXml/") and name.endswith(".xml")
        )
        if custom_xml:
            findings.append(
                self.finding(
                    artifact=artifact,
                    category=FindingCategory.DOCUMENT_METADATA,
                    confidence=1.0,
                    confidence_type=ConfidenceType.DETERMINISTIC,
                    severity=Severity.LOW,
                    evidence_type=EvidenceType.STRUCTURAL,
                    title=f"{self.format_label} custom XML parts",
                    description="The OPC package contains application-defined custom XML parts.",
                    evidence={"parts": custom_xml},
                    provenance_class=ProvenanceClass.METADATA,
                    tags=(self.format_tag, "custom-xml"),
                )
            )
        embedded = sorted(
            name for name in names if name.startswith(f"{self.content_prefix}embeddings/")
        )
        if embedded:
            findings.append(
                self.finding(
                    artifact=artifact,
                    category=FindingCategory.SECURITY_ISSUE,
                    confidence=1.0,
                    confidence_type=ConfidenceType.DETERMINISTIC,
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.SECURITY,
                    title=f"{self.format_label} embedded objects",
                    description=(
                        "The package contains embedded objects. TrueAI does not execute them."
                    ),
                    evidence={"parts": embedded},
                    tags=(self.format_tag, "embedded-object", "passive-scan"),
                )
            )
        macros = sorted(name for name in names if "vbaproject" in name.casefold())
        if macros:
            findings.append(
                self.finding(
                    artifact=artifact,
                    category=FindingCategory.SECURITY_ISSUE,
                    confidence=1.0,
                    confidence_type=ConfidenceType.DETERMINISTIC,
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.SECURITY,
                    title=f"{self.format_label} macro project",
                    description=(
                        "The package carries a VBA macro project. TrueAI reports its presence "
                        "and never parses or executes macro bytecode."
                    ),
                    evidence={"parts": macros},
                    tags=(self.format_tag, "macro", "passive-scan"),
                )
            )
        return findings

    def _relationship_findings(
        self,
        artifact: Artifact,
        root: Element,
        part: str,
    ) -> Iterable[Finding]:
        for relationship in root.iter():
            if local_name(relationship.tag) != "Relationship":
                continue
            target_mode = relationship.attrib.get("TargetMode", "")
            target = relationship.attrib.get("Target", "")
            relation_type = relationship.attrib.get("Type", "")
            suspicious = target_mode.casefold() == "external" or any(
                marker in relation_type.casefold()
                for marker in ("oleobject", "attachedtemplate", "external")
            )
            if not suspicious:
                continue
            yield self.finding(
                artifact=artifact,
                category=FindingCategory.SECURITY_ISSUE,
                confidence=1.0,
                confidence_type=ConfidenceType.DETERMINISTIC,
                severity=Severity.MEDIUM,
                evidence_type=EvidenceType.SECURITY,
                title=f"{self.format_label} external or active relationship",
                description=(
                    "An OPC relationship targets external or active content. The target is "
                    "reported without being opened."
                ),
                evidence={
                    "part": part,
                    "target": target,
                    "target_mode": target_mode,
                    "relationship_type": relation_type,
                },
                location=FindingLocation(package_part=part),
                tags=(self.format_tag, "relationship", "passive-scan"),
            )

    def _custom_xml_content_findings(
        self,
        artifact: Artifact,
        part: str,
        data: bytes,
    ) -> Iterable[Finding]:
        if not contains_protected_provenance_marker(data):
            return
        yield self.finding(
            artifact=artifact,
            category=FindingCategory.C2PA_PROVENANCE,
            confidence=1.0,
            confidence_type=ConfidenceType.DETERMINISTIC,
            severity=Severity.MEDIUM,
            evidence_type=EvidenceType.PROVENANCE,
            title=f"Provenance marker in {self.format_label} custom XML",
            description=(
                "A C2PA/Content Credentials marker occurs in a safely parsed custom XML part. "
                "Marker presence is not cryptographic verification."
            ),
            evidence={"part": part, "authenticated": False},
            location=FindingLocation(package_part=part),
            provenance_class=ProvenanceClass.PROVENANCE_METADATA,
            tags=(self.format_tag, "custom-xml", "c2pa", "unverified", "preserve"),
        )

    def metadata_attribution(
        self,
        artifact: Artifact,
        part: str,
        field: str,
        value: str,
    ) -> Iterable[Finding]:
        """Report literal AI attribution inside a metadata or comment value."""

        if part == CUSTOM_PROPERTIES_PART:
            remediation_id: str | None = self.custom_property_remediation_id
        elif part in {CORE_PROPERTIES_PART, APP_PROPERTIES_PART}:
            remediation_id = self.metadata_remediation_id
        else:
            remediation_id = None
        for rule in attribution_rules():
            if AttributionContext.METADATA not in rule.contexts:
                continue
            for match in rule.finditer(value):
                standalone = is_standalone_attribution(value, match.start(), match.end())
                yield self.finding(
                    artifact=artifact,
                    category=FindingCategory.EXPLICIT_AI_ATTRIBUTION,
                    confidence=rule.confidence,
                    confidence_type=ConfidenceType.DETERMINISTIC,
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.METADATA,
                    title=f"AI attribution in {self.format_label} metadata",
                    description=(
                        rule.explanation
                        + (
                            " The metadata value contains other substantive text and is not "
                            "removed by attribution-only cleanup."
                            if not standalone
                            else ""
                        )
                    ),
                    evidence={
                        "part": part,
                        "field": field,
                        "value": value,
                        "match": match.group(0),
                    },
                    location=FindingLocation(package_part=part),
                    provider=rule.provider,
                    removable=remediation_id is not None and standalone,
                    remediation_id=remediation_id if standalone else None,
                    provenance_class=ProvenanceClass.ATTRIBUTION,
                    tags=(self.format_tag, "metadata", "literal", rule.provider),
                )
