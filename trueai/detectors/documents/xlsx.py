"""Excel-specific OPC evidence on top of the shared Office Open XML inspector.

Workbooks hide residue in places a spreadsheet view does not show: cell comments
and their authors, hidden worksheets, external workbook links that reach off the
machine when opened, and defined names left behind by tooling. Each is reported
as an observation about the package, never opened or resolved.
"""

from __future__ import annotations

import zipfile
from collections.abc import Iterable
from xml.etree.ElementTree import Element

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
from trueai.detectors.documents.ooxml import OOXML_CATEGORIES, OfficeOpenXmlDetector
from trueai.detectors.documents.opc import local_name, parse_xml, read_opc_xml_part

_WORKBOOK_PART = "xl/workbook.xml"
_COMMENTS_PREFIX = "xl/comments"
_THREADED_COMMENTS_PREFIX = "xl/threadedComments/"
_PERSONS_PART = "xl/persons/person.xml"
_EXTERNAL_LINKS_PREFIX = "xl/externalLinks/"
_TEXT_EXCERPT_LIMIT = 160
_HIDDEN_STATES = {"hidden", "veryHidden"}


class XLSXDetector(OfficeOpenXmlDetector):
    """Inspect XLSX package parts without opening links, formulas, or macros."""

    id = "documents.xlsx-forensics.v1"
    supported_types = frozenset({ArtifactType.XLSX})
    categories = OOXML_CATEGORIES | {
        FindingCategory.HIDDEN_ELEMENT,
        FindingCategory.TOOLING_RESIDUE,
    }
    format_label = "XLSX"
    format_tag = "xlsx"
    content_prefix = "xl/"

    def content_findings(
        self,
        artifact: Artifact,
        package: zipfile.ZipFile,
        names: set[str],
        context: ScanContext,
    ) -> Iterable[Finding]:
        findings: list[Finding] = []
        if _WORKBOOK_PART in names:
            root = parse_xml(
                read_opc_xml_part(package, _WORKBOOK_PART, context.options),
                _WORKBOOK_PART,
            )
            findings.extend(self._hidden_sheet_findings(artifact, root))
            findings.extend(self._defined_name_findings(artifact, root))
        for part in sorted(
            name for name in names if name.startswith(_COMMENTS_PREFIX) and name.endswith(".xml")
        ):
            root = parse_xml(read_opc_xml_part(package, part, context.options), part)
            findings.extend(self._comment_findings(artifact, root, part))
        for part in sorted(
            name
            for name in names
            if name.startswith(_THREADED_COMMENTS_PREFIX) and name.endswith(".xml")
        ):
            root = parse_xml(read_opc_xml_part(package, part, context.options), part)
            findings.extend(self._threaded_comment_findings(artifact, root, part))
        if _PERSONS_PART in names:
            root = parse_xml(
                read_opc_xml_part(package, _PERSONS_PART, context.options),
                _PERSONS_PART,
            )
            findings.extend(self._person_findings(artifact, root))
        findings.extend(self._external_link_findings(artifact, names))
        return findings

    def _hidden_sheet_findings(self, artifact: Artifact, root: Element) -> Iterable[Finding]:
        for sheet in root.iter():
            if local_name(sheet.tag) != "sheet":
                continue
            state = sheet.attrib.get("state", "visible")
            if state not in _HIDDEN_STATES:
                continue
            yield self.finding(
                artifact=artifact,
                category=FindingCategory.HIDDEN_ELEMENT,
                confidence=1.0,
                confidence_type=ConfidenceType.DETERMINISTIC,
                severity=Severity.MEDIUM,
                evidence_type=EvidenceType.STRUCTURAL,
                title="XLSX hidden worksheet",
                description=(
                    "A worksheet is hidden from the normal sheet tabs. Its content ships with "
                    "the workbook and is recoverable by any reader."
                ),
                evidence={
                    "part": _WORKBOOK_PART,
                    "sheet_name": sheet.attrib.get("name", ""),
                    "state": state,
                },
                location=FindingLocation(package_part=_WORKBOOK_PART),
                tags=("xlsx", "hidden-sheet", "structure"),
            )

    def _defined_name_findings(self, artifact: Artifact, root: Element) -> Iterable[Finding]:
        for defined_name in root.iter():
            if local_name(defined_name.tag) != "definedName":
                continue
            name = defined_name.attrib.get("name", "")
            value = (defined_name.text or "").strip()
            if not name:
                continue
            yield self.finding(
                artifact=artifact,
                category=FindingCategory.TOOLING_RESIDUE,
                confidence=1.0,
                confidence_type=ConfidenceType.DETERMINISTIC,
                severity=Severity.LOW,
                evidence_type=EvidenceType.STRUCTURAL,
                title="XLSX defined name",
                description=(
                    "The workbook declares a defined name. Add-ins and export tooling leave "
                    "these behind; the reference is reported without being resolved."
                ),
                evidence={"part": _WORKBOOK_PART, "field": name, "value": value},
                location=FindingLocation(package_part=_WORKBOOK_PART),
                tags=("xlsx", "defined-name", "tooling"),
            )
            yield from self.metadata_attribution(artifact, _WORKBOOK_PART, name, value)

    def _comment_findings(
        self,
        artifact: Artifact,
        root: Element,
        part: str,
    ) -> Iterable[Finding]:
        authors = [
            (element.text or "").strip()
            for element in root.iter()
            if local_name(element.tag) == "author"
        ]
        for author in authors:
            if not author:
                continue
            yield self.finding(
                artifact=artifact,
                category=FindingCategory.PERSONAL_METADATA,
                confidence=1.0,
                confidence_type=ConfidenceType.DETERMINISTIC,
                severity=Severity.MEDIUM,
                evidence_type=EvidenceType.METADATA,
                title="XLSX comment author",
                description=(
                    "A cell comment records an author identity inside the package, independent "
                    "of the document properties."
                ),
                evidence={"part": part, "field": "author", "value": author},
                location=FindingLocation(package_part=part),
                provenance_class=ProvenanceClass.METADATA,
                tags=("xlsx", "comment", "author"),
            )
            yield from self.metadata_attribution(artifact, part, "author", author)
        for comment in root.iter():
            if local_name(comment.tag) != "comment":
                continue
            text = "".join(comment.itertext()).strip()
            yield self.finding(
                artifact=artifact,
                category=FindingCategory.DOCUMENT_METADATA,
                confidence=1.0,
                confidence_type=ConfidenceType.DETERMINISTIC,
                severity=Severity.LOW,
                evidence_type=EvidenceType.METADATA,
                title="XLSX cell comment",
                description="A cell comment is stored in the workbook package.",
                evidence={
                    "part": part,
                    "cell": comment.attrib.get("ref", ""),
                    "text_excerpt": text[:_TEXT_EXCERPT_LIMIT],
                },
                location=FindingLocation(package_part=part),
                provenance_class=ProvenanceClass.METADATA,
                tags=("xlsx", "comment", "review"),
            )
            yield from self.metadata_attribution(artifact, part, "comment", text)

    def _threaded_comment_findings(
        self,
        artifact: Artifact,
        root: Element,
        part: str,
    ) -> Iterable[Finding]:
        for comment in root.iter():
            if local_name(comment.tag) != "threadedComment":
                continue
            text = "".join(comment.itertext()).strip()
            yield self.finding(
                artifact=artifact,
                category=FindingCategory.DOCUMENT_METADATA,
                confidence=1.0,
                confidence_type=ConfidenceType.DETERMINISTIC,
                severity=Severity.LOW,
                evidence_type=EvidenceType.METADATA,
                title="XLSX threaded comment",
                description=(
                    "A modern threaded comment is stored with a persistent person identifier."
                ),
                evidence={
                    "part": part,
                    "cell": comment.attrib.get("ref", ""),
                    "person_id": comment.attrib.get("personId", ""),
                    "text_excerpt": text[:_TEXT_EXCERPT_LIMIT],
                },
                location=FindingLocation(package_part=part),
                provenance_class=ProvenanceClass.METADATA,
                tags=("xlsx", "comment", "threaded"),
            )
            yield from self.metadata_attribution(artifact, part, "threadedComment", text)

    def _person_findings(self, artifact: Artifact, root: Element) -> Iterable[Finding]:
        for person in root.iter():
            if local_name(person.tag) != "person":
                continue
            display_name = person.attrib.get("displayName", "").strip()
            if not display_name:
                continue
            yield self.finding(
                artifact=artifact,
                category=FindingCategory.PERSONAL_METADATA,
                confidence=1.0,
                confidence_type=ConfidenceType.DETERMINISTIC,
                severity=Severity.MEDIUM,
                evidence_type=EvidenceType.METADATA,
                title="XLSX comment participant identity",
                description=(
                    "The workbook stores a directory identity for a threaded-comment "
                    "participant, including the provider account identifier where present."
                ),
                evidence={
                    "part": _PERSONS_PART,
                    "field": "displayName",
                    "value": display_name,
                    "user_id": person.attrib.get("userId", ""),
                    "provider_id": person.attrib.get("providerId", ""),
                },
                location=FindingLocation(package_part=_PERSONS_PART),
                provenance_class=ProvenanceClass.METADATA,
                tags=("xlsx", "identity", "threaded"),
            )
            yield from self.metadata_attribution(
                artifact, _PERSONS_PART, "displayName", display_name
            )

    def _external_link_findings(self, artifact: Artifact, names: set[str]) -> list[Finding]:
        links = sorted(
            name
            for name in names
            if name.startswith(_EXTERNAL_LINKS_PREFIX)
            and name.endswith(".xml")
            and "/_rels/" not in name
        )
        if not links:
            return []
        return [
            self.finding(
                artifact=artifact,
                category=FindingCategory.SECURITY_ISSUE,
                confidence=1.0,
                confidence_type=ConfidenceType.DETERMINISTIC,
                severity=Severity.MEDIUM,
                evidence_type=EvidenceType.SECURITY,
                title="XLSX external workbook links",
                description=(
                    "The workbook references external workbooks. Opening it in a spreadsheet "
                    "application may reach the link targets; TrueAI never resolves them."
                ),
                evidence={"parts": links},
                tags=("xlsx", "external-link", "passive-scan"),
            )
        ]
