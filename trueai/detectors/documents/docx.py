"""Word-specific OPC evidence on top of the shared Office Open XML inspector."""

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
from trueai.detectors.documents.ooxml import OfficeOpenXmlDetector
from trueai.detectors.documents.opc import local_name, parse_xml, read_opc_xml_part

_COMMENTS_PART = "word/comments.xml"
_DOCUMENT_PART = "word/document.xml"
_AUTHOR_ATTRIBUTE = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}author"


class DOCXDetector(OfficeOpenXmlDetector):
    """Inspect DOCX package parts without invoking Microsoft Word or macros."""

    id = "documents.docx-forensics.v1"
    supported_types = frozenset({ArtifactType.DOCX})
    format_label = "DOCX"
    format_tag = "docx"
    content_prefix = "word/"

    def content_findings(
        self,
        artifact: Artifact,
        package: zipfile.ZipFile,
        names: set[str],
        context: ScanContext,
    ) -> Iterable[Finding]:
        findings: list[Finding] = []
        if _COMMENTS_PART in names:
            root = parse_xml(
                read_opc_xml_part(package, _COMMENTS_PART, context.options),
                _COMMENTS_PART,
            )
            findings.extend(self._comment_findings(artifact, root))
        if _DOCUMENT_PART in names:
            document_root = parse_xml(
                read_opc_xml_part(package, _DOCUMENT_PART, context.options),
                _DOCUMENT_PART,
            )
            findings.extend(self._revision_findings(artifact, document_root))
        return findings

    def _comment_findings(self, artifact: Artifact, root: Element) -> Iterable[Finding]:
        for comment in root.iter():
            if local_name(comment.tag) != "comment":
                continue
            author = comment.attrib.get(_AUTHOR_ATTRIBUTE, "")
            text = "".join(comment.itertext()).strip()
            yield self.finding(
                artifact=artifact,
                category=FindingCategory.DOCUMENT_METADATA,
                confidence=1.0,
                confidence_type=ConfidenceType.DETERMINISTIC,
                severity=Severity.LOW,
                evidence_type=EvidenceType.METADATA,
                title="DOCX comment",
                description="The document contains a review comment and optional author metadata.",
                evidence={
                    "part": _COMMENTS_PART,
                    "author": author,
                    "text_excerpt": text[:160],
                },
                location=FindingLocation(package_part=_COMMENTS_PART),
                provenance_class=ProvenanceClass.METADATA,
                tags=("docx", "comment", "review"),
            )
            yield from self.metadata_attribution(artifact, _COMMENTS_PART, "comment", text)

    def _revision_findings(self, artifact: Artifact, root: Element) -> list[Finding]:
        revision_kinds = {
            local_name(element.tag)
            for element in root.iter()
            if local_name(element.tag) in {"ins", "del", "moveFrom", "moveTo"}
        }
        if not revision_kinds:
            return []
        return [
            self.finding(
                artifact=artifact,
                category=FindingCategory.STRUCTURAL_SIGNAL,
                confidence=1.0,
                confidence_type=ConfidenceType.DETERMINISTIC,
                severity=Severity.MEDIUM,
                evidence_type=EvidenceType.STRUCTURAL,
                title="DOCX tracked changes",
                description="The main document XML contains tracked revision elements.",
                evidence={"part": _DOCUMENT_PART, "revision_types": sorted(revision_kinds)},
                location=FindingLocation(package_part=_DOCUMENT_PART),
                tags=("docx", "tracked-changes"),
            )
        ]
