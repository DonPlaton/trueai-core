"""PowerPoint-specific OPC evidence on top of the shared Office Open XML inspector.

Presentations carry two kinds of residue a slide deck reader never sees: speaker
notes, which routinely hold drafting context that was never meant to ship, and
review comments with author identities. Both are reported as observations about
the package, not as claims about authorship.
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
from trueai.detectors.documents.ooxml import OfficeOpenXmlDetector
from trueai.detectors.documents.opc import local_name, parse_xml, read_opc_xml_part

_NOTES_PREFIX = "ppt/notesSlides/"
_SLIDES_PREFIX = "ppt/slides/"
_COMMENTS_PREFIX = "ppt/comments/"
_AUTHORS_PART = "ppt/commentAuthors.xml"
_TEXT_EXCERPT_LIMIT = 160


class PPTXDetector(OfficeOpenXmlDetector):
    """Inspect PPTX package parts without invoking PowerPoint, macros, or media."""

    id = "documents.pptx-forensics.v1"
    supported_types = frozenset({ArtifactType.PPTX})
    format_label = "PPTX"
    format_tag = "pptx"
    content_prefix = "ppt/"

    def content_findings(
        self,
        artifact: Artifact,
        package: zipfile.ZipFile,
        names: set[str],
        context: ScanContext,
    ) -> Iterable[Finding]:
        findings: list[Finding] = []
        for part in sorted(
            name for name in names if name.startswith(_NOTES_PREFIX) and name.endswith(".xml")
        ):
            root = parse_xml(read_opc_xml_part(package, part, context.options), part)
            findings.extend(self._speaker_note_findings(artifact, root, part))
        for part in sorted(
            name for name in names if name.startswith(_COMMENTS_PREFIX) and name.endswith(".xml")
        ):
            root = parse_xml(read_opc_xml_part(package, part, context.options), part)
            findings.extend(self._comment_findings(artifact, root, part))
        if _AUTHORS_PART in names:
            root = parse_xml(
                read_opc_xml_part(package, _AUTHORS_PART, context.options),
                _AUTHORS_PART,
            )
            findings.extend(self._comment_author_findings(artifact, root))
        findings.extend(self._structure_findings(artifact, names))
        return findings

    def _speaker_note_findings(
        self,
        artifact: Artifact,
        root: Element,
        part: str,
    ) -> Iterable[Finding]:
        text = " ".join(
            fragment.strip()
            for element in root.iter()
            if local_name(element.tag) == "t"
            for fragment in [element.text or ""]
            if fragment.strip()
        )
        if not text:
            return
        yield self.finding(
            artifact=artifact,
            category=FindingCategory.DOCUMENT_METADATA,
            confidence=1.0,
            confidence_type=ConfidenceType.DETERMINISTIC,
            severity=Severity.LOW,
            evidence_type=EvidenceType.METADATA,
            title="PPTX speaker notes",
            description=(
                "The presentation carries speaker notes. They are not visible in presentation "
                "mode and often retain drafting context."
            ),
            evidence={"part": part, "text_excerpt": text[:_TEXT_EXCERPT_LIMIT]},
            location=FindingLocation(package_part=part),
            provenance_class=ProvenanceClass.METADATA,
            tags=("pptx", "speaker-notes", "hidden-content"),
        )
        yield from self.metadata_attribution(artifact, part, "speaker-notes", text)

    def _comment_findings(
        self,
        artifact: Artifact,
        root: Element,
        part: str,
    ) -> Iterable[Finding]:
        for comment in root.iter():
            if local_name(comment.tag) not in {"cm", "comment"}:
                continue
            text = "".join(comment.itertext()).strip()
            yield self.finding(
                artifact=artifact,
                category=FindingCategory.DOCUMENT_METADATA,
                confidence=1.0,
                confidence_type=ConfidenceType.DETERMINISTIC,
                severity=Severity.LOW,
                evidence_type=EvidenceType.METADATA,
                title="PPTX comment",
                description=(
                    "The presentation contains a review comment and optional author metadata."
                ),
                evidence={
                    "part": part,
                    "author_id": comment.attrib.get("authorId", ""),
                    "text_excerpt": text[:_TEXT_EXCERPT_LIMIT],
                },
                location=FindingLocation(package_part=part),
                provenance_class=ProvenanceClass.METADATA,
                tags=("pptx", "comment", "review"),
            )
            yield from self.metadata_attribution(artifact, part, "comment", text)

    def _comment_author_findings(self, artifact: Artifact, root: Element) -> Iterable[Finding]:
        for author in root.iter():
            if local_name(author.tag) != "cmAuthor":
                continue
            name = author.attrib.get("name", "").strip()
            if not name:
                continue
            yield self.finding(
                artifact=artifact,
                category=FindingCategory.PERSONAL_METADATA,
                confidence=1.0,
                confidence_type=ConfidenceType.DETERMINISTIC,
                severity=Severity.MEDIUM,
                evidence_type=EvidenceType.METADATA,
                title="PPTX comment author",
                description=(
                    "A comment author identity is stored in the package and survives deleting "
                    "the comment text itself."
                ),
                evidence={
                    "part": _AUTHORS_PART,
                    "field": "name",
                    "value": name,
                    "initials": author.attrib.get("initials", ""),
                },
                location=FindingLocation(package_part=_AUTHORS_PART),
                provenance_class=ProvenanceClass.METADATA,
                tags=("pptx", "comment", "author"),
            )
            yield from self.metadata_attribution(artifact, _AUTHORS_PART, "name", name)

    def _structure_findings(self, artifact: Artifact, names: set[str]) -> list[Finding]:
        slides = sorted(
            name
            for name in names
            if name.startswith(_SLIDES_PREFIX) and name.endswith(".xml") and "/_rels/" not in name
        )
        if not slides:
            return []
        return [
            self.finding(
                artifact=artifact,
                category=FindingCategory.STRUCTURAL_SIGNAL,
                confidence=1.0,
                confidence_type=ConfidenceType.DETERMINISTIC,
                severity=Severity.INFO,
                evidence_type=EvidenceType.STRUCTURAL,
                title="PPTX slide inventory",
                description=(
                    "Slide parts present in the package. The count is structural context for a "
                    "reviewer, not evidence about authorship."
                ),
                evidence={"slide_count": len(slides), "parts": slides},
                tags=("pptx", "structure"),
            )
        ]
