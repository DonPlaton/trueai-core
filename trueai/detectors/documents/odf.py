"""OpenDocument metadata inspection, on the ZIP safety layer already in place.

ODF passed the `FMT-06` bar and legacy binary Office did not, for reasons worth
stating where the code is rather than only in a document.

ODF is a ZIP package. Every hostile-input control this project already built for
Office Open XML — path traversal, encrypted entries, entry counts, compression
ratios, uncompressed-size caps, defused XML — applies unchanged, because it is
the same container with different part names. The parser is `zipfile` plus
`defusedxml`, both maintained, both already in the dependency set. And the
integrity proof has an obvious shape: `content.xml` carries the document text,
`meta.xml` carries the metadata, and they are separate entries, so proving a
metadata-only edit means proving `content.xml` is byte-identical.

Legacy binary Office (`.doc`, `.xls`, `.ppt`) is a Compound File Binary
container: a FAT-chained pseudo-filesystem holding property-set streams. Reading
it needs a new dependency, writing it needs one that does not exist, and an
integrity proof would have to reason about sector chains rather than about
independent entries. It is identified here and reported as not inspected, which
is the honest outcome — a file silently skipped looks exactly like a file that
was clean.
"""

from __future__ import annotations

import zipfile
from collections.abc import Iterable
from typing import Final
from xml.etree.ElementTree import Element

from trueai.core.artifact import Artifact
from trueai.core.errors import CorruptArtifactError
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
from trueai.detectors.base import BaseDetector, FindingBuffer
from trueai.detectors.documents.opc import (
    local_name,
    open_validated_opc,
    parse_xml,
)

#: The metadata part. Unlike OOXML, ODF keeps everything in one place.
META_PART: Final = "meta.xml"
#: The content part, whose bytes a metadata-only edit must not touch.
CONTENT_PART: Final = "content.xml"
#: Present in every ODF package, uncompressed and first, naming the subtype.
MIMETYPE_PART: Final = "mimetype"

#: `meta.xml` fields worth reporting, and how to categorise each. A producer's
#: private extension is left alone rather than guessed at.
_META_FIELDS: Final[dict[str, tuple[FindingCategory, Severity]]] = {
    "generator": (FindingCategory.GENERATOR_METADATA, Severity.MEDIUM),
    "initial-creator": (FindingCategory.PERSONAL_METADATA, Severity.MEDIUM),
    "creator": (FindingCategory.PERSONAL_METADATA, Severity.MEDIUM),
    "title": (FindingCategory.DOCUMENT_METADATA, Severity.LOW),
    "subject": (FindingCategory.DOCUMENT_METADATA, Severity.LOW),
    "description": (FindingCategory.DOCUMENT_METADATA, Severity.LOW),
    "keyword": (FindingCategory.DOCUMENT_METADATA, Severity.LOW),
    "date": (FindingCategory.DOCUMENT_METADATA, Severity.LOW),
    "creation-date": (FindingCategory.DOCUMENT_METADATA, Severity.LOW),
    "printed-by": (FindingCategory.PERSONAL_METADATA, Severity.MEDIUM),
    "print-date": (FindingCategory.DOCUMENT_METADATA, Severity.LOW),
    "language": (FindingCategory.DOCUMENT_METADATA, Severity.LOW),
    "editing-cycles": (FindingCategory.DOCUMENT_METADATA, Severity.LOW),
    "editing-duration": (FindingCategory.DOCUMENT_METADATA, Severity.LOW),
}

#: Subtypes, so a finding can say what kind of document it came from.
ODF_MIME_TYPES: Final[dict[str, str]] = {
    "application/vnd.oasis.opendocument.text": "text",
    "application/vnd.oasis.opendocument.spreadsheet": "spreadsheet",
    "application/vnd.oasis.opendocument.presentation": "presentation",
    "application/vnd.oasis.opendocument.graphics": "graphics",
    "application/vnd.oasis.opendocument.formula": "formula",
    "application/vnd.oasis.opendocument.text-template": "text template",
    "application/vnd.oasis.opendocument.spreadsheet-template": "spreadsheet template",
    "application/vnd.oasis.opendocument.presentation-template": "presentation template",
}


def read_odf_mimetype(package: zipfile.ZipFile) -> str:
    """Return the package's declared subtype, or an empty string.

    Read from the `mimetype` entry rather than inferred from the file name,
    because an extension is attacker-controlled and this decides what the finding
    says the document is.
    """

    try:
        return package.read(MIMETYPE_PART).decode("ascii", "replace").strip()
    except KeyError:
        return ""


def odf_user_defined_name(element: Element) -> str:
    """Return the declared name of a `meta:user-defined` field."""

    for key, value in element.attrib.items():
        if local_name(key) == "name":
            return value
    return "user-defined"


class OpenDocumentDetector(BaseDetector):
    """Inspect `meta.xml` without opening any other part for content."""

    id = "documents.odf-forensics.v1"
    supported_types = frozenset({ArtifactType.ODF})
    categories = frozenset(
        {
            FindingCategory.DOCUMENT_METADATA,
            FindingCategory.PERSONAL_METADATA,
            FindingCategory.GENERATOR_METADATA,
            FindingCategory.STRUCTURAL_SIGNAL,
        }
    )

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        if artifact.path is None:
            raise CorruptArtifactError("An OpenDocument package must be a file on disk")
        findings = FindingBuffer(context.options.max_findings, self.id)
        with open_validated_opc(artifact.path, context.options) as package:
            names = set(package.namelist())
            mimetype = read_odf_mimetype(package)
            if CONTENT_PART not in names:
                raise CorruptArtifactError("An OpenDocument package must contain content.xml")
            if META_PART in names:
                root = parse_xml(package.read(META_PART), META_PART)
                findings.extend(self._metadata_findings(artifact, root, mimetype))
            findings.extend(self._structure_findings(artifact, names, mimetype))
        return list(findings)

    def _metadata_findings(
        self, artifact: Artifact, root: Element, mimetype: str
    ) -> Iterable[Finding]:
        for element in root.iter():
            tag = local_name(element.tag)
            value = (element.text or "").strip()
            if not value:
                continue
            if tag == "user-defined":
                yield self._finding_for(
                    artifact,
                    field=f"user-defined:{odf_user_defined_name(element)}",
                    value=value,
                    category=FindingCategory.DOCUMENT_METADATA,
                    severity=Severity.LOW,
                    mimetype=mimetype,
                )
                continue
            entry = _META_FIELDS.get(tag)
            if entry is None:
                continue
            category, severity = entry
            yield self._finding_for(
                artifact,
                field=tag,
                value=value,
                category=category,
                severity=severity,
                mimetype=mimetype,
            )

    def _finding_for(
        self,
        artifact: Artifact,
        *,
        field: str,
        value: str,
        category: FindingCategory,
        severity: Severity,
        mimetype: str,
    ) -> Finding:
        protected = contains_protected_provenance_marker(value)
        return self.finding(
            artifact=artifact,
            category=category,
            confidence=1.0,
            confidence_type=ConfidenceType.DETERMINISTIC,
            severity=severity,
            evidence_type=EvidenceType.METADATA,
            title=f"OpenDocument metadata: {field}",
            description=(
                "A meta.xml field records information about the document or its author."
                + (
                    " It contains a provenance marker and is protected from cleanup."
                    if protected
                    else ""
                )
            ),
            evidence={
                "part": META_PART,
                "field": field,
                "value": value,
                "document_kind": ODF_MIME_TYPES.get(mimetype, mimetype or "unknown"),
            },
            removable=not protected,
            remediation_id=None if protected else "odf.remove-metadata-field",
            provenance_class=(
                ProvenanceClass.PROVENANCE_METADATA if protected else ProvenanceClass.METADATA
            ),
            tags=("odf", "metadata", field.casefold()),
        )

    def _structure_findings(
        self, artifact: Artifact, names: set[str], mimetype: str
    ) -> Iterable[Finding]:
        """Report parts a reader should know about, without reading them for content."""

        macros = sorted(name for name in names if name.startswith(("Basic/", "Scripts/")))
        if macros:
            yield self.finding(
                artifact=artifact,
                category=FindingCategory.STRUCTURAL_SIGNAL,
                confidence=1.0,
                confidence_type=ConfidenceType.DETERMINISTIC,
                severity=Severity.MEDIUM,
                evidence_type=EvidenceType.STRUCTURAL,
                title="OpenDocument package contains macro storage",
                description=(
                    "The package carries Basic or Scripts entries. They are listed, never "
                    "parsed and never executed."
                ),
                evidence={
                    "entries": macros[:50],
                    "entry_count": len(macros),
                    "document_kind": ODF_MIME_TYPES.get(mimetype, mimetype or "unknown"),
                },
                removable=False,
                provenance_class=ProvenanceClass.NONE,
                tags=("odf", "macros", "structure"),
            )
        if mimetype and mimetype not in ODF_MIME_TYPES:
            yield self.finding(
                artifact=artifact,
                category=FindingCategory.STRUCTURAL_SIGNAL,
                confidence=1.0,
                confidence_type=ConfidenceType.DETERMINISTIC,
                severity=Severity.INFO,
                evidence_type=EvidenceType.STRUCTURAL,
                title="Unrecognised OpenDocument subtype",
                description=(
                    "The package declares a mimetype this build does not recognise. Metadata "
                    "was still read; the subtype is reported so a reader is not left guessing."
                ),
                evidence={"mimetype": mimetype},
                removable=False,
                provenance_class=ProvenanceClass.NONE,
                tags=("odf", "structure"),
            )


__all__ = [
    "CONTENT_PART",
    "META_PART",
    "MIMETYPE_PART",
    "ODF_MIME_TYPES",
    "OpenDocumentDetector",
    "odf_user_defined_name",
    "read_odf_mimetype",
]
