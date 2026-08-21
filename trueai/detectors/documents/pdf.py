"""Bounded passive PDF metadata inspection without rendering content."""

from __future__ import annotations

import re
from collections.abc import Iterator

from trueai.core.artifact import Artifact
from trueai.core.errors import CorruptArtifactError
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
from trueai.core.provenance import contains_protected_provenance_marker
from trueai.detectors.base import BaseDetector, FindingBuffer

_INFO_PATTERN = re.compile(
    rb"/(Author|Creator|Producer|CreationDate|ModDate|Title|Subject|Keywords)\s*"
    rb"(\((?:\\.|[^\\)])*\)|<[0-9A-Fa-f\s]+>)"
)


class PDFDetector(BaseDetector):
    """Inspect common PDF Info/XMP markers without executing actions or attachments."""

    id = "documents.pdf-forensics.v1"
    supported_types = frozenset({ArtifactType.PDF})
    categories = frozenset(
        {
            FindingCategory.DOCUMENT_METADATA,
            FindingCategory.PERSONAL_METADATA,
            FindingCategory.GENERATOR_METADATA,
            FindingCategory.STRUCTURAL_SIGNAL,
        }
    )

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        data = artifact.read_bytes(context.options.max_file_size)
        if not data.startswith(b"%PDF-"):
            raise CorruptArtifactError("PDF signature is missing")
        if b"%%EOF" not in data[-4096:]:
            raise CorruptArtifactError("PDF end-of-file marker is missing from the bounded tail")
        findings = FindingBuffer(context.options.max_findings, self.id)
        for field, raw_value, byte_offset in self._info_entries(data):
            value = self._decode_pdf_value(raw_value)
            protected = contains_protected_provenance_marker(value)
            if field == "Author":
                category = FindingCategory.PERSONAL_METADATA
            elif field in {"Creator", "Producer"}:
                category = FindingCategory.GENERATOR_METADATA
            else:
                category = FindingCategory.DOCUMENT_METADATA
            findings.append(
                self.finding(
                    artifact=artifact,
                    category=category,
                    confidence=1.0,
                    confidence_type=ConfidenceType.DETERMINISTIC,
                    severity=Severity.MEDIUM
                    if field in {"Author", "Creator", "Producer"}
                    else Severity.LOW,
                    evidence_type=EvidenceType.METADATA,
                    title=f"PDF Info metadata: {field}",
                    description=(
                        "A literal Info dictionary entry is present. Full object validation and "
                        "cleanup require the optional pikepdf adapter."
                    ),
                    evidence={"field": field, "value": value},
                    location=FindingLocation(byte_offset=byte_offset),
                    removable=not protected,
                    remediation_id=None if protected else "pdf.remove-metadata-field",
                    provenance_class=(
                        ProvenanceClass.PROVENANCE_METADATA
                        if protected
                        else ProvenanceClass.METADATA
                    ),
                    tags=("pdf", "info-dictionary", field.casefold()),
                )
            )
        xmp_packet = self._linked_xmp_packet(data)
        if xmp_packet:
            xmp_bytes, xmp_offset = xmp_packet
            protected = contains_protected_provenance_marker(xmp_bytes)
            findings.append(
                self.finding(
                    artifact=artifact,
                    category=FindingCategory.DOCUMENT_METADATA,
                    confidence=1.0,
                    confidence_type=ConfidenceType.DETERMINISTIC,
                    severity=Severity.LOW,
                    evidence_type=EvidenceType.METADATA,
                    title="PDF linked XMP metadata packet",
                    description=(
                        "The catalog references an XML metadata stream containing an XMP packet."
                        + (
                            " It contains a provenance marker and is protected from cleanup."
                            if protected
                            else ""
                        )
                    ),
                    evidence={
                        "length": len(xmp_bytes),
                        "protected_provenance_marker": protected,
                    },
                    location=FindingLocation(byte_offset=xmp_offset),
                    removable=not protected,
                    remediation_id=None if protected else "pdf.remove-xmp",
                    provenance_class=(
                        ProvenanceClass.PROVENANCE_METADATA
                        if protected
                        else ProvenanceClass.METADATA
                    ),
                    tags=("pdf", "xmp", "metadata"),
                )
            )
        if b"/EmbeddedFile" in data or b"/Filespec" in data:
            findings.append(
                self.finding(
                    artifact=artifact,
                    category=FindingCategory.STRUCTURAL_SIGNAL,
                    confidence=1.0,
                    confidence_type=ConfidenceType.DETERMINISTIC,
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.STRUCTURAL,
                    title="PDF embedded-file lexical marker",
                    description=(
                        "A raw PDF token names an embedded-file or file-specification type. "
                        "The bounded core scanner does not resolve the full attachment graph."
                    ),
                    evidence={"embedded_file_marker": b"/EmbeddedFile" in data},
                    tags=("pdf", "embedded-file", "raw-marker", "passive-scan"),
                )
            )
        if b"/Annots" in data:
            findings.append(
                self.finding(
                    artifact=artifact,
                    category=FindingCategory.STRUCTURAL_SIGNAL,
                    confidence=1.0,
                    confidence_type=ConfidenceType.DETERMINISTIC,
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.STRUCTURAL,
                    title="PDF annotation lexical marker",
                    description=(
                        "A raw /Annots token is present. The bounded core scanner does not claim "
                        "that the token is reachable from a page tree."
                    ),
                    evidence={"marker": "/Annots"},
                    tags=("pdf", "annotations", "raw-marker"),
                )
            )
        return findings

    @staticmethod
    def _info_entries(data: bytes) -> Iterator[tuple[str, bytes, int]]:
        trailer_start = data.rfind(b"trailer")
        if trailer_start < 0:
            return
        trailer_end = data.find(b"startxref", trailer_start)
        if trailer_end < 0:
            trailer_end = len(data)
        trailer = data[trailer_start:trailer_end]
        info_reference = re.search(rb"/Info\s+(\d+)\s+(\d+)\s+R\b", trailer)
        if info_reference is not None:
            object_number = re.escape(info_reference.group(1))
            generation = re.escape(info_reference.group(2))
            object_pattern = re.compile(
                rb"(?m)(?:^|[\r\n\t ])" + object_number + rb"\s+" + generation + rb"\s+obj\b"
            )
            object_match: re.Match[bytes] | None = None
            for candidate in object_pattern.finditer(data[:trailer_start]):
                object_match = candidate
            if object_match is None:
                return
            object_start = object_match.end()
            object_end = data.find(b"endobj", object_start, trailer_start)
            if object_end < 0:
                return
            info_object = data[object_start:object_end]
            for match in _INFO_PATTERN.finditer(info_object):
                yield (
                    match.group(1).decode("ascii"),
                    match.group(2),
                    object_start + match.start(),
                )
            return

        direct_info = re.search(rb"/Info\s*<<(.*?)>>", trailer, flags=re.DOTALL)
        if direct_info is None:
            return
        for match in _INFO_PATTERN.finditer(direct_info.group(1)):
            yield (
                match.group(1).decode("ascii"),
                match.group(2),
                trailer_start + direct_info.start(1) + match.start(),
            )

    @staticmethod
    def _linked_xmp_packet(data: bytes) -> tuple[bytes, int] | None:
        trailer_start = data.rfind(b"trailer")
        if trailer_start < 0:
            return None
        trailer_end = data.find(b"startxref", trailer_start)
        if trailer_end < 0:
            trailer_end = len(data)
        trailer = data[trailer_start:trailer_end]
        root_reference = re.search(rb"/Root\s+(\d+)\s+(\d+)\s+R\b", trailer)
        if root_reference is None:
            return None
        root_object = PDFDetector._indirect_object(
            data,
            root_reference.group(1),
            root_reference.group(2),
            trailer_start,
        )
        if root_object is None:
            return None
        root_body, _ = root_object
        metadata_reference = re.search(rb"/Metadata\s+(\d+)\s+(\d+)\s+R\b", root_body)
        if metadata_reference is None:
            return None
        metadata_object = PDFDetector._indirect_object(
            data,
            metadata_reference.group(1),
            metadata_reference.group(2),
            trailer_start,
        )
        if metadata_object is None:
            return None
        metadata_body, metadata_offset = metadata_object
        stream_start = metadata_body.find(b"stream")
        if stream_start < 0:
            return None
        dictionary = metadata_body[:stream_start]
        if not (
            re.search(rb"/Type\s*/Metadata\b", dictionary)
            and re.search(rb"/Subtype\s*/XML\b", dictionary)
        ):
            return None
        packet = re.search(rb"<\?xpacket[\s\S]{0,2097152}?</x:xmpmeta>", metadata_body)
        if packet is None:
            return None
        return packet.group(0), metadata_offset + packet.start()

    @staticmethod
    def _indirect_object(
        data: bytes,
        object_number: bytes,
        generation: bytes,
        before: int,
    ) -> tuple[bytes, int] | None:
        object_pattern = re.compile(
            rb"(?m)(?:^|[\r\n\t ])"
            + re.escape(object_number)
            + rb"\s+"
            + re.escape(generation)
            + rb"\s+obj\b"
        )
        object_match: re.Match[bytes] | None = None
        for candidate in object_pattern.finditer(data[:before]):
            object_match = candidate
        if object_match is None:
            return None
        object_start = object_match.end()
        object_end = data.find(b"endobj", object_start, before)
        if object_end < 0:
            return None
        return data[object_start:object_end], object_start

    @staticmethod
    def _decode_pdf_value(raw: bytes) -> str:
        if raw.startswith(b"<"):
            try:
                decoded = bytes.fromhex(re.sub(rb"\s", b"", raw[1:-1]).decode("ascii"))
                return decoded.decode("utf-8", errors="replace")
            except ValueError:
                return raw.decode("latin-1", errors="replace")
        value = raw[1:-1]
        value = re.sub(rb"\\([()\\])", rb"\1", value)
        return value.decode("utf-8", errors="replace")
