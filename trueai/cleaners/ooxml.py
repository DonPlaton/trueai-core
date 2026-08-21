"""Surgical Office Open XML metadata cleanup with package-level integrity proofs.

Every OOXML family stores its document properties in the same three parts, so the
mutation itself is shared. What differs is the invariant that proves the cleanup
was harmless: Word content tokens, slide text, or cell values. Each subclass
declares its own content parts and the shared code re-verifies them, so a new
format cannot be added without also stating how its integrity is proved.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import cast
from xml.etree import ElementTree

from trueai.cleaners.base import CleanerOutcome
from trueai.core.errors import RemediationError
from trueai.core.integrity import (
    DOCX_CONTENT_TAGS,
    PPTX_CONTENT_TAGS,
    XLSX_CONTENT_TAGS,
    verify_ooxml_metadata_only,
)
from trueai.core.models import Remediation, ScanOptions
from trueai.core.provenance import contains_protected_provenance_marker
from trueai.detectors.documents.ooxml import CUSTOM_PROPERTIES_PART
from trueai.detectors.documents.opc import (
    local_name,
    open_validated_opc,
    parse_xml_preserving_misc,
)


class OfficeOpenXmlCleaner:
    """Remove selected property nodes while preserving every other OPC entry."""

    #: Remediation namespace, matching the detector's ``format_tag``.
    remediation_namespace = "ooxml"
    #: Human-facing format name used in errors and integrity explanations.
    format_label = "OOXML"
    #: Package prefix whose text content must survive cleanup unchanged.
    content_prefix = ""
    #: Element names inside that prefix which carry reader-visible text.
    content_tags: frozenset[str] = frozenset()
    #: Operations this cleaner is allowed to apply. Declared per subclass so an
    #: unlisted operation cannot reach the mutation path by inheritance.
    supported_remediation_ids: frozenset[str] = frozenset()

    def apply(
        self,
        source: Path,
        destination: Path,
        remediations: tuple[Remediation, ...],
    ) -> CleanerOutcome:
        """Rewrite the package with approved properties removed, then prove the result."""

        custom_property_operation = f"{self.remediation_namespace}.remove-custom-property"
        targets: dict[str, set[str]] = {}
        custom_fields: set[str] = set()
        changed_fields: list[str] = []
        for remediation in remediations:
            if remediation.remediation_id not in self.supported_remediation_ids:
                raise RemediationError(
                    f"{self.format_label} cleaner does not support {remediation.remediation_id}"
                )
            findings = remediation.payload.get("findings", [])
            if not isinstance(findings, (list, tuple)):
                raise RemediationError(f"Malformed {self.format_label} remediation payload")
            for raw in findings:
                if not isinstance(raw, dict):
                    continue
                evidence = raw.get("evidence", {})
                if not isinstance(evidence, dict):
                    continue
                part = evidence.get("part")
                field = evidence.get("field")
                if not isinstance(part, str) or not isinstance(field, str):
                    continue
                if remediation.remediation_id == custom_property_operation:
                    custom_fields.add(field)
                else:
                    targets.setdefault(part, set()).add(field)
                changed_fields.append(f"{part}:{field}")
        changed_parts = set(targets)
        if custom_fields:
            changed_parts.add(CUSTOM_PROPERTIES_PART)
        with (
            open_validated_opc(source, ScanOptions()) as source_zip,
            zipfile.ZipFile(destination, "w") as destination_zip,
        ):
            for info in source_zip.infolist():
                data = source_zip.read(info.filename)
                if info.filename in targets:
                    data = self._remove_fields(data, info.filename, targets[info.filename])
                if info.filename == CUSTOM_PROPERTIES_PART and custom_fields:
                    data = self._remove_custom_fields(data, custom_fields)
                destination_zip.writestr(info, data)
        integrity = verify_ooxml_metadata_only(
            source,
            destination,
            changed_parts,
            changed_fields,
            content_prefix=self.content_prefix,
            content_tags=self.content_tags,
            format_label=self.format_label,
        )
        return CleanerOutcome(
            changed_fields=tuple(sorted(set(changed_fields))), integrity=integrity
        )

    def _remove_fields(self, data: bytes, part: str, fields: set[str]) -> bytes:
        root = parse_xml_preserving_misc(data, part)
        parent_map = {child: parent for parent in root.iter() for child in parent}
        removed: set[str] = set()
        for element in list(root.iter()):
            tag_object: object = element.tag
            if tag_object in {ElementTree.Comment, ElementTree.ProcessingInstruction}:
                continue
            name = local_name(str(tag_object))
            if name not in fields:
                continue
            if contains_protected_provenance_marker(
                ElementTree.tostring(element, encoding="utf-8")
            ):
                raise RemediationError(
                    f"Refusing to remove {self.format_label} field {name} containing provenance"
                )
            parent = parent_map.get(element)
            if parent is None:
                element.text = None
            else:
                parent.remove(element)
            removed.add(name)
        missing = fields - removed
        if missing:
            raise RemediationError(
                f"{self.format_label} metadata changed after scan; "
                f"missing fields: {sorted(missing)}"
            )
        return cast(bytes, ElementTree.tostring(root, encoding="utf-8", xml_declaration=True))

    def _remove_custom_fields(self, data: bytes, fields: set[str]) -> bytes:
        root = parse_xml_preserving_misc(data, CUSTOM_PROPERTIES_PART)
        removed: set[str] = set()
        for element in list(root):
            tag_object: object = element.tag
            if (
                tag_object not in {ElementTree.Comment, ElementTree.ProcessingInstruction}
                and local_name(str(tag_object)) == "property"
                and element.attrib.get("name") in fields
            ):
                if contains_protected_provenance_marker(
                    ElementTree.tostring(element, encoding="utf-8")
                ):
                    raise RemediationError(
                        f"Refusing to remove a {self.format_label} custom property "
                        "containing provenance"
                    )
                removed.add(element.attrib["name"])
                root.remove(element)
        missing = fields - removed
        if missing:
            raise RemediationError(
                f"{self.format_label} custom properties changed after scan; "
                f"missing: {sorted(missing)}"
            )
        return cast(bytes, ElementTree.tostring(root, encoding="utf-8", xml_declaration=True))


class DOCXCleaner(OfficeOpenXmlCleaner):
    """Word package cleanup verified against Word content tokens."""

    remediation_namespace = "docx"
    format_label = "DOCX"
    content_prefix = "word/"
    content_tags = DOCX_CONTENT_TAGS
    supported_remediation_ids = frozenset(
        {"docx.remove-metadata-field", "docx.remove-custom-property"}
    )


class PPTXCleaner(OfficeOpenXmlCleaner):
    """PowerPoint package cleanup verified against slide and notes text."""

    remediation_namespace = "pptx"
    format_label = "PPTX"
    content_prefix = "ppt/"
    content_tags = PPTX_CONTENT_TAGS
    supported_remediation_ids = frozenset(
        {"pptx.remove-metadata-field", "pptx.remove-custom-property"}
    )


class XLSXCleaner(OfficeOpenXmlCleaner):
    """Excel package cleanup verified against cell values, formulas, and shared strings."""

    remediation_namespace = "xlsx"
    format_label = "XLSX"
    content_prefix = "xl/"
    content_tags = XLSX_CONTENT_TAGS
    supported_remediation_ids = frozenset(
        {"xlsx.remove-metadata-field", "xlsx.remove-custom-property"}
    )
