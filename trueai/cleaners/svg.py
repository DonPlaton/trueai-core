"""Metadata-only SVG cleanup with canonical visible-structure verification."""

from __future__ import annotations

import re
from pathlib import Path
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

from defusedxml.ElementTree import DefusedXMLParser

from trueai.cleaners.base import CleanerOutcome
from trueai.core.errors import CorruptArtifactError, RemediationError
from trueai.core.integrity import svg_outer_misc, verify_svg_visible_structure
from trueai.core.models import Remediation, ScanOptions
from trueai.core.provenance import contains_protected_provenance_marker
from trueai.detectors.documents.opc import local_name

_EDITOR_MARKERS = ("inkscape", "sodipodi", "adobe", "serif", "sketch")


class SVGCleaner:
    """Remove explicit metadata/residue without changing visible SVG structure."""

    supported_remediation_ids = frozenset(
        {
            "svg.remove-metadata-element",
            "svg.remove-editor-attributes",
            "svg.remove-generator-comment",
        }
    )

    def apply(
        self,
        source: Path,
        destination: Path,
        remediations: tuple[Remediation, ...],
        options: ScanOptions | None = None,
    ) -> CleanerOutcome:
        before = source.read_bytes()
        if contains_protected_provenance_marker(before):
            raise RemediationError(
                "Refusing SVG cleanup because the artifact contains a provenance marker"
            )
        root = self._parse(before)
        prefix_misc, suffix_misc = svg_outer_misc(before)
        requested = {item.remediation_id for item in remediations}
        unsupported = requested - self.supported_remediation_ids
        if unsupported:
            raise RemediationError(f"SVG cleaner does not support: {sorted(unsupported)}")
        comment_matches: set[str] = set()
        selected_attributes: set[str] = set()
        for remediation in remediations:
            findings = remediation.payload.get("findings", [])
            if not isinstance(findings, (list, tuple)):
                continue
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                evidence = finding.get("evidence", {})
                if not isinstance(evidence, dict):
                    continue
                for key in ("match", "comment"):
                    value = evidence.get(key)
                    if isinstance(value, str):
                        normalized = value.strip()
                        if normalized.startswith("<!--") and normalized.endswith("-->"):
                            normalized = normalized[4:-3].strip()
                        comment_matches.add(normalized)
                if remediation.remediation_id == "svg.remove-editor-attributes":
                    attributes = evidence.get("attributes")
                    if isinstance(attributes, (list, tuple)):
                        selected_attributes.update(
                            item for item in attributes if isinstance(item, str)
                        )
        changed: list[str] = []
        parent_map = {child: parent for parent in root.iter() for child in parent}
        if "svg.remove-metadata-element" in requested:
            for element in list(root.iter()):
                tag_object: object = element.tag
                if tag_object is ElementTree.Comment:
                    continue
                tag = local_name(str(tag_object))
                if tag not in {"metadata", "rdf", "RDF", "xmpmeta"}:
                    continue
                if contains_protected_provenance_marker(
                    ElementTree.tostring(element, encoding="utf-8")
                ):
                    raise RemediationError(
                        "Refusing to remove SVG metadata containing a provenance marker"
                    )
                parent = parent_map.get(element)
                if parent is not None:
                    parent.remove(element)
                    changed.append(f"metadata element:{tag}")
        if "svg.remove-editor-attributes" in requested:
            if not selected_attributes:
                raise RemediationError(
                    "The editor-attribute plan names no attributes; refusing a blanket removal"
                )
            removed_attributes: set[str] = set()
            for element in root.iter():
                for attribute in list(element.attrib):
                    # Only the exact attribute names the detector reported and the
                    # policy approved. A blanket sweep would also delete
                    # attributes the detector marked non-removable, and the
                    # canonical form filters editor attributes out, so the
                    # integrity gate could not see the difference.
                    if attribute not in selected_attributes:
                        continue
                    if not any(marker in attribute.casefold() for marker in _EDITOR_MARKERS):
                        continue
                    if contains_protected_provenance_marker(
                        f"{attribute} {element.attrib[attribute]}"
                    ):
                        raise RemediationError(
                            "Refusing to remove an SVG editor attribute containing provenance"
                        )
                    del element.attrib[attribute]
                    removed_attributes.add(attribute)
                    changed.append(f"editor attribute:{attribute}")
            missing = selected_attributes - removed_attributes
            if missing:
                raise RemediationError(
                    f"SVG editor attributes changed after scan; missing: {sorted(missing)}"
                )
        if "svg.remove-generator-comment" in requested:
            parent_map = {child: parent for parent in root.iter() for child in parent}
            for element in list(root.iter()):
                comment_tag: object = element.tag
                if comment_tag is not ElementTree.Comment:
                    continue
                content = (element.text or "").strip()
                if contains_protected_provenance_marker(content):
                    raise RemediationError(
                        "Refusing to remove an SVG comment containing a provenance marker"
                    )
                is_generator = re.search(
                    r"(?i)\b(?:generator|created with|exported by|AI[- ]generated)\b",
                    content,
                )
                is_selected = any(match and match in content for match in comment_matches)
                if is_generator or is_selected:
                    parent = parent_map.get(element)
                    if parent is not None:
                        parent.remove(element)
                        changed.append(f"generator comment:{content[:80]}")
            prefix_misc = self._filter_outer_comments(prefix_misc, comment_matches, changed)
            suffix_misc = self._filter_outer_comments(suffix_misc, comment_matches, changed)
        if not changed:
            raise RemediationError("No planned SVG metadata matched the current artifact")
        after = self._serialize_with_outer_misc(root, prefix_misc, suffix_misc)
        destination.write_bytes(after)
        integrity = verify_svg_visible_structure(before, after, changed)
        return CleanerOutcome(changed_fields=tuple(changed), integrity=integrity)

    @staticmethod
    def _parse(data: bytes) -> Element:
        parser = DefusedXMLParser(
            target=ElementTree.TreeBuilder(insert_comments=True, insert_pis=True),
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
        try:
            return ElementTree.fromstring(data, parser=parser)
        except Exception as exc:
            raise CorruptArtifactError(f"Unable to parse SVG safely: {exc}") from exc

    @staticmethod
    def _filter_outer_comments(
        nodes: tuple[bytes, ...],
        selected: set[str],
        changed: list[str],
    ) -> tuple[bytes, ...]:
        retained: list[bytes] = []
        for node in nodes:
            if not node.startswith(b"<!--"):
                retained.append(node)
                continue
            content = node[4:-3].decode("utf-8", errors="replace").strip()
            if contains_protected_provenance_marker(content):
                raise RemediationError(
                    "Refusing to remove an SVG comment containing a provenance marker"
                )
            is_generator = re.search(
                r"(?i)\b(?:generator|created with|exported by|AI[- ]generated)\b",
                content,
            )
            is_selected = any(match and match in content for match in selected)
            if is_generator or is_selected:
                changed.append(f"generator comment:{content[:80]}")
            else:
                retained.append(node)
        return tuple(retained)

    @staticmethod
    def _serialize_with_outer_misc(
        root: Element,
        prefix_misc: tuple[bytes, ...],
        suffix_misc: tuple[bytes, ...],
    ) -> bytes:
        serialized = ElementTree.tostring(root, encoding="utf-8", xml_declaration=True)
        declaration_end = serialized.find(b"?>")
        if declaration_end < 0:
            raise RemediationError("SVG serializer omitted the XML declaration")
        declaration_end += 2
        document = bytearray(serialized[:declaration_end])
        document.extend(b"\n")
        for node in prefix_misc:
            document.extend(node)
            document.extend(b"\n")
        document.extend(serialized[declaration_end:].lstrip(b"\r\n"))
        for node in suffix_misc:
            document.extend(b"\n")
            document.extend(node)
        return bytes(document)
