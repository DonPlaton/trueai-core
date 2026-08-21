"""Content-integrity proofs for supported predictable remediation paths."""

from __future__ import annotations

import hashlib
import json
import re
import zipfile
from collections.abc import Iterable
from pathlib import Path
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

from defusedxml.ElementTree import DefusedXMLParser

from trueai.core.errors import CorruptArtifactError
from trueai.core.models import IntegrityReport, IntegrityStatus
from trueai.detectors.documents.opc import local_name, parse_xml, parse_xml_preserving_misc


def sha256_bytes(data: bytes) -> str:
    """Return a lowercase SHA-256 digest."""

    return hashlib.sha256(data).hexdigest()


def verify_exact_transform(
    before: bytes,
    after: bytes,
    expected_after: bytes,
    *,
    intentionally_removed: Iterable[str] = (),
    explanation: str,
) -> IntegrityReport:
    """Prove that emitted bytes equal the cleaner's bounded expected transform."""

    status = IntegrityStatus.PASS if after == expected_after else IntegrityStatus.FAIL
    return IntegrityReport(
        status=status,
        explanation=explanation
        if status == IntegrityStatus.PASS
        else "Output differs from the planned transform.",
        before_sha256=sha256_bytes(before),
        after_sha256=sha256_bytes(after),
        logical_before_sha256=sha256_bytes(expected_after),
        logical_after_sha256=sha256_bytes(after),
        intentionally_removed=tuple(intentionally_removed),
    )


#: Content-bearing element names per Office Open XML family. Only these carry
#: text a reader would notice, so they define the logical invariant that metadata
#: cleanup must not disturb.
DOCX_CONTENT_TAGS = frozenset({"t", "tab", "br", "cr", "delText", "instrText"})
PPTX_CONTENT_TAGS = frozenset({"t", "fld"})
XLSX_CONTENT_TAGS = frozenset({"t", "v", "f", "is"})


def ooxml_logical_text(
    package_path: Path,
    content_prefix: str,
    content_tags: frozenset[str],
    format_label: str,
) -> bytes:
    """Extract ordered textual tokens from one Office Open XML family's content parts."""

    tokens: list[tuple[str, str, str]] = []
    try:
        with zipfile.ZipFile(package_path) as package:
            for name in sorted(package.namelist()):
                if not name.startswith(content_prefix) or not name.endswith(".xml"):
                    continue
                root = parse_xml(package.read(name), name)
                for element in root.iter():
                    tag = local_name(element.tag)
                    if tag in content_tags:
                        tokens.append((name, tag, element.text or ""))
    except (OSError, zipfile.BadZipFile) as exc:
        raise CorruptArtifactError(f"Unable to extract {format_label} logical text: {exc}") from exc
    return json.dumps(tokens, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def docx_logical_text(package_path: Path) -> bytes:
    """Extract ordered textual tokens from DOCX content parts."""

    return ooxml_logical_text(package_path, "word/", DOCX_CONTENT_TAGS, "DOCX")


def verify_ooxml_metadata_only(
    before_path: Path,
    after_path: Path,
    changed_parts: set[str],
    changed_fields: Iterable[str],
    *,
    content_prefix: str,
    content_tags: frozenset[str],
    format_label: str,
) -> IntegrityReport:
    """Prove that all non-approved OPC entries and logical content are unchanged."""

    changed_fields_tuple = tuple(changed_fields)
    try:
        with zipfile.ZipFile(before_path) as before_zip, zipfile.ZipFile(after_path) as after_zip:
            before_names = set(before_zip.namelist())
            after_names = set(after_zip.namelist())
            unchanged = before_names == after_names
            if unchanged:
                for name in before_names - changed_parts:
                    if before_zip.read(name) != after_zip.read(name):
                        unchanged = False
                        break
            if unchanged:
                exclusions = _ooxml_changed_fields(changed_fields_tuple)
                for name in changed_parts:
                    if name not in before_names or name not in after_names:
                        unchanged = False
                        break
                    before_part = _canonical_ooxml_metadata_part(
                        before_zip.read(name),
                        name,
                        exclusions.get(name, set()),
                    )
                    after_part = _canonical_ooxml_metadata_part(
                        after_zip.read(name),
                        name,
                        exclusions.get(name, set()),
                    )
                    if before_part != after_part:
                        unchanged = False
                        break
    except (OSError, zipfile.BadZipFile) as exc:
        return IntegrityReport(
            status=IntegrityStatus.FAIL,
            explanation=f"Could not compare OPC entries: {exc}",
        )
    before_logical = ooxml_logical_text(before_path, content_prefix, content_tags, format_label)
    after_logical = ooxml_logical_text(after_path, content_prefix, content_tags, format_label)
    logical_equal = before_logical == after_logical
    status = IntegrityStatus.PASS if unchanged and logical_equal else IntegrityStatus.FAIL
    return IntegrityReport(
        status=status,
        explanation=(
            f"Only approved metadata package parts changed; all {format_label} content tokens "
            "and other OPC entries are byte-identical."
            if status == IntegrityStatus.PASS
            else f"A non-approved OPC entry or logical {format_label} content changed."
        ),
        before_sha256=sha256_bytes(before_path.read_bytes()),
        after_sha256=sha256_bytes(after_path.read_bytes()),
        logical_before_sha256=sha256_bytes(before_logical),
        logical_after_sha256=sha256_bytes(after_logical),
        intentionally_removed=changed_fields_tuple,
    )


def verify_docx_metadata_only(
    before_path: Path,
    after_path: Path,
    changed_parts: set[str],
    changed_fields: Iterable[str],
) -> IntegrityReport:
    """Prove that all non-approved OPC entries and logical Word content are unchanged."""

    return verify_ooxml_metadata_only(
        before_path,
        after_path,
        changed_parts,
        changed_fields,
        content_prefix="word/",
        content_tags=DOCX_CONTENT_TAGS,
        format_label="DOCX",
    )


def _ooxml_changed_fields(changed_fields: Iterable[str]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for changed_field in changed_fields:
        part, separator, field = changed_field.partition(":")
        if separator and field:
            result.setdefault(part, set()).add(field)
    return result


def _canonical_ooxml_metadata_part(data: bytes, part: str, excluded: set[str]) -> bytes:
    root = parse_xml_preserving_misc(data, part)
    rows: list[tuple[str, tuple[tuple[str, str], ...], str, str]] = []

    def visit(element: Element) -> None:
        tag_object: object = element.tag
        if tag_object is ElementTree.Comment:
            rows.append(("#comment", (), element.text or "", element.tail or ""))
            return
        if tag_object is ElementTree.ProcessingInstruction:
            rows.append(("#processing-instruction", (), element.text or "", element.tail or ""))
            return
        tag = local_name(str(tag_object))
        if part == "docProps/custom.xml" and tag == "property":
            if element.attrib.get("name") in excluded:
                return
        elif tag in excluded:
            return
        rows.append(
            (
                str(tag_object),
                tuple(sorted(element.attrib.items())),
                element.text or "",
                element.tail or "",
            )
        )
        for child in element:
            visit(child)

    visit(root)
    return json.dumps(rows, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _parse_svg_with_comments(data: bytes) -> Element:
    parser = DefusedXMLParser(
        target=ElementTree.TreeBuilder(insert_comments=True, insert_pis=True),
        forbid_dtd=True,
        forbid_entities=True,
        forbid_external=True,
    )
    try:
        return ElementTree.fromstring(data, parser=parser)
    except Exception as exc:
        raise CorruptArtifactError(
            f"Unable to parse SVG for integrity verification: {exc}"
        ) from exc


_SVG_ROOT_START = re.compile(rb"<(?:(?:[A-Za-z_][\w.-]*):)?svg(?:\s|>)", re.IGNORECASE)
_SVG_ROOT_END = re.compile(rb"</(?:(?:[A-Za-z_][\w.-]*):)?svg\s*>", re.IGNORECASE)
_XML_OUTER_MISC = re.compile(
    rb"<!--[\s\S]*?-->|<\?(?!xml(?:\s|\?>))[\s\S]*?\?>",
    re.IGNORECASE,
)


def svg_outer_misc(data: bytes) -> tuple[tuple[bytes, ...], tuple[bytes, ...]]:
    """Return comments/PIs outside the SVG root so a cleaner can preserve them."""

    start = _SVG_ROOT_START.search(data)
    if start is None:
        return (), ()
    tag_end = _xml_tag_end(data, start.start())
    if tag_end is None:
        return tuple(_XML_OUTER_MISC.findall(data[: start.start()])), ()
    start_tag = data[start.start() : tag_end + 1]
    if start_tag.rstrip().endswith(b"/>"):
        root_end = tag_end + 1
    else:
        closing = None
        for candidate in _SVG_ROOT_END.finditer(data, tag_end + 1):
            closing = candidate
        root_end = closing.end() if closing is not None else len(data)
    return (
        tuple(_XML_OUTER_MISC.findall(data[: start.start()])),
        tuple(_XML_OUTER_MISC.findall(data[root_end:])),
    )


def _xml_tag_end(data: bytes, start: int) -> int | None:
    quote: int | None = None
    for index in range(start, len(data)):
        value = data[index]
        if quote is not None:
            if value == quote:
                quote = None
            continue
        if value in {ord('"'), ord("'")}:
            quote = value
        elif value == ord(">"):
            return index
    return None


def canonical_visible_svg(data: bytes) -> bytes:
    """Canonicalize visible/active SVG structure while excluding ordinary metadata and comments."""

    root = _parse_svg_with_comments(data)
    rows: list[tuple[str, tuple[tuple[str, str], ...], str]] = []
    prefix_misc, suffix_misc = svg_outer_misc(data)
    for placement, nodes in (("prolog", prefix_misc), ("epilog", suffix_misc)):
        for node in nodes:
            if node.startswith(b"<?"):
                rows.append(
                    (
                        f"processing-instruction:{placement}",
                        (),
                        node.decode("utf-8", errors="replace"),
                    )
                )

    def visit(element: Element) -> None:
        tag_object: object = element.tag
        if tag_object is ElementTree.Comment:
            return
        if tag_object is ElementTree.ProcessingInstruction:
            rows.append(("processing-instruction", (), element.text or ""))
            return
        tag = local_name(str(tag_object))
        if tag in {"metadata", "rdf", "RDF", "xmpmeta"}:
            return
        attributes = tuple(
            sorted(
                (key, value)
                for key, value in element.attrib.items()
                if not any(
                    marker in key.casefold()
                    for marker in ("inkscape", "sodipodi", "adobe", "serif", "sketch")
                )
            )
        )
        rows.append((tag, attributes, (element.text or "").strip()))
        for child in element:
            visit(child)

    visit(root)
    return json.dumps(rows, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def verify_svg_visible_structure(
    before: bytes,
    after: bytes,
    intentionally_removed: Iterable[str],
) -> IntegrityReport:
    """Compare metadata-independent SVG structure before and after cleanup."""

    before_logical = canonical_visible_svg(before)
    after_logical = canonical_visible_svg(after)
    status = IntegrityStatus.PASS if before_logical == after_logical else IntegrityStatus.FAIL
    return IntegrityReport(
        status=status,
        explanation=(
            "Visible and active SVG structure is unchanged after removing approved metadata."
            if status == IntegrityStatus.PASS
            else "Visible or active SVG structure changed during cleanup."
        ),
        before_sha256=sha256_bytes(before),
        after_sha256=sha256_bytes(after),
        logical_before_sha256=sha256_bytes(before_logical),
        logical_after_sha256=sha256_bytes(after_logical),
        intentionally_removed=tuple(intentionally_removed),
    )
