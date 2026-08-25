"""Surgical OpenDocument metadata cleanup with a package-level integrity proof.

The proof is simpler than the OOXML one, and that simplicity is the reason ODF
passed the `FMT-06` bar while legacy binary Office did not. In an ODF package the
document text lives in `content.xml` and the metadata lives in `meta.xml`, as two
separate archive entries. Proving a metadata-only edit therefore means proving
that `content.xml` is byte-identical and that every entry except `meta.xml` is
unchanged — a comparison, not a reconstruction.

The `mimetype` entry gets special handling. The specification requires it to be
first in the archive and stored without compression, and a package that loses
either property stops being recognised by the applications that read it. The
rewrite preserves both explicitly rather than relying on `zipfile` to happen to
do the right thing.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import cast
from xml.etree import ElementTree

from trueai.cleaners.base import CleanerOutcome
from trueai.core.errors import RemediationError
from trueai.core.integrity import sha256_bytes
from trueai.core.models import IntegrityReport, IntegrityStatus, Remediation, ScanOptions
from trueai.core.provenance import contains_protected_provenance_marker
from trueai.detectors.documents.odf import CONTENT_PART, META_PART, MIMETYPE_PART
from trueai.detectors.documents.opc import (
    local_name,
    open_validated_opc,
    parse_xml_preserving_misc,
)


class OpenDocumentCleaner:
    """Remove selected `meta.xml` fields and prove nothing else moved."""

    supported_remediation_ids = frozenset({"odf.remove-metadata-field"})

    def apply(
        self,
        source: Path,
        destination: Path,
        remediations: tuple[Remediation, ...],
        options: ScanOptions | None = None,
    ) -> CleanerOutcome:
        fields: set[str] = set()
        for remediation in remediations:
            if remediation.remediation_id not in self.supported_remediation_ids:
                raise RemediationError(
                    f"OpenDocument cleaner does not support {remediation.remediation_id}"
                )
            findings = remediation.payload.get("findings", [])
            if not isinstance(findings, (list, tuple)):
                raise RemediationError("Malformed OpenDocument remediation payload")
            for raw in findings:
                if not isinstance(raw, dict):
                    continue
                evidence = raw.get("evidence", {})
                if not isinstance(evidence, dict):
                    continue
                part = evidence.get("part")
                field = evidence.get("field")
                if part != META_PART or not isinstance(field, str):
                    continue
                fields.add(field)
        if not fields:
            raise RemediationError("No OpenDocument metadata fields were selected")

        limits = options or ScanOptions()
        with (
            open_validated_opc(source, limits) as source_zip,
            zipfile.ZipFile(destination, "w") as destination_zip,
        ):
            names = source_zip.namelist()
            if META_PART not in names:
                raise RemediationError("The package has no meta.xml to clean")
            if CONTENT_PART not in names:
                raise RemediationError("The package has no content.xml to verify against")

            for info in source_zip.infolist():
                data = source_zip.read(info.filename)
                if info.filename == META_PART:
                    data = self._remove_fields(data, fields)
                if info.filename == MIMETYPE_PART:
                    # Stored, not deflated, and written first. A package whose
                    # mimetype entry is compressed or displaced stops being
                    # recognised, which would be a cleanup that broke the file
                    # while leaving every byte of its content intact.
                    stored = zipfile.ZipInfo(MIMETYPE_PART, date_time=info.date_time)
                    stored.compress_type = zipfile.ZIP_STORED
                    stored.external_attr = info.external_attr
                    destination_zip.writestr(stored, data)
                    continue
                destination_zip.writestr(info, data)

        integrity = self._verify(source, destination, sorted(fields))
        return CleanerOutcome(changed_fields=tuple(sorted(fields)), integrity=integrity)

    def _remove_fields(self, data: bytes, fields: set[str]) -> bytes:
        root = parse_xml_preserving_misc(data, META_PART)
        parent_map = {child: parent for parent in root.iter() for child in parent}
        removed: set[str] = set()
        for element in list(root.iter()):
            tag_object: object = element.tag
            if tag_object in {ElementTree.Comment, ElementTree.ProcessingInstruction}:
                continue
            name = local_name(str(tag_object))
            if name == "user-defined":
                declared = next(
                    (value for key, value in element.attrib.items() if local_name(key) == "name"),
                    None,
                )
                name = f"user-defined:{declared}" if declared else "user-defined"
            if name not in fields:
                continue
            if contains_protected_provenance_marker(
                ElementTree.tostring(element, encoding="utf-8")
            ):
                raise RemediationError(
                    f"Refusing to remove OpenDocument field {name} containing provenance"
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
                f"OpenDocument metadata changed after scan; missing fields: {sorted(missing)}"
            )
        return cast(bytes, ElementTree.tostring(root, encoding="utf-8", xml_declaration=True))

    def _verify(
        self, before_path: Path, after_path: Path, changed_fields: list[str]
    ) -> IntegrityReport:
        """Prove that only `meta.xml` changed, and that `content.xml` is identical."""

        problems: list[str] = []
        content_before = content_after = b""
        try:
            with (
                zipfile.ZipFile(before_path) as before,
                zipfile.ZipFile(after_path) as after,
            ):
                before_names, after_names = before.namelist(), after.namelist()
                if before_names != after_names:
                    problems.append("the entry list or its order changed")
                for name in set(before_names) & set(after_names):
                    if name == META_PART:
                        continue
                    if before.read(name) != after.read(name):
                        problems.append(f"{name} changed")
                content_before = before.read(CONTENT_PART)
                content_after = after.read(CONTENT_PART)
                mimetype_info = next(
                    (item for item in after.infolist() if item.filename == MIMETYPE_PART), None
                )
                if mimetype_info is not None:
                    if mimetype_info.compress_type != zipfile.ZIP_STORED:
                        problems.append("the mimetype entry is no longer stored uncompressed")
                    if after.namelist()[0] != MIMETYPE_PART:
                        problems.append("the mimetype entry is no longer first")
        except (OSError, KeyError, zipfile.BadZipFile) as exc:
            problems.append(f"the package could not be re-read: {exc}")

        status = IntegrityStatus.PASS if not problems else IntegrityStatus.FAIL
        return IntegrityReport(
            status=status,
            explanation=(
                "Only meta.xml changed; content.xml is byte-identical and the mimetype entry "
                "is still stored uncompressed and first."
                if status == IntegrityStatus.PASS
                else "The OpenDocument output is not a metadata-only edit: " + "; ".join(problems)
            ),
            before_sha256=sha256_bytes(before_path.read_bytes()),
            after_sha256=sha256_bytes(after_path.read_bytes()),
            # The logical material is the document text part. Hashing the whole
            # package would answer "did anything change", which is the wrong
            # question for an edit that is meant to change something.
            logical_before_sha256=sha256_bytes(content_before),
            logical_after_sha256=sha256_bytes(content_after),
            intentionally_removed=tuple(changed_fields),
        )


__all__ = ["OpenDocumentCleaner"]
