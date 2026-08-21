"""Optional pikepdf-backed surgical metadata cleanup."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from trueai.cleaners.base import CleanerOutcome
from trueai.core.errors import OptionalDependencyError, RemediationError
from trueai.core.models import IntegrityReport, IntegrityStatus, Remediation
from trueai.core.provenance import contains_protected_provenance_marker

_MAX_PDF_BYTES = 64 * 1024 * 1024
_MAX_PDF_OBJECTS = 100_000
_MAX_PDF_PAGES = 10_000
_MAX_OBJECT_REPRESENTATION_BYTES = 8 * 1024 * 1024
_MAX_FINGERPRINT_BYTES = 128 * 1024 * 1024
_MAX_GRAPH_DEPTH = 128
_MAX_GRAPH_NODES = 1_000_000


@dataclass(frozen=True, slots=True)
class _FingerprintPlan:
    """Metadata fields intentionally excluded from the integrity comparison."""

    info_keys: frozenset[str]
    remove_xmp: bool


class _PDFGraphCanonicalizer:
    """Serialize a reachable PDF object graph without persisted object numbers."""

    def __init__(
        self,
        pikepdf_module: Any,
        *,
        root_objgen: tuple[int, int],
        info_objgen: tuple[int, int] | None,
        plan: _FingerprintPlan,
    ) -> None:
        self._pikepdf = pikepdf_module
        self._root_objgen = root_objgen
        self._info_objgen = info_objgen
        self._plan = plan
        self._assigned: dict[tuple[int, int], int] = {}
        self._queue: list[Any] = []
        self._consumed = 0
        self._nodes = 0

    def reference(self, obj: Any) -> bytes:
        """Return a stable reference token and enqueue new indirect objects."""

        if bool(getattr(obj, "is_indirect", False)):
            objgen = PDFCleaner._indirect_objgen(obj, "PDF graph object")
            canonical_id = self._assigned.get(objgen)
            if canonical_id is None:
                canonical_id = len(self._queue) + 1
                self._assigned[objgen] = canonical_id
                self._queue.append(obj)
                if len(self._queue) > _MAX_PDF_OBJECTS:
                    raise RemediationError(
                        f"Reachable PDF object count exceeds safety limit {_MAX_PDF_OBJECTS}"
                    )
            return f"R{canonical_id}".encode("ascii")
        return self._serialize_value(obj, depth=0, resolve_scalar=False)

    def trailer(self, trailer: Any, *, include_info: bool) -> bytes:
        """Serialize semantic trailer entries while excluding writer bookkeeping."""

        omitted = {"/ID", "/Prev", "/Size", "/XRefStm"}
        if not include_info:
            omitted.add("/Info")
        return self._serialize_dictionary(trailer, frozenset(omitted), depth=0)

    def digest(self, trailer_representation: bytes) -> str:
        """Hash all queued objects, including objects discovered during traversal."""

        digest = hashlib.sha256()
        self._consume(len(trailer_representation))
        digest.update(b"semantic-trailer\x00")
        digest.update(trailer_representation)
        index = 0
        while index < len(self._queue):
            obj = self._queue[index]
            canonical_id = index + 1
            representation = self._serialize_queued_object(obj)
            self._consume(len(representation))
            digest.update(f"\nobject:{canonical_id}\x00".encode("ascii"))
            digest.update(representation)
            index += 1
        return digest.hexdigest()

    def _serialize_queued_object(self, obj: Any) -> bytes:
        objgen = PDFCleaner._indirect_objgen(obj, "PDF graph object")
        omitted: frozenset[str] = frozenset()
        if objgen == self._root_objgen and self._plan.remove_xmp:
            omitted = frozenset({"/Metadata"})
        elif self._info_objgen is not None and objgen == self._info_objgen:
            omitted = self._plan.info_keys

        if isinstance(obj, self._pikepdf.Stream):
            raw_stream = PDFCleaner._bounded_raw_stream(obj)
            stream_omissions = omitted | {"/Length"}
            if not raw_stream:
                stream_omissions |= {"/Filter", "/DecodeParms"}
            dictionary = self._serialize_dictionary(obj, stream_omissions, depth=0)
            return b"stream-dictionary\x00" + dictionary + b"\x00raw-stream\x00" + raw_stream
        if isinstance(obj, self._pikepdf.Dictionary):
            return self._serialize_dictionary(obj, omitted, depth=0)
        if isinstance(obj, self._pikepdf.Array):
            return self._serialize_array(obj, depth=0)
        return b"scalar\x00" + PDFCleaner._bounded_unparse(obj, resolved=True)

    def _serialize_value(self, obj: Any, *, depth: int, resolve_scalar: bool) -> bytes:
        self._visit(depth)
        if bool(getattr(obj, "is_indirect", False)):
            return self.reference(obj)
        if isinstance(obj, self._pikepdf.Stream):
            raise RemediationError("Direct PDF streams are unsupported for integrity verification")
        if isinstance(obj, self._pikepdf.Dictionary):
            return self._serialize_dictionary(obj, frozenset(), depth=depth)
        if isinstance(obj, self._pikepdf.Array):
            return self._serialize_array(obj, depth=depth)
        if isinstance(obj, (type(None), bool, int, float, str, bytes)):
            return PDFCleaner._bounded_scalar_representation(obj)
        return PDFCleaner._bounded_unparse(obj, resolved=resolve_scalar)

    def _serialize_dictionary(
        self,
        dictionary: Any,
        omitted_keys: frozenset[str],
        *,
        depth: int,
    ) -> bytes:
        self._visit(depth)
        result = bytearray(b"<<")
        for key in sorted(dictionary.keys(), key=str):
            key_text = str(key)
            if key_text in omitted_keys:
                continue
            key_bytes = key_text.encode("utf-8", errors="surrogatepass")
            result.extend(key_bytes)
            result.extend(b" ")
            result.extend(
                self._serialize_value(
                    dictionary[key],
                    depth=depth + 1,
                    resolve_scalar=False,
                )
            )
            result.extend(b"\n")
            self._check_object_size(result)
        result.extend(b">>")
        return bytes(result)

    def _serialize_array(self, array: Any, *, depth: int) -> bytes:
        self._visit(depth)
        result = bytearray(b"[")
        for value in array:
            result.extend(self._serialize_value(value, depth=depth + 1, resolve_scalar=False))
            result.extend(b" ")
            self._check_object_size(result)
        result.extend(b"]")
        return bytes(result)

    def _visit(self, depth: int) -> None:
        if depth > _MAX_GRAPH_DEPTH:
            raise RemediationError(f"PDF object nesting exceeds safety limit {_MAX_GRAPH_DEPTH}")
        self._nodes += 1
        if self._nodes > _MAX_GRAPH_NODES:
            raise RemediationError(f"PDF graph node count exceeds safety limit {_MAX_GRAPH_NODES}")

    def _consume(self, size: int) -> None:
        self._consumed += size
        PDFCleaner._check_fingerprint_budget(self._consumed)

    @staticmethod
    def _check_object_size(value: bytearray) -> None:
        if len(value) > _MAX_OBJECT_REPRESENTATION_BYTES:
            raise RemediationError("PDF object representation exceeds safety limit")


class PDFCleaner:
    """Remove selected PDF Info/XMP objects without rendering or rebuilding pages."""

    supported_remediation_ids = frozenset({"pdf.remove-metadata-field", "pdf.remove-xmp"})

    def apply(
        self,
        source: Path,
        destination: Path,
        remediations: tuple[Remediation, ...],
    ) -> CleanerOutcome:
        source_bytes = self._read_bounded_file(source)
        if contains_protected_provenance_marker(source_bytes):
            raise RemediationError(
                "Refusing PDF cleanup because the artifact contains a provenance marker"
            )
        try:
            import pikepdf
        except ImportError as exc:
            raise OptionalDependencyError(
                "PDF cleanup requires the optional dependency: pip install 'trueai-core[pdf]'"
            ) from exc

        fields, remove_xmp = self._selected_changes(remediations)
        try:
            with pikepdf.open(source) as pdf:
                fingerprint_plan = self._fingerprint_plan(pdf, fields, remove_xmp)
                before_content = self._document_fingerprint(pdf, pikepdf, fingerprint_plan)
                changed = self._remove_selected_metadata(pdf, fields, remove_xmp)
                pdf.save(
                    destination,
                    object_stream_mode=pikepdf.ObjectStreamMode.preserve,
                    normalize_content=False,
                    recompress_flate=False,
                    fix_metadata_version=False,
                )
            if not changed:
                raise RemediationError("No selected PDF metadata matched the current artifact")
            with pikepdf.open(destination) as cleaned_pdf:
                after_content = self._document_fingerprint(
                    cleaned_pdf,
                    pikepdf,
                    fingerprint_plan,
                )
        except RemediationError:
            raise
        except (OSError, ValueError, RuntimeError) as exc:
            raise RemediationError(f"Unable to clean or verify PDF safely: {exc}") from exc

        status = IntegrityStatus.PASS if before_content == after_content else IntegrityStatus.FAIL
        integrity = IntegrityReport(
            status=status,
            explanation=(
                "Every reachable non-selected PDF object and raw stream payload is unchanged; "
                "only the approved Info/XMP metadata was removed."
                if status == IntegrityStatus.PASS
                else "A reachable non-selected PDF object or raw stream payload changed during "
                "cleanup."
            ),
            before_sha256=hashlib.sha256(source_bytes).hexdigest(),
            after_sha256=self._sha256_file(destination),
            logical_before_sha256=before_content,
            logical_after_sha256=after_content,
            intentionally_removed=tuple(changed),
        )
        return CleanerOutcome(changed_fields=tuple(changed), integrity=integrity)

    @staticmethod
    def _selected_changes(
        remediations: tuple[Remediation, ...],
    ) -> tuple[set[str], bool]:
        fields: set[str] = set()
        remove_xmp = False
        for remediation in remediations:
            if remediation.remediation_id not in PDFCleaner.supported_remediation_ids:
                raise RemediationError(f"PDF cleaner does not support {remediation.remediation_id}")
            remove_xmp = remove_xmp or remediation.remediation_id == "pdf.remove-xmp"
            findings = remediation.payload.get("findings", [])
            if not isinstance(findings, (list, tuple)):
                raise RemediationError("Malformed PDF remediation payload")
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                evidence = finding.get("evidence")
                if not isinstance(evidence, dict):
                    continue
                field = evidence.get("field")
                if isinstance(field, str):
                    fields.add(field)
        return fields, remove_xmp

    @staticmethod
    def _fingerprint_plan(
        pdf: Any,
        fields: set[str],
        remove_xmp: bool,
    ) -> _FingerprintPlan:
        PDFCleaner._indirect_objgen(pdf.Root, "PDF catalog")
        info = pdf.trailer.get("/Info")
        if fields and info is None:
            raise RemediationError("PDF Info dictionary changed after scan")
        if info is not None:
            PDFCleaner._indirect_objgen(info, "PDF Info dictionary")
        metadata = pdf.Root.get("/Metadata")
        if remove_xmp and metadata is None:
            raise RemediationError("PDF XMP metadata changed after scan")
        if metadata is not None:
            PDFCleaner._indirect_objgen(metadata, "PDF XMP stream")
        return _FingerprintPlan(
            info_keys=frozenset(f"/{field}" for field in fields),
            remove_xmp=remove_xmp,
        )

    @staticmethod
    def _remove_selected_metadata(pdf: Any, fields: set[str], remove_xmp: bool) -> list[str]:
        changed: list[str] = []
        info = pdf.trailer.get("/Info")
        for field in sorted(fields):
            key = f"/{field}"
            if info is None or key not in info:
                raise RemediationError(f"PDF Info field changed after scan: {field}")
            if contains_protected_provenance_marker(info[key]):
                raise RemediationError(
                    f"Refusing to remove PDF Info field {field} containing a provenance marker"
                )
            del info[key]
            changed.append(f"Info:{field}")
        if remove_xmp:
            metadata = pdf.Root.get("/Metadata")
            if metadata is None:
                raise RemediationError("PDF XMP metadata changed after scan")
            if metadata.get("/Filter") is not None:
                raise RemediationError(
                    "Compressed PDF XMP cleanup is unsupported because provenance inspection "
                    "cannot be decoded with a bounded-memory guarantee"
                )
            raw_metadata = PDFCleaner._bounded_raw_stream(metadata)
            if contains_protected_provenance_marker(raw_metadata):
                raise RemediationError("Refusing to remove XMP that contains provenance markers")
            del pdf.Root["/Metadata"]
            changed.append("XMP")
        return changed

    @staticmethod
    def _document_fingerprint(
        pdf: Any,
        pikepdf_module: Any,
        plan: _FingerprintPlan,
    ) -> str:
        """Hash the reachable graph and raw stream bytes except selected metadata."""

        objects = pdf.objects
        if len(objects) > _MAX_PDF_OBJECTS:
            raise RemediationError(f"PDF object count exceeds safety limit {_MAX_PDF_OBJECTS}")
        if len(pdf.pages) > _MAX_PDF_PAGES:
            raise RemediationError(f"PDF page count exceeds safety limit {_MAX_PDF_PAGES}")

        root_objgen = PDFCleaner._indirect_objgen(pdf.Root, "PDF catalog")
        info = pdf.trailer.get("/Info")
        include_info = info is not None and any(str(key) not in plan.info_keys for key in info)
        info_objgen = (
            PDFCleaner._indirect_objgen(info, "PDF Info dictionary") if include_info else None
        )
        canonicalizer = _PDFGraphCanonicalizer(
            pikepdf_module,
            root_objgen=root_objgen,
            info_objgen=info_objgen,
            plan=plan,
        )
        canonicalizer.reference(pdf.Root)
        if include_info:
            canonicalizer.reference(info)
        trailer = canonicalizer.trailer(pdf.trailer, include_info=include_info)
        return canonicalizer.digest(trailer)

    @staticmethod
    def _bounded_unparse(obj: Any, *, resolved: bool = False) -> bytes:
        representation = obj.unparse(resolved=resolved)
        if len(representation) > _MAX_OBJECT_REPRESENTATION_BYTES:
            raise RemediationError("PDF object representation exceeds safety limit")
        return bytes(representation)

    @staticmethod
    def _bounded_scalar_representation(value: object) -> bytes:
        """Serialize Python primitives returned by pikepdf container access."""

        if value is None:
            representation = b"null"
        elif isinstance(value, bool):
            representation = b"bool:true" if value else b"bool:false"
        elif isinstance(value, int):
            representation = f"int:{value}".encode("ascii")
        elif isinstance(value, float):
            representation = f"float:{value.hex()}".encode("ascii")
        elif isinstance(value, str):
            encoded = value.encode("utf-8", errors="surrogatepass")
            representation = f"str:{len(encoded)}:".encode("ascii") + encoded
        elif isinstance(value, bytes):
            representation = f"bytes:{len(value)}:".encode("ascii") + value
        else:  # pragma: no cover - guarded by callers
            raise RemediationError(f"Unsupported PDF scalar type: {type(value).__name__}")
        if len(representation) > _MAX_OBJECT_REPRESENTATION_BYTES:
            raise RemediationError("PDF scalar representation exceeds safety limit")
        return representation

    @staticmethod
    def _bounded_raw_stream(stream: Any) -> bytes:
        raw = bytes(stream.read_raw_bytes())
        if len(raw) > _MAX_OBJECT_REPRESENTATION_BYTES:
            raise RemediationError("PDF raw stream exceeds per-object safety limit")
        return raw

    @staticmethod
    def _check_fingerprint_budget(consumed: int) -> None:
        if consumed > _MAX_FINGERPRINT_BYTES:
            raise RemediationError("PDF fingerprint input exceeds aggregate safety limit")

    @staticmethod
    def _indirect_objgen(obj: Any, label: str) -> tuple[int, int]:
        raw_objgen = tuple(int(value) for value in obj.objgen)
        if len(raw_objgen) != 2:
            raise RemediationError(f"{label} has an invalid object identity")
        objgen = (raw_objgen[0], raw_objgen[1])
        if objgen == (0, 0):
            raise RemediationError(f"{label} is direct; safe surgical cleanup is unsupported")
        return objgen

    @staticmethod
    def _read_bounded_file(path: Path) -> bytes:
        with path.open("rb") as handle:
            data = handle.read(_MAX_PDF_BYTES + 1)
        if len(data) > _MAX_PDF_BYTES:
            raise RemediationError(f"PDF exceeds cleaner safety limit {_MAX_PDF_BYTES} bytes")
        return data

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()
