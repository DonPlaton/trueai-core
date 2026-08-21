"""Surgical PNG/JPEG metadata cleanup preserving compressed pixel payloads."""

from __future__ import annotations

import hashlib
import struct
import zlib
from pathlib import Path

from PIL import Image

from trueai.cleaners.base import CleanerOutcome
from trueai.core.errors import CorruptArtifactError, RemediationError
from trueai.core.integrity import sha256_bytes
from trueai.core.models import IntegrityReport, IntegrityStatus, Remediation, ScanOptions
from trueai.core.provenance import contains_protected_provenance_marker

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_RENDERING_CRITICAL_EXIF_TAGS = {274, 282, 283, 296, 40961}
_MAX_DECODED_TEXT_CHUNK = 2 * 1024 * 1024


class ImageMetadataCleaner:
    """Edit metadata segments/chunks without decoding or recompressing pixels."""

    supported_remediation_ids = frozenset({"image.remove-metadata"})

    def apply(
        self,
        source: Path,
        destination: Path,
        remediations: tuple[Remediation, ...],
        options: ScanOptions | None = None,
    ) -> CleanerOutcome:
        if any(item.remediation_id not in self.supported_remediation_ids for item in remediations):
            raise RemediationError("Image cleaner received an unsupported remediation")
        selected_fields, selected_exif_tags = self._selected_fields(remediations)
        before = source.read_bytes()
        if contains_protected_provenance_marker(before):
            raise RemediationError(
                "Refusing image metadata cleanup because the artifact contains a provenance marker"
            )
        protected_tags = selected_exif_tags & _RENDERING_CRITICAL_EXIF_TAGS
        if protected_tags:
            raise RemediationError(
                f"Refusing to remove rendering-critical EXIF tags: {sorted(protected_tags)}"
            )
        replacement_exif = self._replacement_exif(source, selected_exif_tags)
        if before.startswith(_PNG_SIGNATURE):
            after, container_changes, pixel_before, pixel_after = self._clean_png(
                before,
                selected_fields,
                bool(selected_exif_tags),
                replacement_exif,
            )
        elif before.startswith(b"\xff\xd8"):
            after, container_changes, pixel_before, pixel_after = self._clean_jpeg(
                before,
                selected_fields,
                bool(selected_exif_tags),
                replacement_exif,
            )
        else:
            raise CorruptArtifactError("Image signature is neither PNG nor JPEG")
        if not container_changes:
            raise RemediationError("No selected image metadata matched the current artifact")
        destination.write_bytes(after)
        status = IntegrityStatus.PASS if pixel_before == pixel_after else IntegrityStatus.FAIL
        changed = tuple(sorted(set(container_changes)))
        integrity = IntegrityReport(
            status=status,
            explanation=(
                "Compressed pixel-bearing payload is byte-identical; only selected metadata "
                "chunks/segments changed."
                if status == IntegrityStatus.PASS
                else "Pixel-bearing payload changed during metadata cleanup."
            ),
            before_sha256=sha256_bytes(before),
            after_sha256=sha256_bytes(after),
            logical_before_sha256=hashlib.sha256(pixel_before).hexdigest(),
            logical_after_sha256=hashlib.sha256(pixel_after).hexdigest(),
            intentionally_removed=changed,
        )
        return CleanerOutcome(changed_fields=changed, integrity=integrity)

    @staticmethod
    def _selected_fields(
        remediations: tuple[Remediation, ...],
    ) -> tuple[set[str], set[int]]:
        fields: set[str] = set()
        exif_tags: set[int] = set()
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
                field = evidence.get("field")
                if isinstance(field, str):
                    fields.add(field)
                tag_id = evidence.get("tag_id")
                if isinstance(tag_id, int):
                    exif_tags.add(tag_id)
        return fields, exif_tags

    @staticmethod
    def _replacement_exif(source: Path, selected_tags: set[int]) -> bytes | None:
        if not selected_tags:
            return None
        try:
            with Image.open(source) as image:
                exif = image.getexif()
                for tag_id in selected_tags:
                    if tag_id not in exif:
                        raise RemediationError(
                            f"EXIF tag {tag_id} changed or disappeared after scanning"
                        )
                    if contains_protected_provenance_marker(exif[tag_id]):
                        raise RemediationError(
                            f"Refusing to remove EXIF tag {tag_id} containing provenance"
                        )
                    del exif[tag_id]
                return exif.tobytes() if len(exif) else b""
        except OSError as exc:
            raise CorruptArtifactError(f"Unable to update EXIF metadata: {exc}") from exc

    def _clean_png(
        self,
        data: bytes,
        selected_fields: set[str],
        change_exif: bool,
        replacement_exif: bytes | None,
    ) -> tuple[bytes, list[str], bytes, bytes]:
        chunks = self._png_chunks(data)
        output = bytearray(_PNG_SIGNATURE)
        changes: list[str] = []
        before_pixel = bytearray()
        after_pixel = bytearray()
        for chunk_type, payload, full_chunk in chunks:
            if chunk_type in {b"IHDR", b"PLTE", b"tRNS", b"IDAT", b"IEND"}:
                before_pixel.extend(full_chunk)
            replacement: bytes | None = full_chunk
            if chunk_type in {b"tEXt", b"zTXt", b"iTXt"}:
                keyword = payload.split(b"\x00", 1)[0].decode("latin-1", errors="replace")
                if keyword in selected_fields and not self._png_text_protected(
                    chunk_type,
                    payload,
                ):
                    replacement = None
                    changes.append(f"PNG {chunk_type.decode('ascii')}:{keyword}")
            elif chunk_type == b"eXIf" and change_exif:
                if replacement_exif:
                    exif_payload = replacement_exif
                    if exif_payload.startswith(b"Exif\x00\x00"):
                        exif_payload = exif_payload[6:]
                    replacement = self._png_chunk(b"eXIf", exif_payload)
                    changes.append("PNG eXIf: selected tags")
                else:
                    replacement = None
                    changes.append("PNG eXIf")
            if replacement is not None:
                output.extend(replacement)
                if chunk_type in {b"IHDR", b"PLTE", b"tRNS", b"IDAT", b"IEND"}:
                    after_pixel.extend(replacement)
        return bytes(output), changes, bytes(before_pixel), bytes(after_pixel)

    def _clean_jpeg(
        self,
        data: bytes,
        selected_fields: set[str],
        change_exif: bool,
        replacement_exif: bytes | None,
    ) -> tuple[bytes, list[str], bytes, bytes]:
        position = 2
        output = bytearray(data[:2])
        changes: list[str] = []
        pixel_payload = b""
        while position < len(data):
            marker_start = position
            if data[position] != 0xFF:
                raise CorruptArtifactError(f"Invalid JPEG marker at byte {position}")
            while position < len(data) and data[position] == 0xFF:
                position += 1
            if position >= len(data):
                raise CorruptArtifactError("Truncated JPEG marker")
            marker = data[position]
            position += 1
            if marker == 0xDA:
                pixel_payload = data[marker_start:]
                output.extend(pixel_payload)
                break
            if marker in {0xD8, 0xD9, 0x01} or 0xD0 <= marker <= 0xD7:
                output.extend(data[marker_start:position])
                if marker == 0xD9:
                    break
                continue
            if position + 2 > len(data):
                raise CorruptArtifactError("Truncated JPEG segment length")
            segment_length = int.from_bytes(data[position : position + 2], "big")
            if segment_length < 2 or position + segment_length > len(data):
                raise CorruptArtifactError("Invalid JPEG segment length")
            segment_end = position + segment_length
            payload = data[position + 2 : segment_end]
            full_segment = data[marker_start:segment_end]
            replacement: bytes | None = full_segment
            if marker == 0xE1 and payload.startswith(b"Exif\x00\x00") and change_exif:
                if replacement_exif:
                    replacement = self._jpeg_segment(0xE1, replacement_exif)
                    changes.append("JPEG EXIF: selected tags")
                else:
                    replacement = None
                    changes.append("JPEG EXIF")
            elif (
                marker == 0xE1
                and payload.startswith(b"http://ns.adobe.com/xap/1.0/\x00")
                and any(
                    field.casefold() in {"xmp", "xml:com.adobe.xmp"} for field in selected_fields
                )
                and not self._protected(payload)
            ):
                replacement = None
                changes.append("JPEG XMP")
            elif (
                marker == 0xFE
                and any(field.casefold() == "comment" for field in selected_fields)
                and not self._protected(payload)
            ):
                replacement = None
                changes.append("JPEG comment")
            if replacement is not None:
                output.extend(replacement)
            position = segment_end
        if not pixel_payload:
            raise CorruptArtifactError("JPEG scan data marker was not found")
        after = bytes(output)
        # The scan payload was appended last and copied verbatim, so its
        # offset is known by construction. Searching for the SOS marker
        # instead matches the first FF DA anywhere in the output, including
        # inside a retained EXIF thumbnail, ICC profile, or comment, which
        # fails the integrity gate on an image whose pixels never changed.
        after_pixel_offset = len(after) - len(pixel_payload)
        if not after.startswith(pixel_payload, after_pixel_offset):
            raise CorruptArtifactError("Cleaned JPEG scan data was not written verbatim")
        return after, changes, pixel_payload, after[after_pixel_offset:]

    @staticmethod
    def _png_chunks(data: bytes) -> list[tuple[bytes, bytes, bytes]]:
        if not data.startswith(_PNG_SIGNATURE):
            raise CorruptArtifactError("Invalid PNG signature")
        position = len(_PNG_SIGNATURE)
        chunks: list[tuple[bytes, bytes, bytes]] = []
        saw_iend = False
        while position < len(data):
            if position + 12 > len(data):
                raise CorruptArtifactError("Truncated PNG chunk")
            length = struct.unpack(">I", data[position : position + 4])[0]
            end = position + 12 + length
            if end > len(data):
                raise CorruptArtifactError("PNG chunk length exceeds file boundary")
            chunk_type = data[position + 4 : position + 8]
            payload = data[position + 8 : position + 8 + length]
            expected_crc = struct.unpack(">I", data[position + 8 + length : end])[0]
            actual_crc = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
            if expected_crc != actual_crc:
                raise CorruptArtifactError(f"PNG CRC mismatch in {chunk_type!r}")
            full = data[position:end]
            chunks.append((chunk_type, payload, full))
            position = end
            if chunk_type == b"IEND":
                saw_iend = True
                if position != len(data):
                    raise CorruptArtifactError("Unexpected data after PNG IEND")
                break
        if not saw_iend:
            raise CorruptArtifactError("PNG IEND chunk is missing")
        return chunks

    @staticmethod
    def _png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
        crc = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
        return struct.pack(">I", len(payload)) + chunk_type + payload + struct.pack(">I", crc)

    @staticmethod
    def _jpeg_segment(marker: int, payload: bytes) -> bytes:
        length = len(payload) + 2
        if length > 0xFFFF:
            raise RemediationError("Updated JPEG metadata exceeds one APP segment")
        return b"\xff" + bytes([marker]) + length.to_bytes(2, "big") + payload

    @staticmethod
    def _protected(payload: bytes) -> bool:
        return contains_protected_provenance_marker(payload)

    @staticmethod
    def _png_text_protected(chunk_type: bytes, payload: bytes) -> bool:
        """Inspect compressed PNG text with a bounded decoder; preserve on ambiguity."""

        if contains_protected_provenance_marker(payload):
            return True
        try:
            if chunk_type == b"zTXt":
                _, separator, rest = payload.partition(b"\x00")
                if not separator or len(rest) < 2 or rest[0] != 0:
                    return True
                compressed = rest[1:]
                return ImageMetadataCleaner._bounded_zlib_protected(compressed)
            if chunk_type == b"iTXt":
                keyword_end = payload.index(b"\x00")
                rest = payload[keyword_end + 1 :]
                if len(rest) < 2:
                    return True
                compressed_flag = rest[0]
                rest = rest[2:]
                language_end = rest.index(b"\x00")
                rest = rest[language_end + 1 :]
                translated_end = rest.index(b"\x00")
                text = rest[translated_end + 1 :]
                if compressed_flag == 1:
                    return ImageMetadataCleaner._bounded_zlib_protected(text)
                if compressed_flag != 0:
                    return True
                return contains_protected_provenance_marker(text)
        except (IndexError, ValueError):
            return True
        return False

    @staticmethod
    def _bounded_zlib_protected(compressed: bytes) -> bool:
        try:
            decoder = zlib.decompressobj()
            decoded = decoder.decompress(compressed, _MAX_DECODED_TEXT_CHUNK + 1)
            if len(decoded) > _MAX_DECODED_TEXT_CHUNK or decoder.unconsumed_tail:
                return True
            remaining = _MAX_DECODED_TEXT_CHUNK + 1 - len(decoded)
            decoded += decoder.flush(remaining)
            if len(decoded) > _MAX_DECODED_TEXT_CHUNK or not decoder.eof:
                return True
            return contains_protected_provenance_marker(decoded)
        except zlib.error:
            return True
