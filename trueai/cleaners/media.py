"""Surgical WAV, MP3, FLAC, and ISO-BMFF metadata cleanup with format invariants.

The ISO-BMFF branch works differently from the other three, on purpose.

In WAV, MP3, and FLAC a metadata chunk can be cut out and the remaining bytes
close up behind it, because nothing in those formats records where the audio
starts. MP4 does: `stco` and `co64` hold absolute file offsets, so shortening
anything before `mdat` moves every sample while leaving a file that still parses
and still reports the right duration.

Rather than remove bytes and rewrite every offset — which is where that class of
bug lives — the ISO-BMFF branch overwrites the selected box in place with a
zero-filled `free` box of exactly the same length. `free` is the format's own
"ignore this" padding, understood by every demuxer. The metadata is gone, the
file length is unchanged, and **no offset needs correcting because nothing
moved**. A whole category of corruption is avoided by not creating the situation
that causes it.

The cost is honest and stated: the file does not get smaller. The bytes become
padding rather than disappearing. For a delivery pipeline that cares whether the
client can read the shooting location, that is the right trade; for one that
cares about file size it is not, and `FMT-02` does not pretend otherwise.

Either way the result is checked against the executable invariants in
:mod:`trueai.core.iso_bmff` before it is accepted, so a mistake in the
substitution — a wrong length, a clobbered neighbour — fails the gate instead of
shipping.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path
from typing import Literal

from trueai.cleaners.base import CleanerOutcome
from trueai.core.errors import CorruptArtifactError, RemediationError
from trueai.core.integrity import sha256_bytes
from trueai.core.iso_bmff import IsoBmffError, model_iso_bmff, verify_iso_bmff_invariants
from trueai.core.models import IntegrityReport, IntegrityStatus, Remediation, ScanOptions
from trueai.core.provenance import contains_protected_provenance_marker
from trueai.detectors.media.containers import MediaMetadataEntry, parse_media_metadata

_ID3V1_FIELDS = {
    "title": (3, 30),
    "artist": (33, 30),
    "album": (63, 30),
    "year": (93, 4),
    "comment": (97, 30),
}
_BEXT_FIELDS = {
    "description": (0, 256),
    "originator": (256, 32),
    "originator_reference": (288, 32),
    "origination_date": (320, 10),
    "origination_time": (330, 8),
}
_WAVE_WHOLE_CHUNK_METADATA = frozenset({b"iXML", b"_PMX", b"XMP "})

#: Every ISO base media brand this cleaner will touch. A file whose `ftyp` is not
#: here is refused rather than guessed at, because an unrecognised brand may put
#: something other than padding where a `free` box is expected.
_ISO_BRANDS = frozenset(
    {
        b"isom",
        b"iso2",
        b"iso4",
        b"iso5",
        b"iso6",
        b"mp41",
        b"mp42",
        b"avc1",
        b"M4A ",
        b"M4V ",
        b"qt  ",
        b"3gp4",
        b"3gp5",
        b"3g2a",
    }
)


@dataclass(frozen=True, slots=True)
class _Selection:
    container: str
    field: str
    raw_identifier: str
    byte_offset: int
    value_sha256: str

    @classmethod
    def from_entry(cls, entry: MediaMetadataEntry) -> _Selection:
        return cls(
            container=entry.container,
            field=entry.field,
            raw_identifier=entry.raw_identifier,
            byte_offset=entry.byte_offset,
            value_sha256=hashlib.sha256(entry.value.encode("utf-8")).hexdigest(),
        )

    @property
    def label(self) -> str:
        return f"{self.container}:{self.field}@{self.byte_offset}"


@dataclass(frozen=True, slots=True)
class _RiffChunk:
    identifier: bytes
    start: int
    payload_start: int
    payload_end: int
    padded_end: int


@dataclass(frozen=True, slots=True)
class _FlacBlock:
    block_type: int
    start: int
    payload_start: int
    payload_end: int
    last: bool


class MediaMetadataCleaner:
    """Remove selected text tags without decoding or rewriting audio samples."""

    supported_remediation_ids = frozenset({"media.remove-metadata-field"})

    def apply(
        self,
        source: Path,
        destination: Path,
        remediations: tuple[Remediation, ...],
        options: ScanOptions | None = None,
    ) -> CleanerOutcome:
        if any(item.remediation_id not in self.supported_remediation_ids for item in remediations):
            raise RemediationError("Media cleaner received an unsupported remediation")
        limits = options or ScanOptions()
        before = self._read_bounded(source, limits.max_file_size)
        if contains_protected_provenance_marker(before):
            raise RemediationError(
                "Refusing media cleanup because the artifact contains a provenance marker"
            )
        selections = self._selected_findings(remediations)
        media_type = "audio/mpeg" if source.suffix.casefold() in {".mp2", ".mp3", ".mpa"} else None
        entries = parse_media_metadata(
            before,
            media_type,
            max_events=limits.max_parser_events,
        )
        available = {_Selection.from_entry(entry): entry for entry in entries}
        missing = selections - available.keys()
        if missing:
            labels = ", ".join(sorted(item.label for item in missing))
            raise RemediationError(
                f"Selected media metadata no longer matches the artifact: {labels}"
            )
        unsafe = [available[item] for item in selections if not available[item].remediation_safe]
        if unsafe:
            raise RemediationError(
                "Selected media metadata has no safe container-specific transform: "
                + ", ".join(sorted(entry.field for entry in unsafe))
            )
        if any(contains_protected_provenance_marker(available[item].value) for item in selections):
            raise RemediationError("Refusing to remove media metadata containing provenance")

        if before.startswith((b"RIFF", b"RIFX")) and before[8:12] == b"WAVE":
            after = self._clean_wave(before, selections)
            logical_before = self._wave_audio_material(before)
            format_label = "WAV"
        elif before.startswith(b"fLaC"):
            after = self._clean_flac(before, selections)
            logical_before = self._flac_audio_material(before)
            format_label = "FLAC"
        elif before.startswith(b"ID3") or media_type == "audio/mpeg":
            after = self._clean_mp3(before, selections)
            logical_before = self._mp3_audio_material(before)
            format_label = "MP3"
        elif _looks_like_iso_bmff(before):
            return self._clean_iso_bmff(before, destination, selections, available, limits)
        else:
            raise RemediationError(
                "Media cleanup currently supports WAV, MP3, FLAC, and ISO base media containers"
            )
        if after == before:
            raise RemediationError("Selected media metadata produced no byte change")

        destination.write_bytes(after)
        emitted = self._read_bounded(destination, limits.max_file_size)
        if format_label == "WAV":
            logical_after = self._wave_audio_material(emitted)
        elif format_label == "FLAC":
            logical_after = self._flac_audio_material(emitted)
        else:
            logical_after = self._mp3_audio_material(emitted)
        exact = emitted == after
        streams_equal = logical_before == logical_after
        status = IntegrityStatus.PASS if exact and streams_equal else IntegrityStatus.FAIL
        changed = tuple(sorted(item.label for item in selections))
        integrity = IntegrityReport(
            status=status,
            explanation=(
                f"The {format_label} output equals the planned surgical transform and all "
                "audio-bearing bytes are byte-identical."
                if status == IntegrityStatus.PASS
                else f"The {format_label} output or its audio-bearing bytes differ from the "
                "planned metadata-only transform."
            ),
            before_sha256=sha256_bytes(before),
            after_sha256=sha256_bytes(emitted),
            logical_before_sha256=sha256_bytes(logical_before),
            logical_after_sha256=sha256_bytes(logical_after),
            intentionally_removed=changed,
        )
        return CleanerOutcome(changed_fields=changed, integrity=integrity)

    def _clean_iso_bmff(
        self,
        before: bytes,
        destination: Path,
        selections: frozenset[_Selection],
        available: dict[_Selection, MediaMetadataEntry],
        limits: ScanOptions,
    ) -> CleanerOutcome:
        """Overwrite the selected boxes with padding, then prove nothing else moved."""

        # A C2PA manifest binds byte ranges of the file it lives in, so *any*
        # change invalidates it — including one that leaves the manifest box
        # untouched. The substring scan over the raw bytes does not catch this:
        # the box is identified by a binary UUID, and a manifest payload need
        # not contain the letters "c2pa" anywhere. Structural detection is the
        # only kind that works here.
        try:
            provenance = model_iso_bmff(before).provenance_boxes
        except IsoBmffError as exc:
            raise RemediationError(f"ISO-BMFF container could not be modelled: {exc}") from exc
        if provenance:
            raise RemediationError(
                "Refusing ISO-BMFF cleanup: the container carries a signed provenance box, "
                "and it binds byte ranges that any edit would invalidate"
            )

        ranges: list[tuple[int, int]] = []
        for selection in sorted(selections, key=lambda item: item.byte_offset):
            entry = available[selection]
            if entry.removable_range is None:
                raise RemediationError(
                    f"{selection.label} has no removable box range; refusing to guess one"
                )
            start, end = entry.removable_range
            if start < 0 or end > len(before) or end - start < _FREE_BOX_HEADER:
                raise RemediationError(
                    f"{selection.label} names an unusable byte range {start}..{end}"
                )
            ranges.append((start, end))

        for (first_start, first_end), (second_start, _) in pairwise(ranges):
            if second_start < first_end:
                # Two selections covering the same bytes would have the second
                # overwrite padding the first already wrote, which is not the
                # edit either of them described.
                raise RemediationError(
                    f"Selected ISO-BMFF boxes overlap at {first_start}..{first_end}"
                )

        buffer = bytearray(before)
        for start, end in ranges:
            # A free box of exactly the same length: same file, same offsets, and
            # the payload zeroed so the metadata is gone rather than hidden.
            buffer[start : start + 4] = (end - start).to_bytes(4, "big")
            buffer[start + 4 : start + 8] = b"free"
            buffer[start + 8 : end] = b"\x00" * (end - start - _FREE_BOX_HEADER)
        after = bytes(buffer)

        if after == before:
            raise RemediationError("Selected media metadata produced no byte change")

        try:
            report = verify_iso_bmff_invariants(before, after)
        except IsoBmffError as exc:
            raise RemediationError(f"ISO-BMFF invariants could not be evaluated: {exc}") from exc
        if not report.safe_to_apply():
            raise RemediationError(f"ISO-BMFF invariants refused the edit: {report.explain()}")

        destination.write_bytes(after)
        emitted = self._read_bounded(destination, limits.max_file_size)
        if emitted != after:
            raise RemediationError("The written ISO-BMFF output differs from the planned edit")

        changed = tuple(sorted(item.label for item in selections))
        integrity = IntegrityReport(
            status=IntegrityStatus.PASS,
            explanation=(
                "The ISO base media output replaces only the selected metadata boxes with "
                "same-length free padding, so every sample offset still resolves to identical "
                "bytes. All seven container invariants held: " + report.explain()
            ),
            before_sha256=sha256_bytes(before),
            after_sha256=sha256_bytes(emitted),
            # The logical material is the sample bytes reached through the offset
            # tables, which is the thing that must not change. Hashing mdat would
            # answer a different and less useful question.
            logical_before_sha256=_iso_sample_digest(before),
            logical_after_sha256=_iso_sample_digest(emitted),
            intentionally_removed=changed,
        )
        return CleanerOutcome(changed_fields=changed, integrity=integrity)

    @staticmethod
    def _read_bounded(path: Path, maximum: int) -> bytes:
        with path.open("rb") as handle:
            data = handle.read(maximum + 1)
        if len(data) > maximum:
            raise RemediationError(f"Media artifact exceeds the cleanup limit of {maximum} bytes")
        return data

    @staticmethod
    def _selected_findings(remediations: tuple[Remediation, ...]) -> frozenset[_Selection]:
        selections: set[_Selection] = set()
        for remediation in remediations:
            findings = remediation.payload.get("findings", [])
            if not isinstance(findings, (list, tuple)):
                raise RemediationError("Malformed media remediation payload")
            for finding in findings:
                if not isinstance(finding, dict):
                    raise RemediationError("Malformed media finding payload")
                if finding.get("detector_id") != "media.container-metadata.v1":
                    raise RemediationError(
                        "Media remediation was not produced by the media detector"
                    )
                evidence = finding.get("evidence")
                location = finding.get("location")
                if not isinstance(evidence, dict) or not isinstance(location, dict):
                    raise RemediationError("Media remediation is missing exact evidence location")
                container = evidence.get("container")
                field = evidence.get("field")
                raw_identifier = evidence.get("raw_identifier")
                value_sha256 = evidence.get("value_sha256")
                byte_offset = location.get("byte_offset")
                if not (
                    isinstance(container, str)
                    and isinstance(field, str)
                    and isinstance(raw_identifier, str)
                    and isinstance(value_sha256, str)
                    and isinstance(byte_offset, int)
                ):
                    raise RemediationError("Media remediation evidence is incomplete")
                selections.add(
                    _Selection(
                        container=container,
                        field=field,
                        raw_identifier=raw_identifier,
                        byte_offset=byte_offset,
                        value_sha256=value_sha256,
                    )
                )
        if not selections:
            raise RemediationError("Media remediation contains no selected fields")
        return frozenset(selections)

    @classmethod
    def _clean_wave(cls, data: bytes, selections: frozenset[_Selection]) -> bytes:
        endian: Literal["little", "big"] = "little" if data[:4] == b"RIFF" else "big"
        declared_end, chunks = cls._riff_chunks(data)
        selected_offsets = {item.byte_offset for item in selections}
        body = bytearray(b"WAVE")
        for chunk in chunks:
            if (
                chunk.identifier == b"LIST"
                and data[chunk.payload_start : chunk.payload_start + 4] == b"INFO"
            ):
                payload = cls._clean_riff_info(data, chunk, endian, selected_offsets)
                body.extend(cls._build_riff_chunk(chunk.identifier, payload, endian))
            elif chunk.identifier == b"bext":
                body.extend(cls._clean_bext(data, chunk, selections))
            elif (
                chunk.identifier in _WAVE_WHOLE_CHUNK_METADATA
                and chunk.payload_start in selected_offsets
            ):
                continue
            else:
                body.extend(data[chunk.start : chunk.padded_end])
        if len(body) > 0xFFFFFFFF:
            raise RemediationError("Cleaned RIFF body exceeds the 32-bit container limit")
        return data[:4] + len(body).to_bytes(4, endian) + bytes(body) + data[declared_end:]

    @classmethod
    def _clean_riff_info(
        cls,
        data: bytes,
        chunk: _RiffChunk,
        endian: Literal["little", "big"],
        selected_offsets: set[int],
    ) -> bytes:
        output = bytearray(b"INFO")
        offset = chunk.payload_start + 4
        while offset < chunk.payload_end:
            if chunk.payload_end - offset < 8:
                if not any(data[offset : chunk.payload_end]):
                    break
                raise CorruptArtifactError("Truncated RIFF INFO field during cleanup")
            size = int.from_bytes(data[offset + 4 : offset + 8], endian)
            value_start = offset + 8
            value_end = value_start + size
            padded_end = value_end + (size & 1)
            if padded_end > chunk.payload_end:
                raise CorruptArtifactError("RIFF INFO field exceeds its LIST chunk during cleanup")
            if value_start not in selected_offsets:
                output.extend(data[offset:padded_end])
            offset = padded_end
        return bytes(output)

    @classmethod
    def _clean_bext(
        cls,
        data: bytes,
        chunk: _RiffChunk,
        selections: frozenset[_Selection],
    ) -> bytes:
        full = bytearray(data[chunk.start : chunk.padded_end])
        for selection in selections:
            if selection.container != "wave.bext":
                continue
            relative = selection.byte_offset - chunk.payload_start
            if selection.field == "coding_history":
                expected_relative = 602
                size = chunk.payload_end - (chunk.payload_start + expected_relative)
            else:
                expected_relative, declared_size = _BEXT_FIELDS[selection.field]
                size = min(declared_size, chunk.payload_end - selection.byte_offset)
            if relative != expected_relative or size <= 0:
                continue
            full_start = 8 + relative
            full[full_start : full_start + size] = b"\x00" * size
        return bytes(full)

    @staticmethod
    def _build_riff_chunk(
        identifier: bytes,
        payload: bytes,
        endian: Literal["little", "big"],
    ) -> bytes:
        return (
            identifier
            + len(payload).to_bytes(4, endian)
            + payload
            + (b"\x00" if len(payload) & 1 else b"")
        )

    @staticmethod
    def _riff_chunks(data: bytes) -> tuple[int, tuple[_RiffChunk, ...]]:
        if len(data) < 12 or data[:4] not in {b"RIFF", b"RIFX"} or data[8:12] != b"WAVE":
            raise CorruptArtifactError("Invalid RIFF/WAVE header during cleanup")
        endian: Literal["little", "big"] = "little" if data[:4] == b"RIFF" else "big"
        declared_end = int.from_bytes(data[4:8], endian) + 8
        if declared_end < 12 or declared_end > len(data):
            raise CorruptArtifactError("RIFF size exceeds available bytes during cleanup")
        chunks: list[_RiffChunk] = []
        offset = 12
        while offset < declared_end:
            if declared_end - offset < 8:
                raise CorruptArtifactError("Truncated RIFF chunk header during cleanup")
            size = int.from_bytes(data[offset + 4 : offset + 8], endian)
            payload_start = offset + 8
            payload_end = payload_start + size
            padded_end = payload_end + (size & 1)
            if padded_end > declared_end:
                raise CorruptArtifactError("RIFF chunk exceeds declared bytes during cleanup")
            chunks.append(
                _RiffChunk(
                    data[offset : offset + 4], offset, payload_start, payload_end, padded_end
                )
            )
            offset = padded_end
        return declared_end, tuple(chunks)

    @classmethod
    def _wave_audio_material(cls, data: bytes) -> bytes:
        declared_end, chunks = cls._riff_chunks(data)
        output = bytearray(data[:4] + b"WAVE")
        for chunk in chunks:
            is_info = (
                chunk.identifier == b"LIST"
                and data[chunk.payload_start : chunk.payload_start + 4] == b"INFO"
            )
            if (
                is_info
                or chunk.identifier == b"bext"
                or chunk.identifier in _WAVE_WHOLE_CHUNK_METADATA
            ):
                continue
            output.extend(data[chunk.start : chunk.padded_end])
        output.extend(data[declared_end:])
        return bytes(output)

    @classmethod
    def _clean_mp3(cls, data: bytes, selections: frozenset[_Selection]) -> bytes:
        selected_v2 = {
            item.byte_offset for item in selections if item.container.startswith("id3v2.")
        }
        output = data
        if selected_v2:
            major, flags, frames_start, tag_end, _ = cls._id3v2_layout(data)
            if flags & 0x90:
                raise RemediationError(
                    "ID3 unsynchronization or footer prevents safe frame removal"
                )
            header_size = 6 if major == 2 else 10
            retained = bytearray(data[10:frames_start])
            offset = frames_start
            while offset + header_size <= tag_end:
                identifier_size = 3 if major == 2 else 4
                identifier = data[offset : offset + identifier_size]
                if not any(identifier):
                    break
                if not all(byte in b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" for byte in identifier):
                    raise CorruptArtifactError("Invalid ID3 frame identifier during cleanup")
                size = (
                    int.from_bytes(data[offset + 3 : offset + 6], "big")
                    if major == 2
                    else (
                        cls._decode_synchsafe(data[offset + 4 : offset + 8])
                        if major == 4
                        else int.from_bytes(data[offset + 4 : offset + 8], "big")
                    )
                )
                payload_start = offset + header_size
                payload_end = payload_start + size
                if payload_end > tag_end:
                    raise CorruptArtifactError("ID3 frame exceeds tag during cleanup")
                if payload_start not in selected_v2:
                    retained.extend(data[offset:payload_end])
                offset = payload_end
            padding = data[offset:tag_end]
            if any(padding):
                raise RemediationError("Ambiguous non-zero ID3 padding prevents safe cleanup")
            retained.extend(padding)
            if len(retained) > 0x0FFFFFFF:
                raise RemediationError("Cleaned ID3 tag exceeds the synchsafe size limit")
            output = (
                data[:6] + cls._encode_synchsafe(len(retained)) + bytes(retained) + data[tag_end:]
            )

        selected_v1_fields = {item.field for item in selections if item.container == "id3v1"}
        if selected_v1_fields:
            if len(output) < 128 or output[-128:-125] != b"TAG":
                raise RemediationError("Selected ID3v1 tag no longer exists")
            mutable = bytearray(output)
            start = len(mutable) - 128
            for field in selected_v1_fields:
                relative, size = _ID3V1_FIELDS[field]
                mutable[start + relative : start + relative + size] = b"\x00" * size
            output = bytes(mutable)
        return output

    @classmethod
    def _id3v2_layout(cls, data: bytes) -> tuple[int, int, int, int, int]:
        if len(data) < 10 or not data.startswith(b"ID3"):
            raise CorruptArtifactError("Selected ID3v2 metadata has no tag header")
        major = data[3]
        if major not in {2, 3, 4}:
            raise CorruptArtifactError(f"Unsupported ID3v2 major version: {major}")
        flags = data[5]
        allowed_flags = {2: 0xC0, 3: 0xE0, 4: 0xF0}[major]
        if flags & ~allowed_flags:
            raise CorruptArtifactError("ID3v2 header contains reserved flag bits")
        tag_end = 10 + cls._decode_synchsafe(data[6:10])
        footer_end = tag_end + (10 if major == 4 and flags & 0x10 else 0)
        if tag_end > len(data) or footer_end > len(data):
            raise CorruptArtifactError("ID3v2 tag exceeds available bytes during cleanup")
        if flags & 0x10 and data[tag_end:footer_end] != b"3DI" + data[3:10]:
            raise CorruptArtifactError("ID3v2 footer does not match its header")
        frames_start = 10
        if flags & 0x40:
            if major == 2 or tag_end - frames_start < 4:
                raise CorruptArtifactError("Unsupported or truncated ID3 extended header")
            declared = (
                cls._decode_synchsafe(data[frames_start : frames_start + 4])
                if major == 4
                else int.from_bytes(data[frames_start : frames_start + 4], "big") + 4
            )
            if declared < 4 or frames_start + declared > tag_end:
                raise CorruptArtifactError("Invalid ID3 extended-header size during cleanup")
            frames_start += declared
        return major, flags, frames_start, tag_end, footer_end

    @classmethod
    def _mp3_audio_material(cls, data: bytes) -> bytes:
        start = 0
        if data.startswith(b"ID3"):
            _, _, _, _, start = cls._id3v2_layout(data)
        end = (
            len(data) - 128 if len(data) - start >= 128 and data[-128:-125] == b"TAG" else len(data)
        )
        if end < start:
            raise CorruptArtifactError("MP3 metadata boundaries overlap the audio payload")
        return data[start:end]

    @staticmethod
    def _decode_synchsafe(raw: bytes) -> int:
        if len(raw) != 4 or any(byte & 0x80 for byte in raw):
            raise CorruptArtifactError("Invalid synchsafe ID3 size")
        return (raw[0] << 21) | (raw[1] << 14) | (raw[2] << 7) | raw[3]

    @staticmethod
    def _encode_synchsafe(value: int) -> bytes:
        return bytes((value >> shift) & 0x7F for shift in (21, 14, 7, 0))

    @classmethod
    def _clean_flac(cls, data: bytes, selections: frozenset[_Selection]) -> bytes:
        blocks, audio_start = cls._flac_blocks(data)
        selected_offsets = {item.byte_offset for item in selections}
        output = bytearray(b"fLaC")
        for block in blocks:
            if block.block_type != 4:
                output.extend(data[block.start : block.payload_end])
                continue
            payload = cls._clean_vorbis_comment_payload(data, block, selected_offsets)
            if len(payload) > 0xFFFFFF:
                raise RemediationError("Cleaned FLAC metadata block exceeds 24-bit size limit")
            header = (0x80 if block.last else 0) | block.block_type
            output.extend(bytes([header]) + len(payload).to_bytes(3, "big") + payload)
        output.extend(data[audio_start:])
        return bytes(output)

    @staticmethod
    def _clean_vorbis_comment_payload(
        data: bytes,
        block: _FlacBlock,
        selected_offsets: set[int],
    ) -> bytes:
        offset = block.payload_start
        if block.payload_end - offset < 4:
            raise CorruptArtifactError("Truncated FLAC vendor length during cleanup")
        vendor_length = int.from_bytes(data[offset : offset + 4], "little")
        vendor_start = offset + 4
        vendor_end = vendor_start + vendor_length
        if vendor_end + 4 > block.payload_end:
            raise CorruptArtifactError("FLAC vendor exceeds comment block during cleanup")
        vendor = b"" if vendor_start in selected_offsets else data[vendor_start:vendor_end]
        count = int.from_bytes(data[vendor_end : vendor_end + 4], "little")
        offset = vendor_end + 4
        comments: list[bytes] = []
        for _ in range(count):
            if block.payload_end - offset < 4:
                raise CorruptArtifactError("Truncated FLAC comment length during cleanup")
            length = int.from_bytes(data[offset : offset + 4], "little")
            value_start = offset + 4
            value_end = value_start + length
            if value_end > block.payload_end:
                raise CorruptArtifactError("FLAC comment exceeds block during cleanup")
            if value_start not in selected_offsets:
                comments.append(data[value_start:value_end])
            offset = value_end
        if offset != block.payload_end:
            raise CorruptArtifactError("Unexpected trailing FLAC comment bytes during cleanup")
        output = bytearray(len(vendor).to_bytes(4, "little") + vendor)
        output.extend(len(comments).to_bytes(4, "little"))
        for comment in comments:
            output.extend(len(comment).to_bytes(4, "little") + comment)
        return bytes(output)

    @staticmethod
    def _flac_blocks(data: bytes) -> tuple[tuple[_FlacBlock, ...], int]:
        if len(data) < 8 or not data.startswith(b"fLaC"):
            raise CorruptArtifactError("Invalid FLAC header during cleanup")
        blocks: list[_FlacBlock] = []
        offset = 4
        first = True
        while True:
            if len(data) - offset < 4:
                raise CorruptArtifactError("Truncated FLAC metadata block during cleanup")
            header = data[offset]
            block_type = header & 0x7F
            size = int.from_bytes(data[offset + 1 : offset + 4], "big")
            payload_start = offset + 4
            payload_end = payload_start + size
            if payload_end > len(data):
                raise CorruptArtifactError("FLAC metadata block exceeds available bytes")
            if first and (block_type != 0 or size != 34):
                raise CorruptArtifactError("FLAC STREAMINFO must be the first 34-byte block")
            last = bool(header & 0x80)
            blocks.append(_FlacBlock(block_type, offset, payload_start, payload_end, last))
            offset = payload_end
            first = False
            if last:
                break
        return tuple(blocks), offset

    @classmethod
    def _flac_audio_material(cls, data: bytes) -> bytes:
        blocks, audio_start = cls._flac_blocks(data)
        output = bytearray(b"fLaC")
        for block in blocks:
            if block.block_type != 4:
                output.extend(data[block.start : block.payload_end])
        output.extend(data[audio_start:])
        return bytes(output)


__all__ = ["MediaMetadataCleaner"]


_FREE_BOX_HEADER = 8


def _looks_like_iso_bmff(data: bytes) -> bool:
    """Return whether the buffer starts with an ftyp box carrying a known brand."""

    if len(data) < 16 or data[4:8] != b"ftyp":
        return False
    return data[8:12] in _ISO_BRANDS


def _iso_sample_digest(data: bytes) -> bytes:
    """Hash every track's samples, reached through the offset tables.

    Returned as bytes so it flows into the same ``sha256_bytes`` the other
    formats use, keeping one meaning for the logical-material fields.
    """

    model = model_iso_bmff(data)
    joined = b"".join(track.sample_digest(data).encode("ascii") for track in model.tracks)
    return joined
