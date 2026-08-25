"""Hostile-input-bounded metadata readers for common media containers.

The readers never decode audio or video streams. They walk only container
headers and metadata blocks already bounded by ``ScanOptions.max_file_size``.
Every structural event consumes a shared parser budget, and individual text
values are capped so a syntactically valid tag cannot become an allocation
amplifier.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from trueai.core.errors import CorruptArtifactError, ScanLimitExceededError

_MAX_METADATA_VALUE_BYTES = 256 * 1024
_MAX_CONTAINER_DEPTH = 12


@dataclass(frozen=True, slots=True)
class MediaMetadataEntry:
    """One textual field recovered from a media container."""

    container: str
    field: str
    value: str
    byte_offset: int
    raw_identifier: str
    remediation_safe: bool = False
    #: The byte range of the whole box or chunk a cleaner would remove, when the
    #: container has one. A cleaner that re-derived this by parsing again could
    #: disagree with what the detector reported, and the two disagreeing is how a
    #: surgical edit stops being surgical.
    removable_range: tuple[int, int] | None = None


class ParserBudget:
    """Shared deterministic event allowance for one media artifact."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0

    def consume(self, context: str) -> None:
        self.used += 1
        if self.used > self.limit:
            raise ScanLimitExceededError(
                f"Media parser event limit {self.limit} was exceeded while reading {context}"
            )


def parse_media_metadata(
    data: bytes,
    media_type: str | None,
    *,
    max_events: int,
) -> list[MediaMetadataEntry]:
    """Dispatch exact container bytes to a signature-matched metadata reader."""

    budget = ParserBudget(max_events)
    if data.startswith((b"RIFF", b"RIFX")) and data[8:12] == b"WAVE":
        return _parse_wave(data, budget)
    if data.startswith(b"fLaC"):
        return _parse_flac(data, budget)
    if data.startswith(b"ID3") or media_type == "audio/mpeg":
        return _parse_mp3(data, budget)
    if len(data) >= 12 and data[4:8] == b"ftyp":
        return _parse_iso_bmff(data, budget)
    if data.startswith(b"\x1aE\xdf\xa3"):
        return _parse_ebml(data, budget)
    raise CorruptArtifactError("Media signature does not match a supported container")


def _parse_wave(data: bytes, budget: ParserBudget) -> list[MediaMetadataEntry]:
    if len(data) < 12:
        raise CorruptArtifactError("Truncated RIFF/WAVE header")
    endian: Literal["little", "big"] = "little" if data[:4] == b"RIFF" else "big"
    declared_end = int.from_bytes(data[4:8], endian) + 8
    if declared_end < 12 or declared_end > len(data):
        raise CorruptArtifactError("RIFF size exceeds the available WAVE bytes")
    entries: list[MediaMetadataEntry] = []
    offset = 12
    while offset < declared_end:
        budget.consume("RIFF chunk")
        if declared_end - offset < 8:
            raise CorruptArtifactError("Truncated RIFF chunk header")
        chunk_id = data[offset : offset + 4]
        size = int.from_bytes(data[offset + 4 : offset + 8], endian)
        payload_start = offset + 8
        payload_end = payload_start + size
        if payload_end > declared_end:
            raise CorruptArtifactError("RIFF chunk extends beyond the declared container")
        if chunk_id == b"LIST" and size >= 4 and data[payload_start : payload_start + 4] == b"INFO":
            entries.extend(_parse_riff_info(data, payload_start + 4, payload_end, endian, budget))
        elif chunk_id == b"bext":
            entries.extend(_parse_broadcast_wave(data, payload_start, payload_end))
        elif chunk_id in {b"iXML", b"_PMX", b"XMP "}:
            value = _decode_bounded_text(data[payload_start:payload_end], "WAVE XML metadata")
            if value:
                entries.append(
                    MediaMetadataEntry(
                        container="wave",
                        field=chunk_id.decode("ascii", errors="replace").strip(),
                        value=value,
                        byte_offset=payload_start,
                        raw_identifier=chunk_id.hex(),
                        remediation_safe=True,
                    )
                )
        offset = payload_end + (size & 1)
        if offset > declared_end:
            raise CorruptArtifactError("RIFF padding extends beyond the declared container")
    return entries


def _parse_riff_info(
    data: bytes,
    start: int,
    end: int,
    endian: Literal["little", "big"],
    budget: ParserBudget,
) -> list[MediaMetadataEntry]:
    entries: list[MediaMetadataEntry] = []
    offset = start
    while offset < end:
        budget.consume("RIFF INFO field")
        if end - offset < 8:
            if not any(data[offset:end]):
                break
            raise CorruptArtifactError("Truncated RIFF INFO field")
        field = data[offset : offset + 4]
        size = int.from_bytes(data[offset + 4 : offset + 8], endian)
        value_start = offset + 8
        value_end = value_start + size
        if value_end > end:
            raise CorruptArtifactError("RIFF INFO value extends beyond its LIST chunk")
        value = _decode_bounded_text(data[value_start:value_end], "RIFF INFO value")
        if value:
            entries.append(
                MediaMetadataEntry(
                    container="wave.info",
                    field=_RIFF_INFO_NAMES.get(field, field.decode("latin-1")),
                    value=value,
                    byte_offset=value_start,
                    raw_identifier=field.decode("latin-1"),
                    remediation_safe=True,
                )
            )
        offset = value_end + (size & 1)
        if offset > end:
            raise CorruptArtifactError("RIFF INFO padding extends beyond its LIST chunk")
    return entries


_RIFF_INFO_NAMES = {
    b"IART": "artist",
    b"ICMT": "comment",
    b"ICOP": "copyright",
    b"ICRD": "creation_date",
    b"IENG": "engineer",
    b"IGNR": "genre",
    b"INAM": "title",
    b"IPRD": "product",
    b"ISBJ": "subject",
    b"ISFT": "software",
    b"ISRC": "source",
}


def _parse_broadcast_wave(data: bytes, start: int, end: int) -> list[MediaMetadataEntry]:
    fields = (
        ("description", 0, 256),
        ("originator", 256, 32),
        ("originator_reference", 288, 32),
        ("origination_date", 320, 10),
        ("origination_time", 330, 8),
    )
    entries: list[MediaMetadataEntry] = []
    length = end - start
    for field, relative, size in fields:
        if relative >= length:
            continue
        value = _decode_bounded_text(
            data[start + relative : min(start + relative + size, end)],
            "Broadcast WAVE field",
        )
        if value:
            entries.append(
                MediaMetadataEntry(
                    container="wave.bext",
                    field=field,
                    value=value,
                    byte_offset=start + relative,
                    raw_identifier=field,
                    remediation_safe=True,
                )
            )
    if length > 602:
        value = _decode_bounded_text(data[start + 602 : end], "Broadcast WAVE coding history")
        if value:
            entries.append(
                MediaMetadataEntry(
                    container="wave.bext",
                    field="coding_history",
                    value=value,
                    byte_offset=start + 602,
                    raw_identifier="coding_history",
                    remediation_safe=True,
                )
            )
    return entries


def _parse_mp3(data: bytes, budget: ParserBudget) -> list[MediaMetadataEntry]:
    entries: list[MediaMetadataEntry] = []
    if data.startswith(b"ID3"):
        if len(data) < 10:
            raise CorruptArtifactError("Truncated ID3v2 header")
        major = data[3]
        if major not in {2, 3, 4}:
            raise CorruptArtifactError(f"Unsupported ID3v2 major version: {major}")
        flags = data[5]
        allowed_flags = {2: 0xC0, 3: 0xE0, 4: 0xF0}[major]
        if flags & ~allowed_flags:
            raise CorruptArtifactError("ID3v2 header contains reserved flag bits")
        tag_size = _decode_synchsafe(data[6:10])
        tag_end = 10 + tag_size
        if tag_end > len(data):
            raise CorruptArtifactError("ID3v2 tag size exceeds the available MP3 bytes")
        if flags & 0x10:
            footer_end = tag_end + 10
            if major != 4 or footer_end > len(data):
                raise CorruptArtifactError("Truncated or invalid ID3v2 footer")
            if data[tag_end:footer_end] != b"3DI" + data[3:10]:
                raise CorruptArtifactError("ID3v2 footer does not match its header")
        offset = 10
        if flags & 0x40:
            if major == 2:
                raise CorruptArtifactError("ID3v2.2 compression is not supported safely")
            if tag_end - offset < 4:
                raise CorruptArtifactError("Truncated ID3 extended header")
            declared = (
                _decode_synchsafe(data[offset : offset + 4])
                if major == 4
                else int.from_bytes(data[offset : offset + 4], "big") + 4
            )
            if declared < 4 or offset + declared > tag_end:
                raise CorruptArtifactError("Invalid ID3 extended-header size")
            offset += declared
        entries.extend(
            _parse_id3_frames(
                data,
                offset,
                tag_end,
                major,
                budget,
                remediation_safe=not bool(flags & 0x90),
            )
        )
    if len(data) >= 128 and data[-128:-125] == b"TAG":
        entries.extend(_parse_id3v1(data))
    return entries


def _parse_id3_frames(
    data: bytes,
    start: int,
    end: int,
    major: int,
    budget: ParserBudget,
    *,
    remediation_safe: bool,
) -> list[MediaMetadataEntry]:
    entries: list[MediaMetadataEntry] = []
    offset = start
    header_size = 6 if major == 2 else 10
    while offset + header_size <= end:
        identifier_size = 3 if major == 2 else 4
        raw_id = data[offset : offset + identifier_size]
        if not any(raw_id):
            break
        if not all(byte in b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" for byte in raw_id):
            raise CorruptArtifactError("Invalid ID3 frame identifier")
        budget.consume("ID3 frame")
        if major == 2:
            size = int.from_bytes(data[offset + 3 : offset + 6], "big")
            format_flags = 0
        else:
            raw_size = data[offset + 4 : offset + 8]
            size = _decode_synchsafe(raw_size) if major == 4 else int.from_bytes(raw_size, "big")
            format_flags = data[offset + 9]
        payload_start = offset + header_size
        payload_end = payload_start + size
        if payload_end > end:
            raise CorruptArtifactError("ID3 frame extends beyond its declared tag")
        frame_id = _ID3V22_ALIASES.get(raw_id, raw_id).decode("ascii")
        # Compression, encryption, grouping, per-frame unsynchronization, and
        # data-length indicators alter the payload layout. A passive metadata
        # scanner skips flagged frames instead of decoding the wrong bytes.
        value = (
            None if format_flags else _decode_id3_frame(frame_id, data[payload_start:payload_end])
        )
        if value:
            entries.append(
                MediaMetadataEntry(
                    container=f"id3v2.{major}",
                    field=_ID3_FIELD_NAMES.get(frame_id, frame_id),
                    value=value,
                    byte_offset=payload_start,
                    raw_identifier=frame_id,
                    remediation_safe=remediation_safe and not bool(format_flags),
                )
            )
        offset = payload_end
    if any(data[offset:end]):
        raise CorruptArtifactError("Non-zero bytes follow ID3 frame data")
    return entries


_ID3V22_ALIASES = {
    b"TT2": b"TIT2",
    b"TP1": b"TPE1",
    b"TCM": b"TCOM",
    b"TCR": b"TCOP",
    b"TEN": b"TENC",
    b"TSS": b"TSSE",
    b"COM": b"COMM",
}
_ID3_FIELD_NAMES = {
    "TIT2": "title",
    "TPE1": "artist",
    "TPE2": "album_artist",
    "TCOM": "composer",
    "TCOP": "copyright",
    "TENC": "encoded_by",
    "TOWN": "owner",
    "TSSE": "encoder_software",
    "COMM": "comment",
    "TXXX": "user_text",
}


def _decode_id3_frame(frame_id: str, payload: bytes) -> str | None:
    if not payload or frame_id.startswith(("APIC", "PIC", "GEOB", "PRIV")):
        return None
    if frame_id.startswith("T"):
        text = _decode_id3_text(payload)
        if frame_id == "TXXX":
            parts = [part for part in text.split("\x00") if part]
            return ": ".join(parts)
        return text.replace("\x00", "; ").strip()
    if frame_id == "COMM":
        if len(payload) < 4:
            raise CorruptArtifactError("Truncated ID3 comment frame")
        text = _decode_id3_text(bytes([payload[0]]) + payload[4:])
        parts = [part for part in text.split("\x00") if part]
        return ": ".join(parts)
    return None


def _decode_id3_text(payload: bytes) -> str:
    if len(payload) > _MAX_METADATA_VALUE_BYTES + 1:
        raise ScanLimitExceededError(f"ID3 text value exceeds {_MAX_METADATA_VALUE_BYTES} bytes")
    if not payload:
        return ""
    encoding = payload[0]
    body = payload[1:]
    codec = {0: "latin-1", 1: "utf-16", 2: "utf-16-be", 3: "utf-8"}.get(encoding)
    if codec is None:
        raise CorruptArtifactError(f"Unknown ID3 text encoding byte: {encoding}")
    try:
        return body.decode(codec).rstrip("\x00").strip()
    except UnicodeDecodeError as exc:
        raise CorruptArtifactError(f"Invalid {codec} ID3 text: {exc}") from exc


def _parse_id3v1(data: bytes) -> list[MediaMetadataEntry]:
    start = len(data) - 128
    fields = (
        ("title", 3, 30),
        ("artist", 33, 30),
        ("album", 63, 30),
        ("year", 93, 4),
        ("comment", 97, 30),
    )
    entries: list[MediaMetadataEntry] = []
    for field, relative, size in fields:
        value = _decode_bounded_text(
            data[start + relative : start + relative + size], "ID3v1 field", codec="latin-1"
        )
        if value:
            entries.append(
                MediaMetadataEntry(
                    container="id3v1",
                    field=field,
                    value=value,
                    byte_offset=start + relative,
                    raw_identifier=field,
                    remediation_safe=True,
                )
            )
    return entries


def _parse_flac(data: bytes, budget: ParserBudget) -> list[MediaMetadataEntry]:
    if len(data) < 8:
        raise CorruptArtifactError("Truncated FLAC metadata header")
    entries: list[MediaMetadataEntry] = []
    offset = 4
    last = False
    first = True
    while not last:
        budget.consume("FLAC metadata block")
        if len(data) - offset < 4:
            raise CorruptArtifactError("Truncated FLAC metadata block header")
        header = data[offset]
        last = bool(header & 0x80)
        block_type = header & 0x7F
        size = int.from_bytes(data[offset + 1 : offset + 4], "big")
        payload_start = offset + 4
        payload_end = payload_start + size
        if payload_end > len(data):
            raise CorruptArtifactError("FLAC metadata block exceeds the available bytes")
        if first and (block_type != 0 or size != 34):
            raise CorruptArtifactError("FLAC STREAMINFO must be the first 34-byte metadata block")
        if block_type == 4:
            entries.extend(_parse_vorbis_comments(data, payload_start, payload_end, budget))
        elif block_type == 2 and size >= 4:
            application_id = data[payload_start : payload_start + 4].decode(
                "latin-1", errors="replace"
            )
            payload = data[payload_start + 4 : payload_end]
            lowered = payload.lower()
            if any(marker in lowered for marker in (b"c2pa", b"content credentials")):
                entries.append(
                    MediaMetadataEntry(
                        container="flac.application",
                        field=f"application:{application_id}",
                        value="C2PA/Content Credentials marker",
                        byte_offset=payload_start,
                        raw_identifier=application_id,
                    )
                )
        offset = payload_end
        first = False
    return entries


def _parse_vorbis_comments(
    data: bytes,
    start: int,
    end: int,
    budget: ParserBudget,
) -> list[MediaMetadataEntry]:
    offset = start
    vendor_length, offset = _read_u32le(data, offset, end, "FLAC vendor length")
    vendor_start = offset
    vendor_end = vendor_start + vendor_length
    if vendor_end > end:
        raise CorruptArtifactError("FLAC vendor string exceeds the comment block")
    vendor = _decode_bounded_text(data[vendor_start:vendor_end], "FLAC vendor", codec="utf-8")
    offset = vendor_end
    count, offset = _read_u32le(data, offset, end, "FLAC comment count")
    if count > budget.limit:
        raise ScanLimitExceededError(
            f"FLAC declares {count} comments; parser limit is {budget.limit}"
        )
    entries: list[MediaMetadataEntry] = []
    if vendor:
        entries.append(
            MediaMetadataEntry(
                container="flac.vorbis-comment",
                field="vendor",
                value=vendor,
                byte_offset=vendor_start,
                raw_identifier="vendor",
                remediation_safe=True,
            )
        )
    for _ in range(count):
        budget.consume("FLAC Vorbis comment")
        length, offset = _read_u32le(data, offset, end, "FLAC comment length")
        value_start = offset
        value_end = value_start + length
        if value_end > end:
            raise CorruptArtifactError("FLAC comment exceeds the comment block")
        rendered = _decode_bounded_text(data[value_start:value_end], "FLAC comment", codec="utf-8")
        offset = value_end
        if not rendered:
            continue
        if "=" in rendered:
            field, value = rendered.split("=", 1)
        else:
            field, value = "comment", rendered
        if value:
            entries.append(
                MediaMetadataEntry(
                    container="flac.vorbis-comment",
                    field=field.casefold(),
                    value=value,
                    byte_offset=value_start,
                    raw_identifier=field,
                    remediation_safe=True,
                )
            )
    if offset != end:
        raise CorruptArtifactError("Unexpected trailing bytes in FLAC Vorbis comment block")
    return entries


@dataclass(frozen=True, slots=True)
class _Box:
    type: bytes
    start: int
    payload_start: int
    end: int
    user_type: bytes | None = None


_ISO_CONTAINER_BOXES = frozenset({b"moov", b"udta"})
_ISO_LEGACY_FIELDS = {
    b"\xa9nam": "title",
    b"\xa9ART": "artist",
    b"aART": "album_artist",
    b"\xa9wrt": "composer",
    b"\xa9cmt": "comment",
    b"\xa9cpy": "copyright",
    b"\xa9day": "creation_date",
    b"\xa9too": "encoder_software",
}
_XMP_UUID = bytes.fromhex("be7acfcb97a942e89c71999491e3afac")


def _parse_iso_bmff(data: bytes, budget: ParserBudget) -> list[MediaMetadataEntry]:
    top_level = _read_boxes(data, 0, len(data), budget, "ISO BMFF top level")
    if not top_level or top_level[0].type != b"ftyp":
        raise CorruptArtifactError("ISO BMFF file does not begin with an ftyp box")
    entries: list[MediaMetadataEntry] = []
    _walk_iso_boxes(data, top_level, budget, entries, depth=0)
    return entries


def _walk_iso_boxes(
    data: bytes,
    boxes: list[_Box],
    budget: ParserBudget,
    entries: list[MediaMetadataEntry],
    *,
    depth: int,
) -> None:
    if depth > _MAX_CONTAINER_DEPTH:
        raise ScanLimitExceededError(f"ISO BMFF nesting exceeds {_MAX_CONTAINER_DEPTH} levels")
    for box in boxes:
        if box.type in _ISO_CONTAINER_BOXES:
            children = _read_boxes(data, box.payload_start, box.end, budget, _fourcc(box.type))
            _walk_iso_boxes(data, children, budget, entries, depth=depth + 1)
        elif box.type == b"meta":
            if box.end - box.payload_start < 4:
                raise CorruptArtifactError("Truncated ISO BMFF meta full-box header")
            children = _read_boxes(data, box.payload_start + 4, box.end, budget, "ISO BMFF meta")
            keys: dict[int, str] = {}
            for child in children:
                if child.type == b"keys":
                    keys = _parse_iso_keys(data, child, budget)
            for child in children:
                if child.type == b"ilst":
                    entries.extend(_parse_iso_item_list(data, child, keys, budget))
                elif child.type in _ISO_CONTAINER_BOXES:
                    nested = _read_boxes(
                        data, child.payload_start, child.end, budget, _fourcc(child.type)
                    )
                    _walk_iso_boxes(data, nested, budget, entries, depth=depth + 1)
        elif box.type in _ISO_LEGACY_FIELDS:
            entries.extend(_parse_legacy_iso_field(data, box, budget))
        elif box.type == b"XMP_" or (box.type == b"uuid" and box.user_type == _XMP_UUID):
            value = _decode_bounded_text(
                data[box.payload_start : box.end], "ISO BMFF XMP metadata", codec="utf-8"
            )
            if value:
                entries.append(
                    MediaMetadataEntry(
                        container="iso-bmff.xmp",
                        field="xmp",
                        value=value,
                        byte_offset=box.payload_start,
                        raw_identifier=_fourcc(box.type),
                    )
                )


def _read_boxes(
    data: bytes,
    start: int,
    end: int,
    budget: ParserBudget,
    context: str,
) -> list[_Box]:
    boxes: list[_Box] = []
    offset = start
    while offset < end:
        budget.consume(context)
        if end - offset < 8:
            if not any(data[offset:end]):
                break
            raise CorruptArtifactError(f"Truncated {context} box header")
        size32 = int.from_bytes(data[offset : offset + 4], "big")
        box_type = data[offset + 4 : offset + 8]
        header_size = 8
        if size32 == 1:
            if end - offset < 16:
                raise CorruptArtifactError(f"Truncated extended-size {context} box")
            size = int.from_bytes(data[offset + 8 : offset + 16], "big")
            header_size = 16
        elif size32 == 0:
            size = end - offset
        else:
            size = size32
        user_type = None
        if box_type == b"uuid":
            if size < header_size + 16 or end - offset < header_size + 16:
                raise CorruptArtifactError("Truncated ISO BMFF UUID box")
            user_type = data[offset + header_size : offset + header_size + 16]
            header_size += 16
        if size < header_size:
            raise CorruptArtifactError(f"Invalid {_fourcc(box_type)} box size: {size}")
        box_end = offset + size
        if box_end > end:
            raise CorruptArtifactError(f"{_fourcc(box_type)} box exceeds its parent")
        boxes.append(
            _Box(
                type=box_type,
                start=offset,
                payload_start=offset + header_size,
                end=box_end,
                user_type=user_type,
            )
        )
        offset = box_end
    return boxes


def _parse_iso_keys(data: bytes, box: _Box, budget: ParserBudget) -> dict[int, str]:
    if box.end - box.payload_start < 8:
        raise CorruptArtifactError("Truncated ISO BMFF metadata keys box")
    count = int.from_bytes(data[box.payload_start + 4 : box.payload_start + 8], "big")
    if count > budget.limit:
        raise ScanLimitExceededError(
            f"ISO BMFF declares {count} metadata keys; parser limit is {budget.limit}"
        )
    offset = box.payload_start + 8
    keys: dict[int, str] = {}
    for index in range(1, count + 1):
        budget.consume("ISO BMFF metadata key")
        if box.end - offset < 8:
            raise CorruptArtifactError("Truncated ISO BMFF metadata key")
        size = int.from_bytes(data[offset : offset + 4], "big")
        if size < 8 or offset + size > box.end:
            raise CorruptArtifactError("Invalid ISO BMFF metadata key size")
        key = _decode_bounded_text(
            data[offset + 8 : offset + size], "ISO BMFF metadata key", codec="utf-8"
        )
        keys[index] = key or f"key_{index}"
        offset += size
    return keys


def _parse_iso_item_list(
    data: bytes,
    box: _Box,
    keys: dict[int, str],
    budget: ParserBudget,
) -> list[MediaMetadataEntry]:
    items = _read_boxes(data, box.payload_start, box.end, budget, "ISO BMFF ilst")
    entries: list[MediaMetadataEntry] = []
    for item in items:
        index = int.from_bytes(item.type, "big")
        field = keys.get(index) or _ISO_LEGACY_FIELDS.get(item.type) or _fourcc(item.type)
        data_boxes = _read_boxes(
            data, item.payload_start, item.end, budget, "ISO BMFF metadata item"
        )
        for value_box in data_boxes:
            if value_box.type != b"data" or value_box.end - value_box.payload_start < 8:
                continue
            kind = int.from_bytes(
                data[value_box.payload_start : value_box.payload_start + 4], "big"
            )
            value_start = value_box.payload_start + 8
            raw = data[value_start : value_box.end]
            value = _decode_iso_value(raw, kind)
            if value:
                entries.append(
                    MediaMetadataEntry(
                        container="iso-bmff.ilst",
                        field=field,
                        value=value,
                        byte_offset=value_start,
                        raw_identifier=_fourcc(item.type),
                        # The whole item goes, not just the value: an ilst item
                        # with its data box removed is a malformed item rather
                        # than an absent one.
                        remediation_safe=True,
                        removable_range=(item.start, item.end),
                    )
                )
    return entries


def _parse_legacy_iso_field(
    data: bytes, box: _Box, budget: ParserBudget
) -> list[MediaMetadataEntry]:
    field = _ISO_LEGACY_FIELDS[box.type]
    try:
        nested = _read_boxes(data, box.payload_start, box.end, budget, "QuickTime metadata field")
    except CorruptArtifactError:
        nested = []
    entries: list[MediaMetadataEntry] = []
    for value_box in nested:
        if value_box.type != b"data" or value_box.end - value_box.payload_start < 8:
            continue
        value_start = value_box.payload_start + 8
        kind = int.from_bytes(data[value_box.payload_start : value_start - 4], "big")
        value = _decode_iso_value(data[value_start : value_box.end], kind)
        if value:
            entries.append(
                MediaMetadataEntry(
                    container="quicktime.metadata",
                    field=field,
                    value=value,
                    byte_offset=value_start,
                    raw_identifier=_fourcc(box.type),
                    remediation_safe=True,
                    removable_range=(box.start, box.end),
                )
            )
    if entries:
        return entries
    raw = data[box.payload_start : box.end]
    if len(raw) >= 4:
        declared = int.from_bytes(raw[:2], "big")
        if 0 < declared <= len(raw) - 4:
            raw = raw[4 : 4 + declared]
    value = _decode_bounded_text(raw, "QuickTime metadata value", codec="utf-8")
    if not value:
        return []
    return [
        MediaMetadataEntry(
            container="quicktime.metadata",
            field=field,
            value=value,
            byte_offset=box.payload_start,
            raw_identifier=_fourcc(box.type),
            remediation_safe=True,
            removable_range=(box.start, box.end),
        )
    ]


def _decode_iso_value(raw: bytes, kind: int) -> str:
    if len(raw) > _MAX_METADATA_VALUE_BYTES:
        raise ScanLimitExceededError(
            f"ISO BMFF metadata value exceeds {_MAX_METADATA_VALUE_BYTES} bytes"
        )
    if kind == 2:
        codec = "utf-16-be"
    elif kind in {21, 22} and len(raw) <= 8:
        return str(int.from_bytes(raw, "big", signed=kind == 21))
    else:
        codec = "utf-8"
    try:
        return raw.decode(codec).rstrip("\x00").strip()
    except UnicodeDecodeError:
        # A metadata atom may carry an unrecognized registered data type. It is
        # not safe to call arbitrary bytes text, so expose only a bounded summary.
        return f"<{len(raw)} bytes, data type {kind}>"


_EBML_MASTER_IDS = frozenset(
    {
        0x1A45DFA3,  # EBML
        0x18538067,  # Segment
        0x1549A966,  # Info
        0x1654AE6B,  # Tracks
        0xAE,  # TrackEntry
        0x1254C367,  # Tags
        0x7373,  # Tag
        0x63C0,  # Targets
    }
)
_EBML_TEXT_FIELDS = {
    0x4282: "document_type",
    0x5741: "writing_application",
    0x4D80: "muxing_application",
    0x7BA9: "title",
}


def _parse_ebml(data: bytes, budget: ParserBudget) -> list[MediaMetadataEntry]:
    entries: list[MediaMetadataEntry] = []
    _walk_ebml(data, 0, len(data), budget, entries, depth=0)
    document_types = [entry.value.casefold() for entry in entries if entry.field == "document_type"]
    if not document_types:
        raise CorruptArtifactError("EBML document type is missing")
    if document_types[0] not in {"webm", "matroska"}:
        raise CorruptArtifactError(f"Unsupported EBML document type: {document_types[0]}")
    return entries


def _walk_ebml(
    data: bytes,
    start: int,
    end: int,
    budget: ParserBudget,
    entries: list[MediaMetadataEntry],
    *,
    depth: int,
) -> None:
    if depth > _MAX_CONTAINER_DEPTH:
        raise ScanLimitExceededError(f"EBML nesting exceeds {_MAX_CONTAINER_DEPTH} levels")
    offset = start
    while offset < end:
        budget.consume("EBML element")
        element_id, id_width = _read_ebml_vint(data, offset, end, keep_marker=True)
        size, size_width, unknown = _read_ebml_size(data, offset + id_width, end)
        payload_start = offset + id_width + size_width
        payload_end = end if unknown else payload_start + size
        if payload_end > end:
            raise CorruptArtifactError("EBML element exceeds its parent")
        if payload_end <= offset:
            raise CorruptArtifactError("EBML element did not advance the parser")
        if unknown and element_id not in _EBML_MASTER_IDS:
            raise CorruptArtifactError("Unknown-size EBML value is not a master element")
        if element_id == 0x67C8:  # SimpleTag
            entries.extend(
                _parse_ebml_simple_tag(
                    data, payload_start, payload_end, budget, element_range=(offset, payload_end)
                )
            )
        elif element_id in _EBML_MASTER_IDS:
            _walk_ebml(
                data,
                payload_start,
                payload_end,
                budget,
                entries,
                depth=depth + 1,
            )
        elif element_id in _EBML_TEXT_FIELDS:
            value = _decode_bounded_text(
                data[payload_start:payload_end], "EBML text value", codec="utf-8"
            )
            if value:
                entries.append(
                    MediaMetadataEntry(
                        container="ebml",
                        field=_EBML_TEXT_FIELDS[element_id],
                        value=value,
                        byte_offset=payload_start,
                        raw_identifier=f"0x{element_id:x}",
                    )
                )
        offset = payload_end


def _parse_ebml_simple_tag(
    data: bytes,
    start: int,
    end: int,
    budget: ParserBudget,
    element_range: tuple[int, int] | None = None,
) -> list[MediaMetadataEntry]:
    offset = start
    name: str | None = None
    value: str | None = None
    value_offset = start
    nested: list[MediaMetadataEntry] = []
    while offset < end:
        budget.consume("EBML SimpleTag child")
        element_id, id_width = _read_ebml_vint(data, offset, end, keep_marker=True)
        size, size_width, unknown = _read_ebml_size(data, offset + id_width, end)
        payload_start = offset + id_width + size_width
        payload_end = end if unknown else payload_start + size
        if payload_end > end or payload_end <= offset:
            raise CorruptArtifactError("Invalid EBML SimpleTag child size")
        if unknown and element_id != 0x67C8:
            raise CorruptArtifactError("Unknown-size EBML tag value is invalid")
        if element_id == 0x45A3:
            name = _decode_bounded_text(
                data[payload_start:payload_end], "EBML tag name", codec="utf-8"
            )
        elif element_id == 0x4487:
            value = _decode_bounded_text(
                data[payload_start:payload_end], "EBML tag value", codec="utf-8"
            )
            value_offset = payload_start
        elif element_id == 0x67C8:
            nested.extend(_parse_ebml_simple_tag(data, payload_start, payload_end, budget))
        offset = payload_end
    result = nested
    if name and value:
        result.insert(
            0,
            MediaMetadataEntry(
                container="ebml.tag",
                field=name.casefold(),
                value=value,
                byte_offset=value_offset,
                raw_identifier=name,
                # The whole SimpleTag goes. A SimpleTag whose TagString was
                # removed is a malformed tag rather than an absent one.
                remediation_safe=element_range is not None,
                removable_range=element_range,
            ),
        )
    return result


def _read_ebml_vint(data: bytes, offset: int, end: int, *, keep_marker: bool) -> tuple[int, int]:
    if offset >= end:
        raise CorruptArtifactError("Truncated EBML variable-length integer")
    first = data[offset]
    if first == 0:
        raise CorruptArtifactError("Invalid zero-prefixed EBML variable-length integer")
    marker = 0x80
    width = 1
    while width <= 8 and not first & marker:
        marker >>= 1
        width += 1
    if width > 8 or offset + width > end:
        raise CorruptArtifactError("Invalid or truncated EBML variable-length integer")
    if keep_marker and width > 4:
        raise CorruptArtifactError("EBML element identifiers may not exceed four bytes")
    value = first if keep_marker else first & (marker - 1)
    for byte in data[offset + 1 : offset + width]:
        value = (value << 8) | byte
    return value, width


def _read_ebml_size(data: bytes, offset: int, end: int) -> tuple[int, int, bool]:
    value, width = _read_ebml_vint(data, offset, end, keep_marker=False)
    unknown = value == (1 << (7 * width)) - 1
    return value, width, unknown


def _read_u32le(data: bytes, offset: int, end: int, context: str) -> tuple[int, int]:
    if end - offset < 4:
        raise CorruptArtifactError(f"Truncated {context}")
    return int.from_bytes(data[offset : offset + 4], "little"), offset + 4


def _decode_synchsafe(raw: bytes) -> int:
    if len(raw) != 4 or any(byte & 0x80 for byte in raw):
        raise CorruptArtifactError("Invalid ID3 synchsafe integer")
    value = 0
    for byte in raw:
        value = (value << 7) | byte
    return value


def _decode_bounded_text(raw: bytes, context: str, *, codec: str = "latin-1") -> str:
    if len(raw) > _MAX_METADATA_VALUE_BYTES:
        raise ScanLimitExceededError(f"{context} exceeds {_MAX_METADATA_VALUE_BYTES} bytes")
    try:
        return raw.decode(codec).strip("\x00\ufeff \t\r\n")
    except UnicodeDecodeError as exc:
        raise CorruptArtifactError(f"Invalid {codec} in {context}: {exc}") from exc


def _fourcc(value: bytes) -> str:
    return value.decode("latin-1", errors="replace")


__all__ = ["MediaMetadataEntry", "parse_media_metadata"]
