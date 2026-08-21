"""Security boundaries shared by OPC/ZIP document scanners and cleaners."""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path, PurePosixPath
from typing import cast
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

from defusedxml import ElementTree as DefusedElementTree
from defusedxml.ElementTree import DefusedXMLParser

from trueai.core.errors import CorruptArtifactError, ScanLimitExceededError, UnsafeArtifactError
from trueai.core.models import ScanOptions


def validate_opc_package(package: zipfile.ZipFile, options: ScanOptions) -> None:
    """Reject path traversal, encrypted entries, ZIP bombs, and excessive packages."""

    entries = package.infolist()
    if len(entries) > options.max_archive_entries:
        raise UnsafeArtifactError(
            f"Archive has {len(entries)} entries; limit is {options.max_archive_entries}"
        )
    total_uncompressed = 0
    seen_names: set[str] = set()
    for entry in entries:
        normalized = entry.filename.replace("\\", "/")
        pure_path = PurePosixPath(normalized)
        if (
            pure_path.is_absolute()
            or ".." in pure_path.parts
            or (pure_path.parts and ":" in pure_path.parts[0])
        ):
            raise UnsafeArtifactError(f"Unsafe archive path: {entry.filename}")
        if normalized in seen_names:
            raise UnsafeArtifactError(f"Duplicate archive entry: {entry.filename}")
        seen_names.add(normalized)
        if entry.flag_bits & 0x1:
            raise UnsafeArtifactError(f"Encrypted archive entry is not inspected: {entry.filename}")
        total_uncompressed += entry.file_size
        if total_uncompressed > options.max_archive_uncompressed_size:
            raise UnsafeArtifactError(
                f"Archive uncompressed size exceeds {options.max_archive_uncompressed_size} bytes"
            )
        compressed = max(entry.compress_size, 1)
        ratio = entry.file_size / compressed
        if entry.file_size > 1024 and ratio > options.max_compression_ratio:
            raise UnsafeArtifactError(
                f"Archive entry {entry.filename} has suspicious compression ratio {ratio:.1f}"
            )


def open_validated_opc(path: Path, options: ScanOptions) -> zipfile.ZipFile:
    """Open and validate an OPC package; caller owns the returned handle."""

    try:
        _preflight_zip_central_directory(path, options)
        package = zipfile.ZipFile(path)
        validate_opc_package(package, options)
        return package
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise CorruptArtifactError(f"Invalid OPC/ZIP package: {exc}") from exc


def _preflight_zip_central_directory(path: Path, options: ScanOptions) -> None:
    """Bound central-directory allocation before ``ZipFile`` materializes entry objects."""

    file_size = path.stat().st_size
    tail_size = min(file_size, 65_557)
    with path.open("rb") as handle:
        handle.seek(file_size - tail_size)
        tail = handle.read(tail_size)
    signature = b"PK\x05\x06"
    search_end = len(tail)
    eocd_index = -1
    while search_end >= 0:
        candidate = tail.rfind(signature, 0, search_end)
        if candidate < 0:
            break
        if candidate + 22 <= len(tail):
            comment_length = struct.unpack_from("<H", tail, candidate + 20)[0]
            if candidate + 22 + comment_length == len(tail):
                eocd_index = candidate
                break
        search_end = candidate
    if eocd_index < 0:
        raise CorruptArtifactError("ZIP end-of-central-directory record is missing")
    entry_count = struct.unpack_from("<H", tail, eocd_index + 10)[0]
    central_size = struct.unpack_from("<I", tail, eocd_index + 12)[0]
    central_offset = struct.unpack_from("<I", tail, eocd_index + 16)[0]
    if entry_count == 0xFFFF or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
        raise UnsafeArtifactError("ZIP64 OPC packages are unsupported by the v0.1 safety profile")
    if entry_count > options.max_archive_entries:
        raise UnsafeArtifactError(
            f"Archive declares {entry_count} entries; limit is {options.max_archive_entries}"
        )
    if central_size > options.max_archive_uncompressed_size:
        raise UnsafeArtifactError("ZIP central directory exceeds the configured size limit")
    if central_offset + central_size > file_size:
        raise CorruptArtifactError("ZIP central directory exceeds the file boundary")
    with path.open("rb") as handle:
        handle.seek(central_offset)
        central = handle.read(central_size)
    position = 0
    parsed_entries = 0
    while position < len(central):
        if position + 46 > len(central) or central[position : position + 4] != b"PK\x01\x02":
            raise CorruptArtifactError("Malformed ZIP central-directory entry")
        name_length, extra_length, comment_length = struct.unpack_from(
            "<HHH", central, position + 28
        )
        position += 46 + name_length + extra_length + comment_length
        if position > len(central):
            raise CorruptArtifactError("ZIP central-directory entry exceeds its boundary")
        parsed_entries += 1
        if parsed_entries > options.max_archive_entries:
            raise UnsafeArtifactError(
                f"Archive exceeds the {options.max_archive_entries} entry limit"
            )
    if position != len(central) or parsed_entries != entry_count:
        raise CorruptArtifactError("ZIP central-directory entry count is inconsistent")


def parse_xml(data: bytes, part_name: str) -> Element:
    """Parse XML with entity expansion and DTD protections enabled."""

    try:
        return cast(
            "Element[str]",
            DefusedElementTree.fromstring(
                data,
                forbid_dtd=True,
                forbid_entities=True,
                forbid_external=True,
            ),
        )
    except Exception as exc:
        raise CorruptArtifactError(f"Invalid or unsafe XML in {part_name}: {exc}") from exc


def read_opc_xml_part(
    package: zipfile.ZipFile,
    part_name: str,
    options: ScanOptions,
) -> bytes:
    """Read one XML part inside byte and parser-event budgets."""

    try:
        info = package.getinfo(part_name)
    except KeyError as exc:
        raise CorruptArtifactError(f"Missing OPC part: {part_name}") from exc
    if info.file_size > options.max_file_size:
        raise UnsafeArtifactError(
            f"OPC XML part {part_name} is {info.file_size} bytes; limit is {options.max_file_size}"
        )
    data = package.read(info)
    if data.count(b"<") > options.max_parser_events:
        raise ScanLimitExceededError(
            f"OPC XML part {part_name} exceeds the {options.max_parser_events} parser-event limit"
        )
    return data


def parse_xml_preserving_misc(data: bytes, part_name: str) -> Element:
    """Parse XML safely while retaining comments and processing instructions."""

    parser = DefusedXMLParser(
        target=ElementTree.TreeBuilder(insert_comments=True, insert_pis=True),
        forbid_dtd=True,
        forbid_entities=True,
        forbid_external=True,
    )
    try:
        return ElementTree.fromstring(data, parser=parser)
    except Exception as exc:
        raise CorruptArtifactError(f"Invalid or unsafe XML in {part_name}: {exc}") from exc


def local_name(tag: str) -> str:
    """Return the local component of an expanded XML name."""

    return tag.rsplit("}", 1)[-1]
