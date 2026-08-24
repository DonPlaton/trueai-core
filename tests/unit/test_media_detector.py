"""Synthetic, redistribution-safe tests for bounded media metadata inspection."""

from __future__ import annotations

from pathlib import Path

import pytest

from trueai import ArtifactDiscovery, ArtifactType, FindingCategory, ScanOptions, TrueAIEngine
from trueai.core.models import IntegrityStatus, ProvenanceClass
from trueai.core.policy import PolicyStore
from trueai.core.remediation import RemediationPlanner, RemediationService


def _riff_chunk(identifier: bytes, payload: bytes) -> bytes:
    padding = b"\x00" if len(payload) & 1 else b""
    return identifier + len(payload).to_bytes(4, "little") + payload + padding


def _wave(*info_fields: tuple[bytes, str], audio_payload: bytes = b"") -> bytes:
    info = b"INFO" + b"".join(
        _riff_chunk(identifier, value.encode("latin-1") + b"\x00")
        for identifier, value in info_fields
    )
    payload = b"WAVE" + _riff_chunk(b"fmt ", b"\x01\x00\x01\x00" + b"\x00" * 12)
    payload += _riff_chunk(b"LIST", info)
    if audio_payload:
        payload += _riff_chunk(b"data", audio_payload)
    return b"RIFF" + len(payload).to_bytes(4, "little") + payload


def _synchsafe(value: int) -> bytes:
    return bytes((value >> shift) & 0x7F for shift in (21, 14, 7, 0))


def _id3_frame(identifier: bytes, value: str) -> bytes:
    if identifier == b"COMM":
        payload = b"\x03eng\x00" + value.encode("utf-8")
    else:
        payload = b"\x03" + value.encode("utf-8")
    return identifier + len(payload).to_bytes(4, "big") + b"\x00\x00" + payload


def _mp3(*frames: tuple[bytes, str], audio_frames: bytes = b"\xff\xfb\x90\x64") -> bytes:
    payload = b"".join(_id3_frame(identifier, value) for identifier, value in frames)
    return b"ID3\x03\x00\x00" + _synchsafe(len(payload)) + payload + audio_frames


def _flac(
    *comments: str,
    vendor: str = "reference encoder",
    audio_frames: bytes = b"",
) -> bytes:
    stream_info = b"\x00\x00\x00\x22" + b"\x00" * 34
    encoded_vendor = vendor.encode("utf-8")
    comment_payload = len(encoded_vendor).to_bytes(4, "little") + encoded_vendor
    comment_payload += len(comments).to_bytes(4, "little")
    for comment in comments:
        encoded = comment.encode("utf-8")
        comment_payload += len(encoded).to_bytes(4, "little") + encoded
    comment_header = bytes([0x80 | 4]) + len(comment_payload).to_bytes(3, "big")
    return b"fLaC" + stream_info + comment_header + comment_payload + audio_frames


def _clean(path: Path, policy_name: str = "client-delivery"):
    policy = PolicyStore.get(policy_name)
    report = TrueAIEngine.default(discover_plugins=False).scan(path, policy=policy)
    plan = RemediationPlanner().plan(report, policy)
    result = RemediationService().apply(path, report, plan)
    return report, plan, result


def _box(identifier: bytes, payload: bytes) -> bytes:
    return (len(payload) + 8).to_bytes(4, "big") + identifier + payload


def _mp4_metadata(field: str, value: str, *, brand: bytes = b"isom") -> bytes:
    keys = _box(b"keys", b"\x00" * 4 + (1).to_bytes(4, "big") + _box(b"mdta", field.encode()))
    data = _box(b"data", (1).to_bytes(4, "big") + b"\x00" * 4 + value.encode("utf-8"))
    item = _box((1).to_bytes(4, "big"), data)
    meta = _box(b"meta", b"\x00" * 4 + keys + _box(b"ilst", item))
    return _box(b"ftyp", brand + b"\x00\x00\x00\x00" + brand) + _box(b"moov", meta)


def _ebml_vint(value: int) -> bytes:
    if not 0 <= value < 0x7F:
        raise ValueError("fixture only supports one-byte EBML sizes")
    return bytes([0x80 | value])


def _ebml(identifier: bytes, payload: bytes) -> bytes:
    return identifier + _ebml_vint(len(payload)) + payload


def _webm() -> bytes:
    header = _ebml(b"\x1aE\xdf\xa3", _ebml(b"B\x82", b"webm"))
    info = _ebml(b"\x15I\xa9f", _ebml(b"WA", b"TrueAI muxer"))
    simple_tag = _ebml(
        b"g\xc8",
        _ebml(b"E\xa3", b"AUTHOR") + _ebml(b"D\x87", b"Platon"),
    )
    tags = _ebml(b"\x12T\xc3g", _ebml(b"ss", simple_tag))
    return header + _ebml(b"\x18S\x80g", info + tags)


@pytest.mark.parametrize(
    ("name", "content", "expected_type", "media_type"),
    [
        ("disguised.bin", _wave((b"ISFT", "Tool")), ArtifactType.AUDIO, "audio/wav"),
        ("disguised.bin", _mp3((b"TSSE", "Tool")), ArtifactType.AUDIO, "audio/mpeg"),
        ("disguised.bin", _flac("ENCODER=Tool"), ArtifactType.AUDIO, "audio/flac"),
        ("disguised.bin", _mp4_metadata("title", "Clip"), ArtifactType.VIDEO, "video/mp4"),
        (
            "audio.m4a",
            _mp4_metadata("title", "Clip", brand=b"M4A "),
            ArtifactType.AUDIO,
            "audio/mp4",
        ),
        ("disguised.bin", _webm(), ArtifactType.VIDEO, "video/webm"),
    ],
)
def test_media_types_are_sniffed_from_container_signatures(
    tmp_path: Path,
    name: str,
    content: bytes,
    expected_type: ArtifactType,
    media_type: str,
) -> None:
    path = tmp_path / name
    path.write_bytes(content)

    artifact = ArtifactDiscovery().identify(path)

    assert artifact.artifact_type == expected_type
    assert artifact.media_type == media_type


def test_wave_metadata_is_classified_without_decoding_audio(tmp_path: Path) -> None:
    path = tmp_path / "sample.wav"
    path.write_bytes(_wave((b"ISFT", "OpenAI Audio Tool"), (b"IART", "Platon")))

    report = TrueAIEngine.default(discover_plugins=False).scan(path)

    fields = {finding.evidence["field"]: finding for finding in report.findings}
    assert fields["software"].category == FindingCategory.GENERATOR_METADATA
    assert fields["artist"].category == FindingCategory.PERSONAL_METADATA
    assert all(finding.removable for finding in fields.values())
    assert {finding.remediation_id for finding in fields.values()} == {
        "media.remove-metadata-field"
    }
    assert report.diagnostics == ()


def test_id3_literal_provider_attribution_remains_distinct_from_metadata(tmp_path: Path) -> None:
    path = tmp_path / "sample.mp3"
    path.write_bytes(
        _mp3(
            (b"TSSE", "Reference Encoder"),
            (b"COMM", "Generated with ChatGPT"),
        )
    )

    report = TrueAIEngine.default(discover_plugins=False).scan(path)

    attribution = next(
        finding
        for finding in report.findings
        if finding.category == FindingCategory.EXPLICIT_AI_ATTRIBUTION
    )
    assert attribution.provider == "openai"
    assert attribution.provenance_class == ProvenanceClass.ATTRIBUTION
    assert attribution.evidence["field"] == "comment"
    assert attribution.removable
    assert attribution.remediation_id == "media.remove-metadata-field"


def test_compressed_or_encrypted_id3_frames_are_not_misdecoded(tmp_path: Path) -> None:
    value = b"\x03Generated with ChatGPT"
    flagged_frame = b"TSSE" + len(value).to_bytes(4, "big") + b"\x00\x80" + value
    path = tmp_path / "flagged-frame.mp3"
    path.write_bytes(
        b"ID3\x03\x00\x00" + _synchsafe(len(flagged_frame)) + flagged_frame + b"\xff\xfb\x90\x64"
    )

    report = TrueAIEngine.default(discover_plugins=False).scan(path)

    assert not report.findings
    assert not report.diagnostics


def test_flac_vorbis_comments_and_vendor_are_bounded_metadata(tmp_path: Path) -> None:
    path = tmp_path / "sample.flac"
    path.write_bytes(_flac("ARTIST=Platon", "ENCODER=Reference Encoder", vendor="libFLAC 1.5"))

    report = TrueAIEngine.default(discover_plugins=False).scan(path)

    categories = {finding.evidence["field"]: finding.category for finding in report.findings}
    assert categories["artist"] == FindingCategory.PERSONAL_METADATA
    assert categories["encoder"] == FindingCategory.GENERATOR_METADATA
    assert categories["vendor"] == FindingCategory.GENERATOR_METADATA


def test_iso_bmff_keyed_metadata_and_provenance_marker_are_reported(tmp_path: Path) -> None:
    path = tmp_path / "sample.mp4"
    path.write_bytes(_mp4_metadata("com.apple.quicktime.software", "Content Credentials producer"))

    report = TrueAIEngine.default(discover_plugins=False).scan(path)

    media = next(
        finding
        for finding in report.findings
        if finding.detector_id == "media.container-metadata.v1"
    )
    assert media.category == FindingCategory.GENERATOR_METADATA
    assert media.provenance_class == ProvenanceClass.PROVENANCE_METADATA
    assert not media.removable
    assert "preserve" in media.tags
    assert FindingCategory.C2PA_PROVENANCE in {finding.category for finding in report.findings}


def test_webm_writing_application_and_author_tags_are_classified(tmp_path: Path) -> None:
    path = tmp_path / "sample.webm"
    path.write_bytes(_webm())

    report = TrueAIEngine.default(discover_plugins=False).scan(path)

    categories = {finding.evidence["field"]: finding.category for finding in report.findings}
    assert categories["writing_application"] == FindingCategory.GENERATOR_METADATA
    assert categories["author"] == FindingCategory.PERSONAL_METADATA
    assert categories["document_type"] == FindingCategory.MEDIA_METADATA


@pytest.mark.parametrize(
    "content",
    [
        b"RIFF\xff\xff\xff\xffWAVE",
        b"ID3\x03\x00\x00\x00\x00\x01\x00",
        b"fLaC\x80\x00\x00\x22" + b"\x00" * 3,
        (16).to_bytes(4, "big")
        + b"ftyp"
        + b"isom"
        + b"\x00" * 4
        + (4).to_bytes(4, "big")
        + b"free",
        b"\x1aE\xdf\xa3\x00",
    ],
)
def test_malformed_media_fails_closed(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "hostile.bin"
    path.write_bytes(content)

    report = TrueAIEngine.default(discover_plugins=False).scan(path)

    assert not report.findings
    assert {diagnostic.code for diagnostic in report.diagnostics} & {
        "corrupt_artifact",
        "unsupported_artifact",
    }


def test_media_parser_event_budget_marks_report_incomplete(tmp_path: Path) -> None:
    path = tmp_path / "many.wav"
    path.write_bytes(
        _wave(
            (b"INAM", "one"),
            (b"ICMT", "two"),
            (b"ISFT", "three"),
        )
    )

    report = TrueAIEngine.default(discover_plugins=False).scan(
        path, options=ScanOptions(max_parser_events=2)
    )

    assert not report.findings
    assert [diagnostic.code for diagnostic in report.diagnostics] == ["scan_limit_exceeded"]


def test_ebml_without_document_type_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "missing-doctype.webm"
    path.write_bytes(_ebml(b"\x1aE\xdf\xa3", b"") + _ebml(b"\x18S\x80g", b""))

    report = TrueAIEngine.default(discover_plugins=False).scan(path)

    assert [diagnostic.code for diagnostic in report.diagnostics] == ["corrupt_artifact"]


def test_wave_cleanup_preserves_data_chunk_and_unselected_title(tmp_path: Path) -> None:
    audio = b"\x01\x02\x03\x04\x05\x06"
    original = _wave(
        (b"ISFT", "Reference Generator"),
        (b"IART", "Platon"),
        (b"INAM", "Keep title"),
        audio_payload=audio,
    )
    path = tmp_path / "clean.wav"
    path.write_bytes(original)

    _, plan, result = _clean(path)

    assert plan.remediations
    assert result.integrity.status == IntegrityStatus.PASS
    assert result.integrity.logical_before_sha256 == result.integrity.logical_after_sha256
    assert path.read_bytes() == original
    assert result.output_path is not None
    cleaned = Path(result.output_path).read_bytes()
    assert _riff_chunk(b"data", audio) in cleaned
    cleaned_report = TrueAIEngine.default(discover_plugins=False).scan(result.output_path)
    fields = {finding.evidence.get("field") for finding in cleaned_report.findings}
    assert "title" in fields
    assert "software" not in fields
    assert "artist" not in fields


def test_mp3_cleanup_preserves_frames_and_unselected_title(tmp_path: Path) -> None:
    audio = b"\xff\xfb\x90\x64AUDIO-FRAME-BYTES"
    original = _mp3(
        (b"TSSE", "Reference Encoder"),
        (b"COMM", "Generated with ChatGPT"),
        (b"TIT2", "Keep title"),
        audio_frames=audio,
    )
    path = tmp_path / "clean.mp3"
    path.write_bytes(original)

    _, _, result = _clean(path)

    assert result.integrity.status == IntegrityStatus.PASS
    assert result.integrity.logical_before_sha256 == result.integrity.logical_after_sha256
    assert result.output_path is not None
    cleaned = Path(result.output_path).read_bytes()
    cleaned_tag_end = 10 + int.from_bytes(cleaned[6:10], "big")
    assert cleaned[cleaned_tag_end:] == audio
    cleaned_report = TrueAIEngine.default(discover_plugins=False).scan(result.output_path)
    fields = {finding.evidence.get("field") for finding in cleaned_report.findings}
    assert "title" in fields
    assert "encoder_software" not in fields
    assert "comment" not in fields


def test_flac_cleanup_preserves_audio_frames_and_unselected_title(tmp_path: Path) -> None:
    audio = b"\xff\xf8FLAC-FRAME-BYTES"
    original = _flac(
        "ENCODER=Reference Encoder",
        "ARTIST=Platon",
        "TITLE=Keep title",
        vendor="libFLAC reference encoder",
        audio_frames=audio,
    )
    path = tmp_path / "clean.flac"
    path.write_bytes(original)

    _, _, result = _clean(path)

    assert result.integrity.status == IntegrityStatus.PASS
    assert result.integrity.logical_before_sha256 == result.integrity.logical_after_sha256
    assert result.output_path is not None
    assert Path(result.output_path).read_bytes().endswith(audio)
    cleaned_report = TrueAIEngine.default(discover_plugins=False).scan(result.output_path)
    fields = {finding.evidence.get("field") for finding in cleaned_report.findings}
    assert "title" in fields
    assert "encoder" not in fields
    assert "artist" not in fields
    assert "vendor" not in fields


def test_media_cleanup_is_blocked_for_any_provenance_marker(tmp_path: Path) -> None:
    path = tmp_path / "protected.wav"
    path.write_bytes(
        _wave(
            (b"ISFT", "Reference Generator"),
            (b"ICMT", "C2PA manifest"),
            audio_payload=b"\x00\x01",
        )
    )

    report, plan, result = _clean(path)

    generator = next(
        finding
        for finding in report.findings
        if finding.category == FindingCategory.GENERATOR_METADATA
    )
    assert generator.id in plan.blocked_findings
    assert result.integrity.status == IntegrityStatus.NOT_MODIFIED
    assert result.output_path is None


def test_global_id3_unsynchronization_is_inspection_only(tmp_path: Path) -> None:
    frame = _id3_frame(b"TSSE", "Reference Encoder")
    path = tmp_path / "unsynchronized.mp3"
    path.write_bytes(b"ID3\x03\x00\x80" + _synchsafe(len(frame)) + frame + b"\xff\xfb\x90\x64")

    report = TrueAIEngine.default(discover_plugins=False).scan(path)

    finding = next(
        item for item in report.findings if item.evidence.get("field") == "encoder_software"
    )
    assert not finding.removable
    assert finding.remediation_id is None


def test_id3_footer_metadata_is_inspection_only_and_footer_is_validated(tmp_path: Path) -> None:
    frame = _id3_frame(b"TSSE", "Reference Encoder")
    header_tail = b"\x04\x00\x10" + _synchsafe(len(frame))
    path = tmp_path / "footer.mp3"
    path.write_bytes(b"ID3" + header_tail + frame + b"3DI" + header_tail + b"\xff\xfb\x90\x64")

    report = TrueAIEngine.default(discover_plugins=False).scan(path)

    finding = next(
        item for item in report.findings if item.evidence.get("field") == "encoder_software"
    )
    assert not finding.removable
    assert not report.diagnostics

    path.write_bytes(b"ID3" + header_tail + frame + b"BROKEN-FOOT" + b"\xff\xfb\x90\x64")
    malformed = TrueAIEngine.default(discover_plugins=False).scan(path)
    assert not malformed.findings
    assert [diagnostic.code for diagnostic in malformed.diagnostics] == ["corrupt_artifact"]


def test_id3v1_cleanup_zeros_only_selected_field_and_preserves_audio(tmp_path: Path) -> None:
    audio = b"\xff\xfb\x90\x64RAW-MPEG-AUDIO"
    tag = bytearray(b"TAG" + b"\x00" * 125)
    tag[3:13] = b"Keep title"
    tag[33:39] = b"Platon"
    path = tmp_path / "legacy.mp3"
    path.write_bytes(audio + bytes(tag))

    _, _, result = _clean(path)

    assert result.integrity.status == IntegrityStatus.PASS
    assert result.output_path is not None
    cleaned = Path(result.output_path).read_bytes()
    assert cleaned[:-128] == audio
    assert cleaned[-125:-115] == b"Keep title"
    assert cleaned[-95:-65] == b"\x00" * 30


def test_broadcast_wave_cleanup_zeros_only_selected_identity(tmp_path: Path) -> None:
    audio = b"\x10\x20\x30\x40"
    bext = bytearray(b"\x00" * 602)
    bext[:16] = b"Keep description"
    bext[256:262] = b"Platon"
    body = b"WAVE" + _riff_chunk(b"fmt ", b"\x01\x00\x01\x00" + b"\x00" * 12)
    body += _riff_chunk(b"bext", bytes(bext)) + _riff_chunk(b"data", audio)
    path = tmp_path / "broadcast.wav"
    path.write_bytes(b"RIFF" + len(body).to_bytes(4, "little") + body)

    _, _, result = _clean(path)

    assert result.integrity.status == IntegrityStatus.PASS
    assert result.output_path is not None
    cleaned = Path(result.output_path).read_bytes()
    assert b"Keep description" in cleaned
    assert b"Platon" not in cleaned
    assert _riff_chunk(b"data", audio) in cleaned


def test_wave_xml_attribution_cleanup_removes_only_xml_chunk(tmp_path: Path) -> None:
    audio = b"\x01\x03\x05\x07"
    body = b"WAVE" + _riff_chunk(b"fmt ", b"\x01\x00\x01\x00" + b"\x00" * 12)
    body += _riff_chunk(b"iXML", b"Generated with ChatGPT")
    body += _riff_chunk(b"data", audio)
    path = tmp_path / "xml.wav"
    path.write_bytes(b"RIFF" + len(body).to_bytes(4, "little") + body)

    _, _, result = _clean(path)

    assert result.integrity.status == IntegrityStatus.PASS
    assert result.output_path is not None
    cleaned = Path(result.output_path).read_bytes()
    assert b"iXML" not in cleaned
    assert _riff_chunk(b"data", audio) in cleaned


def test_nonzero_id3_padding_fails_closed_during_scan(tmp_path: Path) -> None:
    frame = _id3_frame(b"TSSE", "Reference Encoder")
    payload = frame + b"\x00\x00\x00\x00BAD"
    path = tmp_path / "invalid-padding.mp3"
    path.write_bytes(b"ID3\x03\x00\x00" + _synchsafe(len(payload)) + payload + b"\xff\xfb\x90\x64")

    report = TrueAIEngine.default(discover_plugins=False).scan(path)

    assert not report.findings
    assert [diagnostic.code for diagnostic in report.diagnostics] == ["corrupt_artifact"]


def test_trailing_flac_comment_bytes_fail_closed(tmp_path: Path) -> None:
    content = bytearray(_flac("ARTIST=Platon"))
    comment_header = 4 + 4 + 34
    original_size = int.from_bytes(content[comment_header + 1 : comment_header + 4], "big")
    content[comment_header + 1 : comment_header + 4] = (original_size + 1).to_bytes(3, "big")
    content.append(0)
    path = tmp_path / "invalid-comment.flac"
    path.write_bytes(content)

    report = TrueAIEngine.default(discover_plugins=False).scan(path)

    assert not report.findings
    assert [diagnostic.code for diagnostic in report.diagnostics] == ["corrupt_artifact"]
