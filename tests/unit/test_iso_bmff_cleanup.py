"""Surgical ISO-BMFF metadata cleanup, and everything it must refuse.

The five kinds of test `FMT-02` asks for, kept apart because they fail for
different reasons: positive, refusal, malformed, signed-provenance, and large
container.

The design under test is deliberately narrow. Instead of removing bytes and
rewriting every `stco` entry — where the interesting bugs live — the selected box
is overwritten in place with a same-length zero-filled `free` box. Nothing moves,
so no offset needs correcting, and the invariants from `FMT-01` verify that
claim rather than assuming it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.unit.test_iso_bmff_invariants import MEDIA, box, build_mp4
from trueai.cleaners.media import MediaMetadataCleaner
from trueai.core.artifact import Artifact
from trueai.core.errors import RemediationError
from trueai.core.iso_bmff import C2PA_UUID, model_iso_bmff, verify_iso_bmff_invariants
from trueai.core.models import (
    ArtifactType,
    Finding,
    IntegrityStatus,
    Remediation,
    RemediationSafety,
    ScanContext,
    ScanOptions,
)
from trueai.detectors.media.containers import parse_media_metadata
from trueai.detectors.media.metadata import MediaMetadataDetector


def entries_for(data: bytes):
    return parse_media_metadata(data, None, max_events=100_000)


def findings_for(source: Path) -> list[Finding]:
    """Run the real detector, so the remediation payload is the shape it ships in.

    Hand-building a Finding would mean testing a cleaner nobody runs: the cleaner
    checks the detector id, the evidence keys, and the byte offset, and a
    convenient fixture would satisfy checks the real pipeline does not.
    """

    artifact = Artifact(
        artifact_type=ArtifactType.VIDEO,
        path=source,
        logical_path=source.name,
    )
    return list(MediaMetadataDetector().scan(artifact, ScanContext(options=ScanOptions())))


def remediation_for(
    findings: list[Finding], remediation_id: str = "media.remove-metadata-field"
) -> Remediation:
    """Wrap findings the way the planner wraps them."""

    return Remediation(
        id=f"rem_{findings[0].id}",
        remediation_id=remediation_id,
        artifact_path=findings[0].artifact_path,
        finding_ids=tuple(item.id for item in findings),
        description=f"Remove {len(findings)} media metadata field(s)",
        safety=RemediationSafety.SAFE_METADATA,
        payload={
            "findings": [item.model_dump(mode="json", exclude_none=True) for item in findings]
        },
    )


def selected_findings(source: Path, fields: tuple[str, ...]) -> list[Finding]:
    chosen = [
        finding
        for finding in findings_for(source)
        if finding.evidence.get("field") in fields and finding.remediation_id
    ]
    assert chosen, f"no removable finding matched {fields}"
    return chosen


def clean_with(
    source_bytes: bytes,
    tmp_path: Path,
    remediation_id: str = "media.remove-metadata-field",
    fields: tuple[str, ...] = ("title",),
):
    """Run the cleaner over one artifact for the named fields."""

    source = tmp_path / "clip.mp4"
    destination = tmp_path / "clip.cleaned.mp4"
    source.write_bytes(source_bytes)
    remediation = remediation_for(selected_findings(source, fields), remediation_id)
    outcome = MediaMetadataCleaner().apply(source, destination, (remediation,), ScanOptions())
    return outcome, destination.read_bytes()


def refuse(source_bytes: bytes, tmp_path: Path, fields: tuple[str, ...] = ("title",)):
    """Prepare a source and its remediation without applying it."""

    source = tmp_path / "clip.mp4"
    source.write_bytes(source_bytes)
    return source, remediation_for(selected_findings(source, fields))


@pytest.fixture
def supported_id() -> str:
    identifiers = sorted(MediaMetadataCleaner().supported_remediation_ids)
    assert identifiers, "the media cleaner declares no remediation ids"
    return identifiers[0]


# -- positive -------------------------------------------------------------------------


def test_the_title_is_gone_and_every_invariant_held(tmp_path: Path, supported_id: str) -> None:
    original = build_mp4()

    outcome, cleaned = clean_with(original, tmp_path, supported_id, ("title",))

    assert b"Original title" in original
    assert b"Original title" not in cleaned
    assert outcome.integrity.status == IntegrityStatus.PASS
    assert verify_iso_bmff_invariants(original, cleaned).safe_to_apply()


def test_the_samples_still_resolve_to_the_same_bytes(tmp_path: Path, supported_id: str) -> None:
    """The point of the whole exercise, checked directly rather than through the gate."""

    original = build_mp4()

    _, cleaned = clean_with(original, tmp_path, supported_id, ("title",))

    track = model_iso_bmff(cleaned).tracks[0]
    assert b"".join(cleaned[start:end] for start, end in track.ranges) == MEDIA


def test_nothing_moved_so_no_offset_needed_correcting(tmp_path: Path, supported_id: str) -> None:
    """The file keeps its length, which is the property that makes this safe."""

    original = build_mp4()

    _, cleaned = clean_with(original, tmp_path, supported_id, ("title",))

    assert len(cleaned) == len(original)
    before = model_iso_bmff(original).tracks[0]
    after = model_iso_bmff(cleaned).tracks[0]
    assert before.ranges == after.ranges


def test_the_removed_box_became_zero_filled_padding(tmp_path: Path, supported_id: str) -> None:
    """Gone, not hidden: the payload is zeroed rather than merely relabelled."""

    original = build_mp4()

    _, cleaned = clean_with(original, tmp_path, supported_id, ("title",))

    differing = [
        index for index, (a, b) in enumerate(zip(original, cleaned, strict=True)) if a != b
    ]
    assert differing
    start = differing[0]
    # The first differing byte is inside the replaced box header; the payload
    # after it must be zeros.
    free_at = cleaned.rfind(b"free", 0, start + 8)
    assert free_at != -1
    size = int.from_bytes(cleaned[free_at - 4 : free_at], "big")
    assert set(cleaned[free_at + 4 : free_at - 4 + size]) <= {0}


def test_the_integrity_report_states_which_invariants_held(
    tmp_path: Path, supported_id: str
) -> None:
    outcome, _ = clean_with(build_mp4(), tmp_path, supported_id, ("title",))

    explanation = outcome.integrity.explanation
    assert "free padding" in explanation
    assert "samples" in explanation
    assert "provenance" in explanation
    assert outcome.integrity.intentionally_removed


def test_the_logical_digest_is_the_samples_not_the_mdat_box(
    tmp_path: Path, supported_id: str
) -> None:
    """Hashing mdat would answer a different and less useful question."""

    outcome, _ = clean_with(build_mp4(), tmp_path, supported_id, ("title",))

    assert outcome.integrity.logical_before_sha256 == outcome.integrity.logical_after_sha256
    assert outcome.integrity.before_sha256 != outcome.integrity.after_sha256


def test_an_encrypted_container_can_still_be_cleaned(tmp_path: Path, supported_id: str) -> None:
    """Nothing moves, so encryption state is untouched by construction."""

    original = build_mp4(with_encryption=True)

    outcome, cleaned = clean_with(original, tmp_path, supported_id, ("title",))

    assert outcome.integrity.status == IntegrityStatus.PASS
    assert verify_iso_bmff_invariants(original, cleaned).safe_to_apply()


def test_a_file_with_an_edit_list_keeps_it(tmp_path: Path, supported_id: str) -> None:
    original = build_mp4(with_edit_list=True)

    _, cleaned = clean_with(original, tmp_path, supported_id, ("title",))

    before = model_iso_bmff(original).tracks[0]
    after = model_iso_bmff(cleaned).tracks[0]
    assert before.edit_list == after.edit_list != b""


# -- refusal --------------------------------------------------------------------------


def test_a_container_with_a_provenance_marker_is_refused(tmp_path: Path, supported_id: str) -> None:
    """A C2PA box present anywhere stops the whole edit, before anything is written."""

    source, remediation = refuse(build_mp4(with_c2pa=True), tmp_path)

    with pytest.raises(RemediationError, match="provenance"):
        MediaMetadataCleaner().apply(source, tmp_path / "out.mp4", (remediation,), ScanOptions())

    assert not (tmp_path / "out.mp4").exists()


def test_metadata_whose_value_is_provenance_is_never_offered(tmp_path: Path) -> None:
    """The refusal happens at detection, one layer before the cleaner sees it.

    A field whose value names a provenance system is still reported — hiding it
    would be worse — but it carries no remediation id, so nothing downstream can
    select it for removal.
    """

    source = tmp_path / "clip.mp4"
    source.write_bytes(build_mp4(title="Produced with c2pa tooling"))

    titles = [
        finding for finding in findings_for(source) if finding.evidence.get("field") == "title"
    ]

    assert titles, "the field must still be reported"
    assert all(finding.remediation_id is None for finding in titles)


def test_an_unknown_brand_is_refused_rather_than_guessed(tmp_path: Path, supported_id: str) -> None:
    """An unrecognised brand may put something other than padding where free goes."""

    source, remediation = refuse(build_mp4(), tmp_path)
    source.write_bytes(source.read_bytes().replace(b"isom", b"zzzz", 1))

    with pytest.raises(RemediationError, match="supports WAV, MP3, FLAC"):
        MediaMetadataCleaner().apply(source, tmp_path / "out.mp4", (remediation,), ScanOptions())


def test_the_xmp_box_is_never_offered_for_removal() -> None:
    """Provenance-adjacent metadata is reported, never marked removable."""

    xmp = box(b"uuid", bytes.fromhex("be7acfcb97a942e89c71999491e3afac") + b"<x:xmpmeta/>")
    original = build_mp4()
    with_xmp = (
        original[: original.index(b"mdat") - 4] + xmp + original[original.index(b"mdat") - 4 :]
    )

    xmp_entries = [entry for entry in entries_for(with_xmp) if entry.container == "iso-bmff.xmp"]

    assert xmp_entries, "the XMP box should still be reported"
    assert not any(entry.remediation_safe for entry in xmp_entries)
    assert all(entry.removable_range is None for entry in xmp_entries)


def test_stale_selections_are_refused(tmp_path: Path, supported_id: str) -> None:
    """A selection made against a different file must not be applied to this one."""

    source, remediation = refuse(build_mp4(), tmp_path)
    source.write_bytes(build_mp4(title="A different title"))

    with pytest.raises(RemediationError, match="no longer matches"):
        MediaMetadataCleaner().apply(source, tmp_path / "out.mp4", (remediation,), ScanOptions())


# -- malformed ------------------------------------------------------------------------


def test_a_truncated_container_is_refused(tmp_path: Path, supported_id: str) -> None:
    """Truncation surfaces as CorruptArtifactError, the same as for every other format.

    Both it and RemediationError derive from TrueAIError, which is what a caller
    catches; the distinction is kept because "this file is broken" and "this edit
    is not allowed" are different things to tell an operator.
    """

    from trueai.core.errors import TrueAIError

    source, remediation = refuse(build_mp4(), tmp_path)
    source.write_bytes(source.read_bytes()[: len(source.read_bytes()) // 2])

    with pytest.raises(TrueAIError):
        MediaMetadataCleaner().apply(source, tmp_path / "out.mp4", (remediation,), ScanOptions())
    assert not (tmp_path / "out.mp4").exists()


def test_a_container_the_invariants_cannot_model_is_refused(
    tmp_path: Path, supported_id: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Indeterminate is not a pass, and the cleaner has to honour that."""

    import trueai.cleaners.media as media_module
    from trueai.core.iso_bmff import Invariant, InvariantReport, InvariantResult, InvariantStatus

    unknown = InvariantReport(
        results=tuple(
            InvariantResult(item, InvariantStatus.INDETERMINATE, "the model was incomplete")
            for item in Invariant
        )
    )
    monkeypatch.setattr(media_module, "verify_iso_bmff_invariants", lambda before, after: unknown)

    source, remediation = refuse(build_mp4(), tmp_path)

    with pytest.raises(RemediationError, match="invariants refused"):
        MediaMetadataCleaner().apply(source, tmp_path / "out.mp4", (remediation,), ScanOptions())
    assert not (tmp_path / "out.mp4").exists()


def test_an_edit_that_would_break_an_invariant_is_not_written(
    tmp_path: Path, supported_id: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The gate runs before the write, not after it."""

    import trueai.cleaners.media as media_module

    source, remediation = refuse(build_mp4(), tmp_path)

    from trueai.core.iso_bmff import Invariant, InvariantReport, InvariantResult, InvariantStatus

    violated = InvariantReport(
        results=(InvariantResult(Invariant.SAMPLES, InvariantStatus.VIOLATED, "the samples moved"),)
    )
    monkeypatch.setattr(media_module, "verify_iso_bmff_invariants", lambda before, after: violated)

    with pytest.raises(RemediationError, match="the samples moved"):
        MediaMetadataCleaner().apply(source, tmp_path / "out.mp4", (remediation,), ScanOptions())
    assert not (tmp_path / "out.mp4").exists()


# -- large container ------------------------------------------------------------------


def test_a_large_container_is_cleaned_without_reading_past_its_limit(
    tmp_path: Path, supported_id: str
) -> None:
    """Padding the media keeps the metadata boxes where they are, and the offsets right."""

    original = build_mp4(media_offset_padding=4 * 1024 * 1024)

    outcome, cleaned = clean_with(original, tmp_path, supported_id, ("title",))

    assert len(original) > 4 * 1024 * 1024
    assert outcome.integrity.status == IntegrityStatus.PASS
    assert len(cleaned) == len(original)
    assert verify_iso_bmff_invariants(original, cleaned).safe_to_apply()


def test_a_container_above_the_read_limit_is_refused(tmp_path: Path, supported_id: str) -> None:
    source, remediation = refuse(build_mp4(media_offset_padding=64 * 1024), tmp_path)

    with pytest.raises(RemediationError):
        MediaMetadataCleaner().apply(
            source, tmp_path / "out.mp4", (remediation,), ScanOptions(max_file_size=1024)
        )


def test_the_c2pa_uuid_constant_is_the_one_the_fixture_uses() -> None:
    """A mismatch here would make the provenance refusal test vacuous."""

    assert C2PA_UUID in build_mp4(with_c2pa=True)
