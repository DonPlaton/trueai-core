"""The ISO-BMFF invariants, and the edits they must catch.

The fixture builder here produces a real, self-consistent MP4: sample tables that
resolve to actual byte ranges inside `mdat`, chunk offsets that point where the
samples really are, and a `moov` that precedes the media. That matters, because
the failure this specification exists to catch is invisible to a byte-level
check: an edit that removes metadata before `mdat` without correcting `stco`
leaves a file that parses, reports the right duration, and plays garbage.

Every "must be caught" test is paired with the corrected version of the same
edit, so the invariants are shown to distinguish a broken edit from a correct
one rather than to refuse all edits.
"""

from __future__ import annotations

import pytest

from trueai.core.iso_bmff import (
    C2PA_UUID,
    MAX_BOX_DEPTH,
    Invariant,
    InvariantStatus,
    IsoBmffError,
    model_iso_bmff,
    read_boxes,
    verify_iso_bmff_invariants,
)

SAMPLE_SIZES = (11, 17, 23, 29)
MEDIA = b"".join(bytes([index + 1]) * size for index, size in enumerate(SAMPLE_SIZES))


def box(identifier: bytes, payload: bytes) -> bytes:
    return (len(payload) + 8).to_bytes(4, "big") + identifier + payload


def full_box(identifier: bytes, payload: bytes, version: int = 0) -> bytes:
    return box(identifier, bytes([version]) + b"\x00\x00\x00" + payload)


def table(identifier: bytes, entries: list[bytes]) -> bytes:
    return full_box(identifier, len(entries).to_bytes(4, "big") + b"".join(entries))


def build_mp4(
    *,
    media_offset_padding: int = 0,
    title: str | None = "Original title",
    with_c2pa: bool = False,
    with_edit_list: bool = True,
    with_encryption: bool = False,
    offset_drift: int = 0,
) -> bytes:
    """Build a self-consistent MP4 whose chunk offsets really point at the media.

    ``offset_drift`` reproduces the mistake the whole specification exists for:
    the layout shifted but `stco` was left describing the old one. A negative
    drift keeps every sample inside the file and is the dangerous case, because
    nothing about the result looks wrong until it is played.
    """

    ftyp = box(b"ftyp", b"isom" + (512).to_bytes(4, "big") + b"isomiso2mp41")
    padding = box(b"free", b"\x00" * media_offset_padding) if media_offset_padding else b""

    tkhd_tail = (
        (0).to_bytes(4, "big")  # layer + alternate group
        + (0x0100).to_bytes(2, "big")  # volume
        + (0).to_bytes(2, "big")
        + b"".join(
            value.to_bytes(4, "big")
            for value in (0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
        )
        + (640 << 16).to_bytes(4, "big")
        + (480 << 16).to_bytes(4, "big")
    )
    tkhd = full_box(
        b"tkhd",
        (0).to_bytes(4, "big")  # creation
        + (0).to_bytes(4, "big")  # modification
        + (1).to_bytes(4, "big")  # track id
        + (0).to_bytes(4, "big")
        + (1000).to_bytes(4, "big")  # duration
        + tkhd_tail,
    )
    mdhd = full_box(
        b"mdhd",
        (0).to_bytes(4, "big")
        + (0).to_bytes(4, "big")
        + (600).to_bytes(4, "big")  # timescale
        + (1000).to_bytes(4, "big")  # duration
        + (0x55C4).to_bytes(2, "big")
        + (0).to_bytes(2, "big"),
    )
    hdlr = full_box(b"hdlr", (0).to_bytes(4, "big") + b"vide" + b"\x00" * 12 + b"track\x00")

    sample_entry = box(b"avc1", b"\x00" * 78)
    stsd = full_box(b"stsd", (1).to_bytes(4, "big") + sample_entry)
    stts = table(b"stts", [(len(SAMPLE_SIZES)).to_bytes(4, "big") + (250).to_bytes(4, "big")])
    ctts = table(b"ctts", [(len(SAMPLE_SIZES)).to_bytes(4, "big") + (0).to_bytes(4, "big")])
    stss = table(b"stss", [(1).to_bytes(4, "big")])
    stsc = table(
        b"stsc",
        [(1).to_bytes(4, "big") + (len(SAMPLE_SIZES)).to_bytes(4, "big") + (1).to_bytes(4, "big")],
    )
    stsz = full_box(
        b"stsz",
        (0).to_bytes(4, "big")
        + len(SAMPLE_SIZES).to_bytes(4, "big")
        + b"".join(size.to_bytes(4, "big") for size in SAMPLE_SIZES),
    )
    elst = (
        box(
            b"edts",
            table(
                b"elst",
                [
                    (1000).to_bytes(4, "big")
                    + (0).to_bytes(4, "big")
                    + (0x00010000).to_bytes(4, "big")
                ],
            ),
        )
        if with_edit_list
        else b""
    )
    encryption = (
        box(b"sinf", full_box(b"schm", b"cenc" + (0x00010000).to_bytes(4, "big")))
        if with_encryption
        else b""
    )
    udta = box(b"udta", box(b"\xa9nam", title.encode("utf-8"))) if title else b""
    c2pa = box(b"uuid", C2PA_UUID + b"{}") if with_c2pa else b""

    def assemble(chunk_offset: int) -> bytes:
        stco = table(b"stco", [chunk_offset.to_bytes(4, "big")])
        stbl = box(b"stbl", stsd + stts + ctts + stss + stsc + stsz + stco)
        minf = box(b"minf", stbl)
        mdia = box(b"mdia", mdhd + hdlr + minf)
        trak = box(b"trak", tkhd + elst + mdia + encryption)
        mvhd = full_box(
            b"mvhd",
            (0).to_bytes(4, "big")
            + (0).to_bytes(4, "big")
            + (600).to_bytes(4, "big")
            + (1000).to_bytes(4, "big")
            + b"\x00" * 76,
        )
        moov = box(b"moov", mvhd + trak + udta + c2pa)
        return ftyp + padding + moov + box(b"mdat", MEDIA)

    # The chunk offset depends on how long the boxes before mdat are, and those
    # lengths do not depend on the offset, so one round of feedback converges.
    provisional = assemble(0)
    media_start = provisional.index(b"mdat", len(ftyp)) + 4
    return assemble(media_start + offset_drift)


@pytest.fixture
def original() -> bytes:
    return build_mp4()


# -- the model ------------------------------------------------------------------------


def test_the_model_resolves_samples_through_the_offsets(original: bytes) -> None:
    """The point of the model: byte ranges derived from the tables, not from mdat."""

    model = model_iso_bmff(original)

    assert model.modelled, model.unresolved
    assert len(model.tracks) == 1
    track = model.tracks[0]
    assert track.sample_sizes == SAMPLE_SIZES
    assert len(track.ranges) == len(SAMPLE_SIZES)
    resolved = b"".join(original[start:end] for start, end in track.ranges)
    assert resolved == MEDIA


def test_the_model_reads_the_movie_and_track_timelines(original: bytes) -> None:
    model = model_iso_bmff(original)

    assert (model.movie_timescale, model.movie_duration) == (600, 1000)
    assert (model.tracks[0].timescale, model.tracks[0].duration) == (600, 1000)


def test_a_provenance_box_is_recorded(original: bytes) -> None:
    with_c2pa = build_mp4(with_c2pa=True)

    assert model_iso_bmff(original).provenance_boxes == ()
    assert model_iso_bmff(with_c2pa).provenance_boxes


# -- the failure this specification exists for ---------------------------------------


def test_removing_bytes_without_correcting_the_offsets_is_caught(original: bytes) -> None:
    """The dangerous case: still in bounds, still parses, reads the wrong bytes.

    The drift is backwards, so every sample range stays inside the file. Nothing
    about the result looks wrong — the duration is right, the tables are
    consistent — and it plays garbage. Only following the offsets catches it.
    """

    broken = build_mp4(title=None, offset_drift=-8)

    report = verify_iso_bmff_invariants(original, broken)

    samples = report.result(Invariant.SAMPLES)
    assert samples is not None
    assert samples.status == InvariantStatus.VIOLATED
    assert "offsets" in samples.explanation
    assert not report.safe_to_apply()


def test_offsets_drifting_past_the_end_are_caught_too(original: bytes) -> None:
    """The obvious case, kept separate so the subtle one above cannot mask it."""

    broken = build_mp4(title=None, offset_drift=8)

    report = verify_iso_bmff_invariants(original, broken)

    samples = report.result(Invariant.SAMPLES)
    assert samples is not None
    assert samples.status == InvariantStatus.VIOLATED
    assert "outside the file" in samples.explanation


def test_the_same_removal_with_corrected_offsets_passes(original: bytes) -> None:
    """Paired with the test above: the invariants distinguish, they do not just refuse."""

    corrected = build_mp4(title=None)

    report = verify_iso_bmff_invariants(original, corrected)

    assert report.safe_to_apply(), report.explain()
    samples = report.result(Invariant.SAMPLES)
    assert samples is not None and samples.held


def test_a_byte_comparison_would_have_missed_it(original: bytes) -> None:
    """Why the structural check exists: mdat is byte-identical in both cases."""

    broken = build_mp4(title=None, offset_drift=-8)

    def mdat_payload(data: bytes) -> bytes:
        at = data.index(b"mdat") + 4
        return data[at : at + len(MEDIA)]

    assert mdat_payload(original) == mdat_payload(broken)
    assert not verify_iso_bmff_invariants(original, broken).safe_to_apply()


# -- one invariant at a time ----------------------------------------------------------


def test_dropping_the_edit_list_is_caught(original: bytes) -> None:
    """A trimmed clip would present the untrimmed take."""

    without = build_mp4(with_edit_list=False)

    report = verify_iso_bmff_invariants(original, without)

    result = report.result(Invariant.EDIT_LISTS)
    assert result is not None
    assert result.status == InvariantStatus.VIOLATED


def test_changing_the_display_matrix_is_caught(original: bytes) -> None:
    """The title in udta is metadata; the matrix beside it is not."""

    rotated = original.replace(
        (0x00010000).to_bytes(4, "big") + (0).to_bytes(4, "big") * 2,
        (0x00020000).to_bytes(4, "big") + (0).to_bytes(4, "big") * 2,
        1,
    )
    if rotated == original:
        pytest.skip("the fixture layout changed; the matrix bytes were not found")

    report = verify_iso_bmff_invariants(original, rotated)

    assert not report.safe_to_apply()


def test_changing_the_sample_description_is_caught(original: bytes) -> None:
    """Same bytes, different codec setup, different picture."""

    swapped = original.replace(b"avc1", b"hvc1", 1)

    report = verify_iso_bmff_invariants(original, swapped)

    result = report.result(Invariant.RENDERING)
    assert result is not None
    assert result.status == InvariantStatus.VIOLATED
    assert any("stsd" in detail for detail in result.details)


def test_dropping_encryption_state_is_caught() -> None:
    encrypted = build_mp4(with_encryption=True)
    stripped = build_mp4(with_encryption=False)

    report = verify_iso_bmff_invariants(encrypted, stripped)

    result = report.result(Invariant.ENCRYPTION)
    assert result is not None
    assert result.status == InvariantStatus.VIOLATED


def test_dropping_a_provenance_box_is_caught() -> None:
    """Removing provenance is the one thing this project will not do silently."""

    with_c2pa = build_mp4(with_c2pa=True)
    without = build_mp4(with_c2pa=False)

    report = verify_iso_bmff_invariants(with_c2pa, without)

    result = report.result(Invariant.PROVENANCE)
    assert result is not None
    assert result.status == InvariantStatus.VIOLATED


def test_a_file_with_no_provenance_box_still_reports_the_invariant(original: bytes) -> None:
    """Held-because-absent and held-because-preserved are both stated, not skipped."""

    report = verify_iso_bmff_invariants(original, build_mp4(title=None))

    result = report.result(Invariant.PROVENANCE)
    assert result is not None
    assert result.held
    assert "no provenance box" in result.explanation


def test_a_dropped_track_is_caught(original: bytes) -> None:
    single = build_mp4()
    trackless = single.replace(b"trak", b"trrk", 1)

    report = verify_iso_bmff_invariants(original, trackless)

    assert not report.safe_to_apply()


# -- indeterminate is not a pass ------------------------------------------------------


def test_an_unmodellable_result_is_indeterminate_not_safe(original: bytes) -> None:
    """A gate that cannot tell must not say yes."""

    report = verify_iso_bmff_invariants(original, b"not an mp4 at all")

    assert not report.safe_to_apply()
    assert len(report.indeterminate) == len(Invariant)


def test_an_unmodellable_original_is_indeterminate(original: bytes) -> None:
    report = verify_iso_bmff_invariants(b"\x00\x00\x00\x08junk", original)

    assert not report.safe_to_apply()
    assert report.indeterminate


def test_every_invariant_is_reported_even_when_one_fails(original: bytes) -> None:
    """A report that stopped at the first failure would hide the rest."""

    report = verify_iso_bmff_invariants(original, build_mp4(title=None, offset_drift=-8))

    assert {result.invariant for result in report.results} == set(Invariant)


def test_the_report_has_no_single_verdict_field(original: bytes) -> None:
    """ "The samples moved" and "provenance was dropped" need different remedies."""

    report = verify_iso_bmff_invariants(original, build_mp4(title=None))

    assert not hasattr(report, "valid")
    assert report.explain()


# -- hostile input --------------------------------------------------------------------


def test_a_box_claiming_more_than_the_file_is_refused() -> None:
    hostile = (0xFFFFFFF0).to_bytes(4, "big") + b"moov" + b"\x00" * 8

    with pytest.raises(IsoBmffError, match="past the end"):
        read_boxes(hostile)


def test_an_impossible_size_is_refused() -> None:
    hostile = (4).to_bytes(4, "big") + b"moov"

    with pytest.raises(IsoBmffError, match="impossible size"):
        read_boxes(hostile)


def test_a_truncated_large_size_header_is_refused() -> None:
    hostile = (1).to_bytes(4, "big") + b"moov" + b"\x00\x00"

    with pytest.raises(IsoBmffError, match="Truncated 64-bit"):
        read_boxes(hostile)


def test_a_truncated_uuid_box_is_refused() -> None:
    hostile = (12).to_bytes(4, "big") + b"uuid" + b"\x00" * 4

    with pytest.raises(IsoBmffError, match="Truncated uuid"):
        read_boxes(hostile)


def test_deep_nesting_is_refused_rather_than_recursed() -> None:
    payload = box(b"free", b"")
    for _ in range(MAX_BOX_DEPTH + 2):
        payload = box(b"moov", payload)

    with pytest.raises(IsoBmffError, match="nesting deeper"):
        read_boxes(payload)


def test_a_table_declaring_millions_of_entries_is_refused() -> None:
    """The count is checked before anything is allocated against it."""

    stsz = full_box(b"stsz", (0).to_bytes(4, "big") + (0xFFFFFFF0).to_bytes(4, "big"))
    stbl = box(b"stbl", stsz)
    trak = box(b"trak", box(b"mdia", box(b"minf", stbl)))
    data = box(b"ftyp", b"isom") + box(b"moov", trak)

    with pytest.raises(IsoBmffError, match="entries"):
        model_iso_bmff(data)


def test_an_empty_buffer_is_refused() -> None:
    with pytest.raises(IsoBmffError, match="No boxes"):
        model_iso_bmff(b"")


def test_a_file_with_neither_ftyp_nor_moov_is_refused() -> None:
    with pytest.raises(IsoBmffError, match="Neither ftyp nor moov"):
        model_iso_bmff(box(b"free", b"\x00" * 16))


def test_tables_that_disagree_leave_the_model_unresolved() -> None:
    """A partially resolved layout would hash itself and prove nothing."""

    stsz = full_box(
        b"stsz",
        (0).to_bytes(4, "big") + (2).to_bytes(4, "big") + (10).to_bytes(4, "big") * 2,
    )
    # One chunk claiming five samples, against a stsz that lists two.
    stsc = table(
        b"stsc", [(1).to_bytes(4, "big") + (5).to_bytes(4, "big") + (1).to_bytes(4, "big")]
    )
    stco = table(b"stco", [(0).to_bytes(4, "big")])
    stbl = box(b"stbl", stsz + stsc + stco)
    trak = box(b"trak", box(b"mdia", box(b"minf", stbl)))
    data = box(b"ftyp", b"isom") + box(b"moov", trak)

    model = model_iso_bmff(data)

    assert not model.modelled
    assert any("sample layout" in item for item in model.unresolved)


def test_offsets_pointing_outside_the_file_are_caught(original: bytes) -> None:
    """A hostile stco cannot make the verifier read past the buffer."""

    model = model_iso_bmff(original)
    track = model.tracks[0]
    beyond = type(track)(
        track_id=track.track_id,
        handler=track.handler,
        timescale=track.timescale,
        duration=track.duration,
        ranges=((len(original) - 4, len(original) + 4096),),
    )

    with pytest.raises(IsoBmffError, match="outside the file"):
        beyond.sample_digest(original)


def test_a_zero_sized_box_terminates_the_walk(original: bytes) -> None:
    """Size zero means "to the end of the container", and must not loop forever."""

    data = box(b"ftyp", b"isom") + (0).to_bytes(4, "big") + b"free" + b"\x00" * 32

    boxes = read_boxes(data)

    assert [item.identifier for item in boxes] == [b"ftyp", b"free"]
    assert boxes[-1].end == len(data)


def test_a_box_budget_that_runs_out_is_refused() -> None:
    data = box(b"free", b"") * 20

    with pytest.raises(IsoBmffError, match="refusing to continue"):
        read_boxes(data, budget=[3])


# -- the gate is specified, and not yet wired to a cleaner ---------------------------


def test_removable_iso_entries_carry_the_box_they_would_remove(tmp_path) -> None:
    """FMT-01 specified the gate; FMT-02 passes through it.

    This test was written under FMT-01 asserting the opposite, so the change
    would be a deliberate rewrite rather than a silent behaviour shift. What it
    now pins is that a removable entry names the *whole box*: removing only a
    value would leave a malformed item rather than an absent one.
    """

    from trueai.detectors.media.containers import parse_media_metadata

    artifact = tmp_path / "clip.mp4"
    artifact.write_bytes(build_mp4())

    entries = parse_media_metadata(artifact.read_bytes(), None, max_events=10_000)

    titles = [entry for entry in entries if "Original title" in entry.value]
    assert titles, "the fixture's udta title should be detected"
    for entry in titles:
        assert entry.remediation_safe
        assert entry.removable_range is not None
        start, end = entry.removable_range
        assert start < entry.byte_offset < end, "the range must enclose the value it describes"


def test_the_invariants_would_pass_a_correct_future_cleanup() -> None:
    """The specification has to be satisfiable, or it is a refusal dressed as a gate.

    This is the edit FMT-02 must produce: the title removed, `stco` corrected by
    exactly the number of bytes that disappeared before `mdat`.
    """

    before = build_mp4()
    after = build_mp4(title=None)

    assert len(after) < len(before)
    report = verify_iso_bmff_invariants(before, after)

    assert report.safe_to_apply(), report.explain()
    assert all(result.held for result in report.results)
