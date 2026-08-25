"""EBML/WebM invariants, and the cleanup that has to pass them.

The fixture builds a self-consistent WebM: a `SeekHead` whose positions really
point at `Info`, `Tracks`, and `Cues`, and a `Cues` index whose
`CueClusterPosition` really points at the start of a cluster. That matters for
the same reason the MP4 fixture had to resolve its chunk offsets — the failure
worth catching is one where the document still parses, the blocks are still
byte-identical, and only the stored positions are now wrong.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from trueai.cleaners.media import MediaMetadataCleaner
from trueai.core.artifact import Artifact
from trueai.core.ebml import (
    EbmlError,
    Invariant,
    InvariantStatus,
    model_ebml,
    read_elements,
    verify_ebml_invariants,
    void_element,
)
from trueai.core.errors import RemediationError
from trueai.core.models import (
    ArtifactType,
    Finding,
    IntegrityStatus,
    Remediation,
    RemediationSafety,
    ScanContext,
    ScanOptions,
)
from trueai.detectors.media.metadata import MediaMetadataDetector

BLOCKS = (b"\x81\x00\x00\x80" + b"\x11" * 20, b"\x81\x00\x20\x80" + b"\x22" * 30)


def vint(value: int, width: int = 1) -> bytes:
    """Encode an EBML size as a variable-length integer of a chosen width."""

    marker = 1 << (8 - width)
    raw = bytearray(value.to_bytes(width, "big"))
    raw[0] |= marker
    return bytes(raw)


def element(identifier: bytes, payload: bytes, *, size_width: int = 1) -> bytes:
    width = size_width
    while (1 << (7 * width)) - 2 < len(payload):
        width += 1
    return identifier + vint(len(payload), width) + payload


def uint(identifier: bytes, value: int, length: int = 1) -> bytes:
    return element(identifier, value.to_bytes(length, "big"))


def build_webm(
    *,
    title: str | None = "Original title",
    with_cues: bool = True,
    with_seek_head: bool = True,
    with_provenance: bool = False,
    cue_position_drift: int = 0,
) -> bytes:
    """Build a WebM whose SeekHead and Cues positions really resolve."""

    header = element(
        b"\x1a\x45\xdf\xa3",
        uint(b"\x42\x86", 1) + element(b"\x42\x82", b"webm") + uint(b"\x42\x87", 2),
    )

    info = element(
        b"\x15\x49\xa9\x66",
        element(b"\x2a\xd7\xb1", (1_000_000).to_bytes(4, "big"))
        + element(b"\x44\x89", (0x40F0000000000000).to_bytes(8, "big"))
        + element(b"\x4d\x80", b"trueai-test"),
    )
    tracks = element(
        b"\x16\x54\xae\x6b",
        element(
            b"\xae",
            uint(b"\xd7", 1)
            + element(b"\x73\xc5", (0x1234).to_bytes(2, "big"))
            + element(b"\x86", b"V_VP9")
            + element(b"\x63\xa2", b"codec-private-setup")
            + element(b"\xe0", uint(b"\xb0", 320, 2) + uint(b"\xba", 240, 2)),
        ),
    )
    tags = (
        element(
            b"\x12\x54\xc3\x67",
            element(
                b"\x73\x73",
                element(b"\x63\xc0", uint(b"\x68\xca", 50))
                + element(
                    b"\x67\xc8",
                    element(b"\x45\xa3", b"TITLE") + element(b"\x44\x87", title.encode("utf-8")),
                ),
            ),
        )
        if title
        else b""
    )
    attachments = (
        element(
            b"\x19\x41\xa4\x69",
            element(
                b"\x61\xa7",
                element(b"\x46\x6e", b"c2pa.jumbf") + element(b"\x46\x5c", b"jumbf-manifest-bytes"),
            ),
        )
        if with_provenance
        else b""
    )

    clusters = b"".join(
        element(b"\x1f\x43\xb6\x75", uint(b"\xe7", index * 20, 2) + element(b"\xa3", block))
        for index, block in enumerate(BLOCKS)
    )

    def assemble(seek_positions: tuple[int, ...], cue_positions: tuple[int, ...]) -> bytes:
        seek_head = (
            element(
                b"\x11\x4d\x9b\x74",
                b"".join(
                    element(
                        b"\x4d\xbb",
                        element(b"\x53\xab", identifier) + uint(b"\x53\xac", position, 4),
                    )
                    for identifier, position in zip(
                        (b"\x15\x49\xa9\x66", b"\x16\x54\xae\x6b"), seek_positions, strict=False
                    )
                ),
            )
            if with_seek_head
            else b""
        )
        cues = (
            element(
                b"\x1c\x53\xbb\x6b",
                b"".join(
                    element(
                        b"\xbb",
                        uint(b"\xb3", index * 20, 2)
                        + element(
                            b"\xb7",
                            uint(b"\xf7", 1) + uint(b"\xf1", position, 4),
                        ),
                    )
                    for index, position in enumerate(cue_positions)
                ),
            )
            if with_cues
            else b""
        )
        body = seek_head + info + tracks + tags + attachments + cues + clusters
        return header + element(b"\x18\x53\x80\x67", body)

    # Two rounds: the positions are fixed-width, so the layout does not change
    # when they are filled in.
    provisional = assemble((0, 0), (0, 0) if with_cues else ())
    model = model_ebml(provisional)
    base = model.segment_data_start
    info_at = next(item.start - base for item in model.elements if item.identifier == 0x1549A966)
    tracks_at = next(item.start - base for item in model.elements if item.identifier == 0x1654AE6B)
    cluster_positions = tuple(
        item.relative_position + cue_position_drift for item in model.clusters
    )
    return assemble((info_at, tracks_at), cluster_positions if with_cues else ())


@pytest.fixture
def original() -> bytes:
    return build_webm()


# -- the model ------------------------------------------------------------------------


def test_the_model_resolves_tracks_clusters_cues_and_seek(original: bytes) -> None:
    model = model_ebml(original)

    assert model.modelled, model.unresolved
    assert [track.codec_id for track in model.tracks] == ["V_VP9"]
    assert model.tracks[0].codec_private == b"codec-private-setup"
    assert len(model.clusters) == len(BLOCKS)
    assert len(model.cues) == len(BLOCKS)
    assert len(model.seek_entries) == 2


def test_the_fixture_positions_really_resolve(original: bytes) -> None:
    """If they did not, every invariant below would be checking a fiction."""

    report = verify_ebml_invariants(original, original)

    assert report.safe_to_apply(), report.explain()


def test_a_provenance_attachment_is_recorded() -> None:
    assert model_ebml(build_webm()).provenance == ()
    assert model_ebml(build_webm(with_provenance=True)).provenance


# -- the failure this specification exists for ---------------------------------------


def test_a_stale_cue_position_is_caught(original: bytes) -> None:
    """The blocks are byte-identical; only the stored position is now wrong."""

    drifted = build_webm(cue_position_drift=3)

    report = verify_ebml_invariants(original, drifted)

    cues = report.result(Invariant.CUES)
    assert cues is not None
    assert cues.status == InvariantStatus.VIOLATED
    assert not report.safe_to_apply()


def test_the_blocks_were_identical_in_that_case(original: bytes) -> None:
    """Why a payload comparison would have missed it."""

    drifted = build_webm(cue_position_drift=3)

    before = model_ebml(original)
    after = model_ebml(drifted)
    assert [item.block_digest for item in before.clusters] == [
        item.block_digest for item in after.clusters
    ]


def test_a_seek_entry_pointing_at_nothing_is_caught(original: bytes) -> None:
    model = model_ebml(original)
    position = model.seek_entries[0][1]
    # Move the recorded position by one byte, so it lands mid-element.
    broken = original.replace(position.to_bytes(4, "big"), (position + 1).to_bytes(4, "big"), 1)
    if broken == original:
        pytest.skip("the fixture layout changed; the seek position was not found")

    report = verify_ebml_invariants(original, broken)

    seek = report.result(Invariant.SEEK_POSITIONS)
    assert seek is not None
    assert seek.status == InvariantStatus.VIOLATED


# -- one invariant at a time ----------------------------------------------------------


def test_losing_codec_private_is_caught_and_named(original: bytes) -> None:
    """A track without its initialisation data is a track nothing can decode."""

    stripped = original.replace(b"codec-private-setup", b"codec-private-XXXXX", 1)

    report = verify_ebml_invariants(original, stripped)

    tracks = report.result(Invariant.TRACKS)
    assert tracks is not None
    assert tracks.status == InvariantStatus.VIOLATED
    assert any("CodecPrivate" in detail for detail in tracks.details)


def test_changing_a_block_is_caught(original: bytes) -> None:
    tampered = original.replace(b"\x11" * 20, b"\x33" * 20, 1)

    report = verify_ebml_invariants(original, tampered)

    clusters = report.result(Invariant.CLUSTERS)
    assert clusters is not None
    assert clusters.status == InvariantStatus.VIOLATED


def test_changing_the_timestamp_scale_is_caught(original: bytes) -> None:
    retimed = original.replace((1_000_000).to_bytes(4, "big"), (2_000_000).to_bytes(4, "big"), 1)

    report = verify_ebml_invariants(original, retimed)

    timing = report.result(Invariant.TIMING)
    assert timing is not None
    assert timing.status == InvariantStatus.VIOLATED


def test_dropping_a_provenance_attachment_is_caught() -> None:
    with_provenance = build_webm(with_provenance=True)
    without = build_webm(with_provenance=False)

    report = verify_ebml_invariants(with_provenance, without)

    provenance = report.result(Invariant.PROVENANCE)
    assert provenance is not None
    assert provenance.status == InvariantStatus.VIOLATED


def test_a_document_without_cues_still_reports_the_invariant() -> None:
    """Held-because-absent is stated, not skipped."""

    document = build_webm(with_cues=False)

    report = verify_ebml_invariants(document, document)

    cues = report.result(Invariant.CUES)
    assert cues is not None
    assert cues.held
    assert "no cue index" in cues.explanation


def test_every_invariant_is_reported_even_when_one_fails(original: bytes) -> None:
    report = verify_ebml_invariants(original, build_webm(cue_position_drift=3))

    assert {result.invariant for result in report.results} == set(Invariant)


def test_an_unmodellable_result_is_indeterminate_not_safe(original: bytes) -> None:
    report = verify_ebml_invariants(original, b"not an ebml document")

    assert not report.safe_to_apply()
    assert len(report.indeterminate) == len(Invariant)


# -- Void encoding --------------------------------------------------------------------


@pytest.mark.parametrize("length", [2, 3, 8, 129, 1000, 20000, 5_000_000])
def test_a_void_element_is_exactly_the_length_asked_for(length: int) -> None:
    """The whole substitution depends on this being exact."""

    padding = void_element(length)

    assert len(padding) == length
    parsed = read_elements(padding)
    assert len(parsed) == 1
    assert parsed[0].identifier == 0xEC
    assert parsed[0].end == length


def test_a_void_element_shorter_than_two_bytes_is_refused() -> None:
    for length in (0, 1):
        with pytest.raises(EbmlError, match="at least two bytes"):
            void_element(length)


# -- hostile input --------------------------------------------------------------------


def test_an_element_claiming_more_than_its_parent_is_refused() -> None:
    # A size of 100 with four bytes present. 0x7F would have meant "unknown
    # size", which is legal, so the claim has to be a real one.
    hostile = b"\x1a\x45\xdf\xa3" + vint(100, 1) + b"\x11" * 4

    with pytest.raises(EbmlError, match="past its parent"):
        read_elements(hostile)


def test_a_zero_prefixed_vint_is_refused() -> None:
    with pytest.raises(EbmlError, match="zero byte"):
        read_elements(b"\x00\x81\x00")


def test_deep_nesting_is_refused_rather_than_recursed() -> None:
    payload = element(b"\xec", b"")
    for _ in range(20):
        payload = element(b"\xae", payload)

    with pytest.raises(EbmlError, match="nesting deeper"):
        read_elements(payload)


def test_an_element_budget_that_runs_out_is_refused() -> None:
    data = element(b"\xec", b"") * 20

    with pytest.raises(EbmlError, match="refusing to continue"):
        read_elements(data, budget=[3])


def test_a_document_without_an_ebml_header_is_refused() -> None:
    with pytest.raises(EbmlError, match="EBML header"):
        model_ebml(element(b"\x18\x53\x80\x67", b""))


def test_a_document_without_a_segment_is_refused() -> None:
    with pytest.raises(EbmlError, match="No Segment"):
        model_ebml(element(b"\x1a\x45\xdf\xa3", element(b"\x42\x82", b"webm")))


# -- cleanup --------------------------------------------------------------------------


def findings_for(source: Path) -> list[Finding]:
    artifact = Artifact(artifact_type=ArtifactType.VIDEO, path=source, logical_path=source.name)
    return list(MediaMetadataDetector().scan(artifact, ScanContext(options=ScanOptions())))


def remediation_for(findings: list[Finding]) -> Remediation:
    return Remediation(
        id=f"rem_{findings[0].id}",
        remediation_id="media.remove-metadata-field",
        artifact_path=findings[0].artifact_path,
        finding_ids=tuple(item.id for item in findings),
        description=f"Remove {len(findings)} field(s)",
        safety=RemediationSafety.SAFE_METADATA,
        payload={
            "findings": [item.model_dump(mode="json", exclude_none=True) for item in findings]
        },
    )


def prepare(document: bytes, tmp_path: Path, field: str = "title"):
    source = tmp_path / "clip.webm"
    source.write_bytes(document)
    chosen = [
        finding
        for finding in findings_for(source)
        if finding.evidence.get("field") == field and finding.remediation_id
    ]
    assert chosen, f"no removable finding matched {field!r}"
    return source, remediation_for(chosen)


def test_the_tag_is_gone_and_every_invariant_held(tmp_path: Path) -> None:
    original = build_webm()
    source, remediation = prepare(original, tmp_path)
    destination = tmp_path / "clean.webm"

    outcome = MediaMetadataCleaner().apply(source, destination, (remediation,), ScanOptions())
    cleaned = destination.read_bytes()

    assert b"Original title" in original
    assert b"Original title" not in cleaned
    assert outcome.integrity.status == IntegrityStatus.PASS
    assert verify_ebml_invariants(original, cleaned).safe_to_apply()


def test_nothing_moved_so_the_positions_stayed_correct(tmp_path: Path) -> None:
    original = build_webm()
    source, remediation = prepare(original, tmp_path)
    destination = tmp_path / "clean.webm"

    MediaMetadataCleaner().apply(source, destination, (remediation,), ScanOptions())
    cleaned = destination.read_bytes()

    assert len(cleaned) == len(original)
    before, after = model_ebml(original), model_ebml(cleaned)
    assert before.seek_entries == after.seek_entries
    assert [item.relative_position for item in before.clusters] == [
        item.relative_position for item in after.clusters
    ]


def test_the_replaced_element_became_void_padding(tmp_path: Path) -> None:
    original = build_webm()
    source, remediation = prepare(original, tmp_path)
    destination = tmp_path / "clean.webm"

    MediaMetadataCleaner().apply(source, destination, (remediation,), ScanOptions())
    cleaned = destination.read_bytes()

    voids = [item for item in read_elements(cleaned) if item.identifier == 0xEC]
    assert voids, "the removed tag should have become a Void element"


def test_a_document_carrying_provenance_is_refused(tmp_path: Path) -> None:
    source, remediation = prepare(build_webm(with_provenance=True), tmp_path)

    with pytest.raises(RemediationError, match="provenance"):
        MediaMetadataCleaner().apply(source, tmp_path / "out.webm", (remediation,), ScanOptions())
    assert not (tmp_path / "out.webm").exists()


def test_an_edit_the_invariants_refuse_is_not_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import trueai.cleaners.media as media_module
    from trueai.core.ebml import InvariantReport, InvariantResult

    refused = InvariantReport(
        results=(InvariantResult(Invariant.CUES, InvariantStatus.VIOLATED, "the cues went stale"),)
    )
    monkeypatch.setattr(media_module, "verify_ebml_invariants", lambda before, after: refused)
    source, remediation = prepare(build_webm(), tmp_path)

    with pytest.raises(RemediationError, match="the cues went stale"):
        MediaMetadataCleaner().apply(source, tmp_path / "out.webm", (remediation,), ScanOptions())
    assert not (tmp_path / "out.webm").exists()


def test_the_logical_digest_is_the_blocks(tmp_path: Path) -> None:
    source, remediation = prepare(build_webm(), tmp_path)
    destination = tmp_path / "clean.webm"

    outcome = MediaMetadataCleaner().apply(source, destination, (remediation,), ScanOptions())

    assert outcome.integrity.logical_before_sha256 == outcome.integrity.logical_after_sha256
    assert outcome.integrity.before_sha256 != outcome.integrity.after_sha256
