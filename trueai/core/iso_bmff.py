"""Executable invariants for ISO base media files: MP4, MOV, and M4A.

This module is a specification written as code. It does not remove anything. It
answers one question — *would this edit still play the same file?* — so that the
cleanup in `FMT-02` can be gated on the answer instead of on hope.

MP4 deserves that gate more than the formats already supported, for a reason
specific to its design. In WAV or FLAC, metadata lives in a chunk and the audio
lives in another, and removing the first leaves the second where it was. In
ISO-BMFF the sample tables store **absolute file offsets** (`stco`, `co64`).
Deleting a single byte anywhere before `mdat` moves every sample, and the file
still parses, still reports the right duration, and plays silence or garbage. A
byte-level "did anything outside the metadata change?" check passes happily,
because the change is that the offsets did *not* change when they should have.

So the invariants are structural, not lexical. Seven of them:

* **Samples** — the bytes each sample table points at must hash the same before
  and after. Not "the mdat box is unchanged": a correct edit is allowed to move
  `mdat`, and an incorrect one is caught by following the offsets.
* **Timing** — timescales, durations, and the `stts`/`ctts` tables that map
  samples to time.
* **Edit lists** — `elst` decides what is actually presented. Dropping it turns
  a trimmed clip back into the untrimmed take.
* **Indexes** — `stsc`, `stsz`, `stss`, and the fragment index `sidx` must stay
  internally consistent with the samples they describe.
* **Encryption state** — `sinf`, `senc`, `saiz`, `saio`, `pssh`. A cleaner that
  breaks these produces a file nothing can decrypt, and the failure surfaces at
  playback rather than at cleaning time.
* **Rendering-critical metadata** — `stsd` sample entries, and the parts of
  `tkhd`/`mvhd` that decide geometry: matrix, width, height, volume. The title
  in `udta` is metadata; the display matrix is not, even though both live in the
  header region.
* **Protected provenance** — a C2PA manifest box must survive, because removing
  provenance is the one thing this project will not do silently.

Everything here is parsed defensively: every offset is bounds-checked against the
buffer, recursion is depth-limited, and a box claiming a size larger than the
file is a parse refusal rather than a slice that silently returns short.
"""

from __future__ import annotations

import hashlib
from bisect import bisect_right
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

#: Deeper than any real file. `moov > trak > mdia > minf > stbl > stsd > entry`
#: is seven, and fragmented files add a couple more.
MAX_BOX_DEPTH: Final = 16

#: A file with more boxes than this is not a media file being cleaned; it is a
#: parser-exhaustion attempt.
MAX_BOXES: Final = 100_000

#: Sample tables larger than this are refused rather than expanded into memory.
MAX_SAMPLE_ENTRIES: Final = 4_000_000

_HEADER_BYTES: Final = 8
_LARGE_SIZE_BYTES: Final = 16

#: Boxes whose children are boxes. Anything else is treated as a leaf, so an
#: unknown box is never walked into on a guess about its layout.
CONTAINER_BOXES: Final = frozenset(
    {
        b"moov",
        b"trak",
        b"mdia",
        b"minf",
        b"stbl",
        b"edts",
        b"dinf",
        b"udta",
        b"moof",
        b"traf",
        b"mvex",
        b"schi",
        b"sinf",
        b"stsd",
    }
)

#: The C2PA manifest box, identified by its UUID. Recorded so an edit that drops
#: it fails the provenance invariant rather than passing quietly.
C2PA_UUID: Final = bytes.fromhex("d8fec3d61b0e483c9297589035ceb4ab")
#: Adobe's XMP box, which commonly carries provenance-adjacent claims.
XMP_UUID: Final = bytes.fromhex("be7acfcb97a942e89c71999491e3afac")


class InvariantStatus(StrEnum):
    """Whether one invariant held, failed, or could not be evaluated."""

    HELD = "held"
    VIOLATED = "violated"
    #: The file could not be modelled well enough to decide. Not a pass: an edit
    #: whose effect cannot be checked is an edit that must not be applied.
    INDETERMINATE = "indeterminate"


class Invariant(StrEnum):
    """What an ISO-BMFF edit must not change."""

    SAMPLES = "samples"
    TIMING = "timing"
    EDIT_LISTS = "edit_lists"
    INDEXES = "indexes"
    ENCRYPTION = "encryption"
    RENDERING = "rendering"
    PROVENANCE = "provenance"


class IsoBmffError(ValueError):
    """Raised when a buffer cannot be modelled as an ISO base media file."""


@dataclass(frozen=True, slots=True)
class Box:
    """One box, located precisely enough to re-read its payload."""

    identifier: bytes
    start: int
    payload_start: int
    end: int
    depth: int
    #: Present only for `uuid` boxes, where the extended type is the identity.
    extended_type: bytes | None = None

    @property
    def path_name(self) -> str:
        name = self.identifier.decode("latin-1")
        if self.extended_type is not None:
            return f"uuid:{self.extended_type.hex()}"
        return name


@dataclass(frozen=True, slots=True)
class SampleTable:
    """One track's sample layout, resolved to absolute byte ranges.

    ``ranges`` is what makes the samples invariant checkable: it is where the
    media actually lives, derived by following `stsc`, `stsz`, and the chunk
    offsets rather than by assuming `mdat` is the payload.
    """

    track_id: int
    handler: str
    timescale: int
    duration: int
    ranges: tuple[tuple[int, int], ...] = ()
    sample_sizes: tuple[int, ...] = ()
    time_to_sample: tuple[tuple[int, int], ...] = ()
    composition_offsets: tuple[tuple[int, int], ...] = ()
    sync_samples: tuple[int, ...] = ()
    #: Raw `stsd` payload. Sample descriptions decide how bytes are decoded, so a
    #: change here is a rendering change even when every sample byte is identical.
    sample_description: bytes = b""
    edit_list: bytes = b""
    #: Geometry from `tkhd`: matrix, width, height. Metadata lives next to it and
    #: is not the same thing.
    presentation: bytes = b""
    encryption: tuple[tuple[str, str], ...] = ()

    def sample_digest(self, data: bytes) -> str:
        """Hash the bytes this table points at, in sample order.

        Following the offsets is the whole point. Hashing `mdat` would call a
        correct edit that relocated the media a violation, and would call an
        incorrect edit that left the offsets stale a success.
        """

        digest = hashlib.sha256()
        digest.update(str(len(self.ranges)).encode("ascii"))
        for start, end in self.ranges:
            if start < 0 or end > len(data) or start > end:
                raise IsoBmffError(
                    f"Track {self.track_id} points at bytes {start}..{end}, outside the file"
                )
            digest.update(data[start:end])
        return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class IsoBmffModel:
    """Everything about a file that an edit must preserve."""

    boxes: tuple[Box, ...]
    tracks: tuple[SampleTable, ...]
    movie_timescale: int
    movie_duration: int
    #: Fragment index payloads, which carry their own offsets and durations.
    segment_indexes: tuple[bytes, ...] = ()
    #: Movie-level protection system headers.
    protection_headers: tuple[str, ...] = ()
    provenance_boxes: tuple[str, ...] = ()
    #: Anything the model could not resolve, so a caller can refuse rather than
    #: treat a partial model as a complete one.
    unresolved: tuple[str, ...] = ()

    @property
    def modelled(self) -> bool:
        """Whether the model is complete enough to decide invariants on."""

        return not self.unresolved and bool(self.tracks)


@dataclass(frozen=True, slots=True)
class InvariantResult:
    """The verdict on one invariant, with what decided it."""

    invariant: Invariant
    status: InvariantStatus
    explanation: str
    details: tuple[str, ...] = ()

    @property
    def held(self) -> bool:
        return self.status == InvariantStatus.HELD


@dataclass(frozen=True, slots=True)
class InvariantReport:
    """Every invariant, evaluated separately.

    There is no single boolean. "The samples moved" and "the provenance box was
    dropped" are different failures with different remedies, and a caller that
    wants one answer can ask :meth:`safe_to_apply`.
    """

    results: tuple[InvariantResult, ...] = ()

    def result(self, invariant: Invariant) -> InvariantResult | None:
        return next((item for item in self.results if item.invariant == invariant), None)

    @property
    def violations(self) -> tuple[InvariantResult, ...]:
        return tuple(item for item in self.results if item.status == InvariantStatus.VIOLATED)

    @property
    def indeterminate(self) -> tuple[InvariantResult, ...]:
        return tuple(item for item in self.results if item.status == InvariantStatus.INDETERMINATE)

    def safe_to_apply(self) -> bool:
        """Whether every invariant held.

        Indeterminate counts as unsafe. An edit whose effect cannot be checked is
        an edit that must not be applied, and treating "could not tell" as "fine"
        is how a gate becomes decoration.
        """

        return bool(self.results) and all(item.held for item in self.results)

    def explain(self) -> str:
        return "; ".join(f"{item.invariant.value}: {item.explanation}" for item in self.results)


# -- parsing -------------------------------------------------------------------------


def read_boxes(
    data: bytes,
    *,
    start: int = 0,
    end: int | None = None,
    depth: int = 0,
    budget: list[int] | None = None,
) -> list[Box]:
    """Walk the box tree, refusing anything that does not fit the buffer.

    A box header that claims more bytes than remain is a parse refusal rather
    than a short slice, because a truncated slice would model a file that does
    not exist and every invariant computed on it would be about that fiction.
    """

    limit = len(data) if end is None else min(end, len(data))
    remaining = budget if budget is not None else [MAX_BOXES]
    boxes: list[Box] = []
    offset = start
    while offset + _HEADER_BYTES <= limit:
        if remaining[0] <= 0:
            raise IsoBmffError(f"More than {MAX_BOXES} boxes; refusing to continue")
        remaining[0] -= 1
        size = int.from_bytes(data[offset : offset + 4], "big")
        identifier = data[offset + 4 : offset + 8]
        payload_start = offset + _HEADER_BYTES
        if size == 1:
            if payload_start + 8 > limit:
                raise IsoBmffError(f"Truncated 64-bit box header at {offset}")
            size = int.from_bytes(data[payload_start : payload_start + 8], "big")
            payload_start += 8
        elif size == 0:
            # A zero size means "to the end of the enclosing container", which is
            # legal and only valid for the last box.
            size = limit - offset
        if size < payload_start - offset:
            raise IsoBmffError(f"Box {identifier!r} at {offset} declares an impossible size")
        box_end = offset + size
        if box_end > limit:
            raise IsoBmffError(
                f"Box {identifier!r} at {offset} claims {size} bytes, past the end of the buffer"
            )

        extended: bytes | None = None
        if identifier == b"uuid":
            if payload_start + 16 > box_end:
                raise IsoBmffError(f"Truncated uuid box at {offset}")
            extended = data[payload_start : payload_start + 16]

        boxes.append(
            Box(
                identifier=identifier,
                start=offset,
                payload_start=payload_start,
                end=box_end,
                depth=depth,
                extended_type=extended,
            )
        )
        if identifier in CONTAINER_BOXES:
            if depth + 1 > MAX_BOX_DEPTH:
                raise IsoBmffError(f"Box nesting deeper than {MAX_BOX_DEPTH}")
            child_start = payload_start
            if identifier == b"stsd":
                # stsd carries a version/flags word and an entry count before its
                # children. Walking from payload_start would misread both.
                child_start = payload_start + 8
            boxes.extend(
                read_boxes(
                    data,
                    start=child_start,
                    end=box_end,
                    depth=depth + 1,
                    budget=remaining,
                )
            )
        offset = box_end
    return boxes


@dataclass
class _TrackDraft:
    track_id: int = 0
    handler: str = ""
    timescale: int = 0
    duration: int = 0
    chunk_offsets: list[int] = field(default_factory=list)
    sample_sizes: list[int] = field(default_factory=list)
    sample_to_chunk: list[tuple[int, int, int]] = field(default_factory=list)
    time_to_sample: list[tuple[int, int]] = field(default_factory=list)
    composition_offsets: list[tuple[int, int]] = field(default_factory=list)
    sync_samples: list[int] = field(default_factory=list)
    sample_description: bytes = b""
    edit_list: bytes = b""
    presentation: bytes = b""
    encryption: list[tuple[str, str]] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


def model_iso_bmff(data: bytes) -> IsoBmffModel:
    """Build the structural model an invariant check needs.

    Unresolvable pieces are recorded rather than guessed. A model that quietly
    filled in a missing sample table would make every later comparison agree
    with itself and prove nothing.
    """

    boxes = read_boxes(data)
    if not boxes:
        raise IsoBmffError("No boxes found; this is not an ISO base media file")
    if not any(box.identifier == b"ftyp" for box in boxes) and not any(
        box.identifier == b"moov" for box in boxes
    ):
        raise IsoBmffError("Neither ftyp nor moov is present")

    unresolved: list[str] = []
    movie_timescale = 0
    movie_duration = 0
    segment_indexes: list[bytes] = []
    protection_headers: list[str] = []
    provenance: list[str] = []

    for box in boxes:
        if box.identifier == b"mvhd":
            movie_timescale, movie_duration = _parse_mvhd(data, box, unresolved)
        elif box.identifier == b"sidx":
            segment_indexes.append(data[box.payload_start : box.end])
        elif box.identifier == b"pssh":
            protection_headers.append(hashlib.sha256(data[box.payload_start : box.end]).hexdigest())
        elif box.extended_type in (C2PA_UUID, XMP_UUID):
            provenance.append(
                f"{box.path_name}:{hashlib.sha256(data[box.payload_start : box.end]).hexdigest()}"
            )

    tracks: list[SampleTable] = []
    for track_box in (box for box in boxes if box.identifier == b"trak"):
        draft = _model_track(data, boxes, track_box)
        unresolved.extend(draft.problems)
        ranges = _resolve_sample_ranges(draft)
        if ranges is None:
            unresolved.append(f"track {draft.track_id}: sample layout could not be resolved")
            ranges = ()
        tracks.append(
            SampleTable(
                track_id=draft.track_id,
                handler=draft.handler,
                timescale=draft.timescale,
                duration=draft.duration,
                ranges=ranges,
                sample_sizes=tuple(draft.sample_sizes),
                time_to_sample=tuple(draft.time_to_sample),
                composition_offsets=tuple(draft.composition_offsets),
                sync_samples=tuple(draft.sync_samples),
                sample_description=draft.sample_description,
                edit_list=draft.edit_list,
                presentation=draft.presentation,
                encryption=tuple(draft.encryption),
            )
        )

    if not tracks:
        unresolved.append("no trak box was found")

    return IsoBmffModel(
        boxes=tuple(boxes),
        tracks=tuple(tracks),
        movie_timescale=movie_timescale,
        movie_duration=movie_duration,
        segment_indexes=tuple(segment_indexes),
        protection_headers=tuple(sorted(protection_headers)),
        provenance_boxes=tuple(sorted(provenance)),
        unresolved=tuple(unresolved),
    )


def _children(boxes: list[Box], parent: Box) -> list[Box]:
    """Return the boxes nested directly inside a parent."""

    return [box for box in _descendants(boxes, parent) if box.depth == parent.depth + 1]


def _descendants(boxes: list[Box], parent: Box) -> list[Box]:
    """Return every box nested inside ``parent``.

    ``boxes`` must be in document order, which is what :func:`read_boxes`
    produces. A parent's descendants are then the run that begins after it and
    ends at its boundary, so this bisects rather than filtering the whole list.

    Filtering was quadratic in the box count, and modelling calls this once per
    `trak`. An empty `trak` is eight bytes, so 100,000 of them fit in 800 KB and
    cost 10^10 list steps — the same defect as in the EBML model, in the other
    container format.
    """

    position = bisect_right(boxes, parent.start, key=lambda box: box.start)
    found: list[Box] = []
    while position < len(boxes) and boxes[position].start < parent.end:
        found.append(boxes[position])
        position += 1
    return found


def _parse_mvhd(data: bytes, box: Box, unresolved: list[str]) -> tuple[int, int]:
    payload = data[box.payload_start : box.end]
    if len(payload) < 4:
        unresolved.append("mvhd is truncated")
        return 0, 0
    version = payload[0]
    try:
        if version == 1:
            timescale = int.from_bytes(payload[20:24], "big")
            duration = int.from_bytes(payload[24:32], "big")
        else:
            timescale = int.from_bytes(payload[12:16], "big")
            duration = int.from_bytes(payload[16:20], "big")
    except (IndexError, ValueError):
        unresolved.append("mvhd could not be read")
        return 0, 0
    return timescale, duration


def _model_track(data: bytes, boxes: list[Box], track_box: Box) -> _TrackDraft:
    draft = _TrackDraft()
    for box in _descendants(boxes, track_box):
        payload = data[box.payload_start : box.end]
        if box.identifier == b"tkhd":
            _parse_tkhd(payload, draft)
        elif box.identifier == b"mdhd":
            _parse_mdhd(payload, draft)
        elif box.identifier == b"hdlr" and len(payload) >= 12:
            draft.handler = payload[8:12].decode("latin-1", "replace")
        elif box.identifier == b"elst":
            draft.edit_list = payload
        elif box.identifier == b"stsd":
            draft.sample_description = payload
        elif box.identifier == b"stco":
            draft.chunk_offsets = _parse_offsets(payload, 4, draft, "stco")
        elif box.identifier == b"co64":
            draft.chunk_offsets = _parse_offsets(payload, 8, draft, "co64")
        elif box.identifier == b"stsz":
            _parse_stsz(payload, draft)
        elif box.identifier == b"stsc":
            _parse_stsc(payload, draft)
        elif box.identifier == b"stts":
            draft.time_to_sample = _parse_pairs(payload, draft, "stts")
        elif box.identifier == b"ctts":
            draft.composition_offsets = _parse_pairs(payload, draft, "ctts")
        elif box.identifier == b"stss":
            draft.sync_samples = tuple(  # type: ignore[assignment]
                value for value, _ in _parse_pairs(payload, draft, "stss", width=4)
            )
        elif box.identifier in (b"sinf", b"senc", b"saiz", b"saio", b"schm", b"tenc"):
            draft.encryption.append(
                (
                    box.identifier.decode("latin-1"),
                    hashlib.sha256(payload).hexdigest(),
                )
            )
    return draft


def _parse_tkhd(payload: bytes, draft: _TrackDraft) -> None:
    if len(payload) < 4:
        draft.problems.append("tkhd is truncated")
        return
    version = payload[0]
    identifier_at = 20 if version == 1 else 12
    if len(payload) < identifier_at + 4:
        draft.problems.append("tkhd is truncated")
        return
    draft.track_id = int.from_bytes(payload[identifier_at : identifier_at + 4], "big")
    # The trailing 44 bytes carry layer, alternate group, volume, the 3x3 display
    # matrix, width, and height. All of them decide how the track is rendered, so
    # they are captured together rather than field by field: a change to any of
    # them is a rendering change.
    if len(payload) >= 44:
        draft.presentation = payload[-44:]


def _parse_mdhd(payload: bytes, draft: _TrackDraft) -> None:
    if len(payload) < 4:
        draft.problems.append("mdhd is truncated")
        return
    version = payload[0]
    try:
        if version == 1:
            draft.timescale = int.from_bytes(payload[20:24], "big")
            draft.duration = int.from_bytes(payload[24:32], "big")
        else:
            draft.timescale = int.from_bytes(payload[12:16], "big")
            draft.duration = int.from_bytes(payload[16:20], "big")
    except (IndexError, ValueError):
        draft.problems.append("mdhd could not be read")


def _entry_count(payload: bytes, at: int = 4) -> int:
    if len(payload) < at + 4:
        raise IsoBmffError("A full box is too short to carry an entry count")
    count = int.from_bytes(payload[at : at + 4], "big")
    if count > MAX_SAMPLE_ENTRIES:
        raise IsoBmffError(f"A table declares {count} entries; the limit is {MAX_SAMPLE_ENTRIES}")
    return count


def _parse_offsets(payload: bytes, width: int, draft: _TrackDraft, name: str) -> list[int]:
    count = _entry_count(payload)
    base = 8
    if len(payload) < base + count * width:
        draft.problems.append(f"{name} declares {count} entries but is truncated")
        return []
    return [
        int.from_bytes(payload[base + index * width : base + (index + 1) * width], "big")
        for index in range(count)
    ]


def _parse_stsz(payload: bytes, draft: _TrackDraft) -> None:
    if len(payload) < 12:
        draft.problems.append("stsz is truncated")
        return
    uniform = int.from_bytes(payload[4:8], "big")
    count = _entry_count(payload, at=8)
    if uniform:
        draft.sample_sizes = [uniform] * count
        return
    base = 12
    if len(payload) < base + count * 4:
        draft.problems.append(f"stsz declares {count} entries but is truncated")
        return
    draft.sample_sizes = [
        int.from_bytes(payload[base + index * 4 : base + (index + 1) * 4], "big")
        for index in range(count)
    ]


def _parse_stsc(payload: bytes, draft: _TrackDraft) -> None:
    count = _entry_count(payload)
    base = 8
    if len(payload) < base + count * 12:
        draft.problems.append(f"stsc declares {count} entries but is truncated")
        return
    entries: list[tuple[int, int, int]] = []
    for index in range(count):
        chunk = base + index * 12
        entries.append(
            (
                int.from_bytes(payload[chunk : chunk + 4], "big"),
                int.from_bytes(payload[chunk + 4 : chunk + 8], "big"),
                int.from_bytes(payload[chunk + 8 : chunk + 12], "big"),
            )
        )
    draft.sample_to_chunk = entries


def _parse_pairs(
    payload: bytes, draft: _TrackDraft, name: str, width: int = 8
) -> list[tuple[int, int]]:
    count = _entry_count(payload)
    base = 8
    if len(payload) < base + count * width:
        draft.problems.append(f"{name} declares {count} entries but is truncated")
        return []
    pairs: list[tuple[int, int]] = []
    for index in range(count):
        at = base + index * width
        first = int.from_bytes(payload[at : at + 4], "big")
        second = int.from_bytes(payload[at + 4 : at + 8], "big") if width == 8 else 0
        pairs.append((first, second))
    return pairs


def _resolve_sample_ranges(draft: _TrackDraft) -> tuple[tuple[int, int], ...] | None:
    """Turn `stsc` + `stsz` + chunk offsets into absolute byte ranges.

    Returns ``None`` when the tables disagree, because a partially resolved
    layout would produce a digest that matches itself and nothing real.
    """

    if not draft.chunk_offsets or not draft.sample_sizes or not draft.sample_to_chunk:
        return None
    ranges: list[tuple[int, int]] = []
    sample = 0
    total = len(draft.sample_sizes)
    entries = draft.sample_to_chunk
    previous_first_chunk = 0
    for index, (first_chunk, per_chunk, _description) in enumerate(entries):
        if first_chunk <= previous_first_chunk or per_chunk < 0:
            # ISO/IEC 14496-12 orders `stsc` by first_chunk, and each entry runs
            # to the chunk before the next entry begins. A table that repeats or
            # rewinds an index has no such reading, and walking it anyway
            # re-sweeps the whole chunk list once per entry while consuming no
            # samples: 100,000 entries over 100,000 chunks is 10^10 steps from a
            # three-megabyte file. Ordering is both what the format requires and
            # what bounds the walk to the number of chunks.
            return None
        previous_first_chunk = first_chunk
        last_chunk = (
            entries[index + 1][0] - 1 if index + 1 < len(entries) else len(draft.chunk_offsets)
        )
        if last_chunk > len(draft.chunk_offsets):
            return None
        for chunk in range(first_chunk, last_chunk + 1):
            offset = draft.chunk_offsets[chunk - 1]
            for _ in range(per_chunk):
                if sample >= total:
                    return None
                size = draft.sample_sizes[sample]
                ranges.append((offset, offset + size))
                offset += size
                sample += 1
    if sample != total:
        return None
    return tuple(ranges)


# -- the invariants ------------------------------------------------------------------


def verify_iso_bmff_invariants(before: bytes, after: bytes) -> InvariantReport:
    """Compare two versions of a file against every invariant.

    ``before`` is the original and ``after`` is the candidate. A failure to model
    either one produces ``indeterminate`` results rather than passes: this is the
    gate `FMT-02` will run before writing anything, and a gate that cannot tell
    must not say yes.
    """

    try:
        original = model_iso_bmff(before)
    except IsoBmffError as exc:
        return _all_indeterminate(f"the original could not be modelled: {exc}")
    try:
        candidate = model_iso_bmff(after)
    except IsoBmffError as exc:
        return _all_indeterminate(f"the result could not be modelled: {exc}")

    if not original.modelled:
        return _all_indeterminate(
            "the original is not fully modelled: " + "; ".join(original.unresolved)
        )
    if not candidate.modelled:
        return _all_indeterminate(
            "the result is not fully modelled: " + "; ".join(candidate.unresolved)
        )

    return InvariantReport(
        results=(
            _check_samples(before, after, original, candidate),
            _check_timing(original, candidate),
            _check_edit_lists(original, candidate),
            _check_indexes(original, candidate),
            _check_encryption(original, candidate),
            _check_rendering(original, candidate),
            _check_provenance(original, candidate),
        )
    )


def _all_indeterminate(reason: str) -> InvariantReport:
    return InvariantReport(
        results=tuple(
            InvariantResult(
                invariant=invariant, status=InvariantStatus.INDETERMINATE, explanation=reason
            )
            for invariant in Invariant
        )
    )


def _paired(
    original: IsoBmffModel, candidate: IsoBmffModel
) -> list[tuple[SampleTable, SampleTable]]:
    """Match tracks by id, so a reordered `trak` list is not a false violation."""

    by_id = {track.track_id: track for track in candidate.tracks}
    return [(track, by_id[track.track_id]) for track in original.tracks if track.track_id in by_id]


def _track_count_problem(original: IsoBmffModel, candidate: IsoBmffModel) -> str | None:
    if len(original.tracks) != len(candidate.tracks):
        return f"the track count changed from {len(original.tracks)} to {len(candidate.tracks)}"
    missing = {track.track_id for track in original.tracks} - {
        track.track_id for track in candidate.tracks
    }
    if missing:
        return f"track(s) {sorted(missing)} are missing"
    return None


def _check_samples(
    before: bytes, after: bytes, original: IsoBmffModel, candidate: IsoBmffModel
) -> InvariantResult:
    """The bytes each table points at must be identical, wherever they now live."""

    problem = _track_count_problem(original, candidate)
    if problem:
        return InvariantResult(Invariant.SAMPLES, InvariantStatus.VIOLATED, problem)

    details: list[str] = []
    for source, result in _paired(original, candidate):
        # Which side failed decides what to report. A table in the *original*
        # that points outside its own file is a broken input, not an edit that
        # broke it, and calling that a violation sends the reader looking for a
        # bug in the cleaner. Indeterminate is still unsafe to apply, so nothing
        # is let through by saying so accurately.
        try:
            expected = source.sample_digest(before)
        except IsoBmffError as exc:
            return InvariantResult(
                Invariant.SAMPLES,
                InvariantStatus.INDETERMINATE,
                f"track {source.track_id} of the original already points outside the file: {exc}",
            )
        try:
            actual = result.sample_digest(after)
        except IsoBmffError as exc:
            return InvariantResult(
                Invariant.SAMPLES,
                InvariantStatus.VIOLATED,
                f"track {source.track_id} points outside the file after the edit: {exc}",
            )
        if expected != actual:
            details.append(
                f"track {source.track_id} ({source.handler}) now points at different bytes"
            )
    if details:
        return InvariantResult(
            Invariant.SAMPLES,
            InvariantStatus.VIOLATED,
            "sample data changed or the chunk offsets were not corrected",
            tuple(details),
        )
    return InvariantResult(
        Invariant.SAMPLES,
        InvariantStatus.HELD,
        f"every sample in {len(original.tracks)} track(s) hashes the same through its offsets",
    )


def _check_timing(original: IsoBmffModel, candidate: IsoBmffModel) -> InvariantResult:
    if (original.movie_timescale, original.movie_duration) != (
        candidate.movie_timescale,
        candidate.movie_duration,
    ):
        return InvariantResult(
            Invariant.TIMING,
            InvariantStatus.VIOLATED,
            f"the movie timeline changed from {original.movie_timescale}/"
            f"{original.movie_duration} to {candidate.movie_timescale}/"
            f"{candidate.movie_duration}",
        )
    details: list[str] = []
    for source, result in _paired(original, candidate):
        if (source.timescale, source.duration) != (result.timescale, result.duration):
            details.append(f"track {source.track_id} timescale or duration changed")
        if source.time_to_sample != result.time_to_sample:
            details.append(f"track {source.track_id} stts changed")
        if source.composition_offsets != result.composition_offsets:
            details.append(f"track {source.track_id} ctts changed")
    if details:
        return InvariantResult(
            Invariant.TIMING, InvariantStatus.VIOLATED, "timing tables changed", tuple(details)
        )
    return InvariantResult(
        Invariant.TIMING,
        InvariantStatus.HELD,
        "timescales, durations, stts, and ctts are unchanged",
    )


def _check_edit_lists(original: IsoBmffModel, candidate: IsoBmffModel) -> InvariantResult:
    details = [
        f"track {source.track_id} edit list changed"
        for source, result in _paired(original, candidate)
        if source.edit_list != result.edit_list
    ]
    if details:
        return InvariantResult(
            Invariant.EDIT_LISTS,
            InvariantStatus.VIOLATED,
            "an edit list changed; a trimmed clip would present differently",
            tuple(details),
        )
    return InvariantResult(
        Invariant.EDIT_LISTS, InvariantStatus.HELD, "every elst is byte-identical"
    )


def _check_indexes(original: IsoBmffModel, candidate: IsoBmffModel) -> InvariantResult:
    details: list[str] = []
    for source, result in _paired(original, candidate):
        if source.sample_sizes != result.sample_sizes:
            details.append(f"track {source.track_id} stsz changed")
        if source.sync_samples != result.sync_samples:
            details.append(f"track {source.track_id} stss changed; seeking would land elsewhere")
        if len(source.ranges) != len(result.ranges):
            details.append(
                f"track {source.track_id} resolves to {len(result.ranges)} samples, "
                f"not {len(source.ranges)}"
            )
    if original.segment_indexes != candidate.segment_indexes:
        details.append("a sidx fragment index changed")
    if details:
        return InvariantResult(
            Invariant.INDEXES, InvariantStatus.VIOLATED, "index tables changed", tuple(details)
        )
    return InvariantResult(
        Invariant.INDEXES,
        InvariantStatus.HELD,
        "sample sizes, sync samples, and fragment indexes are unchanged",
    )


def _check_encryption(original: IsoBmffModel, candidate: IsoBmffModel) -> InvariantResult:
    if original.protection_headers != candidate.protection_headers:
        return InvariantResult(
            Invariant.ENCRYPTION,
            InvariantStatus.VIOLATED,
            "a pssh protection header changed; the file would no longer decrypt",
        )
    details = [
        f"track {source.track_id} encryption boxes changed"
        for source, result in _paired(original, candidate)
        if source.encryption != result.encryption
    ]
    if details:
        return InvariantResult(
            Invariant.ENCRYPTION,
            InvariantStatus.VIOLATED,
            "track encryption state changed",
            tuple(details),
        )
    protected = bool(original.protection_headers) or any(
        track.encryption for track in original.tracks
    )
    return InvariantResult(
        Invariant.ENCRYPTION,
        InvariantStatus.HELD,
        "encryption state is unchanged" if protected else "the file carries no encryption state",
    )


def _check_rendering(original: IsoBmffModel, candidate: IsoBmffModel) -> InvariantResult:
    details: list[str] = []
    for source, result in _paired(original, candidate):
        if source.sample_description != result.sample_description:
            details.append(f"track {source.track_id} stsd changed; the codec setup differs")
        if source.presentation != result.presentation:
            details.append(f"track {source.track_id} display matrix, dimensions, or volume changed")
        if source.handler != result.handler:
            details.append(f"track {source.track_id} handler changed")
    if details:
        return InvariantResult(
            Invariant.RENDERING,
            InvariantStatus.VIOLATED,
            "rendering-critical metadata changed",
            tuple(details),
        )
    return InvariantResult(
        Invariant.RENDERING,
        InvariantStatus.HELD,
        "sample descriptions, geometry, and handlers are unchanged",
    )


def _check_provenance(original: IsoBmffModel, candidate: IsoBmffModel) -> InvariantResult:
    missing = set(original.provenance_boxes) - set(candidate.provenance_boxes)
    if missing:
        return InvariantResult(
            Invariant.PROVENANCE,
            InvariantStatus.VIOLATED,
            "a protected provenance box was removed or altered",
            tuple(sorted(missing)),
        )
    if not original.provenance_boxes:
        return InvariantResult(
            Invariant.PROVENANCE, InvariantStatus.HELD, "the file carries no provenance box"
        )
    return InvariantResult(
        Invariant.PROVENANCE,
        InvariantStatus.HELD,
        f"{len(original.provenance_boxes)} provenance box(es) survived byte-identical",
    )


__all__ = [
    "C2PA_UUID",
    "CONTAINER_BOXES",
    "MAX_BOXES",
    "MAX_BOX_DEPTH",
    "MAX_SAMPLE_ENTRIES",
    "XMP_UUID",
    "Box",
    "Invariant",
    "InvariantReport",
    "InvariantResult",
    "InvariantStatus",
    "IsoBmffError",
    "IsoBmffModel",
    "SampleTable",
    "model_iso_bmff",
    "read_boxes",
    "verify_iso_bmff_invariants",
]
