"""Executable invariants for EBML containers: WebM and Matroska.

The companion to :mod:`trueai.core.iso_bmff`, and it exists for the same reason
expressed in a different notation. ISO-BMFF records where the media lives in
`stco`; EBML records it in `SeekHead` and `Cues`, as positions relative to the
start of segment data. Remove bytes from `Tags` or `Info` and every cluster
after them shifts, while the file still parses, the duration is still right, and
the blocks are still byte-identical. Seeking lands somewhere else.

So the invariants are structural rather than lexical, and they follow the stored
positions to whatever is actually there now:

* **Tracks** — `TrackNumber`, `TrackUID`, `CodecID`, `CodecPrivate`, and the
  video and audio settings. `CodecPrivate` is initialisation data; losing it
  produces a track nothing can decode.
* **Clusters** — the block payloads, hashed in order. Not "the Cluster elements
  are unchanged": an edit is allowed to move a cluster, and one that leaves a
  stale position behind is caught by following the position.
* **Cues** — the cue points themselves, and that every `CueClusterPosition`
  still resolves to a cluster with the same timestamp. A cue that points at the
  middle of an element is worse than no cue at all.
* **Timing** — `TimestampScale`, `Duration`, and each cluster's `Timestamp`.
* **Seek positions** — every `SeekHead` entry still resolves to an element with
  the `SeekID` it names.
* **Provenance** — a C2PA or XMP attachment, or an element carrying one, must
  survive byte-identical.

Parsing assumes hostility: every variable-length integer is bounds-checked, an
element claiming more bytes than its parent holds is a refusal rather than a
short slice, and recursion is depth-limited.
"""

from __future__ import annotations

import hashlib
from bisect import bisect_right
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

MAX_ELEMENT_DEPTH: Final = 12
MAX_ELEMENTS: Final = 200_000

#: EBML identifiers this module needs to know by name. Everything else is walked
#: past as an opaque leaf rather than guessed at.
EBML_HEADER: Final = 0x1A45DFA3
SEGMENT: Final = 0x18538067
SEEK_HEAD: Final = 0x114D9B74
SEEK: Final = 0x4DBB
SEEK_ID: Final = 0x53AB
SEEK_POSITION: Final = 0x53AC
INFO: Final = 0x1549A966
TIMESTAMP_SCALE: Final = 0x2AD7B1
DURATION: Final = 0x4489
TITLE: Final = 0x7BA9
DATE_UTC: Final = 0x4461
MUXING_APP: Final = 0x4D80
WRITING_APP: Final = 0x5741
TRACKS: Final = 0x1654AE6B
TRACK_ENTRY: Final = 0xAE
TRACK_NUMBER: Final = 0xD7
TRACK_UID: Final = 0x73C5
CODEC_ID: Final = 0x86
CODEC_PRIVATE: Final = 0x63A2
VIDEO: Final = 0xE0
AUDIO: Final = 0xE1
CLUSTER: Final = 0x1F43B675
CLUSTER_TIMESTAMP: Final = 0xE7
SIMPLE_BLOCK: Final = 0xA3
BLOCK_GROUP: Final = 0xA0
BLOCK: Final = 0xA1
CUES: Final = 0x1C53BB6B
CUE_POINT: Final = 0xBB
CUE_TIME: Final = 0xB3
CUE_TRACK_POSITIONS: Final = 0xB7
CUE_CLUSTER_POSITION: Final = 0xF1
TAGS: Final = 0x1254C367
TAG: Final = 0x7373
SIMPLE_TAG: Final = 0x67C8
TAG_NAME: Final = 0x45A3
TAG_STRING: Final = 0x4487
ATTACHMENTS: Final = 0x1941A469
ATTACHED_FILE: Final = 0x61A7
FILE_NAME: Final = 0x466E
FILE_DATA: Final = 0x465C
VOID: Final = 0xEC

#: Elements whose children are elements. Anything absent is a leaf.
MASTER_ELEMENTS: Final = frozenset(
    {
        EBML_HEADER,
        SEGMENT,
        SEEK_HEAD,
        SEEK,
        INFO,
        TRACKS,
        TRACK_ENTRY,
        VIDEO,
        AUDIO,
        CLUSTER,
        BLOCK_GROUP,
        CUES,
        CUE_POINT,
        CUE_TRACK_POSITIONS,
        TAGS,
        TAG,
        SIMPLE_TAG,
        ATTACHMENTS,
        ATTACHED_FILE,
        0x63C0,  # Targets
    }
)

#: Markers that make an attachment provenance rather than an extra file.
_PROVENANCE_HINTS: Final = (b"c2pa", b"jumbf", b"xmp", b"x:xmpmeta")


class EbmlError(ValueError):
    """Raised when a buffer cannot be modelled as an EBML document."""


class Invariant(StrEnum):
    """What an EBML edit must not change."""

    TRACKS = "tracks"
    CLUSTERS = "clusters"
    CUES = "cues"
    TIMING = "timing"
    SEEK_POSITIONS = "seek_positions"
    PROVENANCE = "provenance"


class InvariantStatus(StrEnum):
    HELD = "held"
    VIOLATED = "violated"
    #: The document could not be modelled well enough to decide. Not a pass.
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True, slots=True)
class Element:
    """One element, located precisely enough to re-read or replace it."""

    identifier: int
    start: int
    payload_start: int
    end: int
    depth: int
    unknown_size: bool = False

    @property
    def payload_length(self) -> int:
        return self.end - self.payload_start


@dataclass(frozen=True, slots=True)
class TrackModel:
    """One track's identity and decoder setup."""

    number: int
    uid: int
    codec_id: str
    #: Initialisation data. A track that loses it is a track nothing can decode.
    codec_private: bytes = b""
    settings: tuple[tuple[str, bytes], ...] = ()


@dataclass(frozen=True, slots=True)
class ClusterModel:
    """One cluster, by position, timestamp, and the blocks it carries."""

    #: Position relative to the start of segment data, which is what SeekHead
    #: and Cues store. Absolute file offsets would not be comparable to them.
    relative_position: int
    timestamp: int
    block_digest: str
    block_count: int


@dataclass(frozen=True, slots=True)
class CueModel:
    """One cue point and where it says its cluster is."""

    time: int
    cluster_positions: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class EbmlModel:
    """Everything about a document that an edit must preserve."""

    elements: tuple[Element, ...]
    segment_data_start: int
    timestamp_scale: int
    duration: bytes
    tracks: tuple[TrackModel, ...] = ()
    clusters: tuple[ClusterModel, ...] = ()
    cues: tuple[CueModel, ...] = ()
    seek_entries: tuple[tuple[int, int], ...] = ()
    provenance: tuple[str, ...] = ()
    unresolved: tuple[str, ...] = ()

    @property
    def modelled(self) -> bool:
        return not self.unresolved and bool(self.tracks)


@dataclass(frozen=True, slots=True)
class InvariantResult:
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

    No single boolean, for the same reason the ISO-BMFF report has none: a
    dropped cue and a dropped provenance attachment need different remedies.
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
        """Whether every invariant held. Indeterminate counts as unsafe."""

        return bool(self.results) and all(item.held for item in self.results)

    def explain(self) -> str:
        return "; ".join(f"{item.invariant.value}: {item.explanation}" for item in self.results)


# -- parsing -------------------------------------------------------------------------


def read_vint(data: bytes, offset: int, end: int, *, keep_marker: bool) -> tuple[int, int]:
    """Read one EBML variable-length integer, refusing anything malformed."""

    if offset >= end:
        raise EbmlError("Truncated variable-length integer")
    first = data[offset]
    if first == 0:
        raise EbmlError("A variable-length integer may not start with a zero byte")
    marker = 0x80
    width = 1
    while width <= 8 and not first & marker:
        marker >>= 1
        width += 1
    if width > 8 or offset + width > end:
        raise EbmlError("Invalid or truncated variable-length integer")
    if keep_marker and width > 4:
        raise EbmlError("An element identifier may not exceed four bytes")
    value = first if keep_marker else first & (marker - 1)
    for byte in data[offset + 1 : offset + width]:
        value = (value << 8) | byte
    return value, width


def read_elements(
    data: bytes,
    *,
    start: int = 0,
    end: int | None = None,
    depth: int = 0,
    budget: list[int] | None = None,
) -> list[Element]:
    """Walk the element tree, refusing anything that does not fit its parent."""

    limit = len(data) if end is None else min(end, len(data))
    remaining = budget if budget is not None else [MAX_ELEMENTS]
    elements: list[Element] = []
    offset = start
    while offset < limit:
        if remaining[0] <= 0:
            raise EbmlError(f"More than {MAX_ELEMENTS} elements; refusing to continue")
        remaining[0] -= 1
        identifier, id_width = read_vint(data, offset, limit, keep_marker=True)
        size_offset = offset + id_width
        size, size_width = read_vint(data, size_offset, limit, keep_marker=False)
        payload_start = size_offset + size_width
        # An all-ones size means "unknown length", used for live-streamed
        # Segments and Clusters. It runs to the end of the parent.
        unknown = size == (1 << (7 * size_width)) - 1
        if unknown and identifier not in MASTER_ELEMENTS:
            # RFC 8794 allows an unknown size on Master Elements only, and the
            # restriction is load-bearing here. A leaf is not walked into, so an
            # unknown-size leaf ran to the end of its parent and every element
            # after it — Clusters, Cues, an attachment carrying provenance — was
            # never seen. The model came back complete, and every invariant
            # computed over the half of the document that remained visible held.
            raise EbmlError(
                f"Element {identifier:#x} at {offset} is not a master element and may not "
                "declare an unknown size"
            )
        element_end = limit if unknown else payload_start + size
        if element_end > limit:
            raise EbmlError(
                f"Element {identifier:#x} at {offset} claims {size} bytes, past its parent"
            )
        elements.append(
            Element(
                identifier=identifier,
                start=offset,
                payload_start=payload_start,
                end=element_end,
                depth=depth,
                unknown_size=unknown,
            )
        )
        if identifier in MASTER_ELEMENTS:
            if depth + 1 > MAX_ELEMENT_DEPTH:
                raise EbmlError(f"Element nesting deeper than {MAX_ELEMENT_DEPTH}")
            elements.extend(
                read_elements(
                    data,
                    start=payload_start,
                    end=element_end,
                    depth=depth + 1,
                    budget=remaining,
                )
            )
        offset = element_end
    return elements


def void_element(length: int) -> bytes:
    """Return a `Void` element occupying exactly ``length`` bytes.

    `Void` is EBML's own "ignore this" padding, which is what makes in-place
    replacement possible: the document keeps its length, so every `SeekHead` and
    `Cues` position stays correct without being rewritten.
    """

    if length < 2:
        raise EbmlError("A Void element needs at least two bytes")
    # One byte of identifier, then a size VINT wide enough to describe whatever
    # payload is left. Widening the VINT shrinks the payload, so the search
    # converges immediately.
    for size_width in range(1, 9):
        payload = length - 1 - size_width
        if payload < 0:
            continue
        capacity = (1 << (7 * size_width)) - 2
        if payload <= capacity:
            marker = 1 << (8 - size_width)
            size_bytes = payload.to_bytes(size_width, "big")
            header = bytes([VOID, size_bytes[0] | marker]) + size_bytes[1:]
            return header + b"\x00" * payload
    raise EbmlError(f"No Void encoding fits {length} bytes")


def _children(elements: list[Element], parent: Element) -> list[Element]:
    return [item for item in _descendants(elements, parent) if item.depth == parent.depth + 1]


def _descendants(elements: list[Element], parent: Element) -> list[Element]:
    """Return every element nested inside ``parent``.

    ``elements`` must be in document order, which is what :func:`read_elements`
    produces: an element is appended before its children, and every start offset
    is larger than the last. That makes a parent's descendants the run that
    begins after it and ends at its boundary, findable by bisection.

    The obvious implementation — filter the whole list on
    ``parent.start < item.start < parent.end`` — is what this replaces, and it
    was quadratic in the element count. Modelling calls it once per TrackEntry,
    Cluster, CuePoint, Seek, and AttachedFile, and an empty Cluster costs five
    bytes to write: a half-megabyte document of 100,000 of them cost 10^10 list
    steps, minutes of CPU inside a cleaner that is handed untrusted files. A
    fuzzer could not see it, because nothing crashes; it just never finishes.
    """

    position = bisect_right(elements, parent.start, key=lambda item: item.start)
    found: list[Element] = []
    while position < len(elements) and elements[position].start < parent.end:
        found.append(elements[position])
        position += 1
    return found


def _uint(data: bytes, element: Element) -> int:
    return int.from_bytes(data[element.payload_start : element.end], "big")


@dataclass
class _Draft:
    unresolved: list[str] = field(default_factory=list)


def model_ebml(data: bytes) -> EbmlModel:
    """Build the structural model an invariant check needs."""

    elements = read_elements(data)
    if not elements or elements[0].identifier != EBML_HEADER:
        raise EbmlError("The document does not begin with an EBML header")
    segment = next((item for item in elements if item.identifier == SEGMENT), None)
    if segment is None:
        raise EbmlError("No Segment element is present")

    draft = _Draft()
    base = segment.payload_start

    info = next(
        (item for item in elements if item.identifier == INFO and item.start > segment.start),
        None,
    )
    timestamp_scale = 1_000_000
    duration = b""
    if info is not None:
        for child in _children(elements, info):
            if child.identifier == TIMESTAMP_SCALE:
                timestamp_scale = _uint(data, child)
            elif child.identifier == DURATION:
                duration = data[child.payload_start : child.end]
    else:
        draft.unresolved.append("no Info element was found")

    tracks = _model_tracks(data, elements, draft)
    clusters = _model_clusters(data, elements, base, draft)
    cues = _model_cues(data, elements, draft)
    seek_entries = _model_seek_head(data, elements)
    provenance = _model_provenance(data, elements)

    if not tracks:
        draft.unresolved.append("no TrackEntry was found")

    return EbmlModel(
        elements=tuple(elements),
        segment_data_start=base,
        timestamp_scale=timestamp_scale,
        duration=duration,
        tracks=tracks,
        clusters=clusters,
        cues=cues,
        seek_entries=seek_entries,
        provenance=provenance,
        unresolved=tuple(draft.unresolved),
    )


def _model_tracks(data: bytes, elements: list[Element], draft: _Draft) -> tuple[TrackModel, ...]:
    models: list[TrackModel] = []
    for entry in (item for item in elements if item.identifier == TRACK_ENTRY):
        number = uid = 0
        codec_id = ""
        codec_private = b""
        settings: list[tuple[str, bytes]] = []
        for child in _descendants(elements, entry):
            payload = data[child.payload_start : child.end]
            if child.identifier == TRACK_NUMBER:
                number = int.from_bytes(payload, "big")
            elif child.identifier == TRACK_UID:
                uid = int.from_bytes(payload, "big")
            elif child.identifier == CODEC_ID:
                codec_id = payload.decode("ascii", "replace").rstrip("\x00")
            elif child.identifier == CODEC_PRIVATE:
                codec_private = payload
            elif child.depth == entry.depth + 2:
                # Video and audio settings: width, height, sample rate, channels.
                # Captured together because any of them changes playback.
                settings.append((f"{child.identifier:#x}", payload))
        if not number:
            draft.unresolved.append("a TrackEntry has no TrackNumber")
            continue
        models.append(
            TrackModel(
                number=number,
                uid=uid,
                codec_id=codec_id,
                codec_private=codec_private,
                settings=tuple(sorted(settings)),
            )
        )
    return tuple(sorted(models, key=lambda item: item.number))


def _model_clusters(
    data: bytes, elements: list[Element], base: int, draft: _Draft
) -> tuple[ClusterModel, ...]:
    models: list[ClusterModel] = []
    for cluster in (item for item in elements if item.identifier == CLUSTER):
        timestamp = 0
        digest = hashlib.sha256()
        count = 0
        for child in _descendants(elements, cluster):
            if child.identifier == CLUSTER_TIMESTAMP:
                timestamp = _uint(data, child)
            elif child.identifier in (SIMPLE_BLOCK, BLOCK):
                digest.update(data[child.payload_start : child.end])
                count += 1
        if cluster.unknown_size:
            draft.unresolved.append("a Cluster declares an unknown size")
        models.append(
            ClusterModel(
                relative_position=cluster.start - base,
                timestamp=timestamp,
                block_digest=digest.hexdigest(),
                block_count=count,
            )
        )
    return tuple(models)


def _model_cues(data: bytes, elements: list[Element], draft: _Draft) -> tuple[CueModel, ...]:
    models: list[CueModel] = []
    for point in (item for item in elements if item.identifier == CUE_POINT):
        time = 0
        positions: list[int] = []
        for child in _descendants(elements, point):
            if child.identifier == CUE_TIME:
                time = _uint(data, child)
            elif child.identifier == CUE_CLUSTER_POSITION:
                positions.append(_uint(data, child))
        models.append(CueModel(time=time, cluster_positions=tuple(positions)))
    return tuple(models)


def _model_seek_head(data: bytes, elements: list[Element]) -> tuple[tuple[int, int], ...]:
    entries: list[tuple[int, int]] = []
    for seek in (item for item in elements if item.identifier == SEEK):
        seek_id = 0
        position = -1
        for child in _descendants(elements, seek):
            if child.identifier == SEEK_ID:
                seek_id = int.from_bytes(data[child.payload_start : child.end], "big")
            elif child.identifier == SEEK_POSITION:
                position = _uint(data, child)
        if seek_id and position >= 0:
            entries.append((seek_id, position))
    return tuple(sorted(entries))


def _model_provenance(data: bytes, elements: list[Element]) -> tuple[str, ...]:
    """Find attachments and elements that carry provenance, by content."""

    found: list[str] = []
    for attached in (item for item in elements if item.identifier == ATTACHED_FILE):
        name = b""
        payload = b""
        for child in _descendants(elements, attached):
            if child.identifier == FILE_NAME:
                name = data[child.payload_start : child.end]
            elif child.identifier == FILE_DATA:
                payload = data[child.payload_start : child.end]
        haystack = (name + payload).lower()
        if any(hint in haystack for hint in _PROVENANCE_HINTS):
            found.append(
                f"attachment:{name.decode('utf-8', 'replace')}:"
                f"{hashlib.sha256(payload).hexdigest()}"
            )
    for tag in (item for item in elements if item.identifier == SIMPLE_TAG):
        payload = data[tag.payload_start : tag.end].lower()
        if any(hint in payload for hint in _PROVENANCE_HINTS):
            found.append(f"tag:{hashlib.sha256(payload).hexdigest()}")
    return tuple(sorted(found))


# -- the invariants ------------------------------------------------------------------


def verify_ebml_invariants(before: bytes, after: bytes) -> InvariantReport:
    """Compare two versions of a document against every invariant."""

    try:
        original = model_ebml(before)
    except EbmlError as exc:
        return _all_indeterminate(f"the original could not be modelled: {exc}")
    try:
        candidate = model_ebml(after)
    except EbmlError as exc:
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
            _check_tracks(original, candidate),
            _check_clusters(original, candidate),
            _check_cues(original, candidate),
            _check_timing(original, candidate),
            _check_seek(after, original, candidate),
            _check_provenance(original, candidate),
        )
    )


def _all_indeterminate(reason: str) -> InvariantReport:
    return InvariantReport(
        results=tuple(
            InvariantResult(invariant, InvariantStatus.INDETERMINATE, reason)
            for invariant in Invariant
        )
    )


def _check_tracks(original: EbmlModel, candidate: EbmlModel) -> InvariantResult:
    if original.tracks != candidate.tracks:
        details: list[str] = []
        by_number = {track.number: track for track in candidate.tracks}
        for track in original.tracks:
            other = by_number.get(track.number)
            if other is None:
                details.append(f"track {track.number} is missing")
            elif other.codec_private != track.codec_private:
                details.append(
                    f"track {track.number} lost or changed CodecPrivate; nothing could decode it"
                )
            elif other != track:
                details.append(f"track {track.number} changed")
        return InvariantResult(
            Invariant.TRACKS,
            InvariantStatus.VIOLATED,
            "track identity or decoder setup changed",
            tuple(details),
        )
    return InvariantResult(
        Invariant.TRACKS,
        InvariantStatus.HELD,
        f"{len(original.tracks)} track(s) keep their identity, codec, and setup",
    )


def _check_clusters(original: EbmlModel, candidate: EbmlModel) -> InvariantResult:
    if len(original.clusters) != len(candidate.clusters):
        return InvariantResult(
            Invariant.CLUSTERS,
            InvariantStatus.VIOLATED,
            f"the cluster count changed from {len(original.clusters)} to {len(candidate.clusters)}",
        )
    details = [
        f"cluster at {source.relative_position} carries different blocks"
        for source, result in zip(original.clusters, candidate.clusters, strict=True)
        if source.block_digest != result.block_digest or source.block_count != result.block_count
    ]
    if details:
        return InvariantResult(
            Invariant.CLUSTERS, InvariantStatus.VIOLATED, "block payloads changed", tuple(details)
        )
    return InvariantResult(
        Invariant.CLUSTERS,
        InvariantStatus.HELD,
        f"{sum(item.block_count for item in original.clusters)} block(s) are byte-identical",
    )


def _check_cues(original: EbmlModel, candidate: EbmlModel) -> InvariantResult:
    if original.cues != candidate.cues:
        return InvariantResult(
            Invariant.CUES,
            InvariantStatus.VIOLATED,
            "the cue index changed; seeking would land somewhere else",
        )
    positions = {cluster.relative_position for cluster in candidate.clusters}
    dangling = [
        position
        for cue in candidate.cues
        for position in cue.cluster_positions
        if position not in positions
    ]
    if dangling:
        return InvariantResult(
            Invariant.CUES,
            InvariantStatus.VIOLATED,
            "a CueClusterPosition no longer points at the start of a cluster",
            tuple(f"position {item}" for item in sorted(set(dangling))),
        )
    if not original.cues:
        return InvariantResult(
            Invariant.CUES, InvariantStatus.HELD, "the document carries no cue index"
        )
    return InvariantResult(
        Invariant.CUES,
        InvariantStatus.HELD,
        f"{len(original.cues)} cue point(s) are unchanged and still resolve to clusters",
    )


def _check_timing(original: EbmlModel, candidate: EbmlModel) -> InvariantResult:
    if (original.timestamp_scale, original.duration) != (
        candidate.timestamp_scale,
        candidate.duration,
    ):
        return InvariantResult(
            Invariant.TIMING,
            InvariantStatus.VIOLATED,
            "TimestampScale or Duration changed",
        )
    details = [
        f"cluster at {source.relative_position} changed timestamp"
        for source, result in zip(original.clusters, candidate.clusters, strict=True)
        if source.timestamp != result.timestamp
    ]
    if details:
        return InvariantResult(
            Invariant.TIMING, InvariantStatus.VIOLATED, "cluster timestamps changed", tuple(details)
        )
    return InvariantResult(
        Invariant.TIMING,
        InvariantStatus.HELD,
        "TimestampScale, Duration, and every cluster timestamp are unchanged",
    )


def _check_seek(after: bytes, original: EbmlModel, candidate: EbmlModel) -> InvariantResult:
    if original.seek_entries != candidate.seek_entries:
        return InvariantResult(
            Invariant.SEEK_POSITIONS,
            InvariantStatus.VIOLATED,
            "the SeekHead index changed",
        )
    details: list[str] = []
    for seek_id, position in candidate.seek_entries:
        absolute = candidate.segment_data_start + position
        target = next(
            (item for item in candidate.elements if item.start == absolute),
            None,
        )
        if target is None:
            details.append(f"position {position} does not start an element")
        elif target.identifier != seek_id:
            details.append(
                f"position {position} now points at {target.identifier:#x}, not {seek_id:#x}"
            )
    if details:
        return InvariantResult(
            Invariant.SEEK_POSITIONS,
            InvariantStatus.VIOLATED,
            "a SeekHead entry no longer resolves to the element it names",
            tuple(details),
        )
    if not original.seek_entries:
        return InvariantResult(
            Invariant.SEEK_POSITIONS, InvariantStatus.HELD, "the document carries no SeekHead"
        )
    return InvariantResult(
        Invariant.SEEK_POSITIONS,
        InvariantStatus.HELD,
        f"{len(original.seek_entries)} seek entr(ies) still resolve to the elements they name",
    )


def _check_provenance(original: EbmlModel, candidate: EbmlModel) -> InvariantResult:
    missing = set(original.provenance) - set(candidate.provenance)
    if missing:
        return InvariantResult(
            Invariant.PROVENANCE,
            InvariantStatus.VIOLATED,
            "a provenance attachment or tag was removed or altered",
            tuple(sorted(missing)),
        )
    if not original.provenance:
        return InvariantResult(
            Invariant.PROVENANCE, InvariantStatus.HELD, "the document carries no provenance"
        )
    return InvariantResult(
        Invariant.PROVENANCE,
        InvariantStatus.HELD,
        f"{len(original.provenance)} provenance item(s) survived byte-identical",
    )


__all__ = [
    "MASTER_ELEMENTS",
    "MAX_ELEMENTS",
    "MAX_ELEMENT_DEPTH",
    "VOID",
    "ClusterModel",
    "CueModel",
    "EbmlError",
    "EbmlModel",
    "Element",
    "Invariant",
    "InvariantReport",
    "InvariantResult",
    "InvariantStatus",
    "TrackModel",
    "model_ebml",
    "read_elements",
    "read_vint",
    "verify_ebml_invariants",
    "void_element",
]
