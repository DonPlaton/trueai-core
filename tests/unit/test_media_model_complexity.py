"""Container documents a cleaner could not finish reading, and one it misread.

`trueai clean` hands every MP4 and WebM it is given to the invariant models in
:mod:`trueai.core.iso_bmff` and :mod:`trueai.core.ebml` before it writes
anything. Three inputs below made that step take time quadratic in a count the
file chooses, and all three are cheap to write:

* a WebM of many empty `Cluster` elements — five bytes each, and modelling
  scanned the whole element list once per cluster;
* an MP4 of many empty `trak` boxes — eight bytes each, with the same scan per
  track;
* an `stsc` table whose `first_chunk` rewinds instead of advancing, which swept
  the entire chunk list once per entry while consuming no samples.

The fuzzer runs against both models already and found none of them, because
nothing raises and nothing corrupts: the process simply does not come back. The
budgets here are loose on purpose — the fixed code answers in milliseconds and
the broken code took minutes to hours, so what is asserted is the complexity
class rather than a speed.

The fourth case is not a slowdown but a blind spot: an EBML leaf declaring an
unknown size ran to the end of its parent, and every element after it was never
walked. The model reported itself complete and every invariant held over the
half of the document that remained visible.
"""

from __future__ import annotations

import time
from collections.abc import Callable

import pytest

from tests.unit.test_ebml_invariants import element, vint
from tests.unit.test_iso_bmff_invariants import box, build_mp4
from trueai.core.ebml import EbmlError, model_ebml, read_elements
from trueai.core.iso_bmff import (
    Invariant,
    InvariantStatus,
    _resolve_sample_ranges,
    _TrackDraft,
    model_iso_bmff,
    verify_iso_bmff_invariants,
)

#: Large enough that quadratic behaviour is unmistakable, small enough that the
#: fixed implementations stay in the milliseconds.
REPEATS = 40_000

BUDGET_SECONDS = 10.0


def elapsed(work: Callable[[], object]) -> float:
    started = time.perf_counter()
    work()
    return time.perf_counter() - started


def webm_of_empty_clusters(count: int) -> bytes:
    """A document that parses, carries no media, and costs five bytes a cluster."""

    header = bytes.fromhex("1a45dfa3") + b"\x80"
    body = (bytes.fromhex("1f43b675") + b"\x80") * count
    return header + element(bytes.fromhex("18538067"), body)


def mp4_of_empty_tracks(count: int) -> bytes:
    """The same shape in the other container: eight bytes a track."""

    ftyp = box(b"ftyp", b"isom" + (512).to_bytes(4, "big") + b"isomiso2mp41")
    return ftyp + box(b"moov", box(b"trak", b"") * count)


def test_a_document_of_many_clusters_is_modelled_in_linear_time() -> None:
    data = webm_of_empty_clusters(REPEATS)

    assert len(data) < 250_000, "the point is that the input is small"
    duration = elapsed(lambda: model_ebml(data))

    assert duration < BUDGET_SECONDS, f"modelling {REPEATS} clusters took {duration:.1f}s"


def test_a_file_of_many_tracks_is_modelled_in_linear_time() -> None:
    data = mp4_of_empty_tracks(REPEATS)

    assert len(data) < 400_000, "the point is that the input is small"
    duration = elapsed(lambda: model_iso_bmff(data))

    assert duration < BUDGET_SECONDS, f"modelling {REPEATS} tracks took {duration:.1f}s"


def test_a_sample_to_chunk_table_that_rewinds_is_refused() -> None:
    """`stsc` is ordered by `first_chunk`; a table that is not has no reading.

    Walking it anyway re-swept the chunk list once per entry. Refusing is both
    what the format requires and what bounds the walk to the number of chunks.
    """

    draft = _TrackDraft()
    draft.chunk_offsets = [1000 + index for index in range(REPEATS)]
    draft.sample_sizes = [1]
    draft.sample_to_chunk = [
        (1, 0, 1) if index % 2 == 0 else (REPEATS + 1, 0, 1) for index in range(REPEATS)
    ]

    duration = elapsed(lambda: _resolve_sample_ranges(draft))

    assert _resolve_sample_ranges(draft) is None
    assert duration < BUDGET_SECONDS, f"resolving a rewinding table took {duration:.1f}s"


def test_an_ordered_sample_to_chunk_table_still_resolves() -> None:
    """Paired with the test above: the rule refuses malformed tables, not all of them."""

    draft = _TrackDraft()
    draft.chunk_offsets = [100, 200]
    draft.sample_sizes = [10, 10, 10]
    draft.sample_to_chunk = [(1, 2, 1), (2, 1, 1)]

    assert _resolve_sample_ranges(draft) == ((100, 110), (110, 120), (200, 210))


def test_an_unknown_size_leaf_is_refused_rather_than_swallowing_the_document() -> None:
    """RFC 8794 allows an unknown size on master elements only.

    A leaf is never walked into, so an unknown-size leaf ran to the end of its
    parent and hid every element after it — here a Cluster that the model would
    then never see, in a document it would still call complete.
    """

    hidden_cluster = bytes.fromhex("1f43b675") + b"\x80"
    # Void is a leaf, and 0xFF is the one-byte unknown size.
    unknown_size_leaf = bytes.fromhex("ec") + b"\xff"
    header = bytes.fromhex("1a45dfa3") + b"\x80"
    data = header + element(bytes.fromhex("18538067"), unknown_size_leaf + hidden_cluster)

    with pytest.raises(EbmlError, match="may not declare an unknown size"):
        read_elements(data)


def test_an_unknown_size_master_element_is_still_accepted() -> None:
    """Paired with the test above: live-muxed Segments and Clusters are legal."""

    header = bytes.fromhex("1a45dfa3") + b"\x80"
    data = header + bytes.fromhex("18538067") + b"\xff" + bytes.fromhex("1f43b675") + b"\x80"

    elements = read_elements(data)

    assert [item.identifier for item in elements] == [0x1A45DFA3, 0x18538067, 0x1F43B675]
    assert elements[1].unknown_size


def test_an_original_that_points_outside_its_own_file_is_indeterminate() -> None:
    """Which side failed decides what to report.

    A table in the original that already points past the end of its own file is
    a broken input, not an edit that broke it. Calling that a violation sends
    the reader looking for a bug in the cleaner. Indeterminate is still unsafe
    to apply, so nothing is let through by saying so accurately.
    """

    broken = build_mp4(title=None, offset_drift=8)

    report = verify_iso_bmff_invariants(broken, broken)

    samples = report.result(Invariant.SAMPLES)
    assert samples is not None
    assert samples.status == InvariantStatus.INDETERMINATE
    assert "the original already points outside the file" in samples.explanation
    assert not report.safe_to_apply()


def test_the_vint_helper_still_agrees_with_the_reader() -> None:
    """Guards the fixtures above: a size this test writes is a size the reader reads."""

    assert vint(0, 1) == b"\x80"
    assert read_elements(bytes.fromhex("1a45dfa3") + vint(0, 1))[0].payload_length == 0
