# Container invariants: MP4/MOV/M4A and WebM/Matroska

This is a specification, and it is written as code in
[`trueai/core/iso_bmff.py`](../trueai/core/iso_bmff.py). Nothing here removes
anything. It answers one question — *would this edit still play the same file?* —
so the cleanup in `FMT-02` can be gated on the answer rather than on hope.

## Why ISO-BMFF needs its own gate

The formats TrueAI already cleans are forgiving. In WAV or FLAC, metadata lives
in one chunk and the audio in another; removing the first leaves the second
exactly where it was, and a byte comparison of the audio-bearing region proves
the edit was surgical.

ISO-BMFF is not like that. The sample tables store **absolute file offsets** in
`stco` (32-bit) or `co64` (64-bit). Delete a single byte anywhere before `mdat`
and every sample moves, while:

- the file still parses;
- every box is still well formed;
- the duration, timescale, and track list are all still correct;
- `mdat` is byte-for-byte identical.

It plays garbage. A "did anything outside the metadata change?" check passes
happily, because the change is that the offsets did *not* change when they
should have. `tests/unit/test_iso_bmff_invariants.py` contains that exact case
and asserts a byte comparison would have missed it.

So the invariants are structural. They follow the tables to wherever the samples
now live, instead of assuming the samples are `mdat`.

## The seven invariants

| Invariant | What it covers | What breaking it looks like |
|---|---|---|
| `samples` | The bytes each sample table resolves to, hashed in sample order | Silence, garbage, or a decoder error |
| `timing` | `mvhd`/`mdhd` timescale and duration, `stts`, `ctts` | Wrong duration, drifting audio |
| `edit_lists` | `elst` | A trimmed clip presents the untrimmed take |
| `indexes` | `stsz`, `stss`, `sidx`, and sample-count consistency | Seeking lands in the wrong place |
| `encryption` | `pssh`, `sinf`, `senc`, `saiz`, `saio`, `schm`, `tenc` | The file no longer decrypts |
| `rendering` | `stsd` sample entries, `tkhd` matrix/dimensions/volume, handler | Wrong codec setup, rotation, or aspect |
| `provenance` | C2PA and XMP `uuid` boxes | Provenance silently removed |

The `samples` invariant is the one that carries the design. It hashes the bytes
the tables *point at*, so:

- an edit that correctly relocates `mdat` and fixes the offsets **passes**;
- an edit that leaves `mdat` untouched and the offsets stale **fails**.

Both are invisible to a byte-level comparison, in opposite directions.

`rendering` exists because "header region" is not the same as "metadata". The
title in `udta` and the display matrix in `tkhd` sit a few dozen bytes apart. One
is removable; the other decides whether the video appears rotated.

## Three outcomes, not two

```python
from trueai.core.iso_bmff import verify_iso_bmff_invariants

report = verify_iso_bmff_invariants(before, after)
if not report.safe_to_apply():
    raise RemediationError(report.explain())
```

Each invariant reports `held`, `violated`, or `indeterminate`.
**Indeterminate counts as unsafe.** An edit whose effect cannot be checked is an
edit that must not be applied, and treating "could not tell" as "fine" is how a
gate becomes decoration. A file the model cannot fully resolve — sample tables
that disagree with each other, a truncated `stsz` — produces indeterminate
results rather than a pass.

There is no single `valid` field. "The samples moved" and "the provenance box was
dropped" need different remedies, and one boolean would render them identically.
`safe_to_apply()` exists for callers that want the conjunction, and it is
computed from the parts rather than replacing them.

## Parsing hostile input

Every offset is bounds-checked against the buffer. A box header claiming more
bytes than remain is a parse refusal, not a short slice — a truncated slice would
model a file that does not exist, and every invariant computed on it would be
about that fiction.

| Bound | Value | Why |
|---|---|---|
| `MAX_BOX_DEPTH` | 16 | `moov > trak > mdia > minf > stbl > stsd > entry` is seven; fragmented files add a couple |
| `MAX_BOXES` | 100,000 | Beyond this it is not a file being cleaned, it is parser exhaustion |
| `MAX_SAMPLE_ENTRIES` | 4,000,000 | A table's declared count is checked *before* anything is allocated against it |

Only boxes known to contain boxes are walked into, so an unknown box is never
descended on a guess about its layout. `stsd` gets a special case: it carries a
version word and an entry count before its children, and walking from the payload
start would misread both.

## The cleanup that passes through it

`FMT-02` implements removal, and it does so by **not moving anything**.

The obvious implementation cuts the metadata box out and rewrites every `stco`
and `co64` entry by the number of bytes that disappeared before it. That is
where the bug class above lives. Instead, the selected box is overwritten in
place with a zero-filled `free` box of exactly the same length:

```
before:  ... [udta [©nam "Original title"]] [mdat ...]
after:   ... [free 0000000000000000000000] [mdat ...]
```

`free` is the format's own "ignore this" padding, understood by every demuxer.
The metadata is gone — the payload is zeroed, not merely relabelled — the file
length is unchanged, and **no offset needs correcting because nothing moved**. A
whole category of corruption is avoided by not creating the situation that
causes it.

The cost is honest and stated: the file does not get smaller. The bytes become
padding rather than disappearing. For a delivery pipeline that cares whether the
client can read the shooting location that is the right trade; for one that cares
about file size it is not.

The result still goes through `verify_iso_bmff_invariants` before it is accepted,
because "nothing moved" is a claim about the implementation and the gate is what
turns it into a checked fact. A wrong length or a clobbered neighbour fails there
rather than shipping.

### What the cleaner refuses

| Refusal | Why |
|---|---|
| A container carrying a C2PA or XMP provenance box | A manifest binds byte ranges of the file it lives in, so *any* edit invalidates it — including one that leaves the manifest box untouched |
| A metadata value that names a provenance system | Refused a layer earlier: the detector reports the field but assigns it no remediation id |
| An `ftyp` brand outside the known set | An unrecognised brand may put something other than padding where a `free` box is expected |
| Overlapping selections | The second would overwrite padding the first wrote, which is not the edit either described |
| An entry with no removable box range | A range the cleaner re-derived could disagree with the one the detector reported, and two disagreeing is how a surgical edit stops being surgical |
| Any invariant not held, including indeterminate | The gate runs before the write, so a refused edit leaves no output file |

The provenance refusal is **structural, not lexical**. Writing the test found
that the byte-marker scan the other formats rely on does not catch a C2PA box: it
is identified by a binary UUID, and a manifest payload need not contain the
letters `c2pa` anywhere. The ISO-BMFF branch asks the model for
`provenance_boxes` instead.

### The removable unit is the whole box

An `ilst` item with its `data` box removed is a malformed item, not an absent
one, so `MediaMetadataEntry.removable_range` names the enclosing box and the
cleaner uses that range rather than re-deriving one. The detector and the cleaner
agreeing about which bytes are the metadata is the difference between a surgical
edit and a hopeful one.


# WebM and Matroska: the same problem in EBML

[`trueai/core/ebml.py`](../trueai/core/ebml.py) is the companion specification,
and it exists for the same reason written in a different notation. ISO-BMFF
records where the media lives in `stco`; EBML records it in `SeekHead` and
`Cues`, as positions relative to the start of segment data.

Remove bytes from `Tags` and every cluster after them shifts, while:

- the document still parses;
- every element is still well formed;
- `Duration` and `TimestampScale` are still right;
- every block payload is byte-identical.

Seeking lands somewhere else. `tests/unit/test_ebml_invariants.py` builds a WebM
whose `SeekHead` and `Cues` positions genuinely resolve, drifts the cue positions
by three bytes, and asserts that the block digests were identical in that case —
the same demonstration the MP4 tests make about `mdat`.

## The six invariants

| Invariant | What it covers | What breaking it looks like |
|---|---|---|
| `tracks` | `TrackNumber`, `TrackUID`, `CodecID`, `CodecPrivate`, video and audio settings | A track nothing can decode |
| `clusters` | Block payloads, hashed in order | Wrong or missing media |
| `cues` | Cue points, and that each `CueClusterPosition` still starts a cluster | Seeking lands mid-element |
| `timing` | `TimestampScale`, `Duration`, per-cluster `Timestamp` | Wrong duration, drifting playback |
| `seek_positions` | Every `SeekHead` entry still resolves to the `SeekID` it names | A demuxer jumps into the middle of something |
| `provenance` | C2PA/XMP attachments and tags | Provenance silently removed |

`CodecPrivate` gets called out by name in the failure detail, because losing it
is the difference between a file that plays differently and a file that does not
play at all.

## Cleanup: `Void` instead of `free`

EBML has its own padding element, `Void` (`0xEC`), and the cleanup uses it
exactly as the ISO-BMFF branch uses `free`: the selected `SimpleTag` is
overwritten in place with a `Void` of the same total length. Nothing moves, so
every `SeekHead` and `Cues` position stays correct without being rewritten.

`void_element(length)` is exact by construction and tested at 2, 3, 8, 129,
1000, 20,000, and 5,000,000 bytes, because the whole substitution depends on
the replacement being the same size as what it replaced. The minimum is two
bytes — one identifier, one size — which every real element exceeds.

A document carrying a provenance attachment is refused outright, for the same
reason an MP4 with a C2PA box is: a manifest binds byte ranges of the file it
lives in, and any edit invalidates it.
