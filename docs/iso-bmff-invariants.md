# MP4, MOV, and M4A: what a cleanup must not change

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

## Status

`FMT-01` delivers the specification and the verifier. The cleaner still refuses
ISO-BMFF — `parse_media_metadata` marks no MP4 entry `remediation_safe`, and
`MediaCleaner` raises "supports only WAV, MP3, and FLAC audio containers". Two
tests pin that: one asserts the refusal is still in place, and one asserts the
invariants are *satisfiable* by a correct edit, because a specification nothing
can pass is a refusal wearing a gate's clothes.

`FMT-02` is the implementation that has to pass through it.
