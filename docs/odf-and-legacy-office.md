# ODF and legacy binary Office: the evaluation, and what it decided

`FMT-06` was an evaluation with a condition attached: proceed **only** with a
maintained parser, hostile-input tests, and a format-specific integrity proof.
Two formats were assessed against those three. One passed and one did not, and
the reasoning is recorded here because a refusal that is not explained is
indistinguishable from an omission.

## OpenDocument — proceed

| Condition | Assessment |
|---|---|
| Maintained parser | `zipfile` and `defusedxml`, both already in the dependency set and already used for Office Open XML. No new dependency. |
| Hostile-input tests | The ZIP safety layer in `trueai/detectors/documents/opc.py` applies unchanged — same container, different part names. Path traversal, encrypted entries, entry counts, compression ratios, and uncompressed-size caps are all inherited rather than reimplemented. |
| Integrity proof | Obvious and cheap: the document text lives in `content.xml`, the metadata in `meta.xml`, as separate archive entries. Proving a metadata-only edit means proving `content.xml` is byte-identical and every other entry is unchanged. |

All three hold, so ODF is implemented: detection in
`trueai/detectors/documents/odf.py`, cleanup in `trueai/cleaners/odf.py`.

### One type, not three

ODF text, spreadsheets, and presentations share one content part and one
metadata part, unlike OOXML where each family has its own (`word/document.xml`
versus `xl/workbook.xml`). So there is a single `ArtifactType.ODF` and a single
detector, and the subtype is read from the package's `mimetype` entry and
reported in each finding as `document_kind`.

Identification reads that entry from the file's opening bytes. The specification
requires `mimetype` to be first and stored uncompressed, so the declared type
sits in plain bytes near the start — the archive is never opened during type
identification, and a hostile package cannot be inflated merely by being looked
at. The file name is not consulted first, because an extension is
attacker-controlled and the package's own declaration is not.

### The `mimetype` entry during cleanup

The rewrite preserves both of that entry's required properties — first in the
archive, stored without compression — explicitly, rather than relying on
`zipfile` to happen to do the right thing. A package that loses either stops
being recognised by the applications that read it, which would be a cleanup that
broke the file while leaving every byte of its content intact. The integrity
proof checks both, so the failure would be caught rather than shipped.

### What is reported and what is refused

`meta.xml` fields are reported by name, including `meta:user-defined` fields
under their declared name. A field whose value carries a provenance marker is
reported and marked unremovable. Macro storage (`Basic/`, `Scripts/`) is
**listed, never parsed and never executed** — a reader deciding whether to open
a document needs to know it is there.

An unrecognised `opendocument` subtype still has its metadata read, and the
subtype is reported so a reader is not left guessing why the document looks
unfamiliar.

## Legacy binary Office — do not proceed

`.doc`, `.xls`, and `.ppt` are Compound File Binary containers: a FAT-chained
pseudo-filesystem holding property-set streams.

| Condition | Assessment |
|---|---|
| Maintained parser | `olefile` is maintained and is **read-only**. Nothing maintained writes CFB. Cleanup would mean implementing FAT and mini-FAT chain rewriting here. |
| Hostile-input tests | CFB is a well-known parser-attack surface: FAT loops, sector chains that reference themselves, mini-stream cycles, directory entries pointing at each other. Writing those tests is possible; passing them with a hand-rolled writer is a different order of work. |
| Integrity proof | Would have to reason about sector chains rather than about independent entries. Every other integrity proof in this project compares things that are separable — ZIP entries, sample byte ranges, EBML elements. A CFB proof compares a container whose parts are interleaved by design. |

Two of the three fail. The decision is to **identify the format and not inspect
it**.

`ArtifactType.LEGACY_OFFICE` exists so a `.doc` is recognised by its CFB header
and reported as a file that was not inspected. That is the point of the type:
**a file silently skipped looks exactly like a file that was clean**, and a
report that renders those two the same way is telling the reader something
false. `cleaner_for(ArtifactType.LEGACY_OFFICE)` raises, and a test pins the
refusal so it stays a decision rather than decaying into an oversight.

## Revisiting

The bar has not moved. If a maintained CFB writer appears, or if the scope is
narrowed to read-only detection with the hostile-input tests written first, the
evaluation is worth redoing. Until then the honest position is that TrueAI can
tell you a legacy binary Office file is there and cannot tell you what is in it.
