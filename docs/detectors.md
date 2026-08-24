# Built-in detectors

## Stable by default

- `text.unicode-forensics.v1`: named invisible/format/control characters, contextual safety class,
  offsets, line/column, and repeated whitespace measurements. ZWJ, ZWNJ, and variation selectors
  are never marked automatically removable.
- `text.explicit-attribution.v1`: provider rule packs in plain text and Markdown.
- `code.comment-attribution.v1`: Python tokenizer or conservative source-comment spans.
- `git.commit-attribution.v1`: bounded all-ref commit messages and trailers; no checkout or hooks.
- `git.repository-context.v1`: tracked assistant configuration as neutral tooling context.
- `web.html-forensics.v1` / `web.css-forensics.v1`: generator metadata, comments, hidden rules,
  scripts, and embedded data URIs without loading resources.
- `documents.docx-forensics.v1`: validated OPC properties, comments, tracked revisions,
  relationships, custom XML, embeddings, and macro projects.
- `documents.pptx-forensics.v1`: the same OPC evidence plus speaker notes, review comments, comment
  author identities, and a slide inventory. Speaker notes are invisible in presentation mode and
  routinely retain drafting context.
- `documents.xlsx-forensics.v1`: the same OPC evidence plus hidden and very hidden worksheets, cell
  comments and their authors, threaded comments with persistent participant identities, defined
  names left behind by tooling, and external workbook links. Links are reported, never resolved.
- `documents.pdf-forensics.v1`: trailer-bound Info entries plus bounded literal XMP and structure
  markers; no rendering. Optional `pikepdf` is used only for cleanup and reachable-object
  verification.
- `design.svg-forensics.v1`: metadata, editor residue, hidden/off-canvas structure, scripts/data URIs,
  duplicate paths, and potentially unused IDs.
- `design.raster-metadata.v1`: Pillow-exposed PNG/JPEG text, XMP/comment, and EXIF metadata.
- `media.container-metadata.v1`: bounded WAV RIFF INFO/BEXT, MP3 ID3v1/v2, FLAC Vorbis comments,
  ISO BMFF/QuickTime keyed metadata, and WebM/Matroska EBML application/tag fields. It never
  decodes media streams. Exact WAV/MP3/FLAC fields are removable through a separate cleaner;
  ISO BMFF/QuickTime and EBML findings remain inspection-only.
- `provenance.c2pa-marker.v1`: marker discovery only, explicitly unverified and preserved. Scanning
  never verifies a signature; see [provenance](provenance.md).

## Experimental, opt-in

- `text.stylometry-experimental.v1` emits a finding only after `StylometryFeatureExtractor`
  produces sentence, paragraph, punctuation, lexical, transition, phrase-reuse, and symmetry data.
- `design.style-experimental.v1` consumes measurable spacing, radius, color, gradient, shadow,
  typography, and duplicate-path features.

Enable experimental detectors with `trueai scan PATH --experimental`. Their findings say “not
provenance” and use `HEURISTIC` confidence.

## Office Open XML detectors share one implementation

Word, PowerPoint, and Excel packages differ only in their content parts. The shared base collects
document properties, custom properties, custom XML, relationships, embeddings, and macro projects
once, so a security boundary cannot hold for one format and quietly not for another. Each format
subclass contributes its content-specific findings and declares the invariant its cleaner must
preserve: Word content tokens, slide and notes text, or cell values, formulas, and shared strings.

## Adding a detector

Choose a versioned ID, narrow supported artifact types, provide evidence and false-positive tests,
and document provider assumptions. A detector must never mutate, fetch network content, execute
embedded code, or describe a heuristic as authentication.

Default engines discover the `trueai.detectors` entry-point group after reviewing each plugin's
capability manifest against the host policy. Plugins may run in-process as trusted code or in a
worker process with capability guards and a deadline. Persistent file mutation and newly discovered
paths invalidate the scan in either mode. See [plugins](plugins.md).
