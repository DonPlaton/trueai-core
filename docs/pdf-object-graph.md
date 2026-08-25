# PDF: a bounded object graph, and why the regex was not enough

`trueai/core/pdf_objects.py` walks a PDF's object graph. The lexical scanner it
sits in front of finds `trailer`, reads `/Info`, and locates objects by searching
for `N G obj`.

## The coverage hole

That approach works on PDFs written the way they were written in 2003. Since
PDF 1.5 a producer may put the cross-reference table in a **stream** — so the
word `trailer` appears nowhere in the file — and put `/Info` and the catalog
inside a compressed **object stream**, so `/Author` never appears as plain text
either.

Against those files the lexical scanner reports nothing at all. And reporting
nothing looks exactly like finding nothing: a clean scan of a document full of
personal metadata is worse than no scan, because someone acts on it.

`tests/unit/test_pdf_object_graph.py` builds both shapes and asserts the premise
directly: the modern fixture contains neither `trailer` nor `/Author` as bytes,
and the lexical reader returns an empty list for it.

## What the graph reads

- `startxref` to a classic cross-reference table **or** a cross-reference stream;
- `/Prev` back through incremental updates, and `/XRefStm` for hybrid files;
- object streams (`/ObjStm`), which is where the metadata now lives;
- `/Root` to the catalog, `/Info`, `/Metadata` for XMP;
- `/AcroForm/Fields` for signature fields and the byte ranges they cover.

Signature byte ranges are recorded because a signature covers explicit ranges of
the file: any edit inside them invalidates it, and the gap between them is where
the signature itself sits. A cleaner has to know both.

## Why this module is mostly limits

Walking the graph means decompressing attacker-supplied data. A PDF can ask a
parser to allocate as much memory as the parser is willing to allocate, and the
classic attack is a few kilobytes of Flate that expand to gigabytes.

Every decompression goes through `inflate_bounded`, which passes the cap **into**
the decompressor rather than decompressing and then checking the size. That is
the difference between refusing a bomb and detonating it and then complaining
about it.

| Budget | Default | What it stops |
|---|---|---|
| `max_objects` | 50,000 | An object table that exists to be walked forever |
| `max_inflated_bytes` | 64 MB | Charged **per document**, so a file cannot spend a little on each of ten thousand streams |
| `max_stream_bytes` | 16 MB | One stream, raw or decompressed |
| `max_xref_sections` | 64 | A `/Prev` chain that is a loop by another name |
| `max_depth` | 32 | Nested arrays and dictionaries |
| `max_tokens` | 2,000,000 | A document that is syntactically enormous rather than deep |

Two exception types, because they say different things: `PdfStructureError`
means the file is malformed, `PdfLimitExceeded` means it is trying to exhaust the
parser. Only one of those is an attack.

## Filters it refuses to guess at

`FlateDecode` and `ASCIIHexDecode` are decoded. LZW, RunLength, DCT, JBIG2,
CCITT, and any crypt filter are not: the stream is reported as present and
undecoded rather than decoded by guesswork. An inspector that pretends to have
read a stream it could not decode reports absence as evidence.

The same principle covers the model as a whole. When a budget is exhausted or a
section cannot be read, the reason lands in `PdfModel.incomplete` and
`modelled` is false. A caller that treated a partial model as complete would
report "no metadata" for a document whose metadata simply exceeded the budget.

## Two readers, and which one spoke

The detector tries the graph first and falls back to the lexical scan when the
graph cannot model the document within its budget — a file that defeats the
parser should still yield whatever a regular expression can honestly find.

Every finding records which reader produced it, in `evidence["reader"]`.
"Nothing found" and "nothing found because the parser gave up" are different
statements, and a detector that renders them identically is telling the reader
something false.
