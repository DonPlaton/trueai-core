# Safety and provenance boundary

TrueAI may inspect and predictably normalize user-owned files. It may remove ordinary creator,
generator, comment, text-chunk, EXIF, XMP, or explicit attribution material when policy selects a
supported cleaner. Every supported cleaner writes a separate output by default and proves an
artifact-specific integrity invariant before publication.

TrueAI does not defeat, forge, or secretly erase robust forensic watermarks or signed provenance.
It does not implement secret-provider-key inference or a statistical watermark attack. Provider
adapters report support status honestly. Built-in policies preserve C2PA and provider watermark
findings and reject removal rules for those categories.

## Provenance support

- C2PA marker discovery during a scan: literal compatible-marker detection, always reported as
  unverified and never removable.
- C2PA verification as a separate explicit operation: the reference implementation validates the
  manifest signature and content hashes, reports the signing certificate, and reports whether that
  certificate chains to a trust anchor the operator supplied. Available through
  `trueai verify` and `trueai.verify_provenance` with the optional `c2pa` extra installed.
- Anthropic/OpenAI/Google watermarks: official public verification is not integrated; adapters
  return `VERIFICATION_UNAVAILABLE`.
- Generic watermark: no provider can be selected; the adapter returns `NOT_SUPPORTED`.

Marker presence is deterministic evidence of bytes, not authenticated provenance. A `valid`
verification result — correct signature, unknown signer — is not authenticated provenance either.
Only `trusted` establishes it. See [provenance](provenance.md).

Verification never runs implicitly during a scan, and it never fetches a remote manifest unless
explicitly permitted.

## Integrity invariants

- Text: emitted bytes equal the exact planned span transform with encoding preserved.
- DOCX: every non-approved package entry is byte-identical, ordered Word content tokens match, and
  every unselected node/comment/processing instruction in changed metadata parts is canonical-equal.
- PPTX: the same package-level proof, with slide, layout, master, and notes text as the content
  invariant.
- XLSX: the same package-level proof, with cell values, formulas, inline strings, and shared
  strings as the content invariant.
- SVG: metadata-independent visible/active element structure, attributes, text, and processing
  instructions match.
- PNG/JPEG: compressed pixel-bearing chunks/scan data are byte-identical; rendering-critical EXIF
  such as Orientation is preserved.
- PDF optional cleanup: every reachable non-selected indirect object and raw stream payload
  matches before and after. Object/page/stream budgets are enforced without decoding page streams.

An integrity failure prevents the temporary output from replacing or publishing the destination.
Plans are also rejected if the source SHA-256 changed after scanning or if the report contains a
blocking incomplete/corrupt diagnostic.

## Third-party code

Plugins declare a capability manifest; the host policy decides what is granted before any plugin
runs. Detection is read-only, so filesystem writes, process creation, and network access are denied
by default even to a plugin that requests them, and a refused plugin is reported in the scan rather
than silently dropped.

Subprocess isolation contains crashes, hangs, and unbounded output, and re-derives every returned
finding so a plugin cannot forge an identity, reattribute a finding, or impersonate another
detector. Guards are installed before the plugin module is imported, so import-time and constructor
code is covered.

It is not an operating-system sandbox: the worker runs as the same user with the same filesystem
access, restrained only by Python-level guards, and reading a manifest still imports the plugin's
module in the host. See [plugins](plugins.md).

## Text decoding

A textual artifact is decoded exactly or reported as corrupt. Substituting
replacement characters would make every offset a detector reports refer to a
string the cleaner cannot reconstruct, so an approved removal would cut the wrong
bytes. An undecodable file produces a high-severity diagnostic, exit code `3`, and
no remediation.

## Caching

Cached results are keyed by content, configuration, and package version, so a changed byte can
never return a stale finding. Failed and incomplete scans are never cached, and a corrupt cache
entry degrades to a slow scan instead of a wrong one. The cache is local; nothing is uploaded.
