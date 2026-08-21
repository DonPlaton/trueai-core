# Changelog

All notable changes to TrueAI Core are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
semantic versioning. Before `1.0.0` the minor number carries breaking changes.

The **report schema version** moves independently of the package version. A schema
change is called out explicitly and governed by
[docs/schema-compatibility.md](docs/schema-compatibility.md).

## [Unreleased]

### Added

**Office Open XML expansion**

- PPTX inspection (`documents.pptx-forensics.v1`): speaker notes, review comments,
  comment author identities, and a slide inventory, on top of the shared OPC
  metadata evidence.
- XLSX inspection (`documents.xlsx-forensics.v1`): hidden and very hidden
  worksheets, cell comments and their authors, threaded comments with persistent
  participant identities, defined names left by tooling, and external workbook
  links. Links are reported, never resolved.
- Verified metadata cleanup for both formats, with content invariants of their own:
  slide, layout, master, and notes text for PPTX; cell values, formulas, inline and
  shared strings for XLSX.
- Macro-project detection for every Office Open XML family. The presence of a VBA
  project is reported; macro bytecode is never parsed or executed.
- Package identification now recognises the family from the required part rather
  than the file name, including the macro-enabled and template extensions.

**Authenticated provenance**

- `trueai verify` and `trueai.verify_provenance()` validate C2PA manifests through
  the reference implementation, using the optional `c2pa` extra.
- Verification reports the signing certificate, claim generator, assertions, and
  every individual validation check with the verifier's own codes.
- `trusted` (chains to a configured trust anchor) and `valid` (correct signature,
  unknown signer) are separate states. Without the optional dependency the result
  is `verifier_unavailable`; nothing is inferred.
- Remote manifests are never fetched unless explicitly permitted.
- Signed test fixtures are generated at test time from a throwaway CA, so the suite
  covers real signature validation without redistributing anyone's certificates.

**Repository scale**

- `--jobs N` / `ScanOptions.max_workers` inspects several artifacts concurrently.
  The scan is byte-identical to a sequential one, including when truncated, because
  the shared finding budget is charged in artifact order rather than in completion
  order.
- `--cache` / `ScanOptions.cache_directory` reuses detector output for unchanged
  content, keyed by artifact digest, path, type, detector set, resource limits, and
  package and schema versions. Failed and incomplete scans are never cached.
- `trueai cache path` and `trueai cache clear`.
- Nested `.gitignore` and `.trueaiignore` files now use Git's directory-relative
  semantics: a nested file applies only beneath its own directory, a deeper rule
  overrides a shallower one including through negation, and an ignored directory is
  no longer descended into.

**Plugin governance**

- Capability manifests: a plugin declares what it is and what it needs, and the host
  policy decides before the detector is constructed or run. Filesystem writes,
  process creation, and network access are denied by default.
- `PluginIsolation.SUBPROCESS` runs each plugin in a separate interpreter with a
  deadline, a size-bounded response, and capability guards.
- Every finding returned by an isolated plugin is re-derived from its own evidence,
  so a plugin cannot forge a finding identity, reattribute a finding, or impersonate
  another detector.
- Refused plugins appear in the report as `plugin_rejected` diagnostics instead of
  silently reducing coverage.
- `trueai plugins list` and `trueai scan --plugins in_process|subprocess|disabled`.

**Release engineering**

- Cross-platform CI: Python 3.12, 3.13, and 3.14 on Linux, macOS, and Windows.
- Security cases that can only run on POSIX now fail instead of skipping there, so
  the suite cannot report green while covering less than the security policy claims.
- Reproducible-build comparison, packaged-manifest verification, dependency audit,
  license allowlist, and CycloneDX SBOM generation.
- Release workflow with tag/version agreement, build provenance attestation,
  Sigstore signing, and PyPI trusted publishing.
- The source distribution now ships the test suite, docs, published schema, and
  release scripts, so it can rebuild and re-verify itself offline.

**Public schema contract**

- `trueai schema` emits the report JSON Schema for downstream consumers.
- `schema/published/` holds the frozen contract; `trueai.schema` classifies any
  difference between two schema versions as additive or breaking, and CI fails on a
  breaking change or a stale snapshot.

### Changed

- The C2PA marker finding now records `"verification": "not_attempted"` and points
  at `trueai verify`, replacing the previous claim that verification was
  unavailable.
- `ArtifactType` gained `pptx` and `xlsx`. Adding an enum member is a compatible
  change inside schema `0.1`; consumers must tolerate unknown members.
- DOCX detection and cleanup moved onto a shared Office Open XML implementation.
  Detector IDs, finding identities, remediation identifiers, and integrity
  semantics for DOCX are unchanged.
- `pytest` no longer pins its temporary directory inside the repository.

### Fixed

Found in review of the changes above, each with a regression test:

- **SVG cleanup could delete rendered text and still report `PASS`.** The visible
  structure invariant ignored the text that follows a node, so removing a comment
  mid-sentence took the rest of the sentence with it unnoticed. Each element now
  records the character data it renders directly, compared the way SVG renders
  whitespace so indentation between elements is still not treated as content.
- **SVG editor-attribute cleanup removed more than the plan approved.** It swept
  every editor-prefixed attribute in the document rather than the ones the policy
  selected, and the canonical form filters exactly those attributes out, so the
  over-removal was invisible to the integrity gate.
- **JPEG cleanup failed on ordinary photographs.** The cleaned scan payload was
  located by searching for the SOS marker from byte zero, which matched the first
  `FF DA` inside a retained EXIF thumbnail, colour profile, or comment. The offset
  is now known by construction.
- **`trueai clean` aborted when one removal contained another.** An invisible
  character inside an attribution line was treated as an overlap and nothing was
  cleaned. A fully nested span is absorbed into the enclosing one; only a partial
  overlap still requires review.
- **A scanned file could crash the terminal reporter.** Artifact-controlled text
  reached the Rich markup parser unescaped, so a file name or metadata value
  containing an unbalanced tag exited with an internal error, and a crafted C2PA
  manifest could style its own verification verdict.
- **SARIF output dropped scan diagnostics.** A truncated, corrupt, or
  mutated-during-scan run reached a code-scanning dashboard looking like a clean
  one. Diagnostics are now emitted as tool-execution notifications and a blocking
  diagnostic marks the invocation unsuccessful.
- **Undecodable text was scanned with replacement characters.** Every offset then
  referred to a string the cleaner could not reconstruct, so an approved removal
  would have cut the wrong bytes and a malformed UTF-16 file raised an unhandled
  decoding error. Such an artifact is now reported as corrupt.
- **Commits with an empty message were silently dropped** by a strip that removed
  the field delimiter along with the empty field.
- **The OOXML cleaner re-opened packages under its own default limits** instead of
  the boundaries the scan ran under. The scan's options now travel with the
  operation.
- **A duplicate detector id aborted plugin discovery** after earlier plugins were
  already registered, so an installed package could stop the tool from starting.
  Discovery now reviews the whole set and registers only what it accepts.
- **Host policy ran after the plugin was constructed.** A block list, allow list,
  or `require_manifest` could not stop a refused plugin's constructor. The decision
  now precedes construction, and under subprocess isolation the detector is built
  only in the worker.
- **Worker capability guards were installed after the plugin was imported**, so
  import-time and constructor code ran unrestricted while the documentation said
  otherwise. Guards now precede the import.
- **The filesystem guard covered only `builtins.open`,** leaving `Path.open`,
  `io.open`, and `os.open` as ordinary ways to write.
- **A budget-exhausted parallel scan was not reproducible.** The finding budget was
  consumed in completion order, so which artifacts kept findings varied between
  runs. It is now charged in artifact order through a bounded submission window.

### Performance

- Unicode forensics no longer classifies every character individually. A single
  prefiltering pass skips ordinary ASCII, making the detector roughly seven times
  faster on source-like text with byte-identical findings.

### Security

- Ungranted capabilities now fail loudly inside a plugin worker rather than
  succeeding silently, from the moment the plugin module is imported.
- The plugin boundary is documented as containment rather than sandboxing, in the
  module docstring, the security policy, and the plugin guide, including the limit
  that reading a manifest still imports the plugin's module.

## [0.1.0-dev] - 2026-08-21

Initial development baseline: detector registry, policy engine, remediation with
per-format integrity proofs, terminal/JSON/SARIF reporters, CLI, and the
text, source, Git, HTML/CSS, SVG, DOCX, PDF, PNG, and JPEG detectors.
