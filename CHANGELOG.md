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
  A completed scan is byte-identical to a sequential one because results merge in
  artifact order, and the finding budget is shared globally across workers.
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
  policy decides before any of its code is trusted. Filesystem writes, process
  creation, and network access are denied by default.
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

### Security

- Ungranted capabilities now fail loudly inside a plugin worker rather than
  succeeding silently.
- The plugin boundary is documented as containment rather than sandboxing, in the
  module docstring, the security policy, and the plugin guide.

## [0.1.0-dev] - 2026-08-21

Initial development baseline: detector registry, policy engine, remediation with
per-format integrity proofs, terminal/JSON/SARIF reporters, CLI, and the
text, source, Git, HTML/CSS, SVG, DOCX, PDF, PNG, and JPEG detectors.
