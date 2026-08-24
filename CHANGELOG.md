# Changelog

All notable changes to TrueAI Core are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
semantic versioning. Before `1.0.0` the minor number carries breaking changes.

The **report schema version** moves independently of the package version. A schema
change is called out explicitly and governed by
[docs/schema-compatibility.md](docs/schema-compatibility.md).

## [Unreleased]

### Added

**Attestation workflow, evidence adapters, and redaction**

- `trueai attestations init | validate | issue | sign | verify | summarize |
  redact | keygen | schema`, with a matching Python API. Everything runs offline.
- A declarative YAML manifest describes actors, evidence, activities, decisions,
  validations, and claims. The starter manifest claims nothing it cannot support,
  so running `issue` unedited yields a narrow record rather than an overclaiming
  one.
- Local evidence adapters for Git commits and repository state, reviewed diffs,
  command and test receipts, build outputs, research notes, citations, approvals,
  external receipts, tool identity, scan reports, and audit certificates — all
  recorded by digest. A private commit's summary and a private note's contents
  never enter the record, which is asserted rather than assumed.
- Salted commitments, so committing to a short guessable statement cannot be
  confirmed by hashing a guess. The salt is returned to the holder, never stored.
- Deterministic `redact_for_public`: private and committed evidence keeps its
  identifier, kind, and commitment and loses everything identifying, while claims
  are kept in full because they are what the record is for. The redacted variant
  gets a new identifier and drops signatures, which covered the unredacted bytes.
- Summaries print the stage table and always repeat the record's own limitations.
- `attestations verify` reports each property separately and exits 0 only for an
  authenticated declaration, 1 for an unsigned or self-declared record — an honest
  state, not a failure — and 2 for a changed artifact or an invalid signature.


**Human Contribution Records (process attestations)**

- `trueai/core/attestation.py` records who originated, framed, decided, executed,
  validated, integrated, and took responsibility for the work behind an artifact,
  with a content-derived `TAIP1-…` identifier bound to the exact subject bytes.
- Contribution is a vector over eight independent dimensions, never a percentage.
  The module contains no aggregate-score function, and a test asserts none exists.
- AI autonomy is a per-stage property, so a record can say execution was delegated
  to a model while origination, framing, validation, and accountability stayed
  human.
- Claim type (`machine_fact`, `declaration`, `assessment`) travels with every
  claim. A `machine_fact` without recomputable evidence and a `declaration`
  claiming independent assessment of itself are both refused at construction.
- Evidence is referenced by digest, never copied. Private evidence may not carry a
  locator, committed evidence carries a commitment that later disclosure is checked
  against, and omitted evidence must state why.
- Verification returns independent results — schema, content ID, artifact binding,
  each signature role, expiry, profile support, disclosure consistency, dissent,
  limitations — instead of one badge. The only derived property is named
  `authenticated_declaration`, which is the honest ceiling for a self-signed record.
- Four standing limitations are mandatory and a record missing any of them is
  invalid.
- `schema/trueai-process-attestation-0.1.schema.json` is a separate published
  contract from the audit certificate, and `docs/process-attestation.md` documents
  the taxonomy and the threat model with the control for each threat.


**Reproducible auditor environment**

- `uv.lock` pins every dependency by hash, and CI fails when it drifts from
  `pyproject.toml`.
- A `Dockerfile` pinned to its base image by digest builds the wheel and sdist
  with normalised file modes, so the artifacts do not depend on which operating
  system ran `docker build`. Two independent `--no-cache` builds produce
  byte-identical artifacts, checked by `scripts/verify_reproducible_build.py`.
- `scripts/record_build_inputs.py` writes `build-inputs.json` next to the
  artifacts: source commit, build clock, interpreter, tool versions, lock digest,
  base image, and the SHA-256 of everything produced.
- `scripts/compare_builds.py` gained `--content`, which distinguishes a real
  difference in shipped files from ZIP framing that varies between platforms. It
  never reports a content difference as success.
- The source distribution now carries the lock and the container definition, so it
  can rebuild and re-verify itself.
- `docs/reproducible-builds.md` documents the procedure and states precisely where
  byte-for-byte reproduction holds and where it does not.

**Frozen Python API contract**

- `trueai/api.py` enumerates the public modules, describes every exported name,
  and classifies differences between two surfaces as additive or breaking.
- `api/published/trueai-api-0.1.json` is the frozen contract;
  `api/trueai-api-0.1.json` is the snapshot of what the code exposes. A stale
  snapshot fails CI, so no public-surface change merges unreviewed.
- `docs/api-compatibility.md` states what may change inside version `0.1` and the
  announce/warn/wait/remove deprecation rule.


**Clean-delivery verification and audit certificates**

- `trueai clean` now rescans the bytes it actually publishes and reports `clear`,
  `indicators_remain`, or `incomplete`; heuristic findings are reported rather than
  rewritten away.
- `trueai certificates issue|verify|keygen` creates content-bound `TAI1-…` audit
  records for files and recursive inventories, with optional Ed25519 issuer signatures.
- Optional certificate expiry plus signed, finite-lifetime, sequenced revocation lists through
  `trueai certificates revoke`; strict verification can require a current issuer-authenticated list.
- Certificates bind package/schema versions, exact report and artifact hashes, policy,
  detector scope, resource boundaries, diagnostics, findings, and explicit limitations.
- The certificate claim is deliberately “no indicators detected in scope,” never proof
  of human authorship or proof that AI assistance was absent.

**Signed enterprise policy**

- Content-addressed, finite-lifetime Ed25519 policy bundles through
  `trueai policies bundle-create|bundle-verify|bundle-schema`.
- Exact finding-ID baselines, selector-based finite suppressions, and finite action exceptions.
- Controls alter only policy decisions; findings remain serialized and each applied or expired
  control is recorded in `policy_audit`.
- Conflicting exceptions fail closed, and C2PA/provider watermark findings remain preserved
  regardless of enterprise overrides.

**Audio and video metadata**

- Signature-based discovery for WAV, MP3, FLAC, M4A, MP4/MOV, and WebM/Matroska containers.
- `media.container-metadata.v1` reads bounded RIFF INFO/BEXT, ID3v1/v2, Vorbis comments,
  ISO BMFF/QuickTime keyed metadata and XMP boxes, and EBML application/tag fields without
  decoding media streams.
- Generator, personal, ordinary media, literal provider attribution, and protected provenance
  evidence remain separate findings.
- Surgical WAV, MP3, and FLAC cleanup removes only selected RIFF INFO/BEXT/XML fields, ID3v1/v2
  fields, or Vorbis comments. The integrity gate verifies the exact planned transform and
  byte-identical audio-bearing payload; no codec is invoked and protected provenance blocks the
  operation.
- M4A, MP4/MOV, and WebM remain inspection-only until sample-table, timing, index, and provenance
  invariants can prove a container rewrite harmless.

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
- `trueai scan --verify-provenance` can attach typed authenticated results directly to JSON and
  terminal reports while retaining separate marker findings.
- Report-attached verification is content-bound to the scan descriptor; a size or SHA-256 change
  between scanning and verification fails closed.
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
- Plugin manifests are now inspected in a capability-guarded helper without importing
  third-party modules in the scanner process. Subprocess execution is the default.
- Plugin stdout/stderr are discarded rather than captured in unbounded host buffers.
- Helper processes install kernel CPU and memory limits before plugin import through POSIX rlimits
  or a Windows Job Object; inability to install a configured limit fails closed.

**Release engineering**

- Cross-platform CI: Python 3.12, 3.13, and 3.14 on Linux, macOS, and Windows.
- The attestation dependency now requires the security-fixed `cryptography` 50.x line; the
  release audit fails on known vulnerable transitive dependencies.
- Security cases that can only run on POSIX now fail instead of skipping there, so
  the suite cannot report green while covering less than the security policy claims.
- Reproducible-build comparison, packaged-manifest verification, dependency audit,
  license allowlist, and CycloneDX SBOM generation.
- The license gate follows the installed TrueAI runtime dependency closure and selected extras,
  excluding CI tools that are not shipped to users; workflows use the current CycloneDX CLI.
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

- `PluginIsolation.SUBPROCESS` replaces fully trusted in-process execution as the
  default for the Python API, registry discovery, and CLI. `in_process` remains an
  explicit compatibility/trust choice.

- The C2PA marker finding now records `"verification": "not_attempted"` and points
  at `trueai verify`, replacing the previous claim that verification was
  unavailable.
- `ArtifactType` gained `pptx`, `xlsx`, `audio`, and `video`; `FindingCategory` gained
  `media_metadata`. Adding an enum member is a compatible
  change inside schema `0.1`; consumers must tolerate unknown members.
- DOCX detection and cleanup moved onto a shared Office Open XML implementation.
  Detector IDs, finding identities, remediation identifiers, and integrity
  semantics for DOCX are unchanged.
- `pytest` no longer pins its temporary directory inside the repository.

### Fixed

Found in review of the changes above, each with a regression test:

- Caller-supplied directory/repository `Artifact` objects now establish the same
  recursive inventory baseline as path-based scans instead of reporting every existing
  child as a detector-created file.
- Cache entries are size-checked before reading, and cache symlink/junction components
  disable the operation instead of redirecting writes outside the configured tree.
- Invalid C2PA trust settings fail closed instead of silently falling back to an
  unconfigured verifier while reporting that trust anchors were configured.
- The `pathspec` range now includes compatible 1.x releases. The former `<1` cap
  conflicted with supported recent mypy releases and made a fresh `.[dev]` resolve
  impossible even though TrueAI uses the unaffected public `GitIgnoreSpec` API.
- The release license gate now parses simple SPDX `OR`/`AND` expressions instead
  of rejecting dual-licensed dependencies whose individual licenses are allowlisted.

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
