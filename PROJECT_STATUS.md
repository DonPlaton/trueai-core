# TrueAI Core: Project Overview and Status

Status date: 2026-08-30
Package version: `0.1.0-dev`  
Public report schema: `0.1`  
License: Apache-2.0

## Executive summary

TrueAI Core is a local-first forensic scanner and predictable sanitizer for artifacts created or
modified with AI-assisted tools. It identifies concrete traces such as metadata, attribution,
invisible Unicode, repository history, structural residue, provenance markers, and conservative
style measurements.

The project does not make unsupported claims that an artifact is AI-generated. It separates four
fundamentally different evidence classes:

1. deterministic observations;
2. authenticated or officially verified provenance;
3. provider watermark verification results;
4. probabilistic or heuristic style signals.

The current release is a production-oriented development baseline rather than a prototype. All 49
repository-owned backlog items are implemented. This includes the public API and CLI, detector and
policy architecture, bounded scanning, remediation and integrity proofs, official C2PA verification,
PPTX/XLSX/ODF and media support, ISO-BMFF and EBML surgical cleanup, repository-scale parallelism and
cache lifecycle, platform-aware plugin confinement and signed plugin distributions, content-bound
audit certificates, enterprise trust primitives, process attestations (`TAIP1`), HTML/CI/IDE/desktop
projections, research governance contracts, supply-chain gates, reproducible packaging, and incident
response runbooks.

The hosted cross-platform matrix now passes in full: Linux, macOS, and Windows across Python
3.12, 3.13, and 3.14, plus the container reproducibility, supply-chain, plugin trust boundary,
authenticated C2PA, schema, and distribution jobs. Getting there found eleven defects that no amount
of local work could have surfaced, and the audit that followed found a further eight, seven of them
denial-of-service paths a hostile artifact could reach through `trueai scan`.

A second audit pass then read the modules that had not been touched since they were written, and
found thirteen more. Three are denial-of-service paths reachable through `trueai clean`, all of them
work quadratic in a count the file chooses from an input of a few hundred kilobytes: the MP4 and
WebM models scanned their whole element list once per track, cluster, cue point, seek entry, and
attachment, and an `stsc` table whose `first_chunk` rewinds re-swept the chunk list once per entry.
The fuzzer had covered both models since the harness landed and found none of them, because nothing
raises and nothing corrupts — the process simply does not come back. A fourth let an EBML leaf
declaring an unknown size hide every element after it from the model, which then reported itself
complete. The rest are honesty and reporting defects of the kind this project holds itself to: a
manifest verified without opening a file looked like one whose files matched, a finding without a
line number never said which file it was in, and a green post-clean verdict printed over findings
its own rescan was holding, and a saved report could declare a finding count its own findings
contradicted — that last one found by the fuzzer, which mutates a real report and reloads it.

All thirty-two are fixed and each has a regression test. The detail is in `CHANGELOG.md`.

Two validation gates remain and both are external: PyPI/TestPyPI trusted publishing with hosted
release signatures and attestations, and consented design-partner pilots. The code and local gates for those
workflows exist. Platform claims are still deliberately bounded: Windows restricted tokens are not
AppContainer, two operating-system controls report `SKIP` on hosted runners rather than pass — both
verified against a real kernel and a real interactive session instead — and no trained
AI-authorship classifier or secret/statistical watermark remover is shipped.

## Current work board

This section is the operational source of truth for the active development cycle.

### Completed

- [x] Stable finding, artifact, policy, remediation, integrity, report, and certificate models.
- [x] Recursive bounded scanning for repositories and all v0.1 artifact families.
- [x] Deterministic text, Git, web, OPC, PDF, SVG, raster, and media-container inspection.
- [x] Safe cleanup for text, DOCX, PPTX, XLSX, PDF, SVG, PNG, and JPEG with post-clean rescans.
- [x] Provenance-preserving cleanup guards and explicit C2PA verification.
- [x] Content-bound audit certificates with Ed25519 signatures, expiry, and signed offline
  revocation lists.
- [x] JSON, SARIF, terminal reports, frozen schema checks, packaging, and adversarial tests.
- [x] Deterministic parallel repository scanning, incremental cache, and process-isolated plugins.
- [x] Surgical WAV, FLAC, and MP3 metadata cleanup with byte-identical audio-payload verification.
- [x] Format-specific media integrity records plus positive, refusal, and malformed-input tests.
- [x] Kernel CPU/memory quotas installed before third-party plugin import on Windows and POSIX.
- [x] Signed enterprise policy bundles, exact baselines, suppressions, exceptions, and report audit
  trails with protected-provenance enforcement.
- [x] Explicit authenticated C2PA verification embedded in terminal/JSON scan reports without
  mutating marker findings.

### In progress

- No implementation block is currently incomplete. The next block starts with the remaining
  priorities below.

The two unchecked `P0` items are both `external`. Nothing in the repository can complete them, and
a local run must not be presented as having done so.

**Every backlog item that can be completed from this repository is complete.** Three remain, all
`external` and all for the same reason — they need something the repository does not contain:

| Item | What it needs that a working tree cannot supply |
|---|---|
| `REL-02` | Configured TestPyPI/PyPI trusted publishers and protected environments. |
| `REL-03` | Release signing and provenance attestation from hosted CI. |
| `PROC-12` | Design partners who have consented to a pilot, and who will disagree with the rubric. |

The exact activation sequence, environment names, tag restriction, TestPyPI exercise, and
clean-machine verification commands are in [`docs/release.md`](docs/release.md).

The gates each of them would run — licenses, advisories, SBOM completeness, the packaged manifest,
the schema and API snapshots, reproducible rebuild, the documentation check — all run locally and
all pass. What cannot be done locally is running them *somewhere that counts*, and claiming
otherwise would be the kind of overstatement this project spends most of its code refusing to make.

### Known remaining backlog

This is the source of truth for all known unfinished work as of the status date. An unchecked item
is not an implied commitment for `0.1.0`; the priority labels identify sequencing. Tasks that need
external accounts or hosted infrastructure are explicitly marked `external`.

#### P0 — release candidate gates

- [x] `REL-01` Run the complete GitHub Actions matrix on hosted Linux, macOS, and
  Windows, including optional PDF/C2PA/attestation jobs and the symlink security cases.
  **Started.** The repository is published and the matrix has run once. It found six defects, five
  of which no amount of local work could have surfaced, because the suite had only ever run on one
  Windows machine and in a container: a test that confined the test runner and took 1,400 other
  tests down with it, an auditor image that shipped almost nothing it imports while remaining
  byte-for-byte reproducible, 25 unchecked type errors in the Windows plugin path, a `doctor` that
  elided the install command it exists to print, a ledger that could not say "Windows only", and a
  harness that called an unavailable control a broken one. All six are fixed. What remains for this
  item is the part a green run cannot claim on its own: the native confinement checks still report
  `SKIP` on hosted Linux, because unprivileged user namespaces are restricted there, so that control
  needs a container run with `TRUEAI_REQUIRE_CONFINEMENT=1` before the matrix is honestly complete.
  **Second pass.** The test matrix then reported 78 failures, which were two platform defects and
  four wrong tests. Plugins did not run on macOS at all, because one refused `rlimit` discarded the
  other; they did not run in any non-interactive Windows session, because a restricted token cannot
  attach to the creator's desktop; `--plugin-confinement required` on Windows meant "no plugin ever
  runs"; and the Windows confinement report claimed a restriction it never measured. All are fixed,
  and the worker now runs on a desktop of its own.
  **Green.** The whole matrix passes: three operating systems, three Python versions, every optional
  job. The last defect it caught was the most interesting one — `html.parser` in CPython up to 3.12
  rescans from every `<` that never closes, so a document of them made the 3.12 jobs hang for
  thirty-five minutes while 3.13 and 3.14 finished in five. That is a denial of service against any
  user on a supported interpreter, not a runner problem, and it was caught by a complexity test
  written earlier the same night for a different family of the same bug.
  **Closed.** The two controls a hosted runner refuses have now been exercised where they can be,
  with `TRUEAI_REQUIRE_CONFINEMENT=1` set so a skip would have been a failure.
  On Linux, in `python:3.12-slim` with `--security-opt seccomp=unconfined`:
  `scripts/verify_linux_confinement.py` reports the user, network, and read-only mount namespaces
  established and the seccomp filter *killing* the process on a denied syscall — `rc=-31`, SIGSYS,
  for an ungranted socket, for `execve`, and for `ptrace` — with the documented gaps still behaving
  as gaps. `scripts/verify_native_plugins.py` passes all eight checks including the two negative
  controls: with confinement off the same native plugin does escape and does open a socket, which is
  what makes the other six mean something.
  On Windows, on an interactive session, every restricted-token test runs rather than skipping.
  What a hosted runner cannot do is still worth saying: it reports `SKIP` for both, honestly, and
  that is a property of those machines rather than of the controls.
- [ ] `REL-02` (`external`) Configure protected `testpypi` and `pypi` environments plus their
  trusted publishers, then exercise the release workflow against TestPyPI.
- [ ] `REL-03` (`external`) Attest and sign the wheel, sdist, SBOM, build-input record, and checksums
  in hosted CI; verify the complete evidence set from a clean machine before cutting `v0.1.0rc1`.
- [x] `REL-04` Reproducible auditor environment: hash-locked `uv.lock`, a container pinned by base
  image digest, `build-inputs.json` recording source/lock/base/tooling and artifact digests, and a
  verified bit-for-bit reproduction procedure. Two `--no-cache` container builds produce identical
  artifacts; a cross-platform host build differs only in ZIP `create_system` and deflate framing,
  which `scripts/compare_builds.py --content` reports as framing rather than as success.
- [x] `REL-05` Frozen Python API surface in `api/published/`, with additive/breaking classification,
  a stale-snapshot gate, and documented deprecation rules in `docs/api-compatibility.md`.

#### P1 — hostile-plugin confinement and supply chain

- [x] `PLUG-01` `trueai/plugins/broker.py` defines one contract covering all five: a read-only
  artifact handle bound to the digest the host re-checks, a workspace grant confined to one
  resolved root, a host-owned scratch directory with a byte budget charged across every write,
  a `(host, port)` network allowlist, an executable allowlist, and a native-library grant that
  must acknowledge being unmediated. Every grant carries its scope, so a capability the operator
  allowed but never scoped grants nothing rather than everything. `write_temporary` and
  `load_native_library` are new capabilities; the broker is opt-in through `bind_broker`.
- [x] `PLUG-02` `trueai/plugins/confinement.py` and `windows_token.py`. Linux: `no_new_privs`,
  `unshare(CLONE_NEWUSER|CLONE_NEWNET)`, and a seccomp filter that kills on a denied syscall —
  verified against a real kernel by `scripts/verify_linux_confinement.py`, which also asserts the
  documented gaps still exist. Windows: a restricted token via `CreateRestrictedToken` plus
  `CreateProcessAsUserW`, verified by comparing privilege counts; it is *not* AppContainer and the
  report says so. macOS: a generated deny-by-default SBPL profile, unverified for lack of a macOS
  machine and marked as such. `ConfinementLevel.REQUIRED` refuses to run a plugin rather than
  degrading silently, because a degraded run is indistinguishable in a report from a successful
  one.
- [x] `PLUG-03` Hostile native plugins that reach the OS through `ctypes` on both POSIX and
  Windows, run through the whole real path by `scripts/verify_native_plugins.py` and
  `tests/unit/test_plugin_adversarial.py`. Proven on Linux: cannot write outside its grant (a
  read-only mount namespace was added for this), cannot open a socket, cannot start another
  program. Proven everywhere: cannot outlive its deadline, including while blocked inside libc.
  **Not proven, and asserted as gaps rather than left implicit:** reading outside the grant on any
  platform, and everything except the deadline on Windows, where a restricted token is not
  AppContainer. Negative controls run the same plugins with confinement off and require the attack
  to succeed, so a check cannot pass because the attempt would have failed anyway.
- [x] `PLUG-04` `trueai/plugins/distribution.py` signs every file of a plugin together with the
  capabilities it declares, so the host reads the manifest from the signature and never imports a
  plugin to find out what it wants. Verification reports integrity, identity, currency, and
  compatibility as separate properties — there is no `valid` field, because "signed by an unknown
  key" and "signed and revoked an hour ago" must not render identically. `PluginAllowlist` is
  sequenced and finite-lifetime with publisher withdrawals, and `verify_allowlist` takes the
  highest sequence the verifier has seen because a memoryless verifier cannot detect a rollback.
  `trueai plugins sign/verify/allowlist`; `DistributionPolicy(require_signed=True)` is the posture
  that makes it a control.
- [x] `PLUG-05` `scripts/fuzz_plugins.py` fuzzes six targets: the worker protocol, manifests,
  signed distributions, finding validation, resource limits, and broker path resolution. Each
  declares the exceptions it may raise *and* the invariant that must hold when it does not, because
  a parser that accepts a forged finding without crashing is the failure this boundary exists to
  prevent. Half the inputs are mutations of valid documents, which is what reaches the checks after
  parsing. Runs are seeded and replayable per case. `tests/unit/test_plugin_fuzz.py` breaks two
  checks on purpose and requires the fuzzer to notice, so "no findings" cannot mean "cannot find".
  CI runs 20,000 cases per push and ten minutes per target nightly.

#### P1 — artifact coverage and integrity

- [x] `FMT-01` `trueai/core/iso_bmff.py` is the specification, written as code: seven invariants
  over samples, timing, edit lists, indexes, encryption state, rendering-critical metadata, and
  protected provenance. The samples invariant hashes the bytes the tables *point at*, because
  `stco` holds absolute file offsets — an edit that relocates `mdat` correctly passes, and one that
  leaves the offsets stale fails, and a byte comparison gets both backwards. Indeterminate counts
  as unsafe. The cleaner still refuses ISO-BMFF; two tests pin that refusal and that the invariants
  are satisfiable by a correct edit, so `FMT-02` has something it can actually pass.
- [x] `FMT-02` The selected box is overwritten in place with a same-length zero-filled `free` box,
  so no chunk offset needs correcting — the bug class `FMT-01` exists to catch is avoided by not
  creating the situation that causes it. The file keeps its length, which is stated rather than
  hidden. Every result still passes `verify_iso_bmff_invariants` before it is written. Writing the
  signed-provenance test found a real gap: a C2PA box is identified by a binary UUID and its
  payload need not contain the letters `c2pa`, so the byte-marker scan the other formats rely on
  missed it; the ISO-BMFF branch now refuses structurally. Positive, refusal, malformed,
  signed-provenance, and large-container tests all present.
- [x] `FMT-03` `trueai/core/ebml.py` specifies six invariants — tracks, clusters, cues, timing,
  seek positions, provenance — over a model that resolves `SeekHead` and `Cues` positions to the
  elements actually there. Cleanup overwrites the selected `SimpleTag` with a same-length `Void`,
  EBML's own padding element, so nothing moves and no stored position needs rewriting; every result
  passes the invariants before it is written, and a document carrying a provenance attachment is
  refused. `void_element` is exact by construction and tested from 2 bytes to 5 MB, because the
  substitution depends on it.
- [x] `FMT-04` `trueai/core/pdf_objects.py` walks cross-reference tables *and* streams, `/Prev`
  chains, and object streams — closing a real coverage hole: a PDF 1.5+ file has no `trailer`
  keyword and no plain-text `/Info`, so the lexical scanner reported nothing, which looks exactly
  like finding nothing. Bomb-safe by construction: `inflate_bounded` passes the cap *into* the
  decompressor, and the inflated budget is charged per document rather than per stream. Signature
  byte ranges, encryption, and XMP are modelled so a cleaner can refuse. Undecodable filters are
  reported as present-and-undecoded rather than guessed at. The detector tries the graph, falls
  back to the lexical scan, and records which reader spoke in each finding's evidence.
- [x] `FMT-05` `trueai/core/dom_features.py` measures HTML tree shape (depth and tag histograms,
  wrapper-only elements, duplicate ids, class tokens, text vs markup characters reported separately
  so the reader picks the ratio) and stylesheet shape (rules, selectors, declarations, specificity
  histogram using the cascade's own definition, `!important` density, duplicate selectors). Every
  output is a count: no thresholds, no scores, no verdicts, and two tests enforce that by rejecting
  any evidence key that reads like a judgement. Budgets cover nodes, depth, parser events, rules,
  and *retained* bytes; exhaustion returns partial measurements with `complete=False` rather than
  raising. Findings are `STRUCTURAL_SIGNAL`/`INFO`/`ProvenanceClass.NONE` and say in words that
  they are not evidence of authorship.
- [x] `FMT-06` Evaluated both against the three conditions; the reasoning is in
  `docs/odf-and-legacy-office.md`. **ODF proceeds**: it is a ZIP package, so `zipfile`, `defusedxml`,
  and the entire OPC hostile-input layer apply unchanged, and the integrity proof is a comparison
  (`content.xml` byte-identical, every entry but `meta.xml` unchanged, `mimetype` still first and
  stored). Detection and cleanup are implemented, with macro storage listed but never parsed.
  **Legacy binary Office does not**: nothing maintained writes CFB, and an integrity proof would
  have to reason about interleaved sector chains rather than separable entries. It is identified as
  `ArtifactType.LEGACY_OFFICE` and reported as not inspected, because a file silently skipped looks
  exactly like a file that was clean. Writing the ODF registry entry surfaced a real gap: `VIDEO`
  had no cleaner, so the MP4 and WebM cleanup from `FMT-02`/`FMT-03` was unreachable through the
  pipeline.

#### P1 — enterprise trust and certificate infrastructure

- [x] `TRUST-01` `TimestampProvider` with an offline designated-authority implementation and an
  RFC 3161 provider that requires `NetworkPolicy.EXPLICIT_ONLY`, an operator allowlist, and a
  caller-supplied transport. Normal scanning never contacts an authority. An RFC 3161 token is
  carried but reported as not established, because an opaque blob is not evidence.
- [x] `TRUST-02` `TrustProfile` binds keys to organizations for stated periods, with three
  assurance levels. Without a profile the result is `key_only` and says so.
  `authenticated_declaration` and `organizationally_attributed` are separate properties so a bare
  signature cannot read as an organizational endorsement.
- [x] `TRUST-03` `TransparencyLog` is append-only with sequence numbers and a hash chain. Edited
  entries, removed entries, older copies, and same-length rewritten histories are each detected,
  and the API requires the verifier's remembered head because a verifier with no memory cannot
  detect a rollback.
- [x] `TRUST-04` `SigningProvider` with local-file and external implementations. An external
  provider receives bytes and returns a signature; no key material enters a TrueAI process, and a
  provider whose signature its own public key rejects fails at signing rather than at verification.
- [x] `TRUST-05` Retention, access, privacy, and export contracts documented in `docs/trust.md`.
  The boundary is enforced in the scanner: it adds no telemetry, so anything a fleet product knows
  was sent deliberately.

#### P1 — human contribution and process attestation

- [x] `PROC-01` Claim taxonomy and threat model frozen in `docs/process-attestation.md`.
  `ClaimType` keeps `machine_fact`, `declaration`, and `assessment` apart, and the model refuses
  the two conflations that matter: a `machine_fact` without recomputable evidence, and a
  `declaration` claiming independent assessment of itself.
- [x] `PROC-02` `schema/trueai-process-attestation-0.1.schema.json` covers actors, artifact
  bindings, derivation events, per-stage AI autonomy, decisions, validation, contribution
  dimensions, disclosure levels, limitations, and signatures. CI diffs it against the emitted
  schema, and a test asserts it is a different contract from the audit certificate.
- [x] `PROC-03` Immutable models in `trueai/core/attestation.py` with canonical serialization,
  content-derived `TAIP1-…` identifiers, subject binding, expiry, multi-role signatures that do not
  invalidate each other, and verification returning independent results. The `TAI1-…` contract is
  unchanged; the trust primitives are reused, the schema and prefix are not.
- [x] `PROC-04` `trueai attestations init/validate/issue/sign/verify/summarize/redact/keygen/schema`
  plus the matching Python API, all offline. A scan can be attached as evidence but never populates
  a claim, and a test asserts the claims are exactly what the manifest declared. Verification
  prints each property separately and says "authenticated declaration", never "verified human
  contribution".
- [x] `PROC-05` `trueai/core/evidence.py` adapts Git commits and repository state, reviewed diffs,
  command and test receipts, build outputs, research notes, citations, approvals, external
  receipts, tool identity, scan reports, and certificates. Everything is stored by digest; tests
  assert a private commit summary and a private note's contents never reach the record.
- [x] `PROC-06` Four disclosure statuses, deterministic `redact_for_public`, and salted
  commitments so a guessable statement cannot be confirmed by hashing it. `private_material()`
  enumerates exactly what a public variant must not contain, and the leakage test executes that
  check rather than assuming it.
- [x] `PROC-07` Attestations sign through the same `SigningProvider`, resolve identity through the
  same `TrustProfile`, and carry the same `TimestampToken` as certificates, while keeping the
  `TAIP1-` prefix, the process-attestation schema, the contribution vocabulary, and
  `AttestationVerification` distinct from the certificate contract.
- [x] `PROC-08` `trueai/core/evaluation.py` adds Process Assurance Level PAL-0..PAL-4, derived from
  what verification established rather than from what the record claims, and five versioned
  profiles (`research`, `software-delivery`, `creative-work`, `education`, `regulated-enterprise`)
  whose weights and thresholds are fields a reader can disagree with. The answer is
  `meets_review_requirements`, a policy result about process evidence, and a test asserts two
  profiles may legitimately disagree about the same record. No aggregate score exists anywhere.
- [x] `PROC-09` `stage_summary`, `portable_summary`, and `sarif_properties` are the single source
  for every surface. `trueai attestations evaluate --format terminal|json|summary|sarif-properties`
  and `trueai attestations profiles` expose them; `trueai scan --attestation` carries the verified
  facts into a SARIF run's property bag without touching a single finding. Tests assert the word
  "authored" never appears, no output contains a percentage, and an unmet requirement reads as a
  rule rather than an accusation. HTML and desktop surfaces are `UI-01`/`UI-02` and must render
  through these same functions.
- [x] `PROC-10` `tests/unit/test_attestation_adversarial.py` covers all eleven scenarios plus the
  usability side: each test names an attack or a misreading and asserts what the system says
  instead. Two real gaps were closed by it — disclosed bytes that miss their published commitment
  now block the evidenced level, and recorded dissent now blocks the reviewed level, because a
  dispute is not resolved by outranking it. Record collections are now bounded at the model
  boundary, since capped strings alone do not bound a record.
- [x] `PROC-11` `trueai/core/interop.py` exports W3C PROV-JSON, in-toto Statements in DSSE
  envelopes, and C2PA assertion data, through `trueai attestations export --to prov|dsse|c2pa`.
  Standard terms are used where they fit; TrueAI concepts sit under the `trueai:` prefix so a
  `prov:` term always means what PROV says it means. Every export carries `unmapped_concepts()`,
  because an export that silently drops the evidence status turns "alice declared she originated
  this" into "alice originated this". DSSE signatures are made fresh over the PAE: record
  signatures cover different bytes and are never copied in.
- [ ] `PROC-12` (`external`) Run consented design-partner pilots in research, software delivery,
  creative services, and education; publish the rubric, disagreements, false interpretations, and
  revision history before presenting contribution profiles as a stable product feature. Nothing in
  the repository can complete this: it needs organizations who have agreed to take part, and the
  whole point of the item is that the rubric is argued with by people who did not write it. The
  attestation schema stays out of the frozen API surface until they have — see
  [API compatibility](docs/api-compatibility.md).

#### P2 — provenance adapters and trust presentation

- [x] `PROV-01` `AdmissionCriteria` writes the standard down — published mechanism, independently
  runnable, specified semantics, stable contract, all four — and `PROVIDER_ASSESSMENTS` records
  where each provider stands, in code rather than only in prose. C2PA is the only one admitted.
  An unadmitted provider reports `VERIFICATION_UNAVAILABLE` naming the criteria it fails, so
  "unavailable" is a position with reasons; a test pins that C2PA is the only admission and that
  every assessment explains itself.
- [x] `PROV-02` `trueai/core/network.py` is the one gate, requiring all six: `EXPLICIT_ONLY`
  policy, recorded consent scoped to endpoints *and* a purpose, an exact endpoint allowlist,
  timeout and response-size caps, per-request credentials the gate never holds, and an audit record
  of every attempt — refusals included, because a tool that must prove it contacted nothing cannot
  do it from a log of successes. `NetworkTimestampProvider` was carrying a private copy of the
  policy and allowlist checks and now calls through the gate; its original transport shape is
  adapted rather than replaced. An adapter is offline unless handed a gate, and one that has not
  declared `network_required` cannot request anything even with one.
- [x] `PROV-03` `trueai/core/trust_store.py` handles three problems that are not the same problem.
  *Distribution:* a store is signed, sequenced, and expires; it is installed against a remembered
  sequence, so a store claiming to be older than the installed one is a rollback and is refused, and
  an expired store yields no anchors at all rather than quietly continuing. *Rotation:* a replacement
  anchor names what it replaces, and `rotation_problems()` finds the **gap** — a successor starting
  after its predecessor ended leaves a window where nothing verifies, and the failure surfaces months
  later to someone who will not connect it to a key change; installing reports it as a warning,
  because the gap may be deliberate but must not be silent. *Offline updates:* a `TrustStoreUpdate`
  advances exactly one sequence, since jumping 4 to 6 skips whatever 5 revoked. Verification also
  splits an unreadable key file, the wrong key for this store, and a genuinely broken signature into
  three distinct refusals, so a typed path does not send an operator hunting an attacker.
  63 tests; `docs/trust-store.md`.
- [x] `PROV-04` `trueai/core/provenance_view.py` splits every verification into four answers that
  stand on their own, each able to say *not determined* without that reading as *no*. The failure
  this fixes is erasure rather than exaggeration: `no_manifest` and `verifier_unavailable` were both
  "not green" in a single-status view, so "carries no provenance" looked exactly like "we were
  unable to look". `not_examined` is not `absent`, `no_anchors_configured` is not `not_trusted` (the
  first is a property of the scan, not the artifact), and `not_established` is not `not_trusted`
  (a failed signature makes its signer identity meaningless). `establishes_provenance` needs all
  three C2PA facets; a provider watermark cannot contribute, because it carries no signed chain.
  The terminal reporter now renders four columns instead of one status and names every undetermined
  question under "Not determined"; the model is interface-agnostic, so the HTML and desktop work in
  `UI-01`/`UI-02` consumes the same projection. 35 tests; `docs/provenance.md`.

#### P2 — repository scale and public interfaces

- [x] `SCALE-01` `scripts/benchmark_scale.py` and `trueai/core/benchmark.py` measure a seeded
  synthetic corpus cold, warm, and in parallel, publishing wall time, both memory peaks, cache hit
  rate, and two determinism checks — repeat-run agreement and serial/parallel agreement, because a
  speedup that changes the answer is not a speedup. Results at 10,000 and 100,000 files are in
  [`docs/benchmarks.md`](docs/benchmarks.md). Two things the benchmark found, both now fixed or
  written down: **parallelism is the lever and the cache is not** — eight workers give ~4.9x while a
  fully warm cache saves ~5%, because the time is in file I/O rather than in detectors; and the
  end-of-scan "did new files appear" sweep was running full discovery a second time, opening and
  sniffing every file to build type information the comparison discarded. `ArtifactDiscovery.
  inventory()` now walks for paths only (same traversal, ignore rules, symlink containment, and file
  cap), removing 14% of wall time and a latent CRITICAL false positive: a file the first pass could
  not identify was being announced as a detector mutating the repository. Cache statistics count
  misses apart from rejections, since "did not help" and "is damaged" are different problems, and a
  phase whose finding budget or file cap ran out is marked `INCOMPLETE` rather than published as a
  total — the 100,000-file run reaches the default `max_findings` after 29,127 artifacts, and a
  capped count that reads as a result is the failure mode a scale benchmark exists to avoid.
  Benchmarking **real consented repositories** stays `external` — it needs their owners' consent —
  but `--corpus` runs the harness against any directory and writes nothing into it.
- [x] `SCALE-02` `ScanCache` takes a byte budget (256 MB by default) that the engine enforces after
  every scan, using a stat-only size check because parsing a hundred thousand entries to total them
  would cost more than the cache saves. Eviction is deterministic in the sense that matters — the
  same inventory, budget, and run remove the same entries, never a filesystem enumeration order or a
  timestamp whose resolution varies by platform: entries from another build go first because their
  key can never be produced again, then entries this run did not touch, then the rest, oldest
  *generation* first with the key breaking ties. A generation is one scan, taken from a small counter
  on first write, so age is recorded data rather than file metadata; hits are remembered in memory
  because rewriting an entry per hit would cost about what a miss costs. `inspect()` separates
  entries, damaged files, and files TrueAI did not write — the last are reported and left in place.
  `prune()` and `trueai cache prune` require an explicit rule *and* `--yes`, because a prune that
  defaulted to deleting everything would make a typo destructive, and link safety is re-checked at
  deletion time rather than only at inspection time. 38 tests; `docs/cache.md`.
- [x] `SCALE-03` `trueai/core/progress.py`: progress is one callable taking one frozen
  `ProgressEvent`, cancellation is one `cancelled()` predicate. Not a multi-method observer, because
  every method is another thing a caller must implement and another place a UI can break a scan; not
  a `threading.Event` in the signature, because an asyncio or trio caller should supply its own
  object. Events arrive in artifact order, one at a time, from the assembling thread even under
  `--jobs 8`, so an observer needs no lock. An observer that raises is dropped and recorded as a
  `progress_observer_failed` diagnostic rather than aborting a forensic run over a formatting error.
  A cancelled scan **raises** and carries no findings: a shorter report is indistinguishable from a
  clean one to whoever opens it next, and a partial result returned through an exception is one
  somebody eventually treats as a report. The token is polled between detectors as well as between
  artifacts, since a cancel that waits for the next file is not a cancel. Rich stays in the CLI,
  where `trueai scan` draws a bar only when stderr is a terminal and Ctrl-C sets the token instead of
  tracing back. A test asserts the core imports no console library or event loop. 26 tests;
  `docs/progress-and-cancellation.md`.
- [x] `API-01` The API gate covered callers but not *subclasses*: adding an abstract method to
  `BaseDetector` is an addition for anyone calling it and fatal for every third-party detector that
  inherited from it, and a method-count comparison called that additive. `trueai/api.py` now records
  abstractness and classifies a new — or newly — abstract method as breaking, with a guard so a
  contract published before the field existed does not read as a fresh break (absent data is not
  evidence the answer was empty). `SDK_CONTRACT` names what an author actually builds against, kept
  apart from `PUBLIC_MODULES` because the guarantee differs in kind, and a test asserts every entry
  is reachable through a frozen module. `examples/acme_ticket_detector/` is a real installable
  package — entry point, capability manifest, registration read before import — and
  `tests/unit/test_sdk_examples.py` runs it, signs a distribution from it, and **parses its imports**
  to prove none leaves the public surface, so an example that drifts fails the build. 17 example
  tests plus 7 compatibility-rule tests; `docs/sdk.md`, `examples/README.md`.
- [x] `UI-01` `trueai/reporters/html.py`, reachable as `trueai scan -f html`. One file: no script,
  no external stylesheet, font, or image, no attribute that can fetch anything — it opens from a USB
  stick on an air-gapped machine, which is where a forensic report gets read. Every string in a
  report came from the artifact under examination and the report is then opened in a browser by the
  person examining it, so exactly one function turns a value into markup and it escapes `&<>"'`,
  correct in a text node and a quoted attribute alike. The document declares a
  `Content-Security-Policy` it already satisfies (`default-src 'none'; script-src 'none'`), turning
  "we escaped everything" into something the browser enforces. The tests **parse** the output rather
  than grepping it — `onmouseover=&quot;` looks like a handler to a substring check and is inert to a
  parser — and asking `HTMLParser` for the real elements and attributes proves it; with escaping
  deliberately removed, 13 of them fail. Presentation keeps the distinctions: findings grouped by
  confidence class with what each class claims stated at the heading, provenance as PROV-04's four
  facets with unanswered styled as unanswered, caveats printed, and diagnostics as a section because
  a scan that could not read something did not find it clean. 33 tests; `docs/html-report.md`.
- [x] `UI-02` `trueai/adapters/` — one projection (`views.py`) and three formatters (`ci.py`,
  `ide.py`, `desktop.py`), added to `PUBLIC_MODULES`. The part worth centralising is not formatting
  but `FindingExplanation.does_not_claim`: the sentence saying what a finding does *not* establish,
  derivable from the confidence and provenance classes and the first thing a short format drops —
  deriving it centrally means an interface must actively discard it rather than never have had it,
  and every adapter carries it, including the two that only have one line. Both CI formats are
  injection boundaries: a newline in a description does not malform a workflow annotation, it forges
  *a second command*, and a pipe rewrites a Markdown table, so both are escaped. The editor adapter
  is LSP-shaped without an LSP dependency, admits a missing range instead of guessing one from a byte
  offset (a squiggle under the wrong text looks authoritative), lists clean files so stale markers
  can be cleared, and never turns an `INFO` finding into an error. The desktop bundle is versioned,
  keeps coverage beside the findings, and distinguishes "no plan" from "an empty plan".
  `IntegrityEvidence.visible_content_unchanged` is `None` rather than `False` when the digests are
  missing, and `certificate_view` shows all six checks separately so four unknowns cannot hide behind
  one tick. 49 tests; `docs/integrations.md`.

#### P3 — calibrated research features

- [x] `ML-01` `trueai/research/corpus.py` states the five rules as constructors that refuse rather
  than guidance that advises — governance written as prose gets read once and then contradicted by
  whoever is actually collecting the data. A `CorpusManifest` cannot exist without a `CorpusPolicy`,
  which is the ordering the whole module is for. **Consent is not a license:** the person who hands
  over a document is frequently not the person who owns it, so a sample needs a `ConsentRecord`
  *and* `LicenseTerms`, and both refusals are reported together. Consent names purposes, expires,
  and carries a withdrawal contact, because consent nobody can revoke is not consent; withdrawal
  reaches backwards and names every sample already collected under it, without silently dropping
  rows — deleting the record while the bytes remain is worse than not deleting. Contamination is
  compared by **content digest, never path** (a renamed copy is the same document, and scoring it is
  a memory test), enforced at admission, again across a batch so two copies cannot slip past each
  other, and again in the audit. Domain targets are written in advance and must sum to 1; imbalance
  is reported but does not block, since a corpus can be imbalanced on purpose but must not be
  imbalanced quietly. Retention needs a stated deletion method, and indefinite has to be chosen
  rather than defaulted into. Nothing here is imported by a detector, a cleaner, or the engine.
  45 tests; `docs/research-data.md`.
- [x] `ML-02` `trueai/research/evaluation.py` is the protocol as runnable code, not a description
  of one. The headline is the **false positive rate**, not accuracy: accuracy averages the harm of
  telling someone their human-written document was machine-generated together with the harmless kind
  of mistake, so `summary()` emits no accuracy figure and a test asserts it. Every rate carries a
  Wilson interval — the normal approximation gives zero width at a rate of zero, exactly where a
  small sample needs one — and a rate under 30 samples is marked unreliable, because printing "0.0%"
  for a group of five reads like a measurement. Subgroup analysis reports the worst rate among groups
  *large enough to score* (otherwise a five-sample group with one mistake becomes the headline) and
  flags a gap over 5 points: a detector at 3% overall and 15% on second-language writing is not a 3%
  detector. Domain spread is reported because one aggregate hides what a new deployment will meet.
  Coverage travels with every metric, since a detector allowed to abstain reaches any figure by
  answering only the easy cases. `ProtocolRecord` requires corpus digest, model, threshold, seed, and
  code version — a number that cannot be recomputed is an anecdote. `problems()` lists every reason
  a result must not be quoted alone, and a clean run produces none. 37 tests;
  `docs/evaluation-protocol.md`.
- [x] `ML-03` `trueai/research/features.py` makes the arrangement possible: TrueAI computes
  features, a model elsewhere consumes them, neither imports the other's dependencies. A `FeatureSet`
  is named *and ordered* — a vector is positional, so the same names reordered are a different set —
  and its digest covers version, names, and order together. `score_with()` refuses a vector from
  another feature set, and refuses a model that mislabels its own output; the refusal is the whole
  point, since the alternative is a confident number over columns that changed meaning with no
  symptom until someone acts on it. `build_vector()` will not pad a missing feature with zero,
  because a zero is a measurement and an absence is not, and will not swallow an extra one, because
  adding a feature changes the contract. `try_score(None, …)` returns `None` meaning *not measured*,
  never "clean". `ModelScore` carries no author, attribution, or provenance class — the fields that
  would let a caller promote a measurement into a claim are simply absent, and a test asserts it.
  `ModelCard` requires at least one known limitation, because every model has some and a card
  without them is one nobody looked hard at. A test walks every module in the package and fails on
  any import of torch, tensorflow, jax, sklearn, numpy, scipy, pandas, transformers, onnxruntime,
  xgboost, or lightgbm, and a second test proves that check can fail. 26 tests; `docs/models.md`.
- [x] `ML-04` `trueai/research/release.py` gates exposure on five artifacts. A `DatasetStatement`
  requires every field, including `does_not_represent` — a corpus of published English technical
  writing does not represent a student writing in a second language, and the time to say so is
  before a model trained on it judges one; listing demographics while claiming none were collected
  is refused, since one of the two is wrong and a reader cannot tell which. Thresholds are bound to
  one model version and one feature set and carry the evaluation digest that chose them, and
  `may_expose` refuses when the evaluation ran at a threshold no shipped operating point uses.
  Manifests are `TAIMDL1-…`, content-addressed over card, statement, thresholds, and the **digests
  of the model's own files**, so "is this the model that was evaluated" does not depend on a
  filename. The regression gate's central rule: **a rise in the false positive rate blocks a release
  even when everything else improved** — averages let a model get better at finding machine text
  while getting worse at accusing people, and only one of those costs a person something. Three more
  ways to look better without being better are closed: the worst subgroup is gated separately, a
  candidate that scores no subgroup when the baseline did is blocked, and coverage falling is
  blocked because abstaining more improves every other number for free. 34 tests; `docs/models.md`.
- [x] `ML-05` `trueai/research/longitudinal.py` compares a document against a writer's own past and
  produces no verdict: no `same_author`, no probability, no score to threshold, and a test parses the
  module to assert that vocabulary is not in it. The list of things that move a style is long and
  almost none of the entries are "someone else wrote this", so `ALTERNATIVE_EXPLANATIONS` — topic,
  genre, co-author, editor, template, translation, practice, deadline — travels with every result
  rather than living in documentation, and `what_this_is_not()` is meant to be printed beside it.
  Below eight documents or thirty days the band is `UNDETERMINED` and **no distance is reported at
  all**, described as an absence of measurement rather than a finding of no change. Distance is in
  units of the writer's own variability, since a fixed threshold penalises the consistent and excuses
  the erratic, and the bands are coarse because a continuous score invites a threshold and a
  threshold invites the verdict. Per-feature deltas are off by default: "which feature moved and by
  how much" is a recipe for moving it back. The flag exists for debugging a detector and the request
  is recorded in the result — which does not prevent anyone with the extractor from computing them,
  and the module says so rather than overclaiming; it declines to ship a ready-made objective
  function and leaves a record when somebody asks for one. 26 tests; `docs/models.md`.

#### Continuous quality work

- [x] `QA-01` `scripts/fuzz_parsers.py` covers all ten boundaries, coverage-guided through
  `sys.monitoring` with no native dependency and reproducible from a seed. Each target declares what
  a parser may do — refuse — and what must hold when it does not: a validated OPC package names no
  escaping member, an XML part never resolves an external entity, every box and element sits inside
  its input, a damaged cache entry is a miss rather than an exception or a half-decoded result, a
  loaded report's counts match its findings, an accepted Git alternates file contains no path leaving
  the repository. An undeclared exception is a finding too — a parser may refuse, it may not
  surprise. The guidance claim is stated as a **measurement rather than an assertion**: guided loses
  at 3,000 inputs (601 vs 664 lines) and wins at 12,000 (739 vs 709) and 60,000 (757 vs 727), so
  `--no-coverage` stays a real option and half of all mutations still start from a pristine seed,
  because mutating a mutation drifts away from anything a length-prefixed parser will accept. Seeds
  are real artifacts from the fixture builders — a genuine MP4 with a resolved sample table, a WebM
  with tracks and clusters, classic *and* cross-reference-stream PDFs, a signed bundle, an issued
  certificate — worth roughly double the coverage where it matters (PDF went 153 → 348 lines).
  `--self-check` and 28 tests prove the harness can fail, and a short pass of every boundary runs in
  the suite. 25,000 inputs across all ten: no findings. `docs/fuzzing.md`.
- [x] `QA-02` `pip-audit` answers "is there a known CVE right now"; `scripts/check_advisories.py`
  answers the two questions it cannot. **What about the parsers that are not packaged
  dependencies** — most artifact bytes reach `zipfile`, `xml.etree`, `zlib`, `html.parser`, and
  `json`, and a CPython advisory for any of them never appears in a dependency audit, so
  `security/advisories.toml` lists them as components reviewed on the same clock. And **has anybody
  looked** — the gate fails on *staleness*, so it fires when the reviewing stops rather than only
  when a CVE is published. Four failure kinds: stale, unreviewed dependency, orphaned entry
  describing a build that no longer exists, and an accepted risk past its expiry, because an
  acceptance without an expiry becomes permanent by inattention rather than by decision. Writing the
  ledger found something the audit never mentions: `c2pa-python` declares `wheel`, `setuptools`,
  `toml`, `pytest`, and `requests` as **install** requirements, so the `c2pa` extra puts an HTTP
  client and a test runner into an environment for a tool that advertises being offline — recorded
  rather than only noticed. `scripts/generate_sbom.py --check` gates on **completeness**, not
  existence: a component with no version, license, or purl fails, because a document with blanks
  passes a consumer's "do you have an SBOM" check and answers none of their questions. The license
  gate now falls back to installed metadata when `pip-licenses` is absent instead of skipping — a
  gate that quietly does nothing reports success either way — which surfaced three spelling variants
  the two readers disagree on. All four run together in `check_supply_chain.py`, in CI, and at
  release. 34 tests; `docs/supply-chain.md`.
- [x] `QA-03` `trueai/core/remediation_catalog.py` declares all twenty removal operations — what
  each takes out, its safety class, and **why that class and not the neighbouring one**. Writing it
  found a real bug: safety was a prefix match on the identifier, so `odf.remove-metadata-field` was
  classified as a content change for as long as ODF support existed, not by decision but because
  `"odf."` was never added to a tuple. `meta.xml` is a separate part exactly like `docProps`, so it
  is now `safe_metadata` with that sentence attached; it happened to fail safe, which is why nothing
  noticed. Two gates: the catalogue and the code must name the same operations **in both
  directions**, and every catalogued operation must be named by a test. The second found six
  operations the suite exercised without naming, so the coverage question was unanswerable —
  `tests/unit/test_removable_field_fixtures.py` now pins each specifically: planned, applied, and
  through the integrity gate. An uncatalogued identifier falls back to the strictest class in the
  planner and raises in `safety_for`, since a planner is not the place to fail a scan but a caller
  that can handle the error should not be handed a guess. 47 tests; `docs/findings.md`.
- [x] `QA-04` `scripts/check_docs.py` fails when a document names a command, an option, or a file
  that does not exist, or when a page under `docs/` is linked from nowhere — across the README,
  this backlog, `CONTRIBUTING`, `SECURITY`, `AGENTS`, the Codex skill, the examples, and every page
  in `docs/`. It cannot check whether the prose is *true*; it checks whether the nouns exist, which
  is the part that rots first, because prose has no compiler and the reader who is hurt is the one
  who trusts it. Two scoping decisions, both from findings the first version produced: options are
  checked only on lines where `trueai` is followed by whitespace, since checking every long option
  reported pip's `--all-extras` and docker's `--build-arg` and an allowlist of other tools' flags
  would rot faster than the docs it guards; and a command resolves against the *tree* rather than by
  longest prefix, since a group takes no positional arguments and prefix-popping let a misspelt
  subcommand fall back to bare `trueai` and pass. The gate found five orphaned pages — `dom-features`,
  `fuzzing`, `html-report`, `models`, `pdf-object-graph` — now linked. It also caught its own
  regression: a heredoc turned `\b` into a literal backspace, so the pattern matched nothing and the
  option check skipped every line while reporting success; a test now pins the word boundary.
  19 tests; `CONTRIBUTING.md`.
- [x] `QA-05` `docs/incident-response.md`, linked from `SECURITY.md`. Five processes kept separate
  because they have different blast radii and different people to tell — collapsing them means the
  narrow ones get the heavy process and the heavy ones get the narrow one. All five share a second
  half that is the one usually left out: **what already-issued evidence is worth**. A forensic
  tool's reports stay in circulation after the failure that produced them, and somebody may be
  relying on one. They also share a discipline about not *overstating*: "discard all reports" when
  one detector was affected, or "provenance verification was broken" when only signer trust was
  wrong, teaches people to discount the next advisory, and precision here is what keeps the channel
  usable. Each process names mechanisms that exist and tests assert they do — a runbook telling
  somebody to revoke a thing the tool cannot revoke is worse than none, because it is read at three
  in the morning. 23 tests.

#### Explicit non-goals

- [ ] None: TrueAI will not add C2PA forgery/removal, SynthID defeat, statistical-watermark
  suppression, secret-key inference, or artifact optimization intended to evade AI-authorship
  detectors. These are permanent safety boundaries, not unfinished features.
- [ ] None: TrueAI certificates will not claim human authorship or that AI was never used. They
  attest only that a named scanner version and detector scope found no scoped indicators in exact
  artifact bytes at a recorded time.

The permitted indicator-handling plan is documented in
[`docs/indicator-handling.md`](docs/indicator-handling.md).

## Product purpose

TrueAI answers questions such as:

- What observable residue is present in this deliverable?
- Is a finding ordinary metadata, literal attribution, unverified provenance, or a heuristic?
- Is this signed provenance actually valid, and does it chain to a signer we trust?
- Which findings can be removed predictably?
- Which evidence must be preserved?
- Did remediation alter visible or logical content?
- Was the scan complete within its declared resource limits?
- Does a content-bound audit record match these exact artifact bytes and this scanner scope?
- Is that audit record still within its validity period and absent from a current issuer list?

TrueAI is intended to become the shared open-source engine behind future desktop, CI, IDE, studio,
and enterprise products. The core therefore has no UI dependency and exposes versioned Pydantic
models, a Python API, a CLI, detector entry points, reporter adapters, external policy profiles,
and a plugin capability boundary.

## What TrueAI is not

TrueAI Core is not:

- a binary AI-authorship classifier;
- proof that a person or model authored an artifact;
- a cryptographic provenance removal tool;
- a statistical watermark defeat system;
- a mechanism for forging Content Credentials;
- a service that uploads artifacts or emits telemetry;
- an automatic Git history rewriter;
- a universal operating-system sandbox for arbitrary hostile third-party code; available plugin
  confinement is platform-specific and its unproven boundaries are reported.

A deterministic finding means that the stated trace was observed exactly. It does not make the
larger claim that the artifact was generated by AI. A heuristic result is a measurement, not
provenance.

## Operating principles

### 1. Evidence before conclusions

Every finding includes its detector, category, confidence class, severity, evidence type,
explanation, location where available, provenance class, tags, and remediation status. Reports are
designed to be auditable by a person or a downstream policy engine.

### 2. Detection and mutation remain separate

Detectors receive artifacts and return findings. They do not receive a remediation API. Policies
decide what should happen, planners create reviewed operations, and cleaners perform mutations only
in an explicit apply phase.

### 3. Preserve provenance by default

C2PA-compatible markers and provider watermark findings cannot be assigned a removal action by the
built-in policy engine. Format cleaners also perform independent provenance checks so a malformed,
stale, or manually constructed plan cannot silently bypass the policy boundary.

### 4. Verification is explicit and never rounded up

Scanning discovers markers; it never verifies signatures. Verification is a separate operation with
its own command, its own result model, and an operator-supplied trust store. A correct signature
from an unknown signer is reported as `valid`, never as `trusted`, because only chaining to a
configured trust anchor establishes provenance.

### 5. Predictable remediation only

TrueAI removes ordinary metadata, exact attribution spans, or well-understood formatting residue.
It does not claim removal of hidden statistical signals. The default output is a new
`name.cleaned.ext` file; in-place replacement requires explicit opt-in and creates a backup.

### 6. Integrity is a product feature

Cleanup is not considered successful merely because an output file was written. Each cleaner
calculates a format-appropriate invariant and reports `PASS`, `FAIL`, or `NOT_VERIFIABLE`.

Examples include:

- exact expected transforms and hashes for text;
- logical Word content and unselected OPC parts for DOCX;
- slide, layout, master, and notes text for PPTX;
- cell values, formulas, inline and shared strings for XLSX;
- canonical visible and active structure for SVG;
- compressed pixel-bearing payloads and rendering-critical EXIF for images;
- reachable PDF object graphs and raw stream payloads for PDF.

### 7. Incomplete scans fail closed

File, archive, parser-event, finding, Git-output, XML, page, object, and image-pixel budgets are
explicit. Exceeding a completeness boundary creates a high-severity diagnostic and CLI exit code
`3`; a partial scan is never presented as a clean result. The finding budget is global and shared
across workers, so parallelism cannot quietly raise it.

### 8. Certificates attest only observed scope

A `clear` audit certificate means that the recorded scan completed and no scoped indicator was
found for the bound artifact bytes. It never means “human-authored” or “AI was never used.” The
`TAI1-…` content ID detects changed claims; optional Ed25519 signatures authenticate the issuer.

### 9. Local-first privacy

Normal scanning performs no network requests and has no telemetry. Verification is local unless
remote manifests are explicitly permitted. The incremental cache is local and is never uploaded.

## Architecture

```text
artifact identification and bounded discovery
                    |
                    v
  detector registry + reviewed plugin host
                    |
                    v
        immutable Finding[] + diagnostics
                    |
                    v
             policy evaluation
                    |
                    v
          immutable remediation plan
                    |
                    v
 preview -> temporary output -> integrity gate -> publish
                    |
                    v
 terminal / JSON / SARIF / HTML / CI / IDE / desktop

        provenance verification (separate, explicit)
```

The major extension boundaries are:

- `core`: artifacts, models, engine, cache, registry, policies, planning, integrity, and errors;
- `detectors`: read-only artifact-specific evidence collection;
- `providers`: provider-specific rule packs and verification status adapters;
- `cleaners`: explicit, format-specific mutation implementations;
- `plugins`: capability manifests, host policy, and process isolation for third-party detectors;
- `reporters` and `adapters`: terminal, JSON, SARIF, HTML, CI, IDE, and desktop projections;
- `policies`: operational decisions independent of detector implementation;
- `schema`: the published report contract and its compatibility rules;
- `skills/trueai`: a Codex workflow for repeatable artifact audits.

## Current capabilities

| Area | Current state |
|---|---|
| Text and Markdown | Unicode forensics, attribution rules, exact span cleanup, integrity verification |
| Source code | Conservative comment attribution and Unicode inspection |
| Git | All-ref commit/trailer inspection and neutral tooling-context findings |
| HTML and CSS | Generator metadata, comments, hidden structure, scripts, data URIs, and bounded DOM/CSS feature extraction |
| SVG | Metadata, editor residue, hidden elements, scripts, structural and design measurements |
| DOCX | OPC properties, custom XML, comments, revisions, relationships, macros, metadata cleanup |
| PPTX | Shared OPC evidence plus speaker notes, comments, comment authors, slide inventory, cleanup |
| XLSX | Shared OPC evidence plus hidden sheets, cell and threaded comments, participant identities, defined names, external links, cleanup |
| PDF | Bounded Info/XMP inspection and optional surgical metadata cleanup using `pikepdf` |
| PNG and JPEG | EXIF, XMP, comments, text chunks, provenance markers, and metadata cleanup |
| Audio and video | Bounded WAV/MP3/FLAC/M4A/MP4/MOV/WebM metadata; surgical stream-preserving cleanup for WAV/MP3/FLAC plus same-length ISO-BMFF/EBML metadata substitution under format invariants |
| Provenance | Marker detection plus explicit authenticated C2PA verification through the reference implementation; typed results can be attached to terminal/JSON scan reports |
| Watermarks | Explicit unsupported/unavailable provider verification statuses |
| Stylometry | Experimental interpretable feature extraction and heuristic scoring |
| Repository scale | Deterministic parallel scanning, content-addressed incremental caching, nested Git ignore semantics |
| Plugins | Capability manifests and broker, process isolation, signed distributions, output validation, kernel quotas, and platform-specific native confinement |
| Reports | Rich terminal, stable JSON schema `0.1`, SARIF 2.1.0, offline HTML, CI annotations, IDE diagnostics, desktop bundles, policy audit, and authenticated provenance views |
| Interfaces | Stable Python API, Typer CLI, detector entry points, YAML policies, signed enterprise policy bundles, audit certificates, and `TAIP1` process attestations |

## Innovations and differentiators

### Evidence-class separation

Many products collapse metadata, authorship probability, and provenance into one score. TrueAI
models them independently. This reduces misleading conclusions and makes the output usable in
legal, publishing, client-delivery, and enterprise-review workflows.

### Remediation integrity proofs

The strongest technical differentiator is the attempt to prove that approved cleanup did not alter
meaningful content. The invariant changes by format instead of relying on a single byte comparison,
and a new format cannot be added without declaring the invariant that proves its cleanup harmless.

### Provenance-aware defense in depth

Provenance preservation exists in policy validation, remediation planning, and individual cleaners.
The implementation checks concrete elements, ZIP parts, PDF metadata, PNG chunks, JPEG segments,
SVG attributes, and image fields rather than relying only on a top-level finding count.

### Verification that refuses to overstate itself

`trusted` and `valid` are separate results, and the difference is whose signature it was. Most
tooling collapses them, which quietly converts "correctly signed by someone" into "verified".
Without the optional verifier installed, the result is `verifier_unavailable`; nothing is inferred.

### Stale-plan resistance

Plans are bound to the scanned artifact hash, policy, and finding identities. A source that changes
after review is rejected instead of applying old offsets or metadata selections to unreviewed data.

### An executable schema contract

The published schema lives in the repository as a frozen file. Any difference between it and the
current models is classified as additive or breaking by code, not by convention, and a breaking
change fails the build. A stale snapshot also fails, so no model change merges without a maintainer
reading the schema diff.

### Deterministic extensibility and parallelism

Detector execution and report ordering are deterministic, and a completed scan is byte-identical
whether it ran on one worker or eight, because results merge in artifact order rather than
completion order.

### Plugin findings that cannot be asserted into existence

An isolated plugin's output is re-derived from its own evidence before it reaches a report. A
plugin cannot forge a finding identity, reattribute a finding to another artifact, or impersonate
another detector, and a plugin that mutates the artifact while running is caught by re-hashing.

## Security and trust boundaries

The current security model includes:

- bounded reads and fail-closed truncation diagnostics;
- ZIP entry-count, expansion-size, compression-ratio, and path-traversal checks;
- forbidden XML DTDs and external entities;
- safe symlink handling and scan-root containment;
- bounded Git subprocess output and timeouts;
- rejection of external Git directories, object databases, and alternates;
- cleared Git routing environment and disabled interactive/lazy fetches;
- no execution of HTML, SVG, macros, attachments, hooks, or embedded scripts;
- bounded raster dimensions before decoding metadata;
- bounded RIFF, ID3, FLAC, ISO BMFF/QuickTime, and EBML metadata parsing without codec execution;
- detector mutation checks for discovered file hashes and newly appearing paths;
- capability-guarded plugin manifest inspection outside the scanner process;
- subprocess plugin execution by default, with deadlines, discarded stdout/stderr, and bounded responses;
- pre-import kernel CPU and memory quotas through POSIX rlimits or a Windows Job Object;
- re-derivation of every plugin finding from its own evidence.

Plugin isolation contains accidents and catches dishonest output; signed manifests make requested
capabilities reviewable before import. Native confinement is stronger but deliberately scoped.
Linux tests prove denial of writes outside the grant, sockets, and child processes under namespaces
and seccomp, but do not prove denial of every read. Windows uses a restricted token and Job Object,
not AppContainer, so filesystem and network isolation are not claimed. A deny-by-default macOS SBPL
profile exists but still requires execution on a real hosted macOS runner. `required` confinement
fails closed when the selected platform cannot establish its promised level.

## Current project state

The implementation currently satisfies the v0.1 development definition of done:

- the package builds and installs;
- `trueai --help` and every declared command are available;
- directory, text, Git, DOCX, PPTX, XLSX, SVG, PDF, PNG, JPEG, WAV, MP3, FLAC, M4A,
  MP4/MOV, and WebM inspection work;
- safe-clean and integrity workflows are implemented for every cleanable format; WAV/MP3/FLAC use
  byte-identical audio-payload invariants, while ISO-BMFF and EBML cleanup uses same-length native
  padding substitutions plus sample/timing/index/provenance invariants;
- cleaned output is rescanned by default and can produce a content-bound audit certificate;
- unsigned and Ed25519-signed certificates can be issued and verified against files or inventories,
  with optional expiry and issuer-signed finite-lifetime revocation lists;
- authenticated C2PA verification works against synthetic signed fixtures;
- explicit C2PA verification can be attached to scan reports while marker findings remain separate;
- report, audit-certificate, revocation-list, enterprise policy-bundle, and process-attestation JSON
  schemas `0.1`, plus SARIF, HTML, CI, IDE, and desktop projections, are available;
- built-in policy profiles are validated;
- Ed25519 enterprise policy bundles support exact baselines, finite suppressions/exceptions, and
  immutable audit entries without hiding findings;
- offline `TAIP1` process attestations support typed claims, evidence commitments, multi-role
  signatures, redaction, evaluation profiles, and PROV/DSSE/C2PA interoperability without turning
  scanner findings into authorship claims;
- documentation, security policy, contribution guide, AGENTS.md, changelog, and the TrueAI Codex
  skill exist;
- wheel and source distributions pass Twine validation and are byte-reproducible.

Latest local verification on Windows 11 (2026-08-30):

- Python 3.14.4: `1621 passed`, `8 skipped` with PDF, C2PA, and attestation extras installed.
  Five skips require symlink privileges unavailable to this account, two are POSIX permission
  bits, and one is Linux-only. POSIX CI promotes expected capabilities to failures rather than
  silently accepting a skip.
- Python 3.12.10: `1595 passed`, `34 skipped`. The wider skip count is the C2PA runtime closure,
  which is not installed in that environment; the suite says so rather than passing quietly.
- Ruff lint and Ruff format passed; strict mypy passed for 124 source files on both
  `--platform linux` and `--platform win32`.
- Report and Python API snapshots match their emitted contracts; the full suite also validates the
  certificate, revocation, policy-bundle, and process-attestation schemas.
- The documentation gate validated 42 Markdown documents and its own failure-path tests.
- A ten-minute coverage-guided parser campaign found one defect — a loaded report whose summary
  contradicted its findings — which is fixed, has a regression test, and replays clean. A
  five-minute plugin campaign found nothing. Both are recorded here rather than rounded to "no
  findings", because a campaign that finds something is the campaign working.
- The pinned container built the wheel and sdist twice under one fixed `SOURCE_DATE_EPOCH` and
  both were byte-identical. This ran on this machine against a real Docker daemon, not as a
  documented intention.
- All four supply-chain gates passed; 36 runtime distributions passed the license allowlist and
  40 components are current in the advisory ledger, whose next review is due 2026-11-23.

## Known limitations and post-RC directions

### Release engineering

- Run the CI matrix on real hardware and confirm every job passes, including the Windows and macOS
  jobs and the optional-dependency provenance job.
- Configure protected `testpypi` and `pypi` deployment environments plus trusted publishers before
  the first release. Production publication is tag-only; manual branch runs can target TestPyPI.
- Generate hosted Sigstore signatures and GitHub build/SBOM attestations, then verify them from a
  clean machine. The locked auditor container, runtime SBOM, build-input record, and local
  byte-for-byte reproduction gate are implemented.

### Provenance

- Local timestamp-authority trust, organization profiles, transparency chains/rollback detection,
  finite validity, and signed revocation lists are implemented. Live RFC 3161 validation, managed
  organization identity, and HSM/KMS custody remain deployment/integration work.
- Add optional explicit network verification where a provider publishes an API.
- Build a full interactive GUI on top of the implemented offline HTML and versioned desktop bundle.
- Keep marker detection distinct from authenticated verification.

### Artifact formats

- ISO-BMFF and EBML cleanup is deliberately limited to metadata elements replaceable by same-length
  native padding; arbitrary muxing or rendering changes remain out of scope.
- PDF object-graph inspection covers classic xrefs, xref streams, `/Prev` chains, and object streams;
  undecodable filters remain visible refusals rather than guessed content.
- ODF is supported. Legacy binary Office is identified and reported as uninspected because no
  maintained writer can yet support a credible sector-chain integrity proof.
- Codec-level audio/video rewriting remains out of scope; metadata scanning never decodes media.

### Repository scale

- Seeded 10,000- and 100,000-file benchmarks are published. Repeat them on real repositories only
  with owner consent and record hardware/configuration alongside the result.
- Continue performance profiling on Windows and network filesystems. Deterministic cache eviction,
  a 256 MB default budget, progress events, and cancellation are implemented.

### Plugin and enterprise architecture

- Execute the Linux namespace/seccomp, macOS SBPL, and Windows restricted-token suites on hosted
  runners. AppContainer-grade Windows filesystem/network confinement and comprehensive read
  confinement remain unproven and are not claimed.
- Signed plugin distributions and signed policy bundles are implemented; fleet distribution and
  history storage remain premium service concerns.
- Signed policy bundles, baselines, suppressions, finite exceptions, and per-report audit trails are
  implemented; fleet history storage remains a premium service concern.
- Preserve the frozen public Python/report contracts while extending desktop, CI, and IDE clients.

### Heuristics and learned models

- The corpus, evaluation, feature-contract, release-gate, and longitudinal-analysis frameworks are
  implemented. Build labelled, consented datasets before introducing trained classifiers.
- Calibrate scores and measure false-positive rates by artifact domain.
- Keep feature extraction inspectable and model packages optional.
- Add longitudinal style comparison without turning it into authorship proof.
- Publish evaluation methodology before making product claims.

## Recommended development roadmap

### Phase 1: `0.1.0` release candidate — implemented, pending a real CI run

1. Cross-platform CI matrix. **Done.**
2. Initial commit and packaged source manifest review. **Done.**
3. Dependency, license, SBOM, and artifact-signing checks. **Done.**
4. Adversarial fixtures on Linux and macOS. **Done**, with skips promoted to failures there.
5. Schema `0.1` compatibility freeze. **Done**, and enforced by tests.

Remaining: run the matrix on real infrastructure, configure trusted publishing, and cut the tag.

### Phase 2: authenticated provenance — implemented locally

1. Official C2PA verification adapter. **Done.**
2. Structured trust and signature results. **Done.**
3. Optional explicit network adapters where providers support verification. The gate and adapter
   contract are done; no provider-specific claim is added without a published mechanism.
4. Provenance-aware presentation. **Done** for terminal, JSON, HTML, and desktop projections; a
   packaged interactive GUI is commercial/interface work.

### Phase 3: Office and media expansion — implemented within declared scope

1. Generalized OPC engine for PPTX and XLSX. **Done.**
2. Audio and video container abstractions. **Done** for bounded inspection and surgical
   WAV/MP3/FLAC/ISO-BMFF/EBML metadata cleanup without codec execution.
3. Integrity invariants for presentations, spreadsheets, audio payloads, ISO-BMFF sample tables,
   and EBML track/cluster/cue graphs. **Done.**

### Phase 4: repository and enterprise foundation — implemented locally

1. Deterministic parallel scheduling and incremental caching. **Done.**
2. Third-party plugin isolation, signed distributions, kernel quotas, and platform-specific native
   confinement. **Done**, with the documented Windows/macOS/read-access limits above.
3. Content-bound audit certificates, optional Ed25519 issuer signatures, finite validity, and
   signed issuer revocation lists, organization profiles, offline timestamps, and local
   transparency/rollback checks. **Done.** Managed identity services and hardware-backed custody are
   premium deployment work.
4. Signed policy bundles, baselines, suppressions, finite exceptions, and report audit trails.
   **Done.**
5. Stable SDK contracts and projections for desktop, CI, and IDE integrations. **Done** and frozen
   by API/report snapshot gates.

### Phase 5: optional calibrated intelligence — governance foundation implemented

1. Corpus governance and evaluation protocols. **Done as executable contracts.**
2. Replaceable feature/model contract and model-release gates. **Done.**
3. Consent and license real datasets, then train and publish calibrated metrics. **Not started; no
   learned model is shipped.**
4. Keep learned output explicitly non-provenance unless independently authenticated. **Enforced by
   the current model types.**

## Human Contribution and Process Attestation

This section records the design and product rationale behind the implemented **Human Contribution
Record (HCR)** and its signed portable form, the **TrueAI Process Attestation**. It complements the
scan certificate but is a separate schema, identifier, and verification result.

- A `TAI1-…` audit certificate records what a particular scanner scope observed in exact bytes.
- A `TAIP1-…` process attestation records who declared, performed, reviewed, or verified
  particular stages of creating those bytes and which evidence supports each claim.

The first is artifact forensics. The second is accountable workflow provenance. Neither proves
that a human exclusively authored an artifact, that an idea is objectively original, or that AI
was never used.

### Why elapsed time, prompt count, and edit count are invalid measures

Human contribution is not proportional to typing volume. A hundred hours of minor prompt tuning
can contribute less intellectually than one previously unseen causal insight expressed in two
sentences. Conversely, a novel prompt does not establish that the resulting implementation is
correct, safe, lawful, or actually understood by the person who requested it.

TrueAI must reject these shortcuts as primary metrics:

- elapsed time can measure effort, not creative or causal importance;
- number or length of prompts rewards verbosity and is trivial to game;
- number of edits penalizes a correct first insight and rewards unnecessary churn;
- changed-line percentages confuse mechanical execution with design responsibility;
- the presence or absence of a watermark says nothing about the intellectual value of a human
  decision;
- a single aggregate “human percentage” hides which stages were human-controlled and creates
  false precision.

Prompt, edit, and time records may be attached as supporting facts when a user chooses, but they
must never determine an authorship score automatically.

### The contribution model: a vector, not a percentage

The core record should describe independent dimensions. Each claim carries its own evidence level,
issuer, scope, and limitations instead of being averaged silently.

| Dimension | Question answered | Examples of supporting evidence |
|---|---|---|
| `origination` | Who introduced the central insight, hypothesis, aesthetic direction, or invention? | Dated notes, signed concept brief, lab notebook, prior versions, independent witness |
| `framing` | Who converted the idea into constraints, requirements, success criteria, and a tractable problem? | Specification, architecture decision record, experiment plan, acceptance criteria |
| `decision_control` | Who compared alternatives and made consequential choices? | Reviewed options, rejection reasons, design decisions, approved diffs |
| `execution` | Who or what produced the concrete prose, code, design, data transform, or media? | Git patches, tool receipts, build provenance, editing history |
| `validation` | Who tested claims and outputs against reality rather than accepting generation? | Test logs, source checks, experiments, peer review, reproducible build, audit report |
| `integration` | Who reconciled components, resolved conflicts, and adapted the result to its actual context? | Integration commits, interface decisions, migration evidence, deployment review |
| `accountability` | Which person or organization accepts responsibility for the delivered result? | Signed approval, named owner, policy acknowledgement, release authorization |
| `evidence_quality` | How strongly are the preceding claims supported? | Artifact-bound hashes, trusted timestamps, countersignatures, independent verification |

AI autonomy is a separate per-stage property, not the inverse of human value. Suggested values are
`none`, `assistive`, `proposal`, `delegated_execution`, and `autonomous_with_review`. A record can
therefore say that execution was delegated to a model while origination, framing, selection,
validation, and accountability remained human.

The initial rubric should use descriptive levels rather than percentages:

| Level | Meaning for one dimension |
|---|---|
| `not_claimed` | The record makes no claim about this dimension. |
| `supporting` | The actor contributed useful but non-controlling input. |
| `substantial` | The contribution materially shaped the result. |
| `primary` | The actor supplied most of the consequential direction or work in this dimension. |
| `originating_or_controlling` | The actor introduced the central contribution or retained final decision authority. |

Every level must be paired with an evidence status:

- `self_declared`: signed by the claimant but not independently corroborated;
- `artifact_correlated`: consistent with bound local artifacts such as commits, notes, or tests;
- `countersigned`: confirmed by another identified participant;
- `independently_assessed`: evaluated by a separate reviewer under a named rubric;
- `cryptographically_verified`: the integrity and issuer of a receipt are verified, although the
  truth of its semantic claim may still require judgement.

Cryptographic verification proves who signed which bytes. It does not turn a subjective originality
claim into an objective fact.

### The short-genius-insight case

Suppose a person states a genuinely new mechanism in two sentences and an AI system produces a
correct implementation on the first attempt. A faithful record should not describe the result as
“almost entirely AI” merely because the model emitted most tokens. It should report the stage split:

- `origination`: human, `originating_or_controlling`;
- `framing`: human, usually `primary` or `originating_or_controlling` if the two sentences captured
  the decisive mechanism and constraints;
- `execution`: AI, `delegated_execution`;
- `decision_control`: human if the person knowingly selected and approved the implementation;
- `validation`: human only to the extent demonstrated by tests, derivations, experiments, or expert
  review; otherwise `not_claimed` or weakly supported;
- `accountability`: the person or organization that signs the release decision.

The resulting summary can be **“human-originated, AI-executed, human-validated”**. If the output was
accepted without understanding or testing, the accurate summary is **“human-originated,
AI-executed, validation not evidenced.”** The central insight can still be a major human
contribution; TrueAI should not inflate the validation claim to make the overall record look better.

Objective novelty is a separate and difficult claim. Dated evidence can establish that a person
recorded an idea by a certain time. A prior-art search, independent expert assessment, publication,
or peer review can strengthen a novelty claim. None can prove universal nonexistence of the same
idea elsewhere. The schema should therefore record the search scope, assessor, date, conflicts of
interest, and confidence rather than a boolean `is_genius` or `is_original` field.

### Causal contribution and counterfactual reasoning

When an evaluator needs to judge importance, the most defensible question is causal: which input or
decision changed the space of possible outcomes? The assessment should consider:

1. **Specificity:** did the contribution constrain the solution meaningfully, or merely request a
   generic result?
2. **Novelty within the documented context:** was the contribution already present in cited inputs,
   or did it introduce a new direction?
3. **Decisional consequence:** did later work depend on this choice?
4. **Replaceability:** could a competent participant have supplied the same contribution routinely,
   or was it the scarce insight?
5. **Validation burden:** did the contributor establish that the result worked and understand its
   failure modes?
6. **Responsibility:** did the contributor accept the consequences of publication or deployment?

These questions produce an evaluator judgement, not scanner output. TrueAI should store the
judgement, rubric version, evidence references, assessor identity, and dissenting assessments. It
should never conceal disagreement behind a single number.

### Domain-specific evaluation profiles

Different contexts value different dimensions. Core should publish the vector and leave weighting
to explicit, versioned profiles:

- a research profile emphasizes origination, prior-art discipline, experimental validation, and
  reproducibility;
- a software-delivery profile emphasizes framing, architecture decisions, review, testing,
  security, licensing, and accountable release;
- a creative-work profile emphasizes concept, selection, composition, transformation, and rights;
- an education profile may emphasize demonstrated understanding and forbid delegated execution for
  particular assignments;
- a regulated-enterprise profile emphasizes authorized tools, human approval, validation controls,
  retention, and responsibility more than stylistic authorship.

A profile may calculate a policy result such as `meets_review_requirements`; it must expose its
weights and thresholds and must not rename that policy result to `human_authored`. Two profiles can
legitimately reach different decisions from the same contribution vector.

### Process Assurance Level: the simple result that can be issued

Recipients often need one compact trust signal. TrueAI can issue a **Process Assurance Level
(PAL)**, but it must measure evidence strength and governance, not human creativity or token share:

| Level | Minimum meaning |
|---|---|
| `PAL-0 unsubstantiated` | A record is missing, invalid, or not bound to the delivered artifact. |
| `PAL-1 declared` | An identified claimant signed a structured declaration bound to the artifact. |
| `PAL-2 evidenced` | Material claims reference artifact-correlated evidence and disclose AI roles and known omissions. |
| `PAL-3 reviewed` | Consequential human decisions and validation are evidenced and countersigned by an identified reviewer. |
| `PAL-4 independently_assured` | A distinct assessor named by the evaluation applied a verifier-supported profile, and the record uses organization identity, finite validity, and a trusted timestamp or equivalent transparency proof. |

PAL is deliberately orthogonal to the contribution vector. A brilliant two-sentence insight could
have high `origination` but only `PAL-1` if it is merely self-declared. A routine implementation may
reach `PAL-4` because its process was independently audited. A higher PAL means “better supported”,
not “more human”, “more original”, or “better work”.

An example portable summary for the short-insight case is:

```text
TrueAI Process Attestation: TAIP1-…
Artifact binding: verified
Process summary: human-originated, AI-executed, human-validated
Origination: originating_or_controlling / artifact_correlated
Execution: AI / delegated_execution
Validation: primary human / countersigned
Process Assurance Level: PAL-3 reviewed
Originality: not independently assessed
Limitations: process completeness is declared; exclusive authorship is not proven
```

This is the most defensible answer to “what certificate should be issued?”: issue the stage-specific
record and its assurance strength, never a universal human percentage.

### Data and trust model

The `trueai-process-attestation-0.1` schema contains:

- `attestation_id`: content-derived `TAIP1-…` identifier;
- `schema_version`, `created_at`, optional `expires_at`, and producer version;
- `subject`: exact artifact hash or deterministic directory/repository inventory digest;
- `project`: title, declared purpose, policy context, and optional parent attestation;
- `actors`: pseudonymous or identified people, organizations, AI systems, and automation tools;
- `activities`: ordered or partially ordered derivation events;
- `artifact_bindings`: input, intermediate, and output hashes with media types and relationships;
- `claims`: contribution dimension, actor, scope, level, AI autonomy, explanation, and limitations;
- `decisions`: alternatives considered, selection, rationale commitment, and approving actor;
- `validation`: tests, reviews, experiments, citations, build receipts, and outcome hashes;
- `evidence`: typed local references, hashes, issuer, collection method, and disclosure status;
- `evaluation`: optional profile, rubric version, assessor, per-dimension result, confidence, and
  dissent;
- `disclosure`: public, private, committed-for-later-disclosure, or omitted-with-reason;
- `signatures`: claimant, reviewer, organization, and optional independent assessor signatures;
- `limitations`: mandatory machine-readable and human-readable statements about what was not
  verified.

Each activity should be able to express a provenance tuple similar to:

```text
actor -> action -> input bindings -> output bindings -> tool role -> evidence -> review decision
```

The graph must allow multiple humans, multiple models, branching attempts, rejected alternatives,
and later review. A linear “human versus AI” slider cannot represent real collaborative work.

### Evidence capture and privacy

TrueAI should be useful without uploading prompts or private work. Local adapters may calculate
hashes and extract narrow receipts from:

- Git commits, signed tags, pull-request exports, and reviewed diffs;
- architecture decision records and research notes;
- test, benchmark, build, and reproducibility outputs;
- source/citation manifests and licensing checks;
- local model or tool identity records;
- human approval and reviewer countersignatures.

The public record should contain the minimum necessary claim plus commitments to private evidence.
The user can later disclose selected evidence and prove that it matches the earlier commitment.
Raw prompts, proprietary source documents, credentials, personal identifiers, and confidential
feedback must remain private by default. Normal creation and verification remain local-first and
network-free; trusted timestamping or remote issuer validation requires explicit network policy.

### Issuance and verification workflow

The implemented workflow is:

```text
initialize record
      -> bind actors, policy, and artifact inputs
      -> append decisions and evidence during work
      -> bind final artifact and validation outputs
      -> run TrueAI artifact scan separately
      -> review contribution claims and limitations
      -> sign claimant/reviewer/organization statements
      -> optionally countersign or timestamp
      -> emit public summary plus private evidence bundle
      -> verify hashes, schema, signatures, validity, and revocation
```

The artifact scan can be referenced, but its result must not manufacture process claims. Finding no
AI residue cannot populate `execution=human`; finding a provider marker cannot erase a documented
human origination claim.

Implemented public interfaces include:

```console
trueai attestations init manifest.yaml
trueai attestations validate manifest.yaml
trueai attestations issue manifest.yaml --artifact deliverable.pdf --output deliverable.process.json
trueai attestations sign deliverable.process.json --signing-key reviewer.pem
trueai attestations verify deliverable.process.json --artifact deliverable.pdf
trueai attestations summarize deliverable.process.json
trueai attestations redact deliverable.process.json --output deliverable.process.public.json
trueai attestations schema --output trueai-process-attestation-0.1.schema.json
```

The declarative manifest, Python API, and CLI share the same models. An interactive desktop timeline
can consume the versioned desktop projection without changing the attestation schema.

### Verification result semantics

Verification must return independent results rather than one green badge:

- schema validity;
- content-ID validity;
- final artifact binding;
- evidence-binding completeness;
- claimant signature status;
- reviewer or organization signature status;
- certificate validity and revocation status;
- evaluation-profile support;
- disclosed-evidence consistency;
- unresolved conflicts or dissent;
- limitations acknowledged.

A fully valid signature can coexist with `self_declared` evidence. The UI must say “authenticated
declaration” rather than “verified human contribution” unless an applicable assessor actually
verified the semantic claim.

### Abuse resistance and failure modes

The implementation and documentation must address:

- fabricated or selectively omitted events;
- backdated notes and replayed receipts;
- prompt spam intended to inflate apparent effort;
- splitting one actor into many pseudonyms;
- model output presented as a human note;
- an issuer signing its own unsupported novelty claim;
- a changed artifact paired with an old record;
- hidden contradictory evidence;
- disclosure of trade secrets or personal data;
- coercive workplace surveillance;
- educational use that reduces learning to a score;
- organizations treating `not_claimed` as misconduct;
- verifiers confusing cryptographic integrity with truth.

Controls include typed claim provenance, exact artifact binding, independent countersignatures,
finite validity, trusted timestamps, revocation, visible missing fields, competing assessments,
privacy-preserving commitments, and explicit refusal to derive a universal percentage. No technical
system can prove that every offline human action was recorded, so completeness remains a declared
scope.

### Commercial proposition

The commercial product is not “a badge saying no AI”. That badge would be scientifically weak,
easy to misunderstand, and dependent on TrueAI already being trusted. The stronger proposition is
an evidence and policy layer for organizations that need to accept AI-assisted work without losing
accountability.

Buyers pay for reduced review cost and defensible process, not for the existence of a JSON file.
Concrete paid value includes:

- organization identity, managed signing keys, HSM/KMS integration, timestamps, revocation, and
  transparency;
- configurable workflow gates for research, client delivery, software releases, publishing,
  education, and regulated review;
- team review, countersignatures, exception approval, and separation of duties;
- fleet policy distribution, audit history, retention, access control, and export;
- desktop, CI, IDE, document-management, Git-hosting, and publishing integrations;
- premium format support and supported provider-verification adapters where official mechanisms
  exist;
- compliance mappings, evidence packages, service-level agreements, and incident support;
- private deployment and air-gapped enterprise operation.

The open-source engine remains the independently inspectable trust anchor: scanning, schemas,
local issuance, local verification, and basic signatures should stay open. Premium products sell
identity, coordination, governance, integration, support, and operational trust. Keeping the
verifier and schemas open reduces adoption risk and prevents a commercial badge from becoming an
opaque pay-to-trust mechanism.

A practical open-core packaging boundary is:

| Product layer | Primary user | Value | Suggested boundary |
|---|---|---|---|
| TrueAI Core | Individual, integrator, open-source maintainer | Local scan, safe cleanup, schemas, verification, basic attestations | Open source |
| TrueAI Studio | Freelancer, researcher, creator | Desktop review, evidence timeline, private bundles, client-ready reports | Paid desktop |
| TrueAI Guard | Development and content teams | CI gates, reviewer workflow, countersignatures, policy templates, integrations | Paid per team/workspace |
| TrueAI Enterprise | Regulated or large organization | Managed identity, HSM/KMS, policy fleet, retention, audit export, private deployment, SLA | Annual contract |
| TrueAI Trust Services | Issuers and recipients needing external assurance | Trusted timestamps, transparency, revocation distribution, optional independent assessment | Usage or assurance service; never required for local scanning |

The durable moat should come from rigor and workflow adoption rather than a secret detector:

- format-specific integrity proofs and conservative remediation are difficult to implement safely;
- an open, stable attestation schema lowers recipient risk and encourages integrations;
- organization trust, key lifecycle, policy distribution, and evidence workflows create operational
  switching costs without locking artifact owners out of their records;
- domain profiles and a visible revision history can become a shared language between buyers and
  suppliers;
- plugin and integration ecosystems expand coverage while the core trust contract remains stable;
- published false-positive handling and refusal semantics create credibility that an opaque “AI
  score” cannot supply.

TrueAI should not depend on harvesting user artifacts as a data moat. Local-first privacy is part of
the product, so defensibility must come from engineering quality, interoperability, distribution,
institutional integrations, and trusted operations.

### Escaping the popularity trap

TrueAI must have **single-player utility before network authority**. A user should benefit even when
no recipient has heard of TrueAI:

1. find and explain metadata, attribution, provenance, and structural residue locally;
2. clean only predictable fields and prove integrity;
3. assemble a private evidence package for disputes, clients, peer review, or internal approval;
4. enforce the user's own delivery policy in CI;
5. retain an artifact-bound record of decisions and validation.

Network effects are then layered on top:

- verification is free, local, and requires no account;
- every issued attestation is a portable invitation for a recipient to verify it;
- schemas, verifier code, and trust semantics are public;
- integrations show the record inside tools recipients already use;
- organizations can countersign rather than accepting TrueAI itself as the source of truth;
- compatibility with external provenance standards reduces the need for TrueAI to become the sole
  authority.

The first credible users should be design partners with an immediate bilateral problem, not a mass
audience: a freelancer and client, a research team and reviewer, a software vendor and enterprise
buyer, or a university and course team. In each case both sides agree on the rubric before delivery.
Their signatures and policy establish trust; TrueAI transports and verifies the evidence.

The go-to-market sequence should be:

1. ship the open scanner and verifier as useful local tools;
2. publish precise schemas, sample policies, threat model, and reproducible demonstrations;
3. recruit a small number of design partners in two domains and encode their real acceptance
   criteria;
4. make verification frictionless through CLI, web-without-upload, and repository checks;
5. publish case studies about reduced review time and resolved disputes, not unverifiable detection
   accuracy claims;
6. offer paid organization identity, team workflow, audit retention, integrations, and support;
7. pursue interoperability and standards participation after practical semantics stabilize.

Success should be measured by completed and independently verified workflows, repeat verification,
time saved in review, policy violations caught before delivery, accepted countersignatures,
integration retention, and dispute resolution. Download counts or the number of issued badges alone
do not establish trust.

### Product naming and separation

The product family can expose three clearly separated records:

- **TrueAI Audit Certificate (`TAI1`)**: scanner result for exact bytes and declared detector scope;
- **TrueAI Process Attestation (`TAIP1`)**: signed claims and evidence about creation, decisions,
  validation, AI roles, and accountability;
- **TrueAI Independent Assessment**: an optional countersigned evaluator opinion under a named,
  versioned domain profile.

The GUI may present them together, but the schemas, identifiers, verification statuses, and claims
must remain distinct. A clean audit certificate must never upgrade a process attestation, and a
strong human contribution record must never suppress observed artifact provenance.

### Acceptance criteria and external validation

The repository implementation satisfies the following criteria:

- the schema has a frozen compatibility contract independent of scan reports and audit
  certificates;
- one artifact and one deterministic repository inventory can be bound and re-verified;
- multiple human and AI actors plus branched/rejected activities are representable;
- contribution vectors preserve per-dimension evidence and never require an aggregate percentage;
- public/private disclosure and deterministic redaction have adversarial leakage tests;
- unsigned, claimant-signed, reviewer-countersigned, expired, revoked, and modified-artifact cases
  have distinct verification results;
- Git, test, build, and note evidence can be committed by hash without copying private content;
- the CLI and Python API can create and verify a record entirely offline;
- every human-readable summary repeats the applicable limitations;
- no scanner finding automatically asserts authorship, originality, or human execution.

One criterion is intentionally external and remains `PROC-12`: at least two consented domain pilots
must expose rubric disagreements before contribution profiles are presented as a stable product
feature. The code can preserve disagreement; it cannot manufacture an independent party who has one.

## Near-term priorities

The five highest-value next tasks are:

1. run the CI matrix on real infrastructure, then cut the `v0.1.0` release candidate;
2. configure protected TestPyPI/PyPI trusted publishing, exercise TestPyPI, then verify the hosted
   Sigstore/GitHub evidence set from a clean machine;
3. recruit consented research and software-delivery design partners for the first two `TAIP1`
   rubric pilots, followed by creative-work and education pilots;
4. package a desktop/CI product around the existing adapters and add managed organization identity,
   HSM/KMS signing, timestamp, revocation, and transparency services;
5. collect licensed, consented research corpora under the implemented governance contracts and run
   calibrated false-positive studies before deciding whether any learned model should ship.

## Success criteria for the next milestone

TrueAI Core should move from `0.1.0-dev` to a release candidate when:

- all supported Python and operating-system CI jobs pass;
- skipped symlink/security cases execute successfully on at least one CI platform;
- wheel and sdist builds are reproducible; release artifacts are signed by hosted release CI;
- the public schema compatibility policy is documented and enforced;
- hostile-input regression suites remain green;
- no cleaner can remove protected provenance through an overlapping metadata operation;
- every supported cleanup either proves integrity or refuses publication;
- documentation describes only demonstrated capabilities.

The code-side gates can be checked locally. Hosted cross-platform CI, release signatures, and trusted
publishing remain external release gates and are not claimed complete by a local run.

## Strategic direction

The open-source engine should remain evidence-focused, local-first, and conservative. Commercial
products can add workflow, collaboration, policy distribution, fleet management, visual review,
and supported verification services without weakening the core evidence model.

The durable product advantage is not a sensational AI score. It is a trustworthy chain from
inspection, through explanation and policy, to predictable remediation with verifiable content
integrity — and the discipline to report `valid` when a signature is merely correct, and
`verifier_unavailable` when nothing can be checked at all. Audit certificates extend that chain by
binding the exact detector scope and outcome to exact bytes without turning absence of evidence into
an authorship claim.
