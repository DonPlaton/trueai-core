# Changelog

All notable changes to TrueAI Core are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
semantic versioning. Before `1.0.0` the minor number carries breaking changes.

The **report schema version** moves independently of the package version. A schema
change is called out explicitly and governed by
[docs/schema-compatibility.md](docs/schema-compatibility.md).

## [Unreleased]

### Added

**Managed trust stores: distribution, rotation, and offline updates**

- `trueai/core/trust_store.py`. A `TrustProfile` answers "whose key is this" for
  one signature; a trust store is what an organization deploys to a fleet — C2PA
  roots, issuer keys, plugin publisher keys — as one signed, sequenced document
  with a lifetime.
- **Rollback is refused.** A store is installed against the sequence this machine
  already holds, because a rollback reinstates every key the intervening
  sequences revoked. A verifier with no memory cannot detect that, so the API
  asks for the memory rather than pretending it is unnecessary.
- **An expired store yields no anchors at all**, rather than continuing to honour
  what it held. Otherwise the lifetime would be decorative.
- **Rotation gaps are found.** A replacement anchor names what it replaces, and
  `rotation_problems()` reports the window where the successor starts after the
  predecessor ended — the failure nobody connects to a key rotation, because it
  surfaces months later as a signature that will not verify. Installing reports
  it as a warning, not a refusal: the gap may be deliberate, but not silent.
- **Offline updates advance exactly one sequence.** Jumping from 4 to 6 would
  skip whatever 5 revoked, and a revocation you skipped is a key you are still
  trusting. Enforced twice: the update model refuses to describe a jump, and
  `apply_update` refuses one that does not start where the machine is.
- An update carries the whole successor rather than a diff, so "what will I be
  trusting afterwards" needs no computation. A refused update leaves the
  installed store in place, never a partially applied one.
- `AnchorKind` keeps `c2pa_root`, `issuer_key`, `plugin_publisher`, and
  `timestamp_authority` apart: trusting a key to sign C2PA manifests is not
  trusting it to publish plugins.
- `to_trust_profile()` and `c2pa_anchor_pems()` are projections, not second
  sources of truth, and both apply the store lifetime, the anchor window, and
  every revocation before returning.
- `docs/trust-store.md`.

### Changed

- Trust-store verification splits three failures a single "the signature does not
  verify" would collapse: an unreadable key file, the wrong key for this store,
  and a signature that genuinely disagrees with the bytes. Telling an operator
  their signature failed when they typed the wrong filename sends them looking
  for an attacker.

**One network gate, and an admission standard for provider adapters**

- `trueai/core/network.py` is the only place TrueAI may reach the network. Six
  conditions, all required: `NetworkPolicy.EXPLICIT_ONLY`, recorded consent, an
  exact endpoint allowlist, a timeout and response-size cap, per-request
  credentials, and an audit record.
- Consent is separate from policy on purpose. A policy flag says the software
  may; consent says a person decided. It is scoped to endpoints *and* a purpose,
  so consent to check a watermark is not consent to upload a document.
- The audit records **refusals as well as successes**. A forensic tool needs to be
  able to prove it did not contact anything, and a log of successes cannot do
  that. A record carries endpoint, purpose, grantor, duration, response size, and
  header *names* — never a body, never a header value, because a header value can
  be a credential.
- The gate holds no credential. A caller supplies a callable invoked per request
  with the endpoint being contacted, so a credential produced for one destination
  cannot be replayed to another when an allowlist grows.
- `AdmissionCriteria` states what a provider must publish before an adapter is
  written: a published mechanism, independently runnable, specified semantics, and
  a stable contract — all four. Three out of four describes a watermark someone
  reverse-engineered, and shipping that would present a guess as a verification.
- `PROVIDER_ASSESSMENTS` records where each provider stands, in code rather than
  only in prose. C2PA is the only one admitted. An unadmitted provider reports
  `VERIFICATION_UNAVAILABLE` naming the criteria it fails.
- A provider adapter is offline unless handed a configured gate, and one that has
  not declared `network_required` cannot make a request even with one.
- `docs/network-and-providers.md`.

### Changed

- `NetworkTimestampProvider` was carrying its own copy of the policy and
  allowlist checks; it now builds or accepts a `NetworkGate` and calls through it,
  so "did this tool contact anything" has one answer and one audit trail. Its
  original two-argument transport shape is adapted to the gate's protocol rather
  than replaced, because changing it would break every caller who wrote one.

**OpenDocument inspection and cleanup**

- `ArtifactType.ODF` covers OpenDocument text, spreadsheets, presentations, and
  their templates. One type rather than three, because unlike OOXML they share a
  single content part and a single metadata part; the subtype is read from the
  package's `mimetype` entry and reported per finding as `document_kind`.
- Identification reads that entry from the file's opening bytes. The
  specification requires it to be first and stored uncompressed, so the archive is
  never opened during type identification and a hostile package cannot be inflated
  by being looked at. The file name is not consulted first: an extension is
  attacker-controlled, the package's own declaration is not.
- Detection reports `meta.xml` fields including `meta:user-defined` under its
  declared name, marks provenance-bearing values unremovable, and **lists macro
  storage without parsing or executing it**.
- Cleanup removes selected fields and proves the result: `content.xml`
  byte-identical, every entry but `meta.xml` unchanged, and the `mimetype` entry
  still first and still stored uncompressed. A package that loses either mimetype
  property stops being recognised by readers, which would be a cleanup that broke
  the file while leaving its content intact.
- `ArtifactType.LEGACY_OFFICE` identifies `.doc`, `.xls`, and `.ppt` by their
  Compound File Binary header and reports them as not inspected. `FMT-06`
  evaluated the format and declined: nothing maintained writes CFB, and an
  integrity proof would have to reason about interleaved sector chains rather than
  separable entries. A file silently skipped looks exactly like a file that was
  clean, so the format is named instead.
- `docs/odf-and-legacy-office.md` records both decisions and what would change
  them.

### Fixed

- `cleaner_for` had no entry for `ArtifactType.VIDEO`, so the ISO-BMFF and EBML
  cleanup added in `FMT-02` and `FMT-03` was unreachable through the remediation
  pipeline — a plan selecting MP4 or WebM metadata failed with "no cleaner
  supports video". Those cleanups were tested by calling the cleaner directly,
  which is why the gap survived. A test now asserts every artifact type with a
  cleanup resolves.

**HTML topology and stylesheet feature measurements**

- `trueai/core/dom_features.py` measures document and stylesheet shape: depth and
  tag histograms, wrapper-only elements, duplicate ids, class tokens, inline
  styles, external references, and — for stylesheets — rules, selectors,
  declarations, a specificity histogram, `!important` density, vendor prefixes,
  custom properties, and duplicate selectors.
- Everything is a **count**. No thresholds, no scores, no verdicts. A structural
  signal presented as provenance is the error this project exists to avoid, and
  the module is built so it cannot make it. Two tests enforce the boundary by
  rejecting any evidence key that reads like a judgement and any value that is not
  a number or a boolean.
- Text and markup characters are reported separately rather than as a ratio, so a
  reader computes whichever ratio they want. Script and stylesheet bodies count as
  markup: otherwise a page with one large bundle looks text-heavy.
- Specificity uses the cascade's own `(id, class, type)` definition, not an
  approximation.
- The CSS parser matches braces by depth. Finding the next `}` breaks on
  `@media screen { .a { color: red } }`, where `.a { color` then parses as a
  declaration — a parser reporting nonsense with total confidence. The tests
  caught it.
- Budgets cover nodes, depth, parser events, rules, and *retained* bytes.
  Exhaustion returns partial measurements with `complete=False` rather than
  raising, because "as far as N elements, it looks like this" beats an exception
  as long as the partiality is impossible to miss.
- The HTML and CSS detectors report these as `STRUCTURAL_SIGNAL` findings at
  severity `INFO` with `ProvenanceClass.NONE`, whose descriptions say in words
  that they are not evidence of authorship.
- `docs/dom-features.md`.

**Bounded PDF object graph**

- `trueai/core/pdf_objects.py` walks the cross-reference table or stream, follows
  `/Prev` through incremental updates and `/XRefStm` through hybrid files, and
  reads object streams.
- This closes a real coverage hole. Since PDF 1.5 a producer may put the
  cross-reference table in a stream — so `trailer` appears nowhere — and put
  `/Info` inside a compressed object stream, so `/Author` is never plain text.
  Against those files the lexical scanner reported nothing, and reporting nothing
  looks exactly like finding nothing. Tests assert the premise directly.
- Bomb-safe by construction: `inflate_bounded` passes the cap **into** the
  decompressor rather than decompressing and then checking the size. The inflated
  budget is charged per document, so a file cannot spend a little on each of ten
  thousand streams.
- Six budgets, and two exception types. `PdfStructureError` means malformed;
  `PdfLimitExceeded` means the file is trying to exhaust the parser. Only one of
  those is an attack.
- Signature fields and the byte ranges they cover, encryption, and XMP packets are
  modelled, so a cleaner can refuse rather than discover the problem afterwards.
- Filters other than Flate and ASCIIHex are reported as present-and-undecoded
  rather than decoded by guesswork. An inspector that pretends to have read a
  stream reports absence as evidence.
- The PDF detector tries the graph first and falls back to the lexical scan, and
  each finding records which reader produced it in `evidence["reader"]`.
- `docs/pdf-object-graph.md`.

**EBML/WebM invariants and cleanup**

- `trueai/core/ebml.py` specifies six invariants — tracks, clusters, cues,
  timing, seek positions, provenance — over a structural model that resolves
  `SeekHead` and `Cues` positions to whatever elements are actually there.
- The failure it exists to catch is the EBML spelling of the MP4 one: removing
  bytes from `Tags` shifts every cluster after them, while the document still
  parses, the duration is still right, and every block is byte-identical. Only
  the stored positions are now wrong. A test asserts the block digests were
  identical in exactly that case.
- `CodecPrivate` is named in the failure detail, because losing it is the
  difference between a file that plays differently and one that does not play.
- WebM and Matroska metadata can now be removed. The selected `SimpleTag` is
  overwritten with a same-length `Void` — EBML's own padding element — so nothing
  moves and no `SeekHead` or `Cues` position needs rewriting.
- `void_element` is exact by construction and tested from 2 bytes to 5 MB. The
  whole substitution depends on the replacement being the same size.
- A document carrying a provenance attachment is refused outright, as an MP4 with
  a C2PA box is.

**Surgical ISO-BMFF metadata cleanup**

- MP4, MOV, and M4A metadata can now be removed. The selected box is overwritten
  in place with a zero-filled `free` box of exactly the same length, so the file
  keeps its length and **no chunk offset needs correcting** — the failure mode
  `FMT-01` specifies is avoided by not creating the situation that causes it.
- The cost is stated rather than hidden: the file does not get smaller. The
  metadata bytes become padding.
- Every result is checked against the seven invariants before it is written, so
  "nothing moved" is a verified fact rather than a claim about the implementation.
  A refused edit leaves no output file.
- A container carrying a C2PA or XMP provenance box is refused outright: a
  manifest binds byte ranges of the file it lives in, so any edit invalidates it.
  This check is structural, through the box UUID, because the byte-marker scan the
  other formats rely on does not catch a C2PA box whose payload never spells
  `c2pa`.
- Also refused: unknown `ftyp` brands, overlapping selections, and entries with no
  removable box range. `MediaMetadataEntry.removable_range` names the whole
  enclosing box, because an `ilst` item with its `data` box removed is a malformed
  item rather than an absent one.
- The integrity report's logical digest is the sample bytes reached through the
  offset tables, not the `mdat` box, which would answer a different question.

**Executable MP4/MOV/M4A invariants**

- `trueai/core/iso_bmff.py` models an ISO base media file structurally: the box
  tree, and each track's sample layout resolved through `stsc`, `stsz`, and the
  chunk offsets to absolute byte ranges.
- Seven invariants — samples, timing, edit lists, indexes, encryption state,
  rendering-critical metadata, protected provenance — each reported separately.
  There is no single `valid` field: "the samples moved" and "the provenance box
  was dropped" need different remedies.
- The samples invariant hashes the bytes the tables point at rather than the
  `mdat` box, because `stco` stores absolute file offsets. Removing a byte before
  `mdat` without correcting them leaves a file that parses, reports the right
  duration, has a byte-identical `mdat`, and plays garbage. A test asserts a byte
  comparison would have missed exactly that.
- `indeterminate` counts as unsafe. An edit whose effect cannot be checked is an
  edit that must not be applied.
- Parsing is bounded: depth 16, 100,000 boxes, four million sample entries, with
  the declared count checked before anything is allocated against it. A box
  claiming more bytes than remain is a refusal, not a short slice.
- `docs/container-invariants.md` explains why this format needs a structural gate
  where WAV and FLAC did not.
- The media cleaner still refuses ISO-BMFF. Two tests pin the refusal and the
  satisfiability of the invariants, so `FMT-02` implements against a
  specification that something can actually pass.

**Continuous fuzzing of the plugin trust boundary**

- `scripts/fuzz_plugins.py` fuzzes the worker protocol, the manifest and
  distribution parsers, finding validation, resource limits, and broker path
  resolution.
- Each target declares the exceptions it is allowed to raise **and** the invariant
  that must hold when it does not. A crash is not the only failure: a parser that
  accepts a forged finding without crashing is the failure the boundary exists to
  prevent, so the finding target asserts that everything accepted still matches
  its own evidence, its detector, and its artifact.
- Half the generated input is mutations of valid documents rather than random
  structures, because random input mostly exercises "is this JSON" and never
  reaches the checks that run after parsing succeeds.
- Runs are seeded and every case carries a derived seed, so a failure found
  overnight replays with one command.
- `tests/unit/test_plugin_fuzz.py` runs a bounded campaign in the ordinary suite,
  pins the corpus inputs that must always be refused, and deliberately breaks two
  checks to prove the fuzzer reports them. A harness that has never failed is
  indistinguishable from one that cannot fail.
- CI gained a `plugin-boundary` job (a 20,000-case campaign plus the Linux
  confinement checks on every push) and a nightly `nightly-fuzz` matrix running
  ten minutes per target.

**Signed plugin distributions**

- `trueai/plugins/distribution.py` signs every file of a plugin together with the
  capabilities it declares. The host reads the manifest from the signature, so a
  plugin is never imported to find out what it wants — and because the module's
  bytes are covered by the same signature, a declared capability set cannot be
  contradicted by what module-level code actually does.
- Every file is listed, not a chosen subset. `__pycache__` is excluded because the
  interpreter generates it, and `trueai-distribution.json` because a document
  cannot contain its own digest.
- `DistributionVerification` has no `valid` field. Integrity, identity, currency,
  and compatibility are reported separately, and a file that changed, a file that
  is present but unlisted, and a signed file that is missing are three different
  results because they are three different attacks.
- `authenticated_publisher` says a signature verified over content that still
  matches. Naming the publisher's organization needs a `TrustProfile`, the same
  primitive certificates and attestations use.
- `PluginAllowlist` names distributions or publisher keys and carries the
  publisher's withdrawals with a reason. It is sequenced and finite-lifetime, and
  `verify_allowlist` takes the highest sequence the verifier has seen: an
  allowlist replaceable by an older copy allows whatever the older copy allowed.
- `trueai plugins sign`, `trueai plugins verify`, and `trueai plugins allowlist`.
  `DistributionPolicy(require_signed=True)` is what turns any of it into a
  control; without it a distribution is checked when present and absent otherwise,
  which is useful during a rollout and is not enforcement.

**Adversarial tests with hostile native plugins**

- Example plugins that reach the operating system through `ctypes` on both POSIX
  and Windows: a native writer, reader, socket opener, process spawner, and a
  worker that blocks inside a native sleep where no Python deadline can reach it.
- `scripts/verify_native_plugins.py` runs them through the whole real path — entry
  point, manifest review, worker spawn, confinement, guards, deadline — against a
  real kernel in a container. On Linux a hostile native plugin cannot write outside
  its grant, cannot open a socket, and cannot start another program; on every
  platform it cannot outlive its deadline.
- The script carries **negative controls**: the same plugins with confinement off,
  where the attack must succeed. Without them a check that passes because the
  attempt would have failed anyway is indistinguishable from one that passes
  because confinement worked.
- Gaps are asserted, not left implicit. Reading outside the grant still succeeds
  everywhere, and on Windows a restricted token confines nothing native beyond the
  deadline. `test_windows_does_not_stop_a_native_write_and_says_so` fails the day
  that changes, so the docs and the behaviour move together.

**Linux write confinement**

- A read-only mount namespace, with the scratch grant and the worker's protocol
  directory re-opened for writing. Native code cannot write outside the grants
  either — previously only the Python guards stood in the way, and native code
  goes around those.
- Read confinement is still not implemented: it needs `pivot_root` into a
  per-invocation tree. That is recorded as a gap in every report.
- Supplementary groups are dropped by the user namespace, so a file readable only
  through one of them becomes unreadable to the plugin. Stated in the report
  rather than discovered.

**Operating-system confinement for plugin workers**

- `trueai/plugins/confinement.py` asks the kernel to enforce what the broker only
  contracts for. `--plugin-confinement none|best_effort|required` selects the
  posture; `required` refuses to run a plugin when confinement cannot be
  established, because silently degrading to "we tried" is indistinguishable, in a
  report, from having succeeded.
- **Linux**: `PR_SET_NO_NEW_PRIVS`, an empty network namespace when `network` is
  not granted, and a seccomp BPF filter that kills the process on a denied
  syscall rather than returning an error a plugin can retry around. The denied set
  is derived from the grants. `fork` and `vfork` are deliberately absent: glibc
  routes `os.fork()` through `clone`, which threading also uses, so filtering it
  would break the interpreter — the gap is recorded instead of faked. Syscall
  numbers are pinned for x86_64 and aarch64 only; other architectures report the
  mechanism unavailable rather than filtering against guessed numbers.
- **Windows**: `trueai/plugins/windows_token.py` spawns the worker through
  `CreateRestrictedToken` and `CreateProcessAsUserW`, dropping every privilege and
  making `BUILTIN\Administrators` deny-only. It is not AppContainer — no
  filesystem or network isolation — and the report says so instead of reporting
  "confined".
- **macOS**: a generated deny-by-default SBPL profile with writes limited to the
  scratch grant. Unverified: there is no macOS machine here, and the backend is
  marked as untested rather than presented otherwise.
- Every report lists what the mechanism did *not* enforce, and that list is never
  empty for a real backend.
- `scripts/verify_linux_confinement.py` verifies the Linux backend against a real
  kernel in a container, asserting both the controls and the documented gaps.

**Capability broker for plugins**

- `trueai/plugins/broker.py` replaces boolean plugin permissions with scoped
  grants. A capability that cannot express its scope has to be granted at its
  widest, which is how `write_filesystem` came to mean "anywhere the user can
  write".
- `ArtifactGrant` is one file plus the digest the host re-checks. `WorkspaceGrant`
  is one root, with paths resolved before the prefix check so traversal and
  absolute paths are both refused. `TemporaryOutputGrant` is a host-owned
  directory with a byte budget charged across every write, and a refused write
  never reaches the file. `NetworkGrant` and `SubprocessGrant` are allowlists that
  refuse to be constructed empty, because a grant with no scope must grant nothing
  rather than everything. `NativeLibraryGrant` must set `acknowledged_unmediated`,
  since the broker cannot mediate native code and should not imply it can.
- Two new capabilities: `write_temporary` (scratch output, previously only
  expressible as `write_filesystem`) and `load_native_library` (declared, not
  contained).
- A plugin opts in by declaring `bind_broker`. One that does not behaves exactly
  as before. `CapabilityDeniedError` carries the capability and the scope, and
  names the capability in its message even when the caller's text did not.
- The filesystem guards now permit writes inside a granted scratch directory, so
  `write_temporary` is usable rather than granted-and-denied.

**Interoperable provenance exports**

- `trueai/core/interop.py` maps a record onto W3C PROV-JSON, in-toto Statements in
  DSSE envelopes, and C2PA assertion data, with `trueai attestations export
  --to prov|dsse|c2pa` and `trueai attestations interop`.
- Standard terms are used where they fit and TrueAI concepts sit under the
  `trueai:` prefix, so a `prov:`-prefixed term always means what PROV says it
  means. `wasAttributedTo` carries no strength of its own; level, evidence status,
  claim type, and AI autonomy travel beside it as TrueAI properties.
- Every export carries `unmapped_concepts()` — what its target could not express
  and why. An export that silently drops the evidence status turns "alice declared
  she originated this" into "alice originated this".
- DSSE envelopes are signed fresh over the pre-authentication encoding. A record
  signature covers the record's canonical bytes, which are different bytes, so it
  is never copied into an envelope.
- C2PA mapping is conservative: `digitalSourceType` is emitted only where the
  autonomy level licenses it, purely human work gets no code at all, superseded
  attempts produce no action, pseudonymous actors are never named, and the field
  is `creator` rather than `author`. TrueAI produces assertion data and does not
  sign, embed, or produce C2PA manifests.
- `docs/interoperability.md` documents the mappings and the gaps.

**Evaluation profiles and Process Assurance Level**

- `ProcessAssuranceLevel` PAL-0..PAL-4 with `assess_process_assurance`, derived from
  what verification established rather than from what a record claims about itself.
  A record asserting the strongest claims in every dimension with nothing behind
  them stops at PAL-1. `AssuranceAssessment.next_level_requires` says what would
  raise it, so the result is actionable rather than a grade. Undisclosed machine
  work blocks PAL-2 and unresolved dissent blocks PAL-3: both are conditions, not
  deductions from a score.
- Five versioned evaluation profiles — `research`, `software-delivery`,
  `creative-work`, `education`, `regulated-enterprise` — whose weights and
  thresholds are model fields rather than constants, because a profile that will
  not show its weights is asking to be trusted rather than checked. The answer is
  `meets_review_requirements`: a policy result about process evidence, never an
  authorship or originality determination.
- Profiles may disagree about the same record, and that is the design. Delegated
  execution a delivery team expects is exactly what an assignment about
  demonstrated understanding forbids; each result names its profile and version so
  it can be re-derived. An unmet requirement is worded as a rule, not an
  accusation.
- `stage_summary`, `portable_summary`, and `sarif_properties` are the single source
  for every surface. `trueai attestations evaluate` renders terminal, JSON,
  portable-summary, and SARIF-property forms; `trueai attestations profiles` prints
  each profile's weights; `trueai scan --attestation` adds a record's verified facts
  to a SARIF run's property bag without altering any finding.
- `docs/evaluation-profiles.md` documents PAL, the profiles, and the presentation
  rules.


**Shared trust primitives**

- `SigningProvider` narrows key custody to one interface. `ExternalSigningProvider`
  is the HSM/KMS seam: it receives canonical bytes and returns a signature, so no
  private key enters a TrueAI process. A provider whose signature its own public
  key rejects fails at signing time rather than shipping an unusable artifact.
- `TrustProfile` binds keys to organizations for stated periods, with `key_only`,
  `profile_bound`, and `root_attested` assurance levels. TrueAI ships no default
  profile: deciding whom to trust is the operator's decision. Verification exposes
  `authenticated_declaration` and `organizationally_attributed` separately.
- `TimestampToken` records a separate authority's statement about when bytes
  existed, distinct from the signer's own `signed_at`. The offline provider signs
  with a designated timestamping key; the RFC 3161 provider requires
  `NetworkPolicy.EXPLICIT_ONLY`, an operator allowlist, and a caller-supplied
  transport. An RFC 3161 token is carried but reported as not established, because
  TrueAI does not parse it and an opaque blob is not evidence.
- `TransparencyLog` gives revocation and policy state append-only ordering with a
  hash chain. Edited entries, removed entries, older copies, and same-length
  rewritten histories are each detected. Rollback detection requires the verifier's
  remembered head, and the API says so rather than pretending a memoryless verifier
  can detect one.
- Process attestations reuse all of it while keeping their own prefix, schema,
  vocabulary, and verification result.
- `docs/trust.md` documents the primitives and the retention, access, privacy, and
  export contracts for fleet history.


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

**Adversarial and usability coverage for contribution records**

- `tests/unit/test_attestation_adversarial.py` exercises forged evidence, backdated
  claims, markup injection and oversized input, actor impersonation, omitted AI
  roles, conflicting countersignatures, redaction leaks, changed artifacts, expired
  claims, revoked issuers, and unsupported evaluation profiles — each paired with a
  test that the corresponding honest case still passes, so no check is a blanket
  refusal.
- Every collection on a record is now bounded (`claims`, `evidence`, `activities`,
  `decisions`, `validations`, `actors`, `signatures`, `limitations`,
  `Evaluation.results`). String fields were already capped, but an unbounded list
  turns an 8 MB file into tens of thousands of entries every consumer must render.
  The limits sit far above any real record.

### Changed

**Process assurance**

- Disclosed evidence that does not match its published commitment now blocks the
  evidenced level (PAL-2). Offering bytes that fail their commitment falsifies the
  claim they were offered as, which is a worse position than not having disclosed.
- Recorded dissent now blocks the reviewed level (PAL-3). A countersignature that
  records disagreement does not settle anything, and a dispute is not resolved by
  outranking it.

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
