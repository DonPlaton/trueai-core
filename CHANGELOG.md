# Changelog

All notable changes to TrueAI Core are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
semantic versioning. Before `1.0.0` the minor number carries breaking changes.

The **report schema version** moves independently of the package version. A schema
change is called out explicitly and governed by
[docs/schema-compatibility.md](docs/schema-compatibility.md).

## [Unreleased]

### Fixed

**A README example that could not be followed**

`certificates revoke` was demonstrated against the unsigned certificate the
example two lines above had just produced, and revocation needs an authenticated
issuer — so a reader copying the block got "unsigned certificates have no
authenticated issuer to revoke them". `scripts/check_docs.py` could not see it:
every command and option in the line existed, and existing is not working.

`tests/integration/test_readme_commands.py` now runs each `trueai …` line from
the README's console blocks, in order, in one directory, against real fixtures —
the way a reader follows it — and fails on exit code 3 or 4 as the README's own
exit-code table defines them.

### Changed

**`--plugin-confinement required` stopped discovering plugins on macOS**

Making the confinement level decide whether a refused resource limit is fatal was
a shortcut, and it redefined a documented setting: `docs/plugins.md` says
`required` refuses to run a plugin "when confinement cannot be established", and
the Linux backend's own report lists "memory and CPU" among the things
confinement does *not* cover. Since macOS declines `RLIMIT_AS` outright, the
coupling turned "confine my plugins" into "do not run plugins" on every Mac.

Strictness now lives on the budget — `PluginResourceLimits(required=True)` — and
is off by default, so a platform that cannot cap address space is one with a
reported gap rather than one without plugins. `InspectionRequest.confinement`,
added a commit earlier and read by nothing after this, is gone with it.

**A cleaned file said its content had not changed**

`shutil.copystat` copies permission bits and timestamps together, and it is what
both cleanup paths reached for, so `trueai clean` handed back a file whose
modification time was the one it had before the edit. Nothing recorded that as a
decision and no test covered it, which is how a default that nobody chose
becomes behaviour.

Permission bits describe the file's place in the filesystem and still survive.
The modification time is a claim about when the content last changed, and it just
did — putting it back hides the edit from rsync, from build systems, and from
anybody reading timestamps as evidence, which in a forensic tool is the behaviour
being complained about rather than performed. The backup keeps the original
timestamp, because the backup really is the original content.

The in-place write is also documented now: it writes into the original file
rather than renaming a temporary over it, because `os.replace` would give the
artifact a new inode and break hard links and open handles. The backup is what
makes a torn write recoverable.

**Rewriting one field renamed every element in the document**

`ElementTree.tostring` invents a prefix for every namespace it was not told
about, so removing one comment from an SVG returned
`<ns0:svg xmlns:ns0="http://www.w3.org/2000/svg">` with every child renamed to
match, and removing one Word property rewrote `<cp:coreProperties>` as
`<ns0:coreProperties>`. Equivalent XML, and a diff showing the whole part
changed — a strange thing to hand back from a project whose case for its cleanup
is that an edit touches what it says it touches.

`tostring` has a `default_namespace` parameter for exactly this and refuses a
document with unqualified attribute names, which every SVG and OOXML attribute
is. `trueai.core.xml_serialization` reads the prefixes out of the document being
rewritten and installs them for the length of one call, under a lock, instead of
imposing a convention on the process. Parts that are not rewritten are still not
rewritten at all.

**Three places the output was accurate line by line and overstated as a whole**

None of these was a wrong value. Each was a headline, a total, or a count that a
reader is entitled to read one way and that meant another — which for this
project is the defect, not a presentation preference.

- **`trueai certificates verify` printed `VALID`, in green, over a document
  nobody signed and nothing was compared to.** The explanations underneath were
  correct; the word above them is what a reader takes away. `valid` still means
  "nothing that was checked came back false", and it is now joined by
  `CertificateVerification.unchecked()` and `.authenticated`, so the headline can
  say `VALID, NOT FULLY CHECKED` and list what nobody looked at. Revocation is
  reported but does not qualify the verdict, because a caveat that fires on every
  verification is read on none of them. `--require-full-verification` turns the
  caveat into an exit code.
- **The `Evidence class` table did not add up to the finding count.** Evidence
  class is a partition and provenance is an attribute a finding of any class may
  also carry, so `PROVENANCE` as a fifth row made two findings render as three.
  It is a sentence under the table now.
- **One SVG metadata block was reported twice.** `<metadata><rdf:RDF>` is the
  shape every Inkscape file has, and walking every element emitted a finding for
  the container and another for its child, with the same title, description and
  excerpt. The outermost block is reported once and names what it contains.

Report paths are also documented now: every path is relative and the root of a
directory scan is `.`, which is what makes two scans of one corpus compare byte
for byte and keeps the operator's directory layout out of a document that gets
sent to somebody else — and costs a report the ability to say, on its own, which
directory produced it.

### Security

**A signed certificate could have its signature removed and still verify**

`signature_ok` was `certificate.signature is None or signature_verified is True`,
which reads the absence of a signature as nothing to check rather than as the
check failing. Stripping the signature from a signed certificate leaves the
claims and the content identifier intact, so everything else still matched, the
supplied public key was quietly ignored, and `verify_certificate` returned
`valid=True`.

Found by tampering with each field of a signed certificate in turn and asking the
verifier the same question it is asked in production. Six of the seven edits were
refused; that one was not.

The two rules are written separately now, because they are different rules. A
certificate carrying a signature is claiming an issuer, and an unchecked claim is
not a pass: without a public key there is no verdict. A certificate carrying none
claims no issuer and is valid on its content identifier alone — unless the caller
supplied a key, which is them saying they expected one.

`tests/unit/test_certificate_tampering.py` makes each edit an attacker would make
and checks the verifier's answer to each.

**Seven regular expressions a file could stall the scanner with**

Quadratic in the length of the artifact, all of them reachable from
`trueai scan <file>`, in a tool whose only job is reading files somebody else
wrote. Measured rather than suspected: 800 kB of `<!--` with no `-->` did not
finish in a minute, and 60 kB of CSS with no braces took seventeen seconds. Every
one was inside the default 25 MB file limit at the point where it stopped
finishing, so the limits that exist to bound a scan did not bound this.

Three shapes, and the same mistake in each: a search that fails is retried from
the next starting position, and the file chooses how many starting positions
there are.

- **A lazy span looking for a closing delimiter that is not present.** `<!--…-->`
  in the fallback comment reader, `<?…?>` in an XML prolog, `/Info <<…>>` in a
  PDF trailer that runs to the end of the file when `startxref` is missing.
  Replaced with `trueai.core.spans`, which stops at the first failed search:
  a closer that is missing after one opener is missing after every later one, so
  the whole scan becomes forward `find` calls that never reread a byte. The
  regions reported are the same ones, including that an unterminated comment is
  still not a comment.
- **A bracketed group whose contents could contain the bracket that opens it.**
  `[^\]]*` in the CSS attribute-selector feature, `[^)]*` in the pseudo-class
  and colour features, `[^>]*` in the `<path>` and `<meta>` scans. Excluding the
  opener makes a failed attempt stop at the next candidate instead of at the end
  of the file, and is also what the syntax means: none of these nest.
- **Two adjacent quantifiers accepting the same character.** `[^<\r\n]*` followed
  by `\s*` in the Claude and ChatGPT co-author trailers: a run of spaces can be
  divided between them in as many ways as it is long. The first already accepts
  what the second did.

The CSS hidden-rule scan was rewritten rather than patched. `([^{}]+)\{` reads
to the end of a stylesheet from every position not followed by a brace; it now
matches braces with a bounded stack and searches each innermost block, which also
fixes a rule inside an `@media` block being reported through a nested-brace
accident rather than by design.

`tests/unit/test_scanner_complexity.py` scans each hostile shape and fails if it
takes longer than ten seconds, plus one test that doubles the input and requires
less than an eightfold increase — a complexity class rather than a benchmark.

### Fixed

**Plugins did not work on macOS or on any non-interactive Windows session**

The first hosted run left 78 failures across three platforms. They were not three
problems; they were two platform defects, one class of test that could never have
run where it was pointed, and two tests that were simply wrong.

- **No plugin ran on macOS at all.** `setrlimit(RLIMIT_AS, 512MB)` is refused
  there — the interpreter has already mapped more address space than that before
  the helper's first line — and both limits were installed inside one `try`, so
  one refusal discarded the CPU ceiling that *was* available and every plugin was
  rejected at discovery. Each limit is now installed and reported on its own, the
  request is clamped to the hard limit already in place rather than exceeding it,
  and a limit the platform refuses is recorded in a `ResourceLimitReport` instead
  of dropped. `trueai plugins` prints it, and `--plugin-confinement required`
  refuses rather than running without one.
- **No plugin ran in a non-interactive Windows session.** A worker created with
  `lpDesktop = NULL` inherits the creator's desktop and must pass an access check
  against its window station using its own token. The restricted token makes
  `BUILTIN\Administrators` deny-only, so wherever that station's DACL grants
  through the administrators group — the usual shape outside an interactive
  session, and how a service or scheduled task runs — Windows destroys the
  process during DLL initialisation with `STATUS_DLL_INIT_FAILED`. No output, no
  exit code of its own, and indistinguishable from a plugin that crashed. The
  worker now gets a desktop of its own, which fixes it and narrows the sandbox:
  no window enumeration, window messages, or hooks reach the operator's desktop.
  That status is also reported as a spawn failure rather than returned as an exit
  code, because the process never ran.
- **`required` confinement on Windows meant "no plugin ever runs".**
  `apply_confinement` took the spawn-time branch and raised, for every plugin, on
  the one platform whose confinement is applied by somebody else. It works now.
- **The Windows confinement report asserted a restriction without measuring it.**
  `windows_confinement_report` returned `applied=True` with "privileges are
  dropped and administrators membership is deny-only" having read no token — and
  was never in a report at all, because the worker described itself as
  unconfined. The host now states whether it restricted the token, the worker
  reads its own token, job membership and desktop, and the two are compared
  rather than averaged. `WorkerResponse.confinement` was documented as being
  there "so the host reports the confinement that happened"; the host now reads
  it, and under `required` refuses findings from a worker that reported none.
- **A test helper turned a bug into a platform gap.** `create_symlink` swallowed
  `FileExistsError` along with every other `OSError`, so a call with its two
  arguments swapped reported as "symlinks are unavailable on this platform". The
  cache's refusal to delete through a symlink had never run.
- **A high-water mark that fell.** Linux 6.2 moved RSS accounting to per-CPU
  counters and derives `VmHWM` as `max(stored_high_water, approximate_rss)`,
  where the second term is a racy read, so two consecutive samples can descend.
  The reported peak is clamped to the largest ever observed, which is what the
  field has always claimed to be.
- **Seven gates skipped everywhere and were enforced nowhere.** The supply-chain
  tests walk the whole runtime closure and the built distributions; the test
  matrix installs `.[dev,pdf]` on purpose and never builds a wheel. They now skip
  where the prerequisite is genuinely absent, and two CI jobs that *do* provide it
  turn the skip back into a failure.
- **A test that patched one process and asserted about another.**
  `test_required_confinement_reports_rather_than_silently_running` monkeypatched
  `describe_platform` in the test runner and checked a decision made in the
  worker. It passed because Windows refused `required` unconditionally and hosted
  Linux restricts unprivileged user namespaces — two accidents, neither of them
  the property named in the test.

**Six defects the first run on hosted CI found, five of which only Linux could see**

The suite had only ever run on one developer's Windows machine and in a
container. The first push to a repository with Actions enabled ran it on hosted
Linux, macOS, and Windows, and most of what follows had been latent since it was
written.

- **A test confined the test runner.** `apply_confinement` is one-way by design:
  `no_new_privs` cannot be cleared, a seccomp filter cannot be removed, and a
  read-only mount namespace cannot be remounted from inside. Five tests called it
  in the pytest process. On Windows the backend is a report and nothing else, so
  nothing happened. On Linux the first of them made the whole filesystem
  read-only with an empty grant set, and every test after it died in its own
  `tmp_path` fixture — one real failure and fourteen hundred pieces of
  collateral, in a run that looked like a catastrophe and was one test. The
  controls are still measured against a real kernel, now in a child process that
  is allowed to be destroyed by them (`tests.support.confinement_report`), and a
  gate fails if any test module calls it in-process again.
- **The auditor image shipped almost nothing it imports.** The builder installs
  the release group into its own site-packages, and hatchling shares `pathspec`,
  `rich`, `packaging`, `pluggy` and `requests` with the runtime set. pip called
  those "already satisfied" and never wrote them into `--prefix=/runtime`, so
  `trueai --version` in the published image died on `import pathspec` — while the
  build remained byte-for-byte reproducible, because a reproducible build of the
  wrong bytes is still reproducible. Fixed with `--ignore-installed`, and the
  Dockerfile now has a check of its own.
- **Half the codebase was never type-checked.** mypy narrows on `sys.platform`
  and on nothing else; `trueai/plugins/resources.py` guarded its Windows branch
  with `os.name == "nt"`, which reads the same to a person and means nothing to a
  checker. 25 errors sat in the Windows restricted-token path for as long as the
  only Linux checker was CI and the only Windows checker was a developer — each
  correct about the branch it could see. CI now runs `--platform win32` and
  `--platform linux`, and `windows_token` states the platform it needs.
- **`trueai doctor` withheld the thing the reader has to type.** Rich elides an
  overlong cell and the widest row sets the width the narrower ones are cut to,
  so on an 80-column terminal `install trueai-core[pdf]` rendered as a horizontal
  ellipsis: the check reported that something was missing and not what to do
  about it. The Detail column folds now.
- **The advisory ledger could not express a platform.** `colorama` is in the lock
  and installs on Windows only. Reported as `orphaned` on Linux, it invited the
  fix that loses information — deleting a reviewed entry for a package that
  really does ship. A component may now declare `platforms`, an unreadable list
  is a ledger error rather than a silent excuse, and `check()` takes the platform
  as an argument so the answer for Linux can be interrogated from Windows.
- **The native harness called a missing control a broken one.** Check [1]
  measures the read-only mount namespace. Ubuntu 24.04 restricts unprivileged
  user namespaces through AppArmor and GitHub's runners inherit it, so the
  hostile write landed and the harness reported the confinement as failed. That
  is `not_examined` versus `absent` turned on the harness itself. It probes the
  kernel first, prints `SKIP` with the backend's own reason, says plainly that a
  control went unchecked, and `TRUEAI_REQUIRE_CONFINEMENT=1` turns the skip back
  into a failure wherever the control must hold.

### Added

**Incident response for five things that go wrong differently**

- `docs/incident-response.md`, linked from `SECURITY.md`: a vulnerability report,
  a plugin incident, a trust-store compromise, certificate misissuance or key
  compromise, and a release rollback. Kept separate because they have different
  blast radii and different people to tell — one combined procedure gives the
  narrow incidents the heavy process and the heavy ones the narrow process.
- Every process shares a second half that is the one usually left out: **saying
  what already-issued evidence is worth**. A forensic tool's reports stay in
  circulation after the failure that produced them, and somebody may be relying
  on one.
- And a discipline about not overstating. "Discard all reports" when one detector
  was affected, or "provenance verification was broken" when only *signer trust*
  was wrong, teaches people to discount the next advisory. Precision here is not
  a courtesy; it is what keeps the channel usable.
- Each process names mechanisms that exist — `DistributionRevocation`, the
  one-sequence-at-a-time trust-store rule, `trueai certificates revoke`, the
  `detector_mutation` and `plugin_rejected` diagnostic codes — and tests assert
  each one is real. A runbook telling somebody to revoke a thing the tool cannot
  revoke is worse than no runbook, because it is read at three in the morning.

**A documentation gate**

- `scripts/check_docs.py` fails when a document names a command, an option, or a
  file that does not exist, or when a page under `docs/` is linked from nowhere.
  It covers the README, the backlog, `CONTRIBUTING`, `SECURITY`, `AGENTS`, the
  Codex skill, the examples, and every page in `docs/`.
- It does not check whether the prose is *true* — that needs a reader. It checks
  whether the nouns exist, which is the part that rots first: prose has no
  compiler, so a renamed flag leaves a sentence describing the old one
  confidently, and the reader who is hurt is the one who trusts it.
- Options are checked only on lines where `trueai` is followed by whitespace. A
  first version looked at every long option and reported pip's `--all-extras` and
  docker's `--build-arg`; an allowlist of other tools' flags would rot faster
  than the documentation it guards.
- A command resolves against the command *tree* rather than by longest prefix. A
  group takes no positional arguments, so the word after one must be a
  subcommand — prefix-popping let `trueai scna` fall back to bare `trueai` and
  pass, which is how a typo becomes invisible.
- The gate found five orphaned pages: `dom-features`, `fuzzing`, `html-report`,
  `models`, and `pdf-object-graph`. All are now linked from somewhere.

### Fixed

- The gate's own invocation pattern contained a literal backspace for one
  revision — a heredoc collapsed `\b` — so it matched nothing and the option
  check skipped every line while still reporting success. A test now asserts the
  word boundary is there, because a pattern that can never match is a check that
  quietly does nothing.

**A catalogue of everything TrueAI can remove**

- `trueai/core/remediation_catalog.py` declares all twenty removal operations:
  what each takes out, which format it applies to, its safety class, and **why
  that class and not the neighbouring one**.
- Two gates in `tests/unit/test_remediation_catalog.py`. The catalogue and the
  code must name the same operations in **both directions**, so a new removable
  field cannot ship uncatalogued and a stale entry cannot survive a removal. And
  every catalogued operation must be named by a test, which is what stops a
  removable field shipping without a regression fixture.
- `tests/unit/test_removable_field_fixtures.py` — the six fixtures that second
  gate demanded. The suite already exercised those paths; what it could not do
  was answer "which removable fields have a fixture", so it could not notice one
  shipping without.

### Fixed

- Remediation safety was decided by a **prefix match on the identifier**, so
  `odf.remove-metadata-field` was classified as a content change for as long as
  ODF support existed — not because anybody decided ODF metadata was content, but
  because `"odf."` was never added to a tuple. `meta.xml` is a separate part
  exactly like `docProps`, so removing a field from it cannot change what a
  reader sees; it is now `safe_metadata`, declared with that reason. It happened
  to fail safe, which is why nothing noticed. **This is a behaviour change**: ODF
  metadata removal no longer requires review under policies that gate on
  `predictable_content`.
- The planner now asks the catalogue, falling back to the strictest class for an
  unknown identifier rather than guessing from a prefix.

**Advisory tracking that fails when nobody has looked**

- `security/advisories.toml` and `scripts/check_advisories.py`. `pip-audit`
  answers "does a packaged dependency have a known CVE right now". This answers
  the two questions it cannot.
- **The parsers that are not packaged dependencies.** Most artifact bytes reach
  `zipfile`, `xml.etree`, `zlib`, `html.parser`, and `json`. A CPython advisory
  for any of them applies directly to how TrueAI reads a hostile file and passes
  a clean dependency audit without comment, so they are listed and reviewed on
  the same clock as everything else.
- **Whether anybody looked.** The gate fails on *staleness*, so it fires when the
  reviewing stops rather than only when a CVE is published. "No known
  vulnerabilities" from a review done eight months ago is a lie by omission, and
  a green check makes it a confident one.
- Four failure kinds: `stale`, `unreviewed` (a dependency nobody classified),
  `orphaned` (an entry describing a build that no longer exists), and `expired`.
  An acceptance needs a reason, an owner, **and an expiry** — without one it is
  not an acceptance, it is a decision nobody will revisit.
- Filling in the ledger found something the audit never mentions: `c2pa-python`
  declares `wheel`, `setuptools`, `toml`, `pytest`, and `requests` as **install**
  requirements, so installing the `c2pa` extra puts an HTTP client and a test
  runner into an environment for a tool that advertises being offline. TrueAI
  imports none of them and the network gate still governs every request TrueAI
  makes, but it is recorded rather than only noticed.
- `scripts/generate_sbom.py` emits CycloneDX from the installed closure with no
  build tooling, and `--check` gates on **completeness rather than existence**: a
  component with no version, no license, or no package URL fails, because a
  document with blanks passes a "do you have an SBOM" check and answers none of
  the questions it was requested for. The timestamp is injectable so a
  reproducible build can pin it.
- `scripts/check_supply_chain.py` runs all four gates and reports all of them
  rather than stopping at the first — they fail together in practice.
- `docs/supply-chain.md`.

### Changed

- `scripts/check_licenses.py` falls back to reading installed metadata when
  `pip-licenses` is not available, instead of failing to run. A gate that quietly
  does nothing when a tool is missing is worse than one that fails, because it
  reports success either way — and a gate that only runs inside one CI provider
  cannot be run before pushing. The fallback surfaced three licenses the two
  readers spell differently (`ISC License` vs `ISC License (ISCL)`, `PSFL` vs
  `PSF-2.0`, `Apache License` vs `Apache Software License`); the allowlist now
  carries both spellings, with a test that GPL and AGPL are still refused.

**Coverage-guided fuzzing of every parsing boundary**

- `scripts/fuzz_parsers.py` covers ZIP/OPC, XML, PDF, ISO-BMFF, EBML, Git object
  scope, cache entries, policy bundles, certificates, and reports. Seeded and
  replayable: a failure prints the seed, the target, and the input.
- Coverage guidance uses `sys.monitoring` — no native dependency, and the whole
  run reproduces from a seed.
- **Each target declares what it may do and what must hold anyway.** A parser is
  allowed to refuse; it is not allowed to raise a `TypeError` from an unguarded
  attribute access, an `IndexError` from an unchecked slice, or a
  `RecursionError` from an unbounded structure. An exception the target did not
  declare is a finding too: a parser may refuse, it may not surprise.
- The invariants are the point. A validated OPC package names no escaping member;
  an XML part never resolves an external entity; every box and element sits
  inside its input; a damaged cache entry is a miss rather than an exception or a
  half-decoded result; a loaded report's counts match its findings; an accepted
  Git alternates file contains no path leaving the repository.
- **The guidance claim is a measurement, not an assertion.** Guided loses at
  3,000 inputs (601 vs 664 lines) and wins at 12,000 (739 vs 709) and 60,000
  (757 vs 727), so `--no-coverage` stays a real option and half of all mutations
  start from a pristine seed even when guided — mutating a mutation of a mutation
  drifts away from anything a length-prefixed parser will accept.
- Seeds are real artifacts from the fixture builders rather than stubs: a genuine
  MP4 with a resolved sample table, a WebM with tracks and clusters, both a
  classic and a cross-reference-stream PDF, a signed policy bundle, an issued
  certificate, a rendered report. The PDF target went from 153 to 348 lines when
  it stopped starting from a stub.
- `--self-check` proves the harness reports a broken invariant and an unguarded
  error and does not report a clean target. A short pass of every boundary runs
  in the test suite, so a regression fails the build rather than waiting for a
  nightly job.
- `docs/fuzzing.md`.

**Longitudinal style comparison, which stays a question**

- `trueai.research.longitudinal` compares a document against a writer's own past
  and produces **no verdict**: no `same_author` field, no probability, no score
  to threshold. A test parses the module and asserts that vocabulary is absent.
- The list of things that move a writer's style is long and almost none of the
  entries are "someone else wrote this" — topic, genre, co-author, editor,
  template, translation, practice, a deadline. Those travel with every result,
  because a caveat kept in documentation does not travel with the number.
- Below eight documents or thirty days the result is `UNDETERMINED` and **no
  distance is reported at all**. A number attached to an insufficient baseline
  gets quoted without the word "insufficient", and the description says it is an
  absence of measurement rather than a finding of no change.
- Distance is measured in units of the writer's own variability. A fixed
  threshold across writers penalises the consistent ones and excuses the erratic.
  The bands are coarse on purpose: a continuous score invites a threshold, and a
  threshold invites the verdict this refuses to produce.
- A comparison crossing a declared genre boundary is flagged, because a register
  change moves style more than most other causes.
- **Per-feature deltas are off by default.** "Which feature moved and by how
  much" is a recipe for moving it back. The flag exists for debugging a detector
  and the request is recorded in the result. This does not stop anyone with the
  extractor from computing them, and the module says so instead of overclaiming;
  what it does is decline to ship a ready-made objective function and leave a
  record when somebody asks for one.

**A release gate for learned scores**

- `trueai.research.release`. A model that scores text about whether a person
  wrote it is not shipped because it works; it is shipped because someone can
  answer, afterwards and under pressure, what it was trained on, what it is for,
  what it gets wrong, and whether this is the model they think it is.
- `DatasetStatement` requires every field, and the one it exists for is
  `does_not_represent`. A corpus of published English technical writing does not
  represent a student writing in a second language, and the moment to say so is
  before a model trained on it is used to judge one. Listing demographics while
  claiming none were collected is refused: one of the two is wrong and a reader
  cannot tell which.
- `ThresholdSet` binds operating points to one model version and one feature set
  and carries the evaluation digest that chose them. A threshold copied forward
  is a number nobody measured on the model it is applied to, and an operating
  point the evaluation never used blocks the release.
- `ModelManifest` (`TAIMDL1-…`) is content-addressed over the card, the
  statement, the thresholds, and the **digests of the model's own files**, so "is
  this the model that was evaluated" has an answer independent of a filename.
- **`check_regression()` blocks a release when the false positive rate rises,
  even if everything else improved.** Averages let a model get better at finding
  machine text while getting worse at accusing people, and only one of those two
  costs a person something.
- Three more ways to look better without being better are closed: the worst
  subgroup is gated separately, because an improvement in the mean taken out of
  one cohort is not an improvement; a candidate that scores no subgroup when the
  baseline scored one is blocked, because the comparison would hide whichever
  cohort went missing; and a fall in coverage is blocked, because abstaining more
  improves every other number for free.

**A versioned feature contract, so a model can be optional and replaceable**

- `trueai.research.features`. TrueAI computes features, a model elsewhere
  consumes them, and neither imports the other's dependencies.
- A `FeatureSet` is named **and ordered**, because a vector is positional: the
  same names in a different order are a different feature set, and treating them
  as interchangeable permutes every column. The digest covers version, names, and
  order together.
- `score_with()` **refuses** a vector from another feature set, and refuses a
  model that tags its output with a set it was not handed. The alternative is
  scoring columns that changed meaning — a confident number with nothing behind
  it and no symptom until somebody acts on it.
- `build_vector()` will not pad a missing feature with zero (a zero is a
  measurement and an absence is not) and will not swallow an extra one (adding a
  feature changes the contract, so it has to change the version).
- `try_score(None, …)` returns `None`, meaning **not measured**. Never "clean" —
  an interface rendering it as an absence of findings is making a claim the
  function did not.
- `ModelScore` carries no author, attribution, or provenance class. The fields
  that would let a caller promote a measurement into a claim about who wrote
  something are absent, and a test asserts they are.
- `ModelCard` requires the corpus digest, intended use, and **at least one known
  limitation** — every model has some, and a card without them is one nobody
  looked hard at.
- A test walks every module in the package and fails on any import of `torch`,
  `tensorflow`, `jax`, `sklearn`, `numpy`, `scipy`, `pandas`, `transformers`,
  `onnxruntime`, `xgboost`, or `lightgbm`. A second test proves that check can
  fail, because a guard that cannot fail is not a guard.
- `docs/models.md`.

**A detector-evaluation protocol that refuses to publish a flattering number**

- `trueai.research.evaluation`. The headline is the **false positive rate**, not
  accuracy — accuracy averages the harm of telling someone their human-written
  document was machine-generated together with the harmless kind of mistake, and
  reports one number that hides it. `summary()` emits no accuracy figure at all.
- A rate quoted without its operating point is not a measurement, so the
  threshold is required and appears in the summary.
- Every rate carries a 95% **Wilson** interval. The normal approximation gives a
  zero-width interval at a rate of zero, which is exactly where a small sample
  most needs one. A rate over fewer than 30 samples is marked unreliable —
  printing "0.0%" for a group of five is worse than printing nothing.
- **Subgroups.** `worst_subgroup()` reports the worst rate among groups large
  enough to score, and a gap of more than 5 points above the overall rate is a
  problem. A detector at 3% overall and 15% on second-language writing is not a
  3% detector; it is a tool that penalises non-native speakers.
- **Domain shift.** Per-domain rates plus the best-to-worst spread, because one
  aggregate hides what a new deployment will meet.
- **Abstention.** Coverage travels with every metric and an abstention never
  counts as a correct answer. A detector allowed to say "I do not know" can reach
  any figure by answering only the easy cases.
- **Calibration.** Expected calibration error over a reliability diagram; a score
  of 0.9 should be wrong about one time in ten, and an uncalibrated score is a
  number wearing a probability's clothes.
- **Reproducibility.** `ProtocolRecord` requires the corpus digest, model
  identifier, threshold, seed, code version, and an offset-bearing timestamp. A
  number that cannot be recomputed is an anecdote.
- `problems()` lists every reason a result must not be quoted alone, and a clean
  evaluation produces none — a checker that always complains is one people learn
  to ignore.
- `docs/evaluation-protocol.md`.

**Corpus governance as code, before there is a corpus**

- `trueai.research.corpus`. Five rules — consent, licensing, domain balance,
  contamination control, retention — written as constructors that refuse rather
  than guidance that advises. A `CorpusManifest` cannot be built without a
  `CorpusPolicy`: collected first and governed afterwards is the order this
  prevents. No default policy ships, for the same reason no default trust store
  does.
- **Consent is not a license.** The person who hands over a document is
  frequently not the person who owns it, so a sample needs a `ConsentRecord`
  *and* `LicenseTerms` and either one missing refuses it. Both refusals are
  reported together rather than one submission at a time.
- Consent is scoped to named purposes, expires, and records a
  `withdrawal_contact` — consent nobody can revoke is not consent. A policy names
  exactly one purpose, so a narrow grant cannot authorise a broad use.
- **Withdrawal reaches backwards.** `withdraw_consent()` returns every sample
  collected under the consent, and the audit reports the corpus unusable until
  they are gone. It does not drop the rows: deleting the record while the bytes
  remain is worse than not deleting.
- **Contamination is compared by content digest, never by path.** The same
  document under two names in two splits is one document, and an evaluation over
  it is a memory test. Enforced at admission, across a batch so two copies cannot
  slip past each other, and again in the audit. `holdout_only_sources` keeps a
  source out of training so a model cannot learn a shortcut and be scored on it.
- Domain targets are written in advance and must sum to 1; a sample in an
  unplanned domain is refused rather than absorbed. Imbalance is reported and
  does not block — a corpus can be imbalanced on purpose, but not quietly.
- Retention requires a stated deletion method, and indefinite retention has to be
  written rather than arrived at by nobody choosing.
- `CorpusManifest.digest()` is order-independent, so a published result can cite
  the exact corpus and two people can compare numbers.
- `docs/research-data.md`.

**Desktop, CI, and editor adapters over one projection**

- `trueai.adapters` (public): `views.py` derives the five views a surface needs;
  `ci.py`, `ide.py`, and `desktop.py` format them. `trueai scan -f ci`,
  `-f ide`, `-f desktop`.
- `FindingExplanation.does_not_claim` is the reason the projection exists. It is
  the sentence saying what a finding does **not** establish, it is derivable from
  the confidence and provenance classes, and it is the first thing an interface
  drops when short of space. Deriving it centrally means an interface has to
  actively discard it — and every adapter carries it, including the two formats
  that only have one line.
- **The CI formats are injection boundaries.** A newline in a finding description
  does not malform a workflow annotation, it produces *a second command*, and
  descriptions come from the artifact under examination. Values are escaped for
  `%`, CR, and LF; property values also for `:` and `,`. Markdown cells are
  escaped for pipes and newlines, which otherwise rewrite the table.
- `CRITICAL` and `HIGH` become error annotations and nothing else does. A job
  that failed on every `INFO` finding would be switched off within a week.
- The editor adapter is LSP-shaped with **no LSP dependency**. A missing range is
  admitted rather than guessed from a byte offset — a squiggle under the wrong
  text is worse than none because it looks authoritative — every scanned file
  appears so stale markers can be cleared, and `INFO` never becomes an error.
- The desktop bundle is versioned so a client can refuse one it cannot read,
  keeps coverage beside the findings (a client rendering findings alone shows a
  clean page for a half-read scan), and leaves `remediation` and `certificate`
  null so "no plan" differs from "an empty plan".
- `IntegrityEvidence.visible_content_unchanged` is `None`, not `False`, when the
  logical digests are missing: a check that did not run is not a check that
  failed.
- `certificate_view()` reports all six checks separately, so four unknowns cannot
  hide behind one green tick, and every view restates what a TrueAI certificate
  never asserts.
- `docs/integrations.md`.

**A single-file HTML report a hostile artifact cannot turn into a page**

- `trueai/reporters/html.py` and `trueai scan -f html`. One self-contained
  document: no script, no external stylesheet, font, or image, and no attribute
  that can fetch anything. It opens from a USB stick on an air-gapped machine.
- Every string in a report came from the file under examination, and the report
  is opened in a browser by the person examining it. Exactly one function turns a
  value into markup, escaping `&`, `<`, `>`, `"`, and `'` — correct in a text
  node and in a quoted attribute alike, so there is no second one to forget.
- The document declares a `Content-Security-Policy` it already satisfies
  (`default-src 'none'; script-src 'none'`), which turns "we escaped everything"
  from a claim into something the browser enforces.
- The tests **parse** the output instead of grepping it: `onmouseover=&quot;`
  reads as an event handler to a substring check and is inert to a parser, so the
  suite asks `HTMLParser` what elements and attributes exist. With escaping
  deliberately removed, 13 tests fail.
- Findings are grouped by confidence class, strongest first, each group headed by
  what that class actually claims — the reader who does not know the difference
  is the one who will treat a heuristic as a fact.
- Provenance renders as PROV-04's four facets, an unanswered question is styled
  as unanswered rather than as a negative, per-artifact caveats are printed under
  "What these results do not say", and diagnostics are a section rather than a
  footnote, because a scan that could not read something did not find it clean.
- The same report renders byte-identically every time, so two runs can be diffed.
- `docs/html-report.md`.

**A detector SDK that is checked rather than described**

- `examples/acme_ticket_detector/` — a real installable third-party detector
  package: entry point, capability manifest, and a `PluginRegistration` the host
  reads before importing anything that could run.
- `tests/unit/test_sdk_examples.py` runs the example, signs a distribution built
  from it, and **parses its imports** to prove every one comes from a module in
  `PUBLIC_MODULES`. An example that drifts out of the frozen surface fails the
  build — an example that drifts is worse than none, because someone copies it,
  it works locally, and it breaks on the next upgrade with the gate silent.
- `trueai.api.SDK_CONTRACT` names what a detector author builds against, kept
  apart from `PUBLIC_MODULES` because the guarantee differs in kind: these are
  shapes you subclass and construct, not names you import and call. A test
  asserts each one is reachable through a frozen module.
- `docs/sdk.md` and `examples/README.md`.

### Fixed

- The API gate covered callers but not subclasses. Adding an abstract method to
  `BaseDetector` is an addition for anyone calling the class and fatal for every
  third-party detector that inherited from it, and a method-count comparison
  classified it as additive. Abstractness is now recorded in the surface, and a
  new or newly abstract method is breaking. A guard keeps a contract published
  before the field existed from reading as a fresh break: absent data is not
  evidence that the answer was empty.

**Progress and cancellation the core can offer without knowing what a UI is**

- `trueai/core/progress.py`. Progress is one callable taking one frozen
  `ProgressEvent`; cancellation is one `cancelled()` predicate. A multi-method
  observer would be one more thing every caller must implement and one more
  place an interface can break a scan, and putting `threading.Event` in the
  signature would shut out an asyncio or trio caller.
- Events arrive **in artifact order and one at a time**, from the thread that
  assembles the report, even with `--jobs 8`. An observer needs no lock.
- `fraction` is `None` while the total is unknown. During discovery nothing can
  honestly report a percentage, and inventing one is worse than an indeterminate
  bar.
- An observer that raises is dropped, and the report carries a
  `progress_observer_failed` diagnostic naming the exception. A formatting bug
  in an interface must not abort a forensic run — and must not vanish either.
- **A cancelled scan raises `ScanCancelled`** rather than returning a shorter
  report, because a shorter report is indistinguishable from a clean one to
  whoever opens it next. It carries how far the scan got and deliberately no
  findings: a partial result handed back through an exception is a partial
  result someone eventually treats as a report. Callers that want partial data
  collect it from the events, where it is partial by construction.
- The token is polled between detectors as well as between artifacts. One large
  document can hold a worker a long time, and a cancel that waits for the next
  file is not a cancel.
- `trueai scan --progress/--no-progress`. The bar is drawn only when standard
  error is a terminal, since progress in a pipe is noise in a log. Ctrl-C sets
  the token and the run reports how far it got and exits 130 instead of printing
  a traceback.
- A test asserts the core imports no console library and no event loop.
- `docs/progress-and-cancellation.md`.

**A bounded cache with a defined eviction order**

- `ScanCache` takes a `max_bytes` budget, 256 MB by default, and the engine
  enforces it at the end of every scan. An unbounded cache beside a repository is
  a disk-space bug waiting for a large enough checkout.
- Eviction is deterministic in the sense that matters: the same inventory, the
  same budget, and the same run remove the same entries. Entries written under a
  different package, schema, or cache format version go first — those versions
  are part of the key, so the entry is unreachable rather than merely stale —
  then entries this run did not touch, then the rest, oldest generation first,
  with the key breaking ties so the order is never ambiguous.
- A *generation* is one scan. An instance takes the next number from a small
  counter file on first write and stamps every entry with it, so "which entries
  are older" is recorded data rather than file metadata that a copy or a restore
  destroys. Hits are remembered in memory rather than written back: one write per
  hit would cost about what a miss costs.
- `ScanCache.inspect()` separates three things a single listing would blur —
  entries, damaged files at an entry location, and files under the cache
  directory that TrueAI did not write. The last are reported and **left in
  place**.
- `ScanCache.eviction_order()` and `trueai cache inspect --entries N` answer
  "what would go" before it goes rather than after.
- `ScanCache.prune()` and `trueai cache prune` take an explicit rule —
  `--unreachable`, `--older-than`, `--to-fit` — and no rule removes nothing. A
  prune that defaulted to deleting everything would make a mistyped command
  destructive, and this is the one place a wrong deletion is silent: the next
  scan is merely slower. `--yes` is required on top.
- Link safety is re-checked at deletion time, not only at inspection time; a
  refusal is reported with its reason rather than counted as a success.
- `docs/cache.md`.

**Repository-scale benchmarks, and what they found**

- `trueai/core/benchmark.py` and `scripts/benchmark_scale.py`. A seeded synthetic
  corpus is scanned cold, warm, and in parallel; wall time, both memory peaks,
  cache hit rate, and determinism are reported. Results for 10,000 and 100,000
  files are published in `docs/benchmarks.md`.
- Two memory figures, labelled. Process peak RSS is what the machine feels, but
  every OS exposes it as a lifetime high-water mark that never falls, so only the
  first phase's figure is that phase's own peak. Peak Python allocation is
  per-phase and honest about covering only the Python side. Subtracting two
  high-water marks to fake a per-phase RSS would produce a confident wrong
  number, so the harness does not.
- Two determinism checks. Two identical scans must agree with only `scan_id` and
  `generated_at` removed — a comparison that ignored everything unstable would
  always pass — and the parallel scan must agree with the serial one.
- `ScanCache.statistics()` counts hits, misses, **rejections**, stores, and store
  failures. A miss and a damaged entry are different operational facts, and one
  blended hit rate hides the second.
- `TrueAIEngine.scan(cache=...)` accepts a cache instance, so a caller can read
  its statistics back; the engine would otherwise build one and discard it.
- `ArtifactDiscovery.inventory()` returns the logical paths under a root without
  identifying anything.
- `--corpus` benchmarks an existing directory and writes nothing into it — not a
  file, not a cache entry. A benchmark that modified the repository it measured
  would be worse than useless.
- A phase whose finding budget or file cap ran out is marked `INCOMPLETE`, and
  the count is described as a floor rather than a total. The 100,000-file run
  reaches the default `max_findings` after 29,127 artifacts, and a capped count
  published as a result is exactly what a scale benchmark exists to prevent.
- Reports are compared by per-field SHA-256 digest rather than by value. The
  first attempt at 100,000 files died holding three whole reports at once; a
  benchmark should not be the thing that runs out of memory.

### Changed

- The end-of-scan sweep that asks "did new files appear while detectors ran" used
  to run full discovery a second time, opening and sniffing every file to produce
  type information the comparison then discarded. It now walks for paths only,
  with the same traversal, ignore rules, symlink containment, and file cap.
  Measured: 14% of wall time removed on a warm 2,000-file corpus, with no check
  weakened.

### Fixed

- A file the first discovery pass could not identify — a permission error, or one
  deleted between the walk and the open — was absent from that pass's inventory
  and present in the second, and was announced as `detector_mutation` at CRITICAL
  severity: a plugin rewriting your repository. Paths the first pass already
  reported as problems are now excluded from the comparison.

**Provenance as four questions instead of one badge**

- `trueai/core/provenance_view.py`. A verification status is a single value, and
  a single value is what an interface turns into a single badge. Marker
  presence, signature validity, signer trust, and provider verification are four
  separate findings and are now four separate answers.
- **The failure this fixes is erasure, not exaggeration.** `no_manifest` and
  `verifier_unavailable` were both "not green", so "this artifact carries no
  provenance" rendered identically to "we were unable to look". One is a result;
  the other is a hole in the scan.
- Every facet can answer *not determined* without that reading as *no*.
  `UNKNOWN_ANSWERS` collects those answers so an interface can style them apart
  from a negative result.
- `not_examined` is not `absent`; `no_anchors_configured` is not `not_trusted`
  (the first is a property of the scan, not of the artifact); `not_established`
  is not `not_trusted` (a signature that failed makes the identity it carries
  meaningless).
- `establishes_provenance` requires all three C2PA facets. The provider facet
  cannot contribute — a watermark says which tool produced something and carries
  no signed chain.
- `caveats()` states how a positive-looking facet is weaker than it looks, and
  `headline()` claims a verified trusted chain if and only if
  `establishes_provenance` does.
- A projection, not report content: derived from `ScanReport`, so the frozen
  schema keeps one source of truth.

### Changed

- The terminal reporter shows Marker / Signature / Signer trust / Provider as
  four columns instead of one status, and lists every undetermined question
  under "Not determined" so silence is not read as absence. Unknown answers are
  styled apart from negatives, and an unrecognised answer defaults to the
  unknown style rather than the settled one.

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
