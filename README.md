# TrueAI Core

TrueAI Core is a local-first forensic scanner and predictable sanitizer for artifacts created or
modified with AI-assisted tools. It reports individual traces—metadata, explicit attribution,
invisible Unicode, repository context, document structure, provenance markers, and conservative
style measurements—with evidence and a confidence class for every finding.

TrueAI does **not** decide whether content is “AI-generated.” Style is not provenance, a generator
field is not authenticated authorship, and a C2PA marker is not a verified signature. The engine
keeps those evidence classes separate in its public models, policies, CLI, and reports.

Version: `0.1.0-dev` · report schema: `0.1` · license: Apache-2.0

## Installation

Python 3.12 or newer is required.

```console
uv tool install trueai-core
trueai --help
```

For development:

```console
git clone https://github.com/trueai-core/trueai-core.git
cd trueai-core
uv sync --all-extras
uv run trueai --help
```

`pip install -e ".[dev]"` is also supported.

Three capabilities are optional installs, and all report honestly when absent rather than guessing:

```console
uv sync --extra pdf     # surgical PDF cleanup and its reachable-object integrity gate
uv sync --extra c2pa    # authenticated C2PA verification
uv sync --extra attestation  # Ed25519-signed audit certificates
```

`trueai doctor` prints which optional capabilities are present.

## CLI

```console
trueai scan ./repository
trueai scan ./repository --jobs 8 --cache          # parallel, and reuse unchanged results
trueai scan ./repository --no-progress             # no bar; Ctrl-C stops cleanly either way
trueai scan ./repository -f html -o report.html    # one self-contained, script-free file
trueai scan ./repository -f ci                     # workflow annotations plus a job summary
trueai scan ./repository -f ide                    # LSP-shaped diagnostics, keyed by file
trueai scan report.docx --format json --output report.trueai.json
trueai scan deck.pptx --verbose
trueai inspect model.xlsx
trueai clean report.docx --policy client-delivery
trueai clean README.md --dry-run
trueai clean README.md --certificate README.audit.json
trueai verify design.png --trust-anchors roots.pem  # authenticated provenance
trueai scan design.png --verify-provenance --trust-anchors roots.pem --format json
trueai certificates issue deliverable.pdf --output deliverable.audit.json
trueai certificates verify deliverable.audit.json --artifact deliverable.pdf
trueai certificates keygen --private-key issuer.pem --public-key issuer.pub.pem
trueai certificates revoke deliverable.audit.json --revocation-list issuer.crl.json --signing-key issuer.pem
trueai certificates schema --output trueai-certificate-0.1.schema.json
trueai certificates revocation-schema --output trueai-revocation-list-0.1.schema.json
trueai schema --output trueai-report-0.1.schema.json
trueai detectors list
trueai policies list
trueai policies bundle-create strict --output policy.json --signing-key issuer.pem --issuer "Security"
trueai policies bundle-verify policy.json --public-key issuer.pub.pem
trueai plugins list
trueai cache inspect ./repository                   # entries, budget, eviction order
trueai cache prune ./repository --unreachable --yes # remove entries from an older build
trueai cache clear ./repository
trueai doctor
```

`clean` writes `name.cleaned.ext` by default. It never overwrites the source unless `--in-place` is
explicit; in-place mode creates a `.trueai.bak` backup and still applies changes through a verified
temporary file. Unless `--no-verify-residue` is explicit, the command rescans the bytes it actually
published and reports whether scoped machine/tool indicators remain.

### What cleanup can and cannot remove

TrueAI removes only traces with a predictable transform: exact attribution spans, standalone
generator comments, selected ordinary metadata, and Unicode characters a policy explicitly
approves. The integrity gate proves that each supported cleaner changed only approved material.

TrueAI does not rewrite prose, code, images, or designs to make a statistical detector return a
different answer. It does not defeat provider watermarks or remove signed provenance. Heuristic
style findings can therefore remain after cleaning; post-clean verification reports them as
`INDICATORS_REMAIN` instead of manufacturing a false success.

## Current capabilities

| Artifact | Inspection | Predictable cleanup | Integrity verification |
|---|---|---|---|
| Plain text / Markdown | Unicode, explicit provider attribution, optional stylometry | Exact invisible-character and attribution spans | Exact expected transform + hashes |
| Source code | Unicode and parsed/conservative comment attribution | Standalone attribution in syntax-verified comments | Exact expected transform + hashes |
| Git repository | All-ref commit messages/trailers and tracked assistant configuration | History rewrite intentionally unavailable | Not modified |
| HTML / CSS | Generator metadata, comments, hidden rules, scripts/data URIs | Selected generator/comment residue | Exact expected transform |
| DOCX | OPC properties, comments, revisions, custom XML, relationships, embeddings, macros | Selected core/app/custom properties | Logical Word tokens, unchanged entries, canonical unselected metadata |
| PPTX | The same OPC evidence plus speaker notes, comments, comment authors, slide inventory | Selected core/app/custom properties | Slide, layout, master, and notes text |
| XLSX | The same OPC evidence plus hidden sheets, cell and threaded comments, participant identities, defined names, external links | Selected core/app/custom properties | Cell values, formulas, inline and shared strings |
| PDF | Bounded Info/XMP markers, annotations, embedded-file markers | Optional `pikepdf` Info/XMP cleanup | Every reachable non-selected object and raw stream payload |
| SVG | Metadata/RDF/XMP, comments, editor attributes, hidden/off-canvas elements, scripts, duplicated geometry | Metadata, standalone generator comments, editor attributes | Canonical visible/active structure including processing instructions |
| PNG / JPEG | Text chunks, EXIF, XMP/comments exposed by Pillow, provenance markers | Surgical chunk/segment/tag editing; no pixel recompression | Compressed pixel-bearing payload; rendering-critical orientation preserved |
| WAV / MP3 / FLAC | RIFF INFO/BEXT, ID3v1/v2, Vorbis comments, encoder/vendor and literal provider attribution | Selected textual fields and whole XML metadata chunks | Exact planned transform plus byte-identical audio-bearing payload |
| M4A | ISO BMFF keyed/legacy metadata and XMP UUID boxes | Inspection only | Not modified |
| MP4 / MOV / WebM | ISO BMFF keyed/legacy metadata, XMP UUID boxes, EBML writing/muxing applications and tags | Inspection only | Not modified |

Office, SVG, raster, PDF, Git, and recursive filesystem inputs are treated as hostile. Archive,
parser-event, finding, Git-output, file-count, file-size, path, XML, and image-pixel limits are
fail-closed. An incomplete scan emits a high-severity diagnostic and CLI exit code `3`.

## Provenance

Scanning finds markers. Verifying checks signatures. These are different claims and TrueAI keeps
them apart:

```console
trueai verify design.png                            # valid signature, unknown signer  → exit 1
trueai verify design.png --trust-anchors roots.pem  # chains to a trusted root         → exit 0
trueai scan design.png --verify-provenance --trust-anchors roots.pem --format json
```

`trusted` is the only result that establishes provenance. `valid` means the cryptography checks out
but the signer is not established as trusted, which is a materially weaker statement and is reported
as its own state rather than rounded up. Without the optional verifier installed, the result is
`verifier_unavailable`; nothing is inferred. Remote manifests are never fetched unless explicitly
permitted. See [provenance](docs/provenance.md).

The scan flag is still explicit. Marker findings remain unchanged while typed authenticated results
are added under `provenance_verifications`; a marker is never promoted into verified provenance.

## Audit certificates

`trueai certificates issue` creates a JSON audit certificate with a `TAI1-…` content ID. It binds
the exact file hash—or an ordered directory inventory—to the scan report hash, package and schema
versions, policy, detector set, resource boundaries, diagnostics, and individual indicator finding
IDs. The status is one of:

- `clear`: no scoped indicator was detected and the scan completed;
- `indicators_detected`: one or more scoped findings are present;
- `incomplete`: a parser, resource, plugin, or coverage boundary prevented clearance.

The statement is deliberately narrow: “no indicators detected within the documented detector
scope.” It is not proof of human authorship or proof that AI was never used. An unsigned certificate
is content-addressed but does not authenticate its issuer. Install the `attestation` extra and use
an Ed25519 signing key when issuer identity matters. Certificates can carry a finite validity
period. Issuers can publish a finite-lifetime, monotonically sequenced signed revocation list;
verification can require a current authenticated list before returning success. See
[audit certificates](docs/certificates.md).

## Human Contribution Records

A certificate is about bytes. A **Human Contribution Record** is about process: who framed the
work, who decided, who executed, who validated, who is accountable. It is a separate contract with
its own `TAIP1-…` identifier, its own schema, and its own verification result, and it is a
declaration — signing one proves an identified person said it, not that it is true.

Contribution is a vector over eight dimensions, never a percentage. `no_aggregate_score` is a
standing limitation on every record.

Two orthogonal questions get answered separately:

- **Process Assurance Level** (`PAL-0`…`PAL-4`) — how strong the evidence and governance are,
  derived from verification rather than from claims. A record asserting the strongest claims with
  nothing behind them stops at `PAL-1`.
- **Evaluation profile** — whether the record meets one context's stated review requirements.
  Five ship: `research`, `software-delivery`, `creative-work`, `education`, `regulated-enterprise`.
  They are versioned, they show their weights, and they are allowed to disagree with each other.

```console
$ trueai attestations init attestation.yaml && trueai attestations issue attestation.yaml \
    --artifact report.md --signing-key alice.key --claimant alice
$ trueai attestations evaluate report.process.json --profile software-delivery
$ trueai scan report.md --format sarif --attestation report.process.json
```

Summaries say "human-originated, AI-executed, human-validated" and stop there. No combination of
stage claims establishes authorship, and nothing in TrueAI answers "how human is this work".

Records export to W3C PROV, in-toto/DSSE, and C2PA assertion data, each carrying a list of what
its target vocabulary could not express. See
[Human Contribution Records](docs/process-attestation.md),
[evaluation profiles](docs/evaluation-profiles.md),
[interoperability](docs/interoperability.md), [trust](docs/trust.md), and
[trust stores](docs/trust-store.md) — signed, sequenced anchor sets that refuse a rollback,
report rotation gaps, and apply offline updates one sequence at a time.

## Confidence and provenance semantics

| Class | Meaning |
|---|---|
| `DETERMINISTIC` | A parser or literal rule observed the stated evidence. It is not an authorship claim. |
| `VERIFIED` | An authenticated public verification mechanism validated the claim. |
| `PROBABILISTIC` | A statistical model produced a calibrated probability-like score. None ships in v0.1. |
| `HEURISTIC` | An interpretable style or structural rule fired. It is explicitly not provenance. |

The numeric `confidence` has meaning only inside its `confidence_type`. `1.0 DETERMINISTIC` means
the trace was observed exactly; `0.82 HEURISTIC` means an experimental rule score, not an 82%
chance of AI authorship.

Provider watermark adapters for Anthropic, OpenAI, Google, and Generic currently return
`VERIFICATION_UNAVAILABLE`, naming the admission criteria the provider does not meet. An adapter is
written only when a provider publishes a verifier, API, or specification a third party can run; any
remote call goes through one audited gate that records refusals as well as successes. See
[the network boundary](docs/network-and-providers.md). TrueAI does not invent provider watermark
algorithms, reverse-engineer keys, forge provenance, or claim watermark removal. C2PA verification
is real but explicit: default scanning reports markers; `trueai verify` or
`scan --verify-provenance` validates signatures through the official implementation.

Cleanup is gated on format-specific integrity proofs. MP4/MOV/M4A and WebM/Matroska have an
executable specification of what an edit must not change — sample bytes reached through the chunk offsets,
timing, edit lists, indexes, encryption state, rendering geometry, and provenance — in
[container invariants](docs/container-invariants.md) and, for PDF, the
[object graph](docs/pdf-object-graph.md) — a PDF 1.5+ cross-reference stream carries metadata a
lexical scan never sees. Cleanup replaces the selected box with
same-length `free` padding, so nothing moves and no offset needs correcting; the file keeps its
size, and a container carrying a C2PA manifest is refused outright.

OpenDocument packages are inspected and cleaned on the same ZIP safety layer as Office Open XML.
Legacy binary Office (`.doc`, `.xls`, `.ppt`) is identified and reported as *not inspected* rather
than skipped, because a silent skip reads like a clean result; see
[ODF and legacy Office](docs/odf-and-legacy-office.md).

See [safety](docs/safety.md) and [finding semantics](docs/findings.md).

## Policies

Built-in profiles are `audit`, `safe-clean`, `privacy`, `client-delivery`, and `strict`. Policies
map categories to `IGNORE`, `REPORT`, `REVIEW`, `REMOVE`, `PRESERVE`, or `ERROR`; they never change
what detectors observed. Built-in validation rejects `REMOVE` for C2PA provenance and provider
watermarks.

```yaml
policy: client-delivery
default_action: report
rules:
  explicit_ai_attribution: remove
  document_metadata: remove
  c2pa_provenance: preserve
  provider_watermark: preserve
  stylistic_signal: report
```

See [policies](docs/policies.md).

Enterprise bundles sign a profile, exact finding-ID baseline, finite suppressions, and finite
exceptions with Ed25519. Applying one requires its issuer public key. Findings remain in the report,
and every override is recorded in `policy_audit`; protected provenance cannot be suppressed.

## Python API

```python
from pathlib import Path

from trueai import PolicyStore, TrueAIEngine
from trueai.core.remediation import RemediationPlanner, RemediationService

policy = PolicyStore.get("client-delivery")
report = TrueAIEngine.default().scan(Path("report.docx"), policy=policy)
plan = RemediationPlanner().plan(report, policy)

# Mutation is a separate, explicit call and writes report.cleaned.docx by default.
result = RemediationService().apply("report.docx", report, plan)
print(result.integrity.status)
```

Public report and finding models use Pydantic v2 and reject unknown fields.

Third-party detectors register explicitly through `DetectorRegistry.register()` or expose an entry
point in the `trueai.detectors` group. A plugin declares a capability manifest; a guarded helper
inspects it without importing the module in the scanner process, then host policy decides whether
the plugin may run. Detection is read-only, so filesystem writes, process creation, and network
access are denied by default even to a plugin that asks. Subprocess isolation is the default:

```python
from trueai import TrueAIEngine
from trueai.plugins import CapabilityPolicy, PluginIsolation

engine = TrueAIEngine.default(
    plugin_isolation=PluginIsolation.SUBPROCESS,
    capability_policy=CapabilityPolicy(require_manifest=True),
)
```

Subprocess isolation contains host-state corruption, hangs, and unbounded output, and re-derives
every returned finding so a plugin cannot forge an identity or impersonate another detector.
Workers install hard CPU and memory limits before importing third-party code (POSIX rlimits or a
Windows Job Object). This is still not a filesystem/system-call sandbox. See
[plugins](docs/plugins.md). Writing one: [the SDK guide](docs/sdk.md), [integrations](docs/integrations.md), and a runnable
[example detector](examples/acme_ticket_detector/) whose imports the test suite checks against
the frozen public surface.

## Architecture

```text
artifact discovery
      ↓
non-mutating detector registry → Finding[]
      ↓
policy evaluation → RemediationPlan
      ↓
preview → cleaner → temporary output → integrity gate → published output
      ↓
terminal / JSON schema 0.1 / SARIF / future GUI
```

The engine has no UI dependency, performs no telemetry, and makes no network requests during
normal scanning. Future network verification must pass an explicit `NetworkPolicy` boundary and
live in a separate adapter.

More detail: [architecture](docs/architecture.md), [detectors](docs/detectors.md),
[benchmarks](docs/benchmarks.md) — measured wall time, memory, cache hit rate, and
determinism at 10,000 and 100,000 files — [fuzzing](docs/fuzzing.md), which covers every parsing
boundary and states what the coverage guidance is measurably worth, and
[progress and cancellation](docs/progress-and-cancellation.md), which the engine offers as two
one-member protocols so no interface library reaches the core.

The current implementation status, differentiators, limitations, and development roadmap are
maintained in [PROJECT_STATUS.md](PROJECT_STATUS.md).

## Repository scale

- `--jobs N` inspects several artifacts at once. The scan is byte-identical to a sequential one,
  including when the finding budget runs out, because the budget is charged in artifact order
  rather than in completion order.
- `--cache` reuses detector output for content that has not changed. The key covers the artifact
  digest, its path, the detector set, the resource limits, and the package and schema versions, so a
  hit is only ever an exact match. Failed and incomplete scans are never cached. The cache is
  bounded and evicted in a defined order, and pruning requires an explicit rule; see
  [the cache](docs/cache.md).
- `.gitignore` and `.trueaiignore` are applied with Git's directory-relative semantics: a nested
  ignore file applies only beneath its own directory, a deeper rule overrides a shallower one
  including through negation, and an ignored directory is not descended into.

## Report schema

The report schema is a published contract, not a convention. `schema/published/` holds the frozen
version consumers were given; `tests/unit/test_schema_compatibility.py` fails the build on any
breaking change, and a stale snapshot fails CI so no model change merges without a maintainer
reading the schema diff.

Adding an optional property or an enum member is compatible. Removing or renaming either, changing
a type, or changing whether a property is required requires a new schema version. Consumers must
ignore unknown keys and tolerate unknown enum members. See
[schema compatibility](docs/schema-compatibility.md). The HTML output has its own constraints — one file, no script, and a policy the document itself declares: see
[the HTML report](docs/html-report.md).

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Scan or cleanup succeeded; no policy action requires review. |
| 1 | One or more findings require review or a requested removal could not be automatic. |
| 2 | Policy violation (`ERROR`). |
| 3 | Unsupported, corrupt, unsafe, or unavailable optional capability. |
| 4 | Internal error. |

## Development

```console
uv sync --all-extras
uv run ruff check .
uv run mypy trueai
uv run pytest
```

Tests use synthetic fixtures only. Read [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md),
and the repository [AGENTS.md](AGENTS.md) before changing parser or public-model behavior.

## Roadmap

- MP4/MOV/M4A and WebM cleanup after sample-table, timing, index, and provenance invariants are implemented
- Richer HTML DOM topology and stylesheet feature extraction
- HTML report and desktop/IDE consumers
- Filesystem/system-call sandboxing for third-party native code
- Signed plugin distributions and centrally managed policy-bundle distribution
- Calibrated optional ML feature consumers, kept outside the core dependency set

The roadmap does not promise removal of robust statistical or cryptographic watermarks.
See the [indicator-handling boundary and implementation plan](docs/indicator-handling.md) for the
exact distinction between predictable cleanup, provenance verification, heuristics, and prohibited
detector evasion.

## Deliberate limitations

- Provider watermark signals remain status reporting only; no public verifier exists to integrate.
- PDF XMP cleanup refuses compressed metadata streams when bounded provenance inspection cannot be
  guaranteed; PDF cleanup requires `pikepdf`.
- Git worktrees, object databases, and alternates outside the selected root are rejected;
  unreachable or dangling commits remain outside the all-refs history scope.
- Plugin isolation is process-level with Python capability guards and kernel CPU/memory quotas. It
  contains accidents and catches dishonest output; it does not safely run hostile native code.
  `ctypes` and native extensions still require filesystem/system-call confinement for a
  hostile-plugin threat model.
- A textual artifact that cannot be decoded exactly is reported as corrupt rather than scanned with
  replacement characters, because an offset the cleaner cannot reproduce is not a safe basis for
  removing anything.
- With `--jobs` above 1, third-party detectors must be thread-safe or run under subprocess
  isolation.
- Audio/video stream decoding, MP4/MOV/M4A/WebM cleanup, HTML reports, learned classifiers, and
  destructive Git remediation are not implemented. WAV/MP3/FLAC cleanup edits only bounded
  metadata structures and never decodes or re-encodes audio samples.
