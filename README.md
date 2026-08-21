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

Two capabilities are optional installs, and both report honestly when absent rather than guessing:

```console
uv sync --extra pdf     # surgical PDF cleanup and its reachable-object integrity gate
uv sync --extra c2pa    # authenticated C2PA verification
```

`trueai doctor` prints which optional capabilities are present.

## CLI

```console
trueai scan ./repository
trueai scan ./repository --jobs 8 --cache          # parallel, and reuse unchanged results
trueai scan report.docx --format json --output report.trueai.json
trueai scan deck.pptx --verbose
trueai inspect model.xlsx
trueai clean report.docx --policy client-delivery
trueai clean README.md --dry-run
trueai verify design.png --trust-anchors roots.pem  # authenticated provenance
trueai schema --output trueai-report-0.1.schema.json
trueai detectors list
trueai policies list
trueai plugins list
trueai cache clear ./repository
trueai doctor
```

`clean` writes `name.cleaned.ext` by default. It never overwrites the source unless `--in-place` is
explicit; in-place mode creates a `.trueai.bak` backup and still applies changes through a verified
temporary file.

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

Office, SVG, raster, PDF, Git, and recursive filesystem inputs are treated as hostile. Archive,
parser-event, finding, Git-output, file-count, file-size, path, XML, and image-pixel limits are
fail-closed. An incomplete scan emits a high-severity diagnostic and CLI exit code `3`.

## Provenance

Scanning finds markers. Verifying checks signatures. These are different claims and TrueAI keeps
them apart:

```console
trueai verify design.png                            # valid signature, unknown signer  → exit 1
trueai verify design.png --trust-anchors roots.pem  # chains to a trusted root         → exit 0
```

`trusted` is the only result that establishes provenance. `valid` means the cryptography checks out
but the signer is not established as trusted, which is a materially weaker statement and is reported
as its own state rather than rounded up. Without the optional verifier installed, the result is
`verifier_unavailable`; nothing is inferred. Remote manifests are never fetched unless explicitly
permitted. See [provenance](docs/provenance.md).

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
`VERIFICATION_UNAVAILABLE` or `NOT_SUPPORTED`. TrueAI does not invent provider watermark
algorithms, reverse-engineer keys, forge provenance, or claim watermark removal. C2PA verification
is real but explicit: a scan reports markers, `trueai verify` validates signatures.

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
point in the `trueai.detectors` group. A plugin declares a capability manifest; the host policy
decides what it may do before any of its code is trusted. Detection is read-only, so filesystem
writes, process creation, and network access are denied by default even to a plugin that asks:

```python
from trueai import TrueAIEngine
from trueai.plugins import CapabilityPolicy, PluginIsolation

engine = TrueAIEngine.default(
    plugin_isolation=PluginIsolation.SUBPROCESS,
    capability_policy=CapabilityPolicy(require_manifest=True),
)
```

Subprocess isolation contains crashes, hangs, and unbounded output, and re-derives every returned
finding so a plugin cannot forge an identity or impersonate another detector. It is not an OS
sandbox. See [plugins](docs/plugins.md).

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

More detail: [architecture](docs/architecture.md) and [detectors](docs/detectors.md).

The current implementation status, differentiators, limitations, and development roadmap are
maintained in [PROJECT_STATUS.md](PROJECT_STATUS.md).

## Repository scale

- `--jobs N` inspects several artifacts at once. A completed scan is byte-identical to a sequential
  one, because results merge in artifact order rather than completion order.
- `--cache` reuses detector output for content that has not changed. The key covers the artifact
  digest, its path, the detector set, the resource limits, and the package and schema versions, so a
  hit is only ever an exact match. Failed and incomplete scans are never cached.
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
[schema compatibility](docs/schema-compatibility.md).

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

- Audio and video container metadata
- Richer HTML DOM topology and stylesheet feature extraction
- HTML report and desktop/IDE consumers
- Operating-system sandboxing for third-party plugins
- Signed enterprise policy bundles, baselines, suppressions, and audit trails
- Calibrated optional ML feature consumers, kept outside the core dependency set

The roadmap does not promise removal of robust statistical or cryptographic watermarks.

## Deliberate limitations

- Provider watermark signals remain status reporting only; no public verifier exists to integrate.
- PDF XMP cleanup refuses compressed metadata streams when bounded provenance inspection cannot be
  guaranteed; PDF cleanup requires `pikepdf`.
- Git worktrees, object databases, and alternates outside the selected root are rejected;
  unreachable or dangling commits remain outside the all-refs history scope.
- Plugin isolation is process-level with Python-level capability guards. It contains accidents and
  catches dishonest output; it does not safely run hostile native code.
- With `--jobs` above 1, third-party detectors must be thread-safe or run under subprocess
  isolation.
- Audio, video, HTML reports, learned classifiers, and destructive Git remediation are not
  implemented.
