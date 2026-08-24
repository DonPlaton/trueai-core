# Architecture

TrueAI Core is an engine library first. The CLI is one consumer of the same stable Python API that
future desktop, CI, IDE, and enterprise products can use.

## Layers

1. `core.artifact` identifies files by signatures where practical, discovers repositories, applies
   directory-relative ignore rules, rejects unsafe symlink traversal, and exposes bounded reads.
2. `core.registry` owns explicit detector registration, enable/disable state, category/provider
   filtering, and reviewed discovery of the `trueai.detectors` third-party entry-point group.
3. `core.engine` schedules compatible read-only detectors, enforces a global result budget shared
   across workers, isolates expected parser failures, and rechecks discovered file hashes and
   inventory additions after scanning.
4. `core.cache` stores per-artifact detector output addressed by content, so an unchanged file is
   not re-inspected on the next scan. Oversized entries and link-based path redirection fail closed.
5. `core.models` defines immutable Pydantic v2 findings, reports, policy decisions, remediation
   plans/results, provenance verification, and integrity evidence. Report schema versioning is
   independent of package version.
6. `core.policy` maps complete detector output to operational actions. It cannot suppress or mutate
   the evidence and rejects provenance-removal policy rules.
7. `core.policy_bundle` authenticates finite enterprise profiles, exact baselines, suppressions,
   and exceptions. Overrides change decisions rather than findings and produce an immutable audit
   trail; protected provenance remains preserved.
8. `core.remediation` converts selected findings into a plan. A format cleaner writes a temporary
   output; the output is published only after an integrity verifier passes.
9. `core.delivery` rescans published cleaned bytes, while `core.certificates` binds scoped results
   to exact content, optionally authenticates the issuer with Ed25519, enforces finite validity,
   and verifies issuer-signed revocation lists.
10. `plugins` inspects third-party capability manifests in a guarded helper, decides what a plugin
    may do, and runs it in a worker process with pre-import kernel CPU/memory quotas by default.
11. `reporters` render terminal, JSON schema `0.1`, and SARIF output without detector coupling.
   Artifact-controlled text is escaped before it reaches a markup parser, and every surface carries
   scan diagnostics so an incomplete run cannot be mistaken for a clean one.
11. `schema` emits the public JSON Schema and classifies differences between two versions of it as
    additive or breaking.

## Detector contract

```python
class Detector(Protocol):
    id: str
    supported_types: frozenset[ArtifactType]
    provider: str | None
    categories: frozenset[FindingCategory]
    experimental: bool

    def supports(self, artifact: Artifact) -> bool: ...
    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]: ...
```

Detectors receive no mutation API. IDs are versioned because they participate in stable finding
fingerprints and downstream suppressions. Third-party packages expose a detector, a factory, or a
`PluginRegistration` through the `trueai.detectors` entry point.

In-process plugins execute as trusted Python and require explicit selection. Default subprocess
isolation protects host state, terminates hangs, discards output streams, and re-derives every
returned finding so a plugin cannot forge one. Helpers have kernel CPU/memory quotas, but this is
not filesystem/system-call confinement. See [plugins](plugins.md) for the full boundary.

## Format families

Word, PowerPoint, and Excel packages are the same OPC container with different content parts, so
they share one safety layer, one metadata inspector, and one cleaner. Each family contributes only
what actually differs: its content-bearing parts, and the invariant that proves cleanup did not
disturb them. Adding a format therefore requires stating how its integrity is proved, which is
enforced by construction rather than by review.

Audio/video inspection follows a separate bounded media-container layer. It reads metadata headers
from WAV, MP3, FLAC, ISO BMFF/QuickTime, and EBML without decoding streams. WAV/MP3/FLAC have
surgical writers because their metadata boundaries can be reconstructed while hashing the exact
audio-bearing bytes. ISO BMFF/QuickTime and EBML remain inspection-only: inspecting a tag is not
enough to prove that rewriting those containers preserves sample tables, timing, codec
configuration, indexes, provenance, and exact media payloads.

## Determinism and scale

A scan is byte-identical regardless of how it was executed, including when it is truncated.
Artifacts, detectors, findings, and policy decisions are returned in a stable order; parallel
execution inspects several artifacts at once but charges the global finding budget strictly in
artifact order, through a bounded submission window, so an exhausted budget retains the same
findings and emits the same diagnostics as a sequential run. Setting `max_workers` above 1 requires
third-party detectors to be thread-safe, or `PluginIsolation.SUBPROCESS`, which gives each plugin
its own interpreter.

Artifact discovery is iterative, bounded by `max_files`, and applies `.gitignore` and
`.trueaiignore` with Git's directory-relative semantics: a nested ignore file applies only beneath
its own directory, a deeper rule overrides a shallower one including through negation, and an
ignored directory is not descended into. Findings, parser events, archive expansion, Git output,
and image pixels also have explicit limits. Crossing any completeness boundary produces a blocking
diagnostic rather than a clean result.

Incremental caching is content-addressed. The key covers the artifact digest, its logical path
(finding identities are path-derived), the artifact type, the enabled detector set, the resource
limits, and the package and schema versions, so a cache hit is only ever an exact match. Failed and
incomplete scans are never cached, and a corrupt entry is a miss rather than an error.
Cache input is size-checked before reading. A symlink or Windows junction in the cache path disables
that cache operation rather than redirecting scanner writes outside the configured tree.

## Commercial extension points

- Reporters are adapters; a premium GUI can consume `ScanReport` directly.
- Policies do not contain parsing logic; signed bundles provide an implemented enterprise
  distribution contract above `PolicyStore`.
- Cleaners consume a reviewed `RemediationPlan`; premium preview/diff UI does not need detector changes.
- Provenance verification is an adapter over the reference implementation, with an explicit trust
  store and network boundary supplied by the operator. Explicit results can be attached to
  `ScanReport` without changing marker findings.
- Provider watermark verification is an adapter boundary with explicit support status.
- Capability manifests, kernel resource profiles, and host policy are the distribution point for
  enterprise plugin governance; native-code filesystem confinement remains a platform host concern.
- Experimental feature extractors emit measurement vectors before model scores, allowing optional
  learned classifiers without adding an ML framework to core.

Remediation plans are bound to the scan policy, finding fingerprints, artifact name, and source
SHA-256. Application rebuilds cleaner payloads from the immutable scan report, writes a temporary
output, and publishes only after the format-specific integrity invariant passes.

Schema changes are governed by an executable contract rather than a convention. See
[schema compatibility](schema-compatibility.md).
