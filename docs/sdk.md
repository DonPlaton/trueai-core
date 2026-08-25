# Writing a detector: what you may rely on

A working example lives in [`examples/acme_ticket_detector/`](../examples/acme_ticket_detector/),
and it is not decoration. `tests/unit/test_sdk_examples.py` runs it, signs a
distribution built from it, and parses its imports to prove every one comes from
a module TrueAI has frozen. An example that drifts out of the public surface
fails the build, because an example that drifts is worse than no example: someone
copies it, it works locally, and it breaks on the next upgrade with the
compatibility gate silent.

## The contract

```python
class MyDetector(BaseDetector):
    id = "vendor.thing.v1"
    supported_types = frozenset({ArtifactType.MARKDOWN})
    categories = frozenset({FindingCategory.TOOLING_RESIDUE})

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        ...
```

`scan` is the only abstract method, and that is a **promise, not an observation**.
Adding a second one would stop every existing detector from being instantiable —
an addition to anyone calling the class and a break for everyone who inherited
from it. A method-count comparison would have called it additive, so
`trueai/api.py` records abstractness and classifies a new abstract method as
breaking. Two tests hold the line: one that the rule fires, and one that
`BaseDetector.__abstractmethods__` is still exactly `{"scan"}`.

## What you may import

Only the modules in `trueai.api.PUBLIC_MODULES`. Anything else may change in any
release and the compatibility gate will not warn you.

`trueai.api.SDK_CONTRACT` narrows that further to what a detector author actually
touches — the classes you subclass, construct, or are handed:

| From | What you use it for |
|---|---|
| `trueai.detectors.base` | `BaseDetector`, and the `Detector` protocol if you would rather not subclass. |
| `trueai.core.artifact` | `Artifact` — the thing you are given. |
| `trueai.core.models` | `Finding` and every enum that classifies one; `ScanContext` and `ScanOptions` for the limits you must respect. |
| `trueai.core.errors` | `TrueAIError`, the base of anything TrueAI raises at you. |
| `trueai.plugins` | The manifest, the capability enum, the registration, and `ENTRY_POINT_GROUP`. |

The list is kept apart from `PUBLIC_MODULES` because the guarantee differs in
kind: these are not names you import and call, they are shapes you *build
against*. A test asserts every one is reachable through a public module, so the
SDK cannot quietly drift out of the frozen surface.

## Four rules

**1. Never mutate the artifact.** `scan` receives an artifact and returns
findings, and it is never handed a remediation API. This is enforced, not
trusted: the engine hashes each file before its detectors run, re-hashes it
immediately after — which catches a detector that changed the artifact it was
given — and re-lists the whole corpus at the end, which catches one that changed
a *different* artifact. Either produces a `detector_mutation` diagnostic at
CRITICAL severity.

**2. Build findings through `self.finding(...)`.** It derives the finding id from
the artifact path, category, detector id, evidence, and location, so the same
input produces the same id on every machine and two scans can be diffed.
Constructing `Finding` directly works and loses that.

**3. Say what kind of evidence you have.** `ConfidenceType` and `EvidenceType` are
separate fields because "how sure" and "sure of *what*" are different questions.
Neither is provenance. `ProvenanceClass` describes a finding's relationship to a
signed or attributed origin — a lexical match reported with anything other than
`NONE` presents a string in a file as evidence about who wrote it, which is the
mistake this project exists to avoid. See [findings](findings.md).

**4. Respect the limits you are given.** `context.options.max_file_size` is the
caller's boundary, not a suggestion. `artifact.read_text` raises rather than
truncating, so an oversized file is reported as an error instead of silently
half-scanned — and a half-scanned file that reports nothing is a clean bill of
health nobody earned.

## Your bugs stay yours

A detector that raises produces a `detector_failure` diagnostic naming the
detector and the exception. The scan continues, other detectors still report, and
the artifact is marked as having incomplete coverage. Two tests pin this: that
the diagnostic carries your detector id and exception type, and that a working
detector's findings still appear alongside a broken one's failure.

A detector that exceeds its finding limit hits `FindingBuffer` and fails closed
rather than filling a report.

## Declaring capabilities

The entry point returns a `PluginRegistration`, not a detector:

```python
REGISTRATION = PluginRegistration(manifest=MANIFEST, factory=MyDetector)
```

so the host reads the manifest **before importing anything that could run**.
Import time is when hostile code acts, and a declaration the host can read first
is the entire point of the arrangement.

Ask for the narrowest capability set that works. An unused capability is the same
mistake as an over-broad permission on a phone app: it costs the operator their
ability to reason about what ran. See [plugins](plugins.md) for what each
capability admits and how the host enforces it.

## Publishing

Register under `trueai.detectors` — the value of `trueai.plugins.ENTRY_POINT_GROUP`,
so a typo is a plugin that silently never loads:

```toml
[project.entry-points."trueai.detectors"]
my-detector = "my_package:REGISTRATION"

dependencies = ["trueai-core>=0.1,<0.2"]
```

Pin the pair. TrueAI's Python surface and its report schema move together on
purpose, so a detector pins one version range rather than two independent ones.

For anything an operator installs, ship a signed distribution. The signature
covers the module bytes as well as the manifest, so a declared capability set
cannot be contradicted by what module-level code actually does — see
[plugins](plugins.md).

## What will change under you, and what will not

[API compatibility](api-compatibility.md) has the full rules. In short: names,
modules, enum members, and parameters may be added; nothing you depend on is
removed or renamed inside an API version; and the two changes that would silently
break a *subclass* rather than a caller — a new abstract method, a formerly
optional model field becoming required — are classified as breaking and gated.
