# Examples

Minimal, runnable third-party integrations. They exist to be copied, and they are
checked by the test suite — `tests/unit/test_sdk_examples.py` scans with the
detector below, verifies a signed distribution built from it, and asserts that
every import in it comes from a module named in `trueai.api.PUBLIC_MODULES`. An
example that drifts out of the public surface fails the build.

| Example | What it shows |
|---|---|
| [`acme_ticket_detector/`](acme_ticket_detector/) | A detector package: the entry point, the capability manifest, deterministic finding construction, and the imports a third party may rely on. |

## Writing a detector

```python
from trueai.core.artifact import Artifact
from trueai.core.models import Finding, ScanContext
from trueai.detectors.base import BaseDetector

class MyDetector(BaseDetector):
    id = "vendor.thing.v1"
    supported_types = frozenset({ArtifactType.MARKDOWN})
    categories = frozenset({FindingCategory.TOOLING_RESIDUE})

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        return [...]
```

`scan` is the only abstract method, and that is a promise: adding another would
stop every existing detector from being instantiable, so the compatibility gate
classifies a new abstract method as **breaking** rather than as an addition.

Four rules the example follows and yours should:

1. **Import only from `PUBLIC_MODULES`.** Everything else may change in any
   release, and the compatibility gate will not protect you.
2. **Never mutate the artifact.** The engine re-hashes each file after its
   detectors run, and re-lists the whole corpus at the end. A detector that
   writes is reported at CRITICAL severity, not tolerated.
3. **Use `self.finding(...)`.** It derives a stable finding id from the artifact
   path, category, detector id, evidence, and location, so the same input
   produces the same id everywhere. Building `Finding` by hand loses that.
4. **Say what kind of evidence you have.** `ConfidenceType` and `EvidenceType`
   are separate fields because "how sure" and "sure of what" are different
   questions, and neither of them is provenance. A style signal reported as
   `ProvenanceClass` is the mistake this project exists to avoid.

## Declaring capabilities

The entry point returns a `PluginRegistration`, not a detector, so the host reads
your manifest **before importing anything that could run**. Ask for the narrowest
capability set that works: an unused capability costs the operator their ability
to reason about what ran.

## Publishing

Register under the `trueai.detectors` entry-point group —
`trueai.plugins.ENTRY_POINT_GROUP`, so a typo is a plugin that silently never
loads. For anything an operator will install, sign a distribution:

```python
from trueai.plugins import build_distribution, sign_distribution

distribution = sign_distribution(
    build_distribution(
        detector_id="vendor.thing.v1",
        version="1.0",
        entry_point="my_package:REGISTRATION",
        manifest=MANIFEST,
        publisher="Vendor",
        root=package_directory,
        created_at=now,
    ),
    signing_key=private_key_path,
)
```

The signature covers the module bytes as well as the manifest, so a declared
capability set cannot be contradicted by what module-level code actually does.

See [plugins](../docs/plugins.md) for the host side and
[API compatibility](../docs/api-compatibility.md) for what may change under you.
