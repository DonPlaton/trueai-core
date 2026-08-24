# Python API compatibility policy

The [report schema](schema-compatibility.md) is what a consumer parses. The Python
API is what a consumer *calls*: a desktop client constructs an engine, a CI
integration reads model fields, a third-party detector subclasses `BaseDetector`.
A stable schema does not help if those move, so the API surface has the same kind
of executable contract.

The current API version is `0.1`. It tracks the report schema version
deliberately, so an integrator pins one pair rather than two independent numbers.

## What is public

`trueai/api.py` lists it, and that list is the contract:

| Module | Why it is public |
|---|---|
| `trueai` | The convenience surface: engine, policies, models, verification. |
| `trueai.api` | This contract, so a consumer can check it themselves. |
| `trueai.schema` | The report schema and its compatibility rules. |
| `trueai.core.artifact` | Artifact identification and bounded discovery. |
| `trueai.core.engine` | The scanner. |
| `trueai.core.errors` | The exception hierarchy an integrator catches. |
| `trueai.core.models` | Every report, policy, remediation, and certificate model. |
| `trueai.core.policy` | Policy profiles and the built-in store. |
| `trueai.core.remediation` | Planning and applying cleanup. |
| `trueai.detectors.base` | The detector contract third parties implement. |
| `trueai.plugins` | Capability manifests, host policy, and isolation. |
| `trueai.reporters` | Terminal, JSON, and SARIF adapters. |

Anything not listed is internal and may change in any release. That is only a fair
rule because the list is written down rather than inferred from what happens to be
importable.

### Deliberately not yet frozen

`trueai.core.attestation` implements Human Contribution Records and is **not** in
the frozen surface. Its own documentation states that the schema is not called
stable until consented design-partner pilots have exposed rubric disagreements
(`PROC-12`). Freezing a claim model before anyone has argued with it would commit
to vocabulary that field use is expected to change.

It is public and usable; it is not yet contract-bound. When the pilots close, it
joins `PUBLIC_MODULES` and the snapshot in the same change.

## Where the contract lives

| Artifact | Role |
|---|---|
| `api/published/trueai-api-0.1.json` | The frozen contract. Never edited after publication. |
| `api/trueai-api-0.1.json` | Snapshot of what the current code exposes. |
| `trueai/api.py` | Emits the surface and classifies differences. |
| `tests/unit/test_api_compatibility.py` | Fails the build on a breaking change. |
| `scripts/check_api_snapshot.py` | Fails the build when the snapshot is stale. |

## What may change inside version 0.1

Compatible, allowed at any time:

- adding a public module, name, method, or attribute;
- adding a keyword parameter that has a default;
- adding a model field that has a default;
- adding an enum member — consumers must tolerate unknown members;
- widening a type annotation, since annotations are not part of the recorded
  contract. What a consumer depends on is how a function is *called*.

Breaking, requires a new API version:

- removing or renaming a module, name, method, attribute, parameter, model field,
  or enum member;
- adding a required parameter or a required model field;
- making an optional parameter or model field required;
- changing a parameter's kind, for example from positional-or-keyword to
  keyword-only;
- reordering positional parameters, because existing positional calls would bind
  to different parameters;
- changing what a name *is*, for example a class becoming a function.

## Deprecation rules

A name that will be removed is deprecated before it is removed, never at the same
time:

1. **Announce.** The changelog entry names the replacement and the release the
   removal will land in. The docstring gains a `.. deprecated::` note.
2. **Warn.** The call site emits `DeprecationWarning` with the replacement in the
   message. The name keeps working unchanged.
3. **Wait.** At least one full minor release with the warning in place. A
   deprecation announced in `0.2.0` is not removed before `0.4.0`.
4. **Remove.** Only in a release that bumps the API version, with a migration note.

A deprecated name stays in the published surface until it is actually removed, so
the snapshot keeps proving it still works.

## Changing the API

1. Change the code.
2. Regenerate the snapshot: `python scripts/check_api_snapshot.py --write`.
3. Run `pytest tests/unit/test_api_compatibility.py`. It prints every difference
   and marks each one additive or breaking.
4. Review the snapshot diff in the pull request. The diff is the review artifact;
   an unreviewed API change cannot merge because the snapshot check fails.

If a change is breaking, it does not get merged into version `0.1`. It requires a
new `API_VERSION`, a new `api/published/trueai-api-<version>.json`, a migration
note in `CHANGELOG.md`, and a documented support window for the previous version.
