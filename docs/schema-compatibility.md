# Public schema compatibility policy

TrueAI reports are consumed by CI gates, desktop and IDE clients, policy engines,
and archived audit records. Those consumers parse a document, not a screen, so the
report schema is treated as a published interface with explicit rules.

The current public version is `0.1`. It appears in every report as
`schema_version` and is independent of the package version.

## Where the contract lives

| Artifact | Role |
|---|---|
| `schema/published/trueai-report-0.1.schema.json` | The frozen contract. Never edited after publication. |
| `schema/trueai-report-0.1.schema.json` | Snapshot of what the current code emits. |
| `trueai/schema.py` | Emits the schema and classifies differences between two versions. |
| `tests/unit/test_schema_compatibility.py` | Fails the build on a breaking change. |
| `scripts/check_schema_snapshot.py` | Fails the build when the snapshot is stale. |

Consumers can fetch the schema from an installed package without cloning the
repository:

```bash
trueai schema --output trueai-report-0.1.schema.json
```

## What may change inside version 0.1

Compatible, allowed at any time:

- adding a new optional property with a default;
- adding a new member to an existing enum, such as a new `ArtifactType`,
  `FindingCategory`, or `Severity`;
- adding a new definition, such as a model referenced only by a new optional
  property;
- rewording any `description` or `title`, or changing a `default` value that is
  not part of the wire contract for existing data.

Breaking, requires a new schema version:

- removing or renaming a property;
- removing or renaming an enum member, even one the current code never emits,
  because stored reports still contain it;
- changing the type of an existing property;
- making an existing optional property required, or adding a required property;
- removing a definition.

## What consumers must implement

A consumer that follows these two rules will keep working across every compatible
0.1 release:

1. **Ignore unknown keys.** New optional properties are added without notice.
2. **Tolerate unknown enum members.** Route an unrecognized category, severity, or
   artifact type to your own default handling instead of raising. A scanner that
   learns to recognize a new format must not break a report reader.

Do not derive meaning from field order, from `scan_id`, or from the absence of a
key: `exclude_none=True` means optional fields with a `null` value are omitted
entirely rather than serialized as `null`.

## Changing the schema

1. Change the models under `trueai/core/models.py`.
2. Regenerate the snapshot:
   `trueai schema --output schema/trueai-report-0.1.schema.json`.
3. Run `pytest tests/unit/test_schema_compatibility.py`. The suite prints every
   difference and marks each one additive or breaking.
4. Review the snapshot diff in the pull request. The diff is the review artifact;
   an unreviewed schema change cannot merge because the snapshot check fails.

If a change is breaking, it does not get merged into version 0.1. It requires:

- a new `SCHEMA_VERSION` in `trueai/_version.py`;
- a new `schema/published/trueai-report-<version>.schema.json`;
- a migration note in `CHANGELOG.md` describing what moved and how to read both
  versions;
- a documented support window for the previous version.

## Exit codes and error identifiers

The CLI exit codes (`0` success, `1` review required, `2` policy violation,
`3` unsupported or corrupt input, `4` internal error) and the `ScanDiagnostic.code`
identifiers are part of the same contract. Diagnostic codes may be added; existing
codes are not renamed or repurposed inside a schema version.
