# Public report schema

Two files describe the same schema version for two different purposes.

| File | Purpose | May it change? |
|---|---|---|
| `trueai-report-0.1.schema.json` | Snapshot of what the current code emits | Regenerate whenever the models change: `trueai schema --output schema/trueai-report-0.1.schema.json` |
| `published/trueai-report-0.1.schema.json` | The frozen contract published to consumers | No. It is the baseline every compatibility check runs against. |

`scripts/check_schema_snapshot.py` fails when the snapshot is stale, so no model
change reaches `main` without a maintainer looking at the schema diff.

`tests/unit/test_schema_compatibility.py` compares the current schema against the
frozen published baseline and fails on any breaking change. The rules are in
[`docs/schema-compatibility.md`](../docs/schema-compatibility.md).

A breaking change is not fixed by editing the published baseline. It requires a
new schema version, a new published file, and a migration note in the changelog.

Audit certificates, issuer revocation lists, and enterprise policy bundles have independent
contracts:

- `trueai-certificate-0.1.schema.json` is emitted by `trueai certificates schema`;
- `trueai-revocation-list-0.1.schema.json` is emitted by
  `trueai certificates revocation-schema`.
- `trueai-policy-bundle-0.1.schema.json` is emitted by
  `trueai policies bundle-schema`.

All snapshots must match the implementation. They do not change the scan-report schema version.
