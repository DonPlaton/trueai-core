# Public Python API surface

Two files describe the same API version for two different purposes, mirroring
[`schema/`](../schema/README.md).

| File | Purpose | May it change? |
|---|---|---|
| `trueai-api-0.1.json` | Snapshot of what the current code exposes | Regenerate whenever the public surface changes: `python scripts/check_api_snapshot.py --write` |
| `published/trueai-api-0.1.json` | The frozen contract published to consumers | No. It is the baseline every compatibility check runs against. |

`scripts/check_api_snapshot.py` fails when the snapshot is stale, so no change to
a public module reaches `main` without a maintainer reading the diff.

`tests/unit/test_api_compatibility.py` compares the current surface against the
frozen baseline and fails on any breaking change. The rules are in
[`docs/api-compatibility.md`](../docs/api-compatibility.md).

A breaking change is not fixed by editing the published baseline. It requires a
new API version, a new published file, and a migration note in the changelog.
