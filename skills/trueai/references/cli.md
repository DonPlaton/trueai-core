# TrueAI CLI reference for audits

## Commands

```console
trueai scan PATH [--format terminal|json|sarif] [--policy audit] [--experimental]
trueai inspect PATH [--experimental]
trueai clean PATH --policy POLICY [--dry-run] [--output OUTPUT]
trueai explain FINDING_ID --report REPORT.json
trueai detectors list
trueai policies list
trueai doctor
```

Built-in policies: `audit`, `safe-clean`, `privacy`, `client-delivery`, `strict`.

Exit codes: `0` success, `1` review required, `2` policy violation, `3` unsupported/corrupt/unsafe,
`4` internal error. Treat code 1 as evidence requiring review, not command failure.

## Limitations

- Apply cleanup to one file at a time in v0.1; directories and Git history remain scan-only.
- Install `trueai-core[pdf]` for PDF cleanup. PDF scanning needs no optional extra.
- Provider watermark verification is unavailable/unsupported; no watermark removal exists.
- Experimental stylometry/design scores are disabled unless `--experimental` is explicit.

