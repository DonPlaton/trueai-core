# TrueAI CLI reference for audits

## Commands

```console
trueai scan PATH [--format terminal|json|sarif] [--policy audit] [--experimental]
trueai scan PATH --verify-provenance [--trust-anchors ROOTS.pem] [--format json]
trueai scan PATH --policy-bundle BUNDLE.json --policy-key ISSUER-PUBLIC.pem
trueai inspect PATH [--experimental]
trueai clean PATH --policy POLICY [--dry-run] [--output OUTPUT] [--certificate CERTIFICATE.json]
trueai certificates issue PATH [--output CERTIFICATE.json] [--signing-key PRIVATE.pem] [--valid-for-days N]
trueai certificates verify CERTIFICATE.json [--artifact PATH] [--public-key PUBLIC.pem] [--revocation-list LIST.json] [--require-revocation-check]
trueai certificates revoke CERTIFICATE.json --revocation-list LIST.json --signing-key PRIVATE.pem
trueai certificates keygen --private-key PRIVATE.pem --public-key PUBLIC.pem
trueai explain FINDING_ID --report REPORT.json
trueai detectors list
trueai policies list
trueai policies bundle-create POLICY --output BUNDLE.json --signing-key PRIVATE.pem --issuer NAME
trueai policies bundle-verify BUNDLE.json --public-key PUBLIC.pem
trueai doctor
```

Built-in policies: `audit`, `safe-clean`, `privacy`, `client-delivery`, `strict`.

Exit codes: `0` success, `1` review required, `2` policy violation, `3` unsupported/corrupt/unsafe,
`4` internal error. Treat code 1 as evidence requiring review, not command failure.

## Limitations

- Apply cleanup to one file at a time in v0.1; directories and Git history remain scan-only.
- Install `trueai-core[pdf]` for PDF cleanup. PDF scanning needs no optional extra.
- Provider watermark verification is unavailable/unsupported; no watermark removal exists.
- C2PA verification is explicit. The default scan reports markers; `--verify-provenance` adds a
  separate authenticated result and may opt into remote manifests only with another explicit flag.
- Enterprise bundle controls never hide findings. Inspect `policy_audit`, expiry, issuer key, and
  protected-provenance decisions before accepting an override.
- Experimental stylometry/design scores are disabled unless `--experimental` is explicit.
- Post-clean residue verification runs by default. It may report `INDICATORS_REMAIN`; this is not an
  integrity failure and must not be suppressed by rewriting style.
- A `clear` certificate is scoped evidence for exact bytes, not proof of human authorship. Unsigned
  certificates do not authenticate their issuer; signatures and revocation lists require
  `trueai-core[attestation]`. A stale list cannot establish current revocation status.
- WAV, MP3, FLAC, M4A, MP4/MOV, and WebM metadata are inspected without stream decoding.
  WAV/MP3/FLAC have surgical metadata cleanup with byte-identical audio-payload verification;
  M4A/MP4/MOV/WebM remain inspection-only.
