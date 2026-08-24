---
name: trueai
description: Audit local repositories and artifacts with TrueAI Core for AI-tooling residue, metadata, invisible Unicode, Git attribution, document/image properties, provenance markers, and conservative style signals. Use for requests such as “scan this deliverable,” “inspect metadata/provenance,” “check this repo before publishing,” “audit this document,” or “perform a clean-delivery audit.”
---

# TrueAI artifact audit

Use TrueAI as an evidence-first local scanner. Never summarize all findings as “AI-generated.”

## Workflow

1. Determine whether the target is a file, directory, Git repository, or text stream. Keep the
   original path and do not follow external symlinks.
2. Confirm availability with `trueai --version`. When working in the TrueAI source repository, use
   `python -m trueai.cli` if the console script is not installed.
3. Run a non-mutating scan first:

   ```console
   trueai scan PATH --format json --output trueai-report.json
   ```

4. Interpret deterministic findings before heuristics. Separate ordinary metadata, literal
   attribution, unverified provenance markers, authenticated provenance, provider watermark
   findings, and style signals. Read [interpretation.md](references/interpretation.md) when any
   provenance or heuristic finding appears.
   If authenticated provenance is required, rerun explicitly:

   ```console
   trueai scan PATH --verify-provenance --trust-anchors ROOTS.pem --format json
   ```

   Keep marker findings and `provenance_verifications` separate in the summary.
5. If the user asked only for inspection, stop after reporting evidence and suggested review. Do not
   mutate the artifact.
6. If remediation was requested, select an explicit policy and preview it:

   ```console
   trueai clean PATH --policy client-delivery --dry-run
   ```

7. Review blocked/preserved findings. Never remove C2PA/provider watermark evidence, never rewrite
   Git history, and never use `--in-place` unless the user explicitly requested destructive source
   replacement.
8. Apply to a new output path, then require both `Integrity: PASS` and a complete post-clean scan:

   ```console
   trueai clean PATH --policy client-delivery --output OUTPUT
   ```

9. `trueai clean` rescans published output by default. Report `INDICATORS_REMAIN` honestly; never
   alter stylistic content to make a heuristic stop firing. Summarize: original path, output path,
   exact fields/spans changed, preserved provenance, unresolved review items, integrity status, and
   report path.
10. If the user requests a certificate, issue it only from the post-clean bytes:

    ```console
    trueai clean PATH --policy client-delivery --output OUTPUT --certificate OUTPUT.audit.json
    ```

    A `clear` certificate means only that TrueAI found no scoped indicator in a complete scan. It is
   not proof of human authorship. Use an Ed25519 signing key and finite validity when issuer
   authentication is required. If verification policy requires revocation status, supply a current
   issuer-signed list; never treat a missing or expired list as “not revoked.”

Read [cli.md](references/cli.md) for policies, exit codes, and format-specific limitations. Use
`scripts/audit.py` when a deterministic JSON-only wrapper is more convenient than terminal output.

## Guardrails

- Keep all scans local and offline.
- Treat `DETERMINISTIC` as certainty about observed evidence, not authorship.
- Treat `HEURISTIC` as a measurement only, never provenance.
- Describe a C2PA marker as unverified unless an official verifier returned `VERIFIED`.
- When an enterprise policy bundle is supplied, verify its Ed25519 issuer key and report every
  `policy_audit` override; a suppression never means the finding disappeared.
- Preserve originals by default. Report any `FAIL` or `NOT_VERIFIABLE` integrity result directly.
- Do not claim robust/statistical watermark removal; TrueAI Core does not implement it.
- Never describe a `TAI1-…` certificate as proof that AI was never used. Check its artifact binding,
  content ID, validity period, signature when present, revocation status when required, detector
  scope, diagnostics, and experimental-detector flag.
