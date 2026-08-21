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
5. If the user asked only for inspection, stop after reporting evidence and suggested review. Do not
   mutate the artifact.
6. If remediation was requested, select an explicit policy and preview it:

   ```console
   trueai clean PATH --policy client-delivery --dry-run
   ```

7. Review blocked/preserved findings. Never remove C2PA/provider watermark evidence, never rewrite
   Git history, and never use `--in-place` unless the user explicitly requested destructive source
   replacement.
8. Apply to a new output path, then require `Integrity: PASS`:

   ```console
   trueai clean PATH --policy client-delivery --output OUTPUT
   ```

9. Re-scan the cleaned output when preparing a delivery and summarize: original path, output path,
   exact fields/spans changed, preserved provenance, unresolved review items, integrity status, and
   report path.

Read [cli.md](references/cli.md) for policies, exit codes, and format-specific limitations. Use
`scripts/audit.py` when a deterministic JSON-only wrapper is more convenient than terminal output.

## Guardrails

- Keep all scans local and offline.
- Treat `DETERMINISTIC` as certainty about observed evidence, not authorship.
- Treat `HEURISTIC` as a measurement only, never provenance.
- Describe a C2PA marker as unverified unless an official verifier returned `VERIFIED`.
- Preserve originals by default. Report any `FAIL` or `NOT_VERIFIABLE` integrity result directly.
- Do not claim robust/statistical watermark removal; TrueAI Core does not implement it.

