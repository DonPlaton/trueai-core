# TrueAI Core engineering rules

- Run the full test suite, Ruff, and mypy before claiming completion.
- Do not weaken, delete, or broadly skip tests to make a change pass.
- Keep detection read-only; policy selection and remediation remain separate layers.
- Never conflate deterministic, verified, probabilistic, and heuristic findings.
- Never describe style signals as provenance or authorship proof.
- Preserve C2PA/provider watermark findings by default; do not implement defeat, forgery, or secret-key inference.
- Never optimize artifacts to evade AI-authorship detectors or to defeat SynthID, C2PA, provider
  statistical watermarks, or other hidden provenance mechanisms. Detector evaluation is permitted
  only for measurement, calibration, and false-positive analysis; it must not drive an evasion loop.
- Keep provider-specific assumptions in documented provider rule packs or adapters.
- Require explicit opt-in for destructive operations; never automate Git history rewriting.
- Write cleaned output to a new file by default and verify content integrity before publication.
- Treat all parsed input as hostile; bound reads and archives, forbid XML entities, and never execute embedded content.
- Add synthetic fixtures and adversarial tests for every new detector or parser behavior.
- Keep core scanning offline and telemetry-free; network verification requires an explicit adapter and policy.
- Consider backward compatibility before changing public Pydantic models, enum values, finding IDs, or schema fields.
- Use English for code, comments, docstrings, tests, documentation, and commit messages.
- Regenerate `schema/trueai-report-0.1.schema.json` after any public-model change and review the
  diff; never edit a file under `schema/published/`, which is the frozen consumer contract.
- Add a format to the shared Office Open XML layer, never as a parallel implementation, and state
  the integrity invariant that proves its cleanup was harmless.
- Media inspection and cleanup must never invoke codecs. Register cleanup only when a
  format-specific invariant proves streams, timing, rendering-critical metadata, and protected
  provenance survive.
- A completed scan must be byte-identical whether it ran sequentially or in parallel.
- Never cache a failed or incomplete scan result.
- Describe plugin isolation as containment, not as a sandbox; do not claim protection the guards
  do not provide.
- Install plugin CPU/memory quotas before third-party import and fail closed when the platform
  cannot enforce the configured worker budget.
- Enterprise baselines, suppressions, and exceptions may alter policy decisions only; findings
  remain visible, overrides require an audit entry, and protected provenance remains preserved.
- Audit certificates may claim only what the recorded detector scope observed. Never describe a
  `clear` certificate as proof of human authorship or proof that AI was never used.
- A required revocation check fails closed on missing, stale, unsigned, or wrong-issuer lists;
  document that offline lists cannot detect sequence rollback without external state.
- Post-clean residue verification must rescan the published bytes; never suppress heuristic or
  protected-provenance findings to manufacture a clear result.

