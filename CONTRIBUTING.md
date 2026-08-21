# Contributing to TrueAI Core

TrueAI welcomes focused fixes, new forensic detectors, format adapters, policies, reporters, and
adversarial test cases. Contributions must preserve the distinction between observable evidence
and unsupported AI-authorship claims.

## Development setup

```console
git clone https://github.com/trueai-core/trueai-core.git
cd trueai-core
uv sync --all-extras
uv run pytest
```

Before opening a pull request, run:

```console
uv run ruff check .
uv run mypy trueai
uv run pytest
uv build
```

## Change requirements

- Add a synthetic fixture and happy-path, edge, and malformed-input tests for a detector.
- Document provider-specific patterns and include a false-positive test.
- Keep detector output immutable and mutation-free.
- Add remediation only when the transform is predictable and has an integrity verifier.
- Do not add scan-time network access, telemetry, or remote fonts/assets.
- Discuss public model, schema, detector ID, or policy semantics changes before implementation.
- Regenerate the schema snapshot after a model change:
  `uv run trueai schema --output schema/trueai-report-0.1.schema.json`. The snapshot diff is the
  review artifact; `uv run pytest tests/unit/test_schema_compatibility.py` decides whether the
  change is allowed inside the current schema version.
- Use a conventional commit such as `feat(svg): detect editor metadata`.

Security-sensitive parsers need explicit resource limits and adversarial tests for traversal,
entity expansion, decompression bombs, malformed lengths, and unexpected encodings as applicable.

