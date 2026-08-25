# Contributing to TrueAI Core

TrueAI welcomes focused fixes, new forensic detectors, format adapters, policies, reporters, and
adversarial test cases. Contributions must preserve the distinction between observable evidence
and unsupported AI-authorship claims.

## Development setup

```console
git clone https://github.com/DonPlaton/trueai-core.git
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

## Documentation is gated too

`python scripts/check_docs.py` fails when a document names a command, an option,
or a file that does not exist, and when a page under `docs/` is linked from
nowhere.

It cannot check whether the prose is *true* — that needs a reader. It checks
whether the nouns exist, which is the part that rots first: a flag gets renamed
and the sentence keeps describing the old one, confidently, because prose has no
compiler. The reader who is hurt is the one who trusts it.

Two scoping decisions worth knowing before you add a code sample:

- Options are only checked on lines where `trueai` appears **followed by
  whitespace**. A first version looked at every long option in the file and
  reported `--all-extras` and `--build-arg`, which belong to pip and docker, and
  an allowlist of other tools' flags would rot faster than the documentation it
  guards. `docker build -t trueai-core:audit .` is not an invocation.
- A command is resolved against the tree rather than by longest prefix. A group
  takes no positional arguments, so the word after one has to be a subcommand —
  otherwise a misspelt subcommand falls back to bare `trueai` and the typo
  becomes invisible.

  A corollary worth knowing: you cannot write a deliberately wrong command in
  backticks as an illustration, because the gate cannot tell one from a real one
  and neither can a reader skimming for something to copy.

If you add a page under `docs/`, link it from somewhere. An unread document is
one that quietly goes stale, and the gate says so.
