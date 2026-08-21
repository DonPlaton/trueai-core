# Policies

Policies assign operational actions after scanning. They never alter detector output.

## Actions

- `IGNORE`: retain in the raw report but take no operational action.
- `REPORT`: show and serialize normally.
- `REVIEW`: require a person to decide.
- `REMOVE`: create a remediation only when the finding is marked predictably removable.
- `PRESERVE`: explicitly protect evidence or provenance.
- `ERROR`: count a policy violation and use CLI exit code 2.

`REMOVE` is rejected during policy validation for `c2pa_provenance` and `provider_watermark`.
Authenticated/provider watermark provenance is also blocked in the remediation planner even if a
malformed external policy bypasses normal construction.

## Built-in profiles

- `audit`: report all findings and preserve provenance.
- `safe-clean`: remove explicit attribution/generator residue; review Unicode and personal metadata.
- `privacy`: remove ordinary document/image/personal metadata; preserve provenance.
- `client-delivery`: remove predictable ordinary metadata and explicit attribution, review tooling
  and Git residue, report heuristics, preserve provenance.
- `strict`: treat explicit attribution, metadata, and security residue as policy errors.

Custom YAML accepts `policy`, optional `default_action`, and `rules`. Public category names are
documented in `FindingCategory` and validated by Pydantic.

