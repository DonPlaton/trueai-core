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

Built-in profiles report or review ordinary `media_metadata`; they do not strip titles or generic
comments merely because they exist. `generator_metadata`, `personal_metadata`, and literal
`explicit_ai_attribution` inside WAV/MP3/FLAC tags follow their normal category rules and can be
removed by the surgical media cleaner. M4A, MP4/MOV, and WebM remain inspection-only.

Custom YAML accepts `policy`, optional `default_action`, and `rules`. Public category names are
documented in `FindingCategory` and validated by Pydantic.

## Signed enterprise bundles

An enterprise bundle carries a validated PolicyProfile, an exact finding-ID baseline, finite
suppressions, and finite action exceptions in one content-addressed TPB1 document. Applying the
bundle requires an Ed25519 issuer public key. Bundle identity, signature, issue time, and expiry all
fail closed.

~~~bash
trueai policies bundle-create strict --output client-policy.json \\
  --signing-key issuer-private.pem --issuer "Example Security" \\
  --controls controls.yaml --baseline-report reviewed-report.json

trueai policies bundle-verify client-policy.json --public-key issuer-public.pem
trueai scan deliverable --policy-bundle client-policy.json --policy-key issuer-public.pem
~~~

Control authoring YAML is deliberately small:

~~~yaml
suppressions:
  - id: approved.legacy-generator
    selector:
      category: explicit_ai_attribution
      artifact_glob: "docs/**"
    reason: Reviewed legacy disclosure retained for this delivery.
    approved_by: security@example.com
    expires_at: 2026-12-01T00:00:00Z

exceptions:
  - id: remove.reviewed-generator
    selector:
      category: generator_metadata
    action: remove
    reason: Approved predictable metadata cleanup.
    approved_by: delivery@example.com
    expires_at: 2026-12-01T00:00:00Z
~~~

Controls never delete findings from the report. They change only operational policy decisions;
every applied or expired control is recorded in policy_audit. Baselines match exact immutable
finding IDs, not broad text patterns. Conflicting active exceptions fail closed. C2PA provenance
and provider-watermark findings remain PRESERVE even if a baseline, suppression, or exception
matches them.

trueai policies bundle-schema emits the independent schema 0.1 contract. A bundle may live for at
most 366 days, and no contained control may outlive it.
