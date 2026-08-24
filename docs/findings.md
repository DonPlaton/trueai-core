# Finding semantics

A `Finding` is one explainable observation from one detector. It contains a stable fingerprint,
artifact path, category, evidence source, location, confidence semantics, provenance class, and an
optional remediation reference.

## Confidence classes

- `DETERMINISTIC`: exact parser/rule observation. Numeric confidence describes rule/parser
  specificity, not probability of AI authorship.
- `VERIFIED`: an authenticated public verifier validated provenance. v0.1 emits no provider
  watermark finding with this class.
- `PROBABILISTIC`: a calibrated statistical model result. No such model ships in core v0.1.
- `HEURISTIC`: an interpretable style or structure score. It is never provenance.

## Provenance classes

- `NONE`: no provenance relationship.
- `ATTRIBUTION`: literal human/tool attribution text.
- `METADATA`: ordinary workflow or creator metadata.
- `PROVENANCE_METADATA`: a provenance-compatible marker that has not been authenticated.
- `AUTHENTICATED_PROVENANCE`: a verified signed claim.
- `PROVIDER_WATERMARK`: a provider signal verified through an official mechanism.
- `HEURISTIC`: measurement or style inference only.

`generator_metadata`, `explicit_ai_attribution`, `c2pa_provenance`, `provider_watermark`,
`stylistic_signal`, and `design_style_signal` are separate categories by design. Consumers must not
collapse them into a single “AI detected” result.

Authenticated C2PA verification is serialized separately in
`ScanReport.provenance_verifications`. A marker finding remains
`PROVENANCE_METADATA`; an explicit verifier result may independently be `trusted`, `valid`,
`invalid`, `no_manifest`, unsupported, or unavailable. This prevents a literal marker from
being relabelled as cryptographic proof.

Enterprise baselines, suppressions, and exceptions also leave `findings` untouched. They alter
only `policy_decisions`, and `policy_audit` records the selector, approver, reason, expiry, and
selected action.

`media_metadata` records ordinary audio/video container fields. A field named encoder, software,
writing application, or muxing application is instead classified as `generator_metadata`; author,
artist, composer, owner, and copyright fields use `personal_metadata`. Literal provider attribution
inside a media tag is a second `explicit_ai_attribution` finding rather than an inferred claim about
the media stream. WAV, MP3, and FLAC findings carry an exact byte location and value digest when a
format-specific cleaner can remove them; other media-container findings remain non-removable.

## Locations and evidence

Text detectors provide character offsets and one-based line/column values. Binary/container
detectors use byte offsets or OPC package parts. Evidence is structured JSON and should contain
only the minimum material required to explain and safely re-identify the observation.

Finding IDs are SHA-256-derived fingerprints over detector ID, artifact path, category, provider,
evidence, and location. They are stable for identical evidence but are not global content IDs.
