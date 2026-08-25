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

## Paths in a report

Every path a report contains is relative, and the root of a directory scan is
reported as `.`.

That is a deliberate trade and it costs something, so it is written down here
rather than discovered. Relative paths make two scans of the same corpus compare
byte for byte, which is what the determinism check and the reproducibility of an
audit record depend on, and they keep the operator's directory layout — often the
client's name — out of a document that gets sent to somebody else. What they cost
is that a report read on its own does not say which directory produced it. A
consumer that needs to record the target should record it alongside the report,
where it is their decision to disclose rather than the scanner's.

A single-file scan reports the file's own name for the same reason, and binds it
by SHA-256, which identifies the bytes without identifying the machine.

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

## What TrueAI can remove

`trueai/core/remediation_catalog.py` declares every removal operation: what it
takes out, which format it applies to, its safety class, and **why that class
and not the neighbouring one**.

Until it existed, safety was a prefix match on the identifier:

```python
if remediation_id.startswith(("docx.", "pptx.", "xlsx.", "pdf.", "image.", "media.")):
    return RemediationSafety.SAFE_METADATA
```

That works right up until somebody adds a format and does not add its prefix.
`odf.remove-metadata-field` was classified `predictable_content` for as long as
ODF support existed — not because anybody decided ODF metadata was content, but
because `"odf."` was never added to a tuple. `meta.xml` is a separate part
exactly like `docProps`, so removing a field from it cannot change what a reader
sees, and it is now `safe_metadata` with that sentence attached. It happened to
fail safe, which is why nothing noticed; the next such accident might not.

The `why` field is what forces the comparison. Writing "meta.xml is a separate
part, exactly like docProps" is what makes a wrong classification visible.

### Every operation needs a fixture

Two gates in `tests/unit/test_remediation_catalog.py`:

- the catalogue and the code must name the same operations **in both
  directions**, so a new removable field cannot ship uncatalogued and a stale
  entry cannot survive a removal;
- every catalogued operation must be named by a test, which is what stops a
  removable field shipping without a regression fixture.

The second gate found six operations the suite exercised without naming —
`docx.remove-custom-property`, `xlsx.remove-metadata-field`,
`xlsx.remove-custom-property`, `pptx.remove-metadata-field`,
`svg.remove-generator-comment`, `html.remove-attribution-comment`. A privacy-run
over a workbook removes metadata whether or not any test says so; what was
missing was the ability to *answer the question*.
`tests/unit/test_removable_field_fixtures.py` pins each one specifically: that it
is planned, that it is applied, and that the integrity gate agrees.

An identifier the catalogue does not know falls back to the strictest class in
the planner — a planner is not the place to fail a scan — while `safety_for()`
raises, because a caller that can handle the error should not be handed a guess.
