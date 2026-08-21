# Interpreting TrueAI findings

Use both `confidence_type` and `provenance_class`.

| Evidence | Correct interpretation |
|---|---|
| `DETERMINISTIC` + `ATTRIBUTION` | Literal attribution text exists; no independent authorship verification. |
| `DETERMINISTIC` + `METADATA` | A standard property/chunk/field exists. |
| `DETERMINISTIC` + `PROVENANCE_METADATA` | A compatible marker exists but is not authenticated. |
| `VERIFIED` + `AUTHENTICATED_PROVENANCE` | An official/public verifier authenticated a claim. |
| `VERIFIED` + `PROVIDER_WATERMARK` | An official provider mechanism verified its signal. |
| `HEURISTIC` + `HEURISTIC` | Measured style/structure only; never proof of origin. |

Never turn a count or heuristic score into a binary “AI-generated” conclusion. Quote the finding
title, evidence field/code point/location, confidence class, and remediation status. Mention false-
positive context for typography, ZWJ/ZWNJ, hidden SVG/HTML elements, and tracked tool settings.

Provider adapters in v0.1 return unavailable/unsupported. C2PA support is marker-only. Preserve both.

