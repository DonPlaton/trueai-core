# Indicator Handling and Non-Evasion Boundary

## Purpose

TrueAI helps owners inspect and safely prepare their own artifacts. It removes only traces whose
location, meaning, transformation, and integrity effect can be described and verified. It does not
optimize artifacts to deceive AI-authorship detectors, defeat provider watermarks, or invalidate
authenticated provenance while concealing that change.

This boundary is both a safety rule and a product-quality rule. A cleaner cannot honestly certify
an operation that has no public verifier, no stable success criterion, or an unknown effect on the
artifact's meaning.

## Decision matrix

| Evidence class | Examples | TrueAI behavior | Remediation eligibility |
|---|---|---|---|
| Deterministic ordinary residue | generator metadata, exact attribution text, comments, safe invisible formatting artifacts | inspect, explain, plan, clean, verify, and rescan | Eligible only through an exact format-specific remediation contract |
| Context-dependent text or structure | ZWJ/ZWNJ, variation selectors, hidden SVG elements, document revisions | explain context and require review | Eligible only when the transformation is semantically safe and explicitly selected |
| Authenticated provenance | C2PA manifests and Content Credentials | detect markers, verify explicitly, report signature and trust separately, preserve | Not eligible for removal or forgery |
| Provider statistical watermark | SynthID-style or provider-specific signals | use an official verifier if one becomes public; otherwise report verification unavailable | Not eligible for defeat, reverse engineering, or suppression |
| Heuristic/style signal | stylometry, design regularity, repeated structures | expose measurements and uncertainty; never claim authorship | Not a removal target; may inform ordinary editorial review |
| Third-party AI-detector label | an external classifier score or verdict | evaluate calibration and false positives in a controlled benchmark | Must not become an optimization objective for artifact mutation |

## Why hidden-watermark defeat is not a TrueAI feature

1. C2PA is authenticated provenance, not ordinary metadata. Editing or deleting its assertions can
   destroy verifiable history; forging replacement claims would misrepresent provenance.
2. Provider statistical watermarks generally lack a public, stable local verification contract.
   Without one, a tool cannot prove that a signal was removed rather than merely missed.
3. Optimizing repeatedly against an AI detector is an evasion loop. It produces a misleading
   "passed" result tied to one model version and undermines certificates and audit trails.
4. A transformation intended to hide provenance can alter meaning, media quality, or evidentiary
   value in ways that TrueAI's semantic-integrity contract cannot justify.
5. False negatives are not proof of human authorship. Product language must never promote them as
   such.

## Permitted implementation plan

### 1. Complete remediation contracts for deterministic residue

For every removable finding, define the exact source element, permitted mutation, protected fields,
stale-plan binding, output behavior, and format-specific integrity invariant. Add positive,
false-positive, malformed-input, overlap, and provenance-preservation fixtures before registering a
cleaner.

Priority coverage is ordinary metadata and explicit tooling residue in already supported formats,
followed by complex media containers only after executable stream and timing invariants exist.

### 2. Add a quality-oriented editorial workflow

Provide optional review suggestions based on user-selected goals such as clarity, factual support,
terminology consistency, accessibility, citation quality, and audience fit. Preserve tracked change
information in the audit record and require the user to approve meaning-changing edits.

This workflow must not query a detector repeatedly, target a detector score, promise that text will
look human-authored, or remove authenticated provenance. Its success criteria are editorial quality
and semantic integrity, not classifier evasion.

### 3. Build a detector-evaluation laboratory, not an evasion optimizer

Evaluate external and optional TrueAI models on licensed, consented corpora. Record detector
version, domain, threshold, calibration, false-positive rate, false-negative rate, abstentions, and
confidence intervals. Keep evaluation read-only: it may compare labelled samples and generate
reports, but it must not search for transformations that make individual artifacts pass.

The laboratory should support reproducible benchmark manifests and signed result summaries. It
must stay outside normal local scanning and outside certificate issuance criteria unless the exact
model and threshold are part of the declared scope.

### 4. Keep provenance verification explicit

Integrate only official/public verification mechanisms. Network verification must require explicit
operator consent and pass through `NetworkPolicy`; offline scanning remains the default. Reports
must distinguish marker presence, cryptographic validity, signer trust, and verifier availability.

### 5. Rescan published bytes and issue narrowly scoped certificates

Every cleanup output is rescanned. A certificate may say that the recorded TrueAI version and
detector scope found no scoped indicator in the exact output bytes. It must list limitations,
protected provenance findings, incomplete or unavailable verification, policy overrides, expiry,
and signature state.

The certificate must never say that the artifact is human-authored, that no AI was used, or that a
hidden watermark was successfully defeated.

### 6. Preserve evidence and user intent

Default to a new output file, bind plans to source hashes and finding identities, preserve originals
or backups, and provide a machine-readable diff of changed fields. Refuse publication whenever the
integrity invariant fails or the planned operation overlaps protected provenance.

## Acceptance criteria for future indicator-remediation work

A new remediation is eligible for TrueAI Core only when all of the following are true:

- the finding is deterministic and identifies an exact removable element;
- removal is lawful and authorized for the selected artifact;
- the operation is not intended to defeat authentication, watermarking, or a detector;
- protected provenance is independently recognized and preserved;
- the cleaner is surgical and bounded on hostile input;
- the source, plan, and output are cryptographically bound;
- visible or logical content has an executable integrity invariant;
- unchanged, malformed, ambiguous, and stale inputs fail closed;
- post-clean rescanning reports residual findings without suppression;
- documentation states exactly what changed and what was not verified.

If any condition is absent, TrueAI reports the finding and returns `NOT_VERIFIABLE` or refuses the
operation instead of claiming successful removal.
