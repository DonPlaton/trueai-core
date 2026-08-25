# Evaluation profiles and Process Assurance Level

Two questions get asked about a Human Contribution Record, and they are not the
same question:

1. **How strong is the evidence and governance behind this record?** — the
   Process Assurance Level, PAL-0 to PAL-4.
2. **Does this record meet the expectations of *my* context?** — an evaluation
   profile.

Neither answers "how human is this work". Nothing in TrueAI answers that,
because the question has no operational definition that survives contact with a
real project.

## Process Assurance Level

PAL is derived from what verification established, never from what the record
claims about itself. A record asserting the strongest claims in every dimension
with nothing behind them stops at PAL-1.

The delivered artifact must be supplied during verification. A signed record
that names a digest but is evaluated without the corresponding artifact remains
PAL-0: signing a claimed digest is not proof that the recipient received those
bytes.

| Level | Name | What it establishes |
|---|---|---|
| PAL-0 | `unsubstantiated` | The record is missing, invalid, or not bound to the delivered artifact. |
| PAL-1 | `declared` | An identified claimant signed a structured declaration bound to the artifact. |
| PAL-2 | `evidenced` | Material claims reference artifact-correlated evidence, and AI roles are disclosed. |
| PAL-3 | `reviewed` | Consequential decisions and validation are evidenced and countersigned by an identified reviewer. |
| PAL-4 | `independently_assured` | An independent assessor applied a named profile against verified evidence, under organization identity, finite validity, and a trusted timestamp. |

`AssuranceAssessment` carries `reasons` for the level reached and
`next_level_requires` for what would raise it. That makes the result actionable
rather than a grade: a team at PAL-2 can read exactly which countersignature is
missing.

PAL is orthogonal to how much of the work a machine did. A record describing
delegated AI execution, with reviewed decisions and countersigned validation,
outranks a purely human record that nobody corroborated. This is deliberate.
Assurance measures whether the account can be checked, not whether the account
flatters the human.

Three conditions are worth naming because they block the level rather than lower
a score:

- **Undisclosed machine work.** A record describing delegated execution with no
  AI actor listed has left the reader guessing, and cannot reach PAL-2.
- **Unresolved dissent.** A countersigner who recorded disagreement blocks
  PAL-3. A dispute is not resolved by outranking it.
- **Falsified disclosure.** Bytes offered under a published commitment that do
  not hash to it block PAL-2. Offering evidence that fails its own commitment is
  a worse position than never having disclosed.
- **Role aliasing.** A claimant cannot raise the record to PAL-3 by signing again
  under the reviewer role. PAL-4 requires the actor named by the evaluation to
  sign as assessor, and that actor must be distinct from every claimant and
  reviewer.
- **Unrecognised rubric.** Profile support must be stated by the verifier. An
  omitted support list is `not checked`, never implicit acceptance of an
  arbitrary profile name.

## Evaluation profiles

A profile is one context's versioned, inspectable opinion about which dimensions
matter and how strongly. Weights and thresholds are fields on the model, not
constants buried in code, because a profile that will not show its weights is
asking to be trusted rather than checked.

```python
from trueai.core.evaluation import evaluate_with_profile, get_profile

result = evaluate_with_profile(record, verification, get_profile("research"))
print(result.statement)
print(result.weights)  # what produced the answer
print(result.unmet_requirements)
```

Five profiles ship with TrueAI:

| Profile | What it weighs | Minimum assurance |
|---|---|---|
| `research` | Origination, decision control, validation, accountability. Execution assistance is disclosed, not penalised. | PAL-2 |
| `software-delivery` | Framing, architecture decisions, review, testing, accountable release. Delegated execution is expected; unreviewed delegated execution is not. | PAL-3 |
| `creative-work` | Concept, selection, composition, transformation, rights. | PAL-1 |
| `education` | Execution must be the learner's own: delegated and autonomous execution are refused for that dimension. | PAL-1 |
| `regulated-enterprise` | Every material dimension evidenced, reviewed, and independently assessed. | PAL-4 |

The field that carries the answer is `meets_review_requirements`, and the name is
load-bearing. It is a policy result about process evidence. It is not an
authorship determination, an originality finding, or a statement about whether
the claimant is honest, and it must not be renamed into one downstream.

### Profiles are allowed to disagree

The same record can meet `software-delivery` and fail `education`, because the
delegated execution a delivery team expects is exactly what an assignment about
demonstrated understanding forbids. Neither profile is wrong. They encode
different rules, they say which rule was applied, and they name their version so
a result can be re-derived later.

A profile refusing an AI autonomy level for a dimension produces an unmet
requirement worded as a rule — "this profile does not permit delegated_execution
for this dimension" — not as an accusation. TrueAI has no way to know whether a
learner was dishonest, and outputs that imply otherwise would be inventing
evidence.

### Unclaimed dimensions

An unclaimed dimension the profile does not require is satisfied and says so.
An unclaimed dimension the profile does require is unmet and says which claim is
missing. Nothing is inferred from silence in either direction.

## Presentation

Every surface renders the same three things and never merges them:

- **Stage summary** — `stage_summary()` produces phrases like
  "human-originated, AI-executed, human-validated". Each part names a stage and
  who carried it. No combination of stage claims establishes authorship, and the
  word never appears in the output.
- **Assurance level** — the PAL, with its meaning spelled out in the same
  breath, so a bare "PAL-3" cannot travel alone.
- **Profile result** — the profile id, version, weights, and unmet requirements.

```console
$ trueai attestations evaluate record.process.json --artifact deliverable.pdf \
    --profile software-delivery \
    --public-key alice=alice.pub --public-key bob=bob.pub
$ trueai attestations evaluate record.process.json --artifact deliverable.pdf \
    --format summary
$ trueai attestations profiles
```

`--format` selects the surface:

| Format | For |
|---|---|
| `terminal` | A table of dimensions, weights, and what met the profile. |
| `json` | The full `ProfileResult`, weights included. |
| `summary` | `portable_summary()`: the compact text a recipient reads without training. Limitations are part of it, not a footnote someone can crop. |
| `sarif-properties` | The property bag a CI job merges into a SARIF run. |

Exit code 0 means the profile's requirements were met; exit code 1 means review
is required. Exit code 1 is not a failing grade and not an allegation.

### CI

`trueai scan --attestation record.process.json --format sarif` puts the record's
verified facts into the SARIF run's property bag. Detection results are
untouched: an attestation never becomes a finding, a severity, or a rule.

The property keys name what was established rather than what it means —
`trueaiAttestationAuthenticatedDeclaration`,
`trueaiAttestationOrganizationallyAttributed`,
`trueaiProcessAssuranceLevel`, `trueaiProcessStageSummary`,
`trueaiAttestationLimitations` — so a dashboard has nothing to render as an
authorship badge. A scan supplies no public keys, because deciding whom to trust
is not a scanner's decision; the property bag reports the signature as
unverified rather than implying it passed.

## What this deliberately does not do

- No overall percentage, and no way to derive one. `no_aggregate_score` is a
  standing limitation on every record, and the summaries assert it in words.
- No cross-profile comparison. Two profiles produce two answers about two
  different questions, and a ranking between them would be meaningless.
- No originality assessment. When a record carries no assessor evaluation, the
  summary says "Originality: not independently assessed" rather than staying
  silent and letting a reader assume.
- No stability claim for the profiles themselves. The rubric is version `0.1`.
  `PROC-12` holds that consented design-partner pilots must expose rubric
  disagreements before these profiles are presented as a stable product feature.
