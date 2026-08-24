# Human Contribution Records: claim taxonomy and threat model

A TrueAI audit certificate (`TAI1-…`) says what a scanner observed in exact bytes.
A TrueAI process attestation (`TAIP1-…`) says who originated, framed, decided,
executed, validated, integrated, and took responsibility for the work that
produced those bytes — and how strongly each of those claims is supported.

They are separate contracts with separate schemas, separate identifier prefixes,
and separate verification results, because they answer different questions and
neither can substitute for the other. Finding no AI residue cannot populate
`execution=human`. Finding a provider marker cannot erase a documented human
origination claim.

Neither proves that a human exclusively authored an artifact, that an idea is
objectively original, or that AI was never used.

## What this record refuses to measure

Human contribution is not proportional to typing volume. A hundred hours of minor
prompt tuning can contribute less than one previously unseen causal insight
expressed in two sentences. These are therefore rejected as primary metrics:

| Rejected metric | Why |
|---|---|
| Elapsed time | Measures effort, not creative or causal importance. |
| Prompt count or length | Rewards verbosity and is trivial to game. |
| Edit count | Penalises a correct first insight and rewards churn. |
| Changed-line percentage | Confuses mechanical execution with design responsibility. |
| Watermark presence | Says nothing about the value of a human decision. |
| A single "human percentage" | Hides which stages were human-controlled and manufactures false precision. |

Any of them may be *attached* as a supporting fact when the user chooses. None may
determine a contribution level automatically. The module deliberately contains no
function that produces an aggregate score, and a test asserts that no such name
exists.

## The three claim types

Freezing these is the point of the taxonomy. The same sentence about the same
dimension means something different depending on which type it carries, and
collapsing them lets a valid signature launder an opinion into a fact.

| `claim_type` | What it is | What verification can establish |
|---|---|---|
| `machine_fact` | Derived from bound artifacts or receipts | A verifier can recompute it. Must reference the evidence; a `machine_fact` with no evidence is refused at construction. |
| `declaration` | Asserted by an identified actor who signed it | Who said it, and that they stood behind these exact bytes. Not that it is true. |
| `assessment` | A judgement issued under a named rubric | That a named assessor, applying a named rubric version, reached this result. |

A `declaration` may not carry `evidence_status=independently_assessed`. Assessing
your own claim is not independent assessment, and the model refuses it rather than
relying on reviewers to notice.

## The contribution vector

Eight independent dimensions. They are not comparable to each other and must not
be averaged.

| Dimension | Question answered |
|---|---|
| `origination` | Who introduced the central insight, hypothesis, direction, or invention? |
| `framing` | Who turned the idea into constraints, requirements, and success criteria? |
| `decision_control` | Who compared alternatives and made the consequential choices? |
| `execution` | Who or what produced the concrete prose, code, design, data, or media? |
| `validation` | Who tested claims against reality rather than accepting generation? |
| `integration` | Who reconciled components and adapted the result to its context? |
| `accountability` | Which person or organization accepts responsibility? |
| `evidence_quality` | How strongly are the preceding claims supported? |

Each claim carries a **level** (`not_claimed`, `supporting`, `substantial`,
`primary`, `originating_or_controlling`) and, separately, an **evidence status**
(`self_declared`, `artifact_correlated`, `countersigned`,
`independently_assessed`, `cryptographically_verified`).

Level and evidence status are orthogonal on purpose. A strong claim with weak
support is a common and legitimate state; the record says so instead of resolving
the tension silently in either direction.

### AI autonomy is a per-stage property

`ai_autonomy` (`none`, `assistive`, `proposal`, `delegated_execution`,
`autonomous_with_review`) attaches to a stage, not to the record. A faithful
record of the short-insight case reads:

```text
origination        alice      originating_or_controlling   ai_autonomy=none
framing            alice      primary                      ai_autonomy=assistive
execution          assistant  primary                      ai_autonomy=delegated_execution
validation         alice      primary                      ai_autonomy=none
accountability     alice      originating_or_controlling   ai_autonomy=none
```

Describing that result as "almost entirely AI" because a model emitted most tokens
would be false. So would describing it as "human-authored". The stage split is the
answer.

## Threat model

Each control below is implemented, not planned.

| Threat | Control |
|---|---|
| Fabricated or omitted events | Typed claim provenance; `superseded` activities keep rejected attempts representable; missing dimensions stay visibly `not_claimed`. |
| A changed artifact paired with an old record | `subject_sha256` binding, checked at verification. |
| A changed claim paired with an old signature | The content identifier covers every claim; signatures cover the canonical record minus signatures. |
| Backdated notes, replayed receipts | Evidence carries digests, issuer, and collection method; trusted timestamps are `TRUST-01`, still open. |
| Prompt spam inflating apparent effort | Prompt and edit counts cannot set a level; only claim type and evidence status do. |
| One actor split into many pseudonyms | `Actor.pseudonymous` is explicit, and a pseudonymous actor may not also carry a directory identifier. |
| Model output presented as a human note | `ActorKind.AI_SYSTEM` and per-stage `ai_autonomy` are required to describe the stage honestly. |
| An issuer signing its own novelty claim | A `declaration` cannot claim independent assessment; `authenticated_declaration` is the ceiling for a self-signed record. |
| Hidden contradictory evidence | Dissent is a field on assessments and is surfaced by verification as `unresolved_dissent`. |
| Trade-secret or personal-data leakage | Evidence is referenced by hash. Private evidence may not carry a locator; committed evidence carries only a commitment. |
| A verifier confusing integrity with truth | Verification returns independent results, and the only aggregate property is named `authenticated_declaration`. |
| Coercive surveillance, education reduced to a score | No aggregate score exists to demand; `not_claimed` is a valid, first-class value. |

Completeness remains a declared scope. No technical system can prove that every
offline human action was recorded, and every record says so.

## Verification returns results, not a badge

```python
from trueai.core.attestation import load_attestation, verify_attestation

record = load_attestation("deliverable.process.json")
result = verify_attestation(
    record,
    artifact="deliverable.pdf",
    public_keys={"alice": "alice.pub"},
    supported_profiles=frozenset({"research"}),
)
```

`AttestationVerification` reports schema validity, content-ID validity, artifact
binding, evidence-binding completeness, each signature role separately, expiry,
evaluation-profile support, disclosed-evidence consistency, unresolved dissent,
limitation acknowledgement, and the strongest evidence status anywhere in the
record.

The single derived property is `authenticated_declaration`: an identified claimant
signed this record over these bytes and it has not expired. It is named that way so
a caller cannot present it as a verified contribution. A user interface should say
"authenticated declaration", never "verified human contribution", unless an
applicable assessor actually evaluated the semantic claim.

## Privacy

Creation and verification are local and network-free. Evidence is referenced by
digest, never copied into the record. Raw prompts, proprietary source documents,
credentials, personal identifiers, and confidential feedback stay private by
default:

- `public` — the reference and its locator travel with the record;
- `private` — the digest travels, the material does not;
- `committed` — a commitment travels so the material can be revealed and checked
  against it later;
- `omitted` — deliberately left out, with a stated reason and no digest.

A locator on private or committed evidence is refused at construction, because it
would disclose exactly what the status says is withheld.

## Standing limitations

Every record carries these four, and a record missing any of them is invalid:

- `completeness_is_declared`
- `no_exclusive_authorship`
- `signature_is_not_truth`
- `no_aggregate_score`

Each names something a reader could otherwise wrongly infer from a valid
signature. Every human-readable summary must repeat the applicable ones.

## What is not implemented yet

The backlog items `PROC-04` through `PROC-12` cover the CLI and Python workflows,
local evidence adapters, deterministic redaction, trust primitives shared with
certificates, versioned evaluation profiles, presentation rules, adversarial
tests, standards mapping, and consented design-partner pilots. The schema is not
called stable until at least two pilots have exposed rubric disagreements.
