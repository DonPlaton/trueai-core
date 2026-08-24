# Interoperable exports: PROV, in-toto/DSSE, C2PA

A record only readable by TrueAI is a record nobody else can act on. Three
standards already describe parts of what a Human Contribution Record says, and
TrueAI exports to all three.

None of them expresses contribution *strength*, evidence status, or the
difference between a declaration and a machine fact. Those are exactly the
distinctions the record exists to keep, so they are not squeezed into a
standard's vocabulary where they would arrive looking like something they are
not.

Every exporter states what it left behind:

```python
from trueai.core.interop import unmapped_concepts

for item in unmapped_concepts("prov"):
    print(item.concept, "—", item.reason)
```

```console
$ trueai attestations export record.process.json --to prov
$ trueai attestations export record.process.json --to dsse --signing-key alice.key
$ trueai attestations export record.process.json --to c2pa
$ trueai attestations interop record.process.json
```

The export writes to stdout or `--output`; the unmapped concepts go to stderr, so
a pipeline that captures only stdout still gets a clean document while the
operator still sees the gaps.

## W3C PROV

`to_prov()` emits PROV-JSON. The derivation graph maps cleanly, because a graph
of agents, activities, and entities is what PROV was designed for:

| TrueAI | PROV |
|---|---|
| `Actor` (person / organization) | `prov:Person` / `prov:Organization` agent |
| `Actor` (AI system / automation) | `prov:SoftwareAgent` agent |
| `Activity` | `prov:Activity`, with `startTime` / `endTime` |
| `Activity.actor_ids` | `wasAssociatedWith` |
| `Activity.input_binding_ids` | `used` |
| `Activity.output_binding_ids` | `wasGeneratedBy` |
| `ArtifactBinding` | `prov:Entity` with its digest |
| `ContributionClaim` | `wasAttributedTo`, with the strength under `trueai:` |

Everything TrueAI adds sits under the `trueai:` prefix. A `prov:`-prefixed term
that PROV does not define would read as a standard term, and a consumer would
have no way to tell the difference. `wasAttributedTo` deliberately carries no
strength of its own: the level, evidence status, claim type, and AI autonomy
travel as `trueai:` properties beside it.

Superseded activities stay in the graph, flagged. A record that hides rejected
attempts describes a process that did not happen.

**Not carried:** contribution level, evidence status, claim type, and the
standing limitations — PROV has no field for what a record does not establish, so
a PROV export consumed on its own is missing them. They are attached as
`trueai:limitations` and `trueai:unmapped`, which a PROV consumer may ignore.

## in-toto / DSSE

`to_in_toto_statement()` wraps the record as a Statement about its subject's
digest, under predicate type `https://trueai.dev/attestation/process/v0.1`.
`to_dsse_envelope()` puts it in a DSSE envelope.

The envelope's signatures are **new**. A TrueAI signature covers the record's
canonical bytes; a DSSE signature covers the pre-authentication encoding
`DSSEv1 <len> <type> <len> <payload>`. Those are different bytes, so the record's
signatures are never copied into the envelope — a signature that does not verify
over what it appears to cover is worse than no signature. Pass a
`SigningProvider` to sign the envelope, or accept an unsigned one, which is a
legitimate thing to produce and a useless thing to trust.

The predicate excludes the record's own signatures for the same reason.

**Not carried:** per-role signature meaning. A DSSE envelope has a flat signature
list; claimant, reviewer, and assessor mean different things and the envelope
cannot say which is which. Verify a record as a record; use the envelope to hand
it to an in-toto-shaped consumer.

## C2PA

`to_c2pa_assertions()` returns assertion data a manifest-signing tool can embed.
**TrueAI does not sign, embed, or produce C2PA manifests** — that needs a C2PA
implementation, and inventing one here would produce manifests nothing else
accepts.

Activities become `c2pa.actions`, conservatively:

| AI autonomy | `digitalSourceType` |
|---|---|
| `none` | *(omitted)* |
| `assistive`, `proposal` | `compositeWithTrainedAlgorithmicMedia` |
| `delegated_execution`, `autonomous_with_review` | `trainedAlgorithmicMedia` |

A human acting on completion suggestions is not a machine-produced asset, which
is why the middle two levels get the composite code. Purely human work gets no
code at all: absence is the honest output, and a wrong code is worse than none.

Superseded attempts produce no action. C2PA assertions describe the delivered
bytes, and a discarded attempt is not in them. Pseudonymous actors are never
named in the `stds.schema-org.CreativeWork` assertion, and the field is `creator`
— participation — not `author`.

**Not carried:** every dimension except execution, contribution level, evidence
status, claim type, and the assurance level. A C2PA manifest's own signature says
nothing about how well the process was evidenced.

## The rule

Where a standard can express something faithfully, TrueAI uses the standard's
term. Where it cannot, TrueAI keeps its own term, marks it as its own, and says
in the export itself that the standard could not carry it.

The failure mode this guards against is quiet: an export that drops the evidence
status turns "alice declared she originated this" into "alice originated this",
and nothing in the output shows that anything was lost.
