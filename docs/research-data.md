# Collecting a labelled corpus: the rules, before there is data

`trueai.research.corpus` states them as constructors that refuse, not as guidance
that advises. Governance written as prose gets read once and then contradicted by
whoever is actually collecting the data, usually without anyone noticing.

A `CorpusManifest` cannot be built without a `CorpusPolicy`. That ordering is the
point: collected first and governed afterwards is what this exists to prevent.

TrueAI ships **no default policy**, for the same reason it ships no default trust
store. What may be collected is not a decision a library gets to make for an
operator.

## Consent is not a license

The distinction the whole module turns on: the person who hands over a document
is frequently not the person who owns it.

- **`ConsentRecord`** — a person agreeing that their work may be used. Scoped to
  named purposes, with a grant time, an optional expiry, and a
  `withdrawal_contact`, because consent nobody can revoke is not consent.
- **`LicenseTerms`** — the rights holder permitting the use, with `permits` and
  the `obligations` that travel with the sample so share-alike is not discovered
  at publication time.

A sample needs both. Either one missing refuses it, and both failures are
reported together so an operator fixing one sees the other rather than
discovering it on the next submission.

Consent to one purpose does not stretch to another, which is why a policy names
exactly one `purpose`: a policy covering several would let consent given for the
narrow one authorise the broad one.

### Withdrawal reaches backwards

The requirement most easily written down and least often implemented.
`withdraw_consent()` marks the record and returns **every sample collected under
it**, and a subsequent `audit_corpus()` lists them under `must_delete` and reports
the corpus as unusable until they are gone.

It does not remove the rows. Deleting the data is a filesystem operation with its
own obligations under the retention rule, and a function that quietly dropped
rows from a manifest would let an operator believe data was gone when only its
record was.

## Domain balance

`DomainBalance.targets` must be written down in advance and sum to 1 — a target
chosen after the data arrives is a description of whatever arrived. A sample in a
domain the plan does not name is refused rather than absorbed.

A corpus that is ninety percent one domain produces a domain detector wearing an
AI-detector label, and it will be most confident exactly where it is least
entitled to be.

Imbalance is **reported, not blocking**: `CorpusAudit.imbalanced` gives the actual
and target share for every domain outside tolerance, and `usable` stays true. A
corpus can be imbalanced on purpose; what it must not be is imbalanced quietly.

## Contamination control

Compared by **content digest, never by path**. The same document under two names
in two splits is one document, and an evaluation number computed over it is a
memory test.

- Admission refuses a sample whose content is already in a different split.
- `admit_all()` judges each candidate against the ones already accepted from the
  same batch, so two copies cannot slip past each other.
- `audit_corpus()` checks again, because samples can arrive by another route.
- `holdout_only_sources` reserves a source for the held-out split, so a model
  cannot learn a source-specific shortcut and then be scored on it.
- `compare_by_content_digest=False` is refused at construction: without digests
  it compares paths, and a renamed copy would pass.

Exact digests miss a reformatted copy. `near_duplicate_method` records how that
is handled, or records that it is not.

## Retention

`RetentionRule` sets `retain_days` and a `deletion_method` — a rule with no
mechanism is a sentence in a policy document. Indefinite retention is expressed
as `retain_days=None`, which has to be written rather than arrived at by nobody
choosing.

A sample already past its retention period is refused on arrival, and one that
ages out is listed in `CorpusAudit.overdue`.

`withdrawal_requires_derivative_deletion` records whether withdrawing consent
obliges deletion of models derived from the sample or only of the sample itself.
Both are defensible; leaving it unstated is not.

## What blocks, and what only reports

`CorpusAudit.usable` is false when there is a deletion obligation, contamination,
a leaked held-out source, or an overdue sample — each makes a number meaningless
or makes holding the data unlawful. Imbalance reports alongside a result rather
than blocking it.

`CorpusManifest.digest()` covers sample identity, content digest, and split,
independent of ordering, so a published result can cite the exact corpus it was
computed over and two people assembling the same corpus can compare numbers.

## Not in the scanning path

Nothing in `trueai.research` is imported by a detector, a cleaner, or the engine,
and nothing here changes what a scan reports. Data collection is a separate
activity with separate obligations, and the code says so by being separate.
