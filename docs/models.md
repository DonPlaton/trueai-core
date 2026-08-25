# Models: optional, replaceable, and never provenance

The arrangement `trueai.research.features` makes possible: TrueAI computes
features, a model somewhere else consumes them, and neither imports the other's
dependencies. The core stays free of anything that needs a GPU, and a model
becomes something you can add, replace, or delete without touching a detector.

A test enforces the second half of that. It walks every module in the package and
fails if any imports `torch`, `tensorflow`, `jax`, `sklearn`, `numpy`, `scipy`,
`pandas`, `transformers`, `onnxruntime`, `xgboost`, or `lightgbm` — and a second
test proves that check can actually fail, because a guard that cannot fail is not
a guard.

## The contract is versioned, and mismatches refuse

A `FeatureSet` is a named, **ordered** list of features. Order is part of the
contract because a vector is positional: the same names in a different order are
a different feature set, and treating them as interchangeable permutes every
column. `FeatureSet.digest` covers version, names, and order together.

A `ScoreModel` records the `feature_set_version` it was trained against.
`score_with()` refuses a vector from any other:

```python
score_with(model_trained_on_v2, vector_from_v1)   # FeatureError
```

The refusal is the point. The alternative is scoring a vector whose third column
used to mean one thing and now means another, which produces a confident number
with nothing behind it and no symptom until somebody acts on it.

`score_with()` also checks the model's *output* tag, because a model claiming a
feature set it was not handed is not one to trust with the rest.

## Building a vector refuses too

`build_vector()` will not pad a missing feature with zero. A zero is a value a
model will happily consume, and "this feature was not computed" is not the same
statement as "this feature measured zero".

It will not silently drop an extra feature either. Adding one changes the
contract, so it has to change the version.

## A model is optional, and its absence is not a result

`try_score()` returns `None` when no model is available. `None` means **not
measured**. It is never "clean", and an interface that renders it as an absence
of findings is making a claim the function did not.

This is the same rule as everywhere else in the project: a check that did not run
is not a check that passed. See [provenance](provenance.md), where `not_examined`
is kept apart from `absent` for the same reason.

## A score is a measurement, not a statement about a person

`ModelScore` carries a value, a model identifier, a feature set version, and
optionally the threshold it was calibrated at. It carries **no author, no
attribution, and no provenance class** — the fields that would let a caller
promote it into a claim about who wrote something are not there, and a test
asserts they are not.

`describe()` says it out loud: *this is a measurement about the text, not a
statement about who wrote it*.

A finding built from a score belongs to `ConfidenceType.PROBABILISTIC` and never
to a provenance class. See [findings](findings.md).

## Model cards are required, not encouraged

`ModelCard` requires the identifier, version, feature set version, the corpus
digest it was trained on, the intended use, and **at least one known
limitation**. Every model has some, and a card without them is a card nobody
looked hard at. `evaluated_subgroups` records which cohorts were measured, so a
reader can tell which were not — see
[the evaluation protocol](evaluation-protocol.md).

The corpus digest is the order-independent one from
[corpus governance](research-data.md), so a card names the exact data.

## Before a learned score is shown to anyone

`trueai.research.release` is the gate. A model that scores text about whether a
person wrote it is not shipped because it works; it is shipped because someone
can answer, afterwards and under pressure, what it was trained on, what it is
for, what it gets wrong, and whether this is the model they think it is.

Five artifacts, and `may_expose()` refuses without them.

### A dataset statement

Every field required, because a statement with the awkward sections left blank is
the one that gets written and the awkward sections are the reason to write one.

`does_not_represent` is the field the document exists for. A corpus of published
English technical writing does not represent a student writing in a second
language, and the moment to say so is before a model trained on it is used to
judge one.

`author_demographics` empty with `demographics_collected` false means they were
not collected — a fact about the corpus, not about the population. Listing
demographics while claiming none were collected is refused, because one of the
two is wrong and a reader cannot tell which.

### Versioned thresholds

An `OperatingPoint` carries a threshold, what it is *for*, and the false positive
rate measured at it. A threshold without a use is a number waiting to be
misapplied.

A `ThresholdSet` is bound to one model version and one feature set version and
carries the digest of the evaluation that produced it. A manifest refuses
thresholds from another model version or feature set: a threshold copied forward
is a number nobody measured on the model it is being applied to.

`may_expose()` also refuses when the evaluation was run at a threshold no
operating point in the manifest uses — an operating point nobody evaluated is a
number waiting to be quoted.

### A signed manifest

`TAIMDL1-…`, content-addressed over the card, the statement, the thresholds, and
the **digests of the model's own files**. So "is this the model that was
evaluated" has an answer that does not depend on a filename. Editing anything
breaks the identifier and signing is refused until it is rebuilt.

### A regression gate

`check_regression()` compares a candidate against a baseline, and the rule that
makes it worth having is this: **a rise in the false positive rate blocks the
release even when everything else improved**. Averages let a model get better at
finding machine text while getting worse at accusing people, and only one of
those two costs a person something. Default tolerance: 0.5 percentage points.

Three more gates, each closing a way to look better without being better:

- **The worst subgroup is gated separately.** An improvement in the mean that
  comes out of one cohort is not an improvement.
- **A candidate that scores no subgroup at all is blocked** when the baseline
  scored one, because the comparison would otherwise hide whichever cohort went
  missing.
- **Coverage falling more than 5 points is blocked.** Abstaining more improves
  every other number for free.

Calibration getting worse by more than 5 points blocks too.

A first release passes `regression=None`: there is nothing to regress against.
That is not a way to skip the check on a later one — passing `None` for a
replacement is a decision somebody makes deliberately, in code that shows it.

## Where the heavy dependencies live

Outside this package. A model implementation satisfies the `ScoreModel`
protocol — an identifier, a feature set version, and a `score()` method — and
brings whatever runtime it needs with it. Nothing in `trueai` imports it, and
nothing in `trueai` knows it exists until a caller passes one in.
