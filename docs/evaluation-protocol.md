# Evaluating a detector: the protocol, and what it refuses to publish alone

`trueai.research.evaluation` is the protocol as code. Running it produces an
`EvaluationResult` whose `summary()` carries the numbers that must travel
together and the caveats that must travel with them.

## The headline is not accuracy

It is the **false positive rate**: how often the tool tells someone that a
human-written document was machine-generated. Accuracy averages that harm
together with the harmless kind of mistake and reports one number that hides it.

`summary()` produces no accuracy figure at all, and a test asserts it. What it
leads with is the false positive rate, at the stated threshold, with a confidence
interval.

A rate quoted without the operating point it was computed at is not a
measurement. `ProtocolRecord.threshold` is required, and moving it moves the
rate.

## Six requirements

### False positives, with an interval

Every rate is a `RateEstimate` carrying successes, total, a 95% **Wilson**
interval, and a flag for whether the sample was large enough. Wilson rather than
the normal approximation because the latter gives a zero-width interval at a rate
of zero, which is exactly where a small sample most needs one.

Below `DEFAULT_MIN_GROUP_SIZE` (30) a rate is marked insufficient and described
as "too few samples to rely on". Printing "0.0%" for a group of five is worse
than printing nothing, because a reader treats it as a measurement.

### Calibration

A score of 0.9 should be wrong about one time in ten. `calibration()` bins the
scores and compares what each bin claimed to the rate it achieved; the expected
calibration error is the count-weighted mean gap.

An uncalibrated score is a number wearing a probability's clothes, and every
downstream policy that thresholds it inherits the lie. An expected error above
10% is reported as a problem.

### Domain shift

One aggregate over a mixed corpus hides that a detector works on one domain and
not another. Per-domain rates are reported, and `domain_spread()` gives the gap
between best and worst — which is what a new deployment will actually meet. A
spread above 10 points is reported as a problem.

### Subgroups

A detector with a 3% overall false positive rate and 15% on writing in a second
language is not a 3% detector; it is a tool that penalises non-native speakers.

`worst_subgroup()` returns the worst rate among subgroups **large enough to
score** — otherwise a five-sample group with one mistake becomes the headline —
and a gap of more than 5 points above the overall rate is reported as a problem.
The subgroup axis is named by the evaluator, because only they know which one
matters for their deployment.

### Abstention

A detector allowed to say "I do not know" can reach any figure by answering only
the easy cases. Coverage is reported with every metric, an abstention never
counts as a correct answer, and coverage below 90% adds the caveat that every
rate above it "describes only what it chose to answer".

### Reproducibility

`ProtocolRecord` requires the corpus digest, the model identifier, the threshold,
the seed, the code version, and a timestamp with an offset. All six appear in the
summary. A number that cannot be recomputed is an anecdote, including by its
author six months later.

The corpus digest is `CorpusManifest.digest()` from
[corpus governance](research-data.md), which is order-independent, so two people
assembling the same corpus can compare numbers.

## Problems block a headline

`problems()` returns every reason a result must not be quoted alone:

- the negative class is too small for a false positive rate to mean anything;
- a subgroup's rate exceeds the overall rate by more than 5 points;
- groups were too small to score, listed by name rather than dropped;
- calibration could not be assessed, or is poor;
- the detector abstained on more than a tenth of the corpus;
- the false positive rate varies more than 10 points between domains.

Each appears in `summary()` as a `Caveat:` sentence. A clean evaluation produces
none, and a test pins that too — a checker that always complains is one people
learn to ignore.

## What this does not do

It does not train anything, does not decide a threshold, and takes no position on
a labelling scheme: `Prediction.is_positive` is ground truth supplied by the
evaluator and the label vocabulary is theirs. This module scores; deciding what
is worth scoring is a separate judgement.
