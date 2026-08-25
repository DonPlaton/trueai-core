# Fuzzing the parsing boundaries

A scanner's whole job is reading files somebody else made. Two harnesses cover
where that happens:

| Harness | Boundary |
|---|---|
| `scripts/fuzz_parsers.py` | ZIP/OPC, XML, PDF, ISO-BMFF, EBML, Git object scope, cache entries, policy bundles, certificates, reports |
| `scripts/fuzz_plugins.py` | The plugin trust boundary: worker protocol, manifests, distributions, findings, resource limits, capability broker paths |

```
python scripts/fuzz_parsers.py --iterations 20000
python scripts/fuzz_parsers.py --seed 4242 --target pdf
python scripts/fuzz_parsers.py --seconds 600
python scripts/fuzz_parsers.py --self-check
```

Both are seeded and replayable: a failure prints the seed, the target, and the
input, so a bug found in a long run reproduces with one command.

## Each target declares what it may do, and what must hold anyway

A fuzzer that only asks "did it crash" would pass a parser that cheerfully
accepts a forged signature. So every target states two things.

**What a parser is allowed to do with hostile input: refuse it.** A `ValueError`,
a `TrueAIError`, a validation error. It is *not* allowed to raise a `TypeError`
from an unguarded attribute access, an `IndexError` from an unchecked slice, a
`RecursionError` from an unbounded structure, or a `MemoryError` from a length
field nobody read twice. Those are reported as findings, and so is any exception
the target did not declare — a parser may refuse, it may not surprise.

**What must hold when it does not refuse.** A validated OPC package names no
member that would escape the tree. An XML part never resolves an external entity.
Every box and element sits inside the input it was parsed from. A damaged cache
entry is a miss, never an exception and never a half-decoded result. A loaded
report's finding count matches its findings. An accepted Git alternates file
contains no path leaving the repository.

## Coverage guidance, and what it is actually worth

`sys.monitoring` records which lines inside `trueai/` each input reaches. An
input that reaches somewhere new is kept and mutated further. No native
dependency, and the whole run reproduces from a seed.

Guidance is not free, and the honest version is that it pays off late. Measured
on the PDF, ISO-BMFF, and EBML targets with `--seed 11`:

| Inputs | Guided | Unguided |
|---:|---:|---:|
| 3,000 | 601 lines | **664** |
| 12,000 | **739** | 709 |
| 60,000 | **757** | 727 |

Early on, mutating a pristine seed beats mutating whatever the corpus has
accumulated. That is why `--no-coverage` exists as a real option rather than a
curiosity, and why half of all mutations start from a seed even in guided mode:
mutating a mutation of a mutation drifts away from anything structurally valid,
and for a length-prefixed format that means never getting past the header again.

The line count counts lines inside `trueai/` only. That is the right denominator
for "did our code get exercised" and a misleading one for a target whose parser
is a thin wrapper over pydantic or ElementTree — a low number there means the
work happens in a library, not that less was tested.

## Seeds are real artifacts

A seed that fails on its first field never reaches the code worth reaching. So
the seeds are produced by the same builders the fixtures use: a genuine MP4 with
a track and a resolved sample table, a WebM with tracks and clusters, both a
classic and a cross-reference-stream PDF, a signed policy bundle, an issued
certificate, a rendered report.

That is worth roughly double the coverage on the formats where it matters — the
PDF target went from 153 lines to 348 when it stopped starting from a stub.

## The harness is checked for teeth

`--self-check` confirms the harness reports a broken invariant, reports an
unguarded `TypeError`, and does *not* report a clean target.
`tests/unit/test_parser_fuzzing.py` runs a short pass of every boundary on every
test run, so a regression that makes a parser raise on a truncated header fails
the build rather than waiting for somebody to remember a nightly job — and it
asserts the harness can fail, because a fuzzer that cannot report a failure
passes everything, which is indistinguishable from working.
