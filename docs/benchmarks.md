# Repository scale: measured, not estimated

Every number here was produced by `scripts/benchmark_scale.py` on the machine
named below. The corpus is generated from a seed, so a run is reproducible
rather than something to take on faith:

```
python scripts/benchmark_scale.py --files 10000
python scripts/benchmark_scale.py --files 100000 --json results.json
```

## What is measured, and why each one

**Wall time** answers the least interesting question on its own. Three others
decide whether TrueAI is usable on a real repository.

**Peak memory**, because a scanner that is fast and then dies at 80,000 files is
not fast. Two figures are reported and they answer different questions:

- *Process peak RSS* is what the machine feels — but every OS exposes it as a
  process-lifetime high-water mark. It never falls, so **only the first phase's
  figure is that phase's own peak**; a later phase showing a similar number means
  it stayed under the earlier high, not that it used nothing. Subtracting two
  high-water marks to fake a per-phase RSS would produce a confident wrong
  number, so this harness does not do it.
- *Peak Python allocation* is per-phase and honest about covering only the Python
  side. It is always smaller than RSS and is never a substitute for it.

**Cache hit rate**, kept apart from the rejection rate. "The cache did not help"
and "the cache is damaged" are different problems, and one blended percentage
hides the second.

**Determinism**, because a report that varies between identical runs cannot back
an audit certificate. Two scans are compared with only `scan_id` and
`generated_at` removed — a comparison that ignored everything unstable would
always pass. A third check compares the parallel scan against the serial one,
because a speedup that changes the answer is not a speedup.

## Results

Environment: Windows 11 (10.0.26200), AMD Ryzen 7 7700 (8C/16T), Python 3.14.4,
NVMe storage. Corpus: seeded mix of Markdown, Python, text, HTML, CSS, SVG, and
JSON, spread three directories deep — a flat tree would not exercise traversal
and would flatter the numbers.

### 10,000 files — 3,422 findings

| Phase | Seconds | Files/s | Process peak RSS | Python alloc peak | Cache |
|---|---:|---:|---:|---:|---:|
| cold (serial) | 103.3 | 96.8 | 123.8 MB | 39.4 MB | 0% hit, 10,000 stored |
| warm (serial) | 97.6 | 102.5 | 155.9 MB | 46.0 MB | **100% hit** |
| parallel, 8 workers | **21.1** | **473.1** | 168.7 MB | 44.7 MB | not used |

Determinism: two scans byte-identical. Parallel and serial agree.

### 100,000 files — stopped by the default finding budget

| Phase | Seconds | Files/s | Process peak RSS | Python alloc peak | Cache |
|---|---:|---:|---:|---:|---:|
| cold (serial) | 938.3 | 106.6 | 727.2 MB | 322.3 MB | 0% hit, 29,126 stored |
| warm (serial) | 399.9 | 250.1 | 758.5 MB | 334.2 MB | **100% hit** |
| parallel, 8 workers | **267.0** | **374.5** | 758.5 MB | 317.8 MB | not used |

Determinism: two scans byte-identical. Parallel and serial agree.

**Read this row with the cap in mind.** The default finding budget is
`max_findings = 10_000`, and 100,000 files of this corpus produce more than
that. The scan recorded 10,000 findings, emitted a `finding_limit_exceeded`
diagnostic at HIGH severity, and stopped — after detector-scanning 29,127 of the
100,001 artifacts it had discovered. So:

- **The findings count is a floor, not a total.** The harness now marks a phase
  `findings_truncated` and prints `INCOMPLETE` rather than letting a capped count
  read as a result.
- **Files/s mixes two different populations.** Discovery walked all 100,001
  artifacts; detectors ran on 29,127 of them. The rate divides the full discovery
  count by the wall time, so it is not comparable to the 10,000-file row.
- A complete pass needs `--max-findings` raised. The default is what an ordinary
  scan uses, so it is what is published here.

**The warm speedup here is mostly the operating system, not TrueAI's cache.** At
10,000 files the corpus is small enough that both phases run against a warm OS
file cache, which isolates TrueAI's own contribution: ~5%. At 100,000 files the
cold phase reads from disk for the first time and the warm phase does not, so the
2.3x gap is dominated by the OS. Reporting the 100,000 warm figure as a cache
speedup would be attributing someone else's work.

**Memory scales roughly linearly and stays modest.** 727 MB peak RSS for 100,000
files against 124 MB for 10,000. The scan holds one artifact at a time; what
grows is the report — one descriptor per discovered artifact.

## What the numbers say

**Parallelism is the lever; the cache is not.** Eight workers give a 4.9×
speedup. A *fully* warm cache — every one of 10,000 lookups a hit — saves 5.5%.
That is worth stating plainly, because "incremental scanning" sounds like the
answer to repository scale and here it is not: the cache eliminates detector
work, and detector work is not where the time goes.

**Where the time actually goes.** Profiling a 2,000-file scan put 69% of wall
time inside artifact discovery, and nearly all of that inside `open()`. The scan
opens each file several times, and that is mostly deliberate:

- once to sniff its type,
- once to hash it before detectors run,
- once for the detectors to read it,
- once to re-hash it immediately afterwards, which catches a detector that
  mutated the artifact it was given,
- and once more in a whole-corpus sweep at the end, which catches a detector
  that mutated a *different* artifact.

The last two are the read-only guarantee, and they are not free: the corpus is
hashed three times per scan. That is the price of being able to say a scan
changed nothing, and it is a price this project pays deliberately rather than
one it failed to notice.

**One of those passes was not deliberate.** The end-of-scan sweep asks "did new
files appear while detectors ran", which needs a set of paths. It was built by
running full discovery a second time — opening and sniffing every file to
produce type information the comparison then discarded.
`ArtifactDiscovery.inventory()` now walks for paths only, using the same
traversal, ignore rules, symlink containment, and file cap, so a sweep cannot
report differences that are its own. Measured on a warm 2,000-file corpus: 3.45 s
→ 2.96 s, **14% of wall time removed**, with no check weakened.

That change also fixed a latent false positive. A file that the first pass could
not identify — a permission error, or a file deleted between the walk and the
open — was absent from the first pass's inventory and present in the second, and
was announced as `detector_mutation` at CRITICAL severity: a plugin rewriting
your repository. Paths the first pass already reported as problems are now
excluded.

**Memory is not the constraint — but the harness nearly was.** 124 MB peak RSS
for 10,000 files, 727 MB for 100,000, with the scan holding one artifact at a
time. The first attempt at 100,000 files died without printing anything: the
harness was holding three whole reports at once to compare them. It now compares
a per-field SHA-256 digest, which still names the field that differs and fits in
a few hundred bytes. A benchmark should not be the thing that runs out of memory.

## Real repositories

The published numbers above are synthetic. Benchmarking real repositories needs
their owners' consent, which makes it an `external` task rather than one this
harness can complete on its own. The harness runs against any directory:

```
python scripts/benchmark_scale.py --corpus /path/to/repository
```

`--corpus` writes nothing into the directory it measures — not one file, not a
cache entry. The cache lives in a temporary workspace that is removed
afterwards. A benchmark that modified the repository it measured would be worse
than useless.

## Run notes

- The cold phase reads from cold OS cache; warm and parallel phases do not.
  Comparing the parallel figure directly to the cold one therefore overstates the
  parallel speedup somewhat. It is reported as measured rather than adjusted, and
  the effect is much larger at 100,000 files than at 10,000.
- `--max-findings` and `--max-files` raise the scan's limits. Runs published here
  use the defaults, because those are what an operator gets.
- The parallel phase runs **without** a cache, so its time is comparable to the
  cold phase rather than to a run that skipped the work.
- `--workers` controls the parallel phase; the default `max_workers` for an
  ordinary scan is 1.
