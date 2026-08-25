"""Measure what a repository scan actually costs, and whether it repeats itself.

A benchmark that reports only wall time answers the least interesting question.
Three others decide whether TrueAI is usable on a real repository:

* **Peak memory**, because a scanner that is fast and then dies at 80,000 files
  is not fast.  Two numbers, and they answer different questions.  Peak resident
  set is what an operator's machine feels, but every OS exposes it as a
  *process-lifetime high-water mark*: it never falls, so after the first phase it
  answers "did this phase push the process higher", not "what did this phase
  cost".  Peak traced Python allocation is per-phase and honest about being only
  the Python side.  Reporting either one alone, or subtracting high-water marks
  to fake a per-phase RSS, would produce a confident wrong number.
* **Cache hit rate**, split from the rejection rate, because "the cache did not
  help" and "the cache is damaged" are different problems.
* **Determinism**, because a report that varies between identical runs cannot be
  the basis of an audit certificate.  It is checked by running the scan twice
  and comparing the reports with only the fields that are *expected* to vary
  removed — a comparison that ignored everything unstable would always pass.
  The comparison is done on a per-field digest rather than on the reports
  themselves, because at 100,000 files holding three whole reports in memory to
  compare them makes the harness the thing that runs out of memory.

Corpus generation is seeded and the layout is written down, so a number from this
harness can be reproduced rather than believed.
"""

from __future__ import annotations

import hashlib
import json
import platform
import random
import sys
import time
import tracemalloc
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from trueai.core.cache import CacheStatistics, ScanCache
from trueai.core.certificates import canonical_json_bytes
from trueai.core.engine import TrueAIEngine
from trueai.core.models import ScanOptions, ScanReport

#: Report fields that legitimately differ between two identical scans. Anything
#: not listed here must be byte-identical, so the check cannot pass by ignoring
#: the interesting parts.
VOLATILE_REPORT_FIELDS: Final[frozenset[str]] = frozenset({"scan_id", "generated_at"})

#: The synthetic corpus mix, as (extension, share, template). Shares are relative
#: weights, not percentages, so adding a type does not require rebalancing the
#: others.
CORPUS_MIX: Final[tuple[tuple[str, int, str], ...]] = (
    ("md", 30, "# {name}\n\nWritten by hand.\n\n- item one\n- item two\n"),
    ("md", 6, "# {name}\n\nGenerated with ChatGPT.\n\nDraft copy for review.\n"),
    ("py", 20, '"""Module {name}."""\n\n\ndef run() -> int:\n    return {index}\n'),
    ("txt", 15, "Notes for {name}\nrevision {index}\n"),
    (
        "html",
        10,
        '<!doctype html><html><head><meta name="generator" content="handwritten">'
        "</head><body><p>{name}</p></body></html>\n",
    ),
    ("css", 8, ".{name} {{ color: #333; margin: {index}px; }}\n"),
    (
        "svg",
        6,
        '<svg xmlns="http://www.w3.org/2000/svg"><title>{name}</title>'
        "<rect width='10' height='10'/></svg>\n",
    ),
    ("json", 5, '{{"name": "{name}", "index": {index}}}\n'),
)


@dataclass(frozen=True, slots=True)
class ResourceUse:
    """What one measured operation cost."""

    seconds: float
    #: The process-lifetime peak resident set in bytes as of the end of this
    #: phase, or ``None`` where the platform does not expose it. Monotonic across
    #: phases by construction — an OS high-water mark does not fall — so only the
    #: first phase's figure is that phase's own peak, and a later one being equal
    #: means it stayed under the earlier high, not that it used nothing.
    process_peak_rss_bytes: int | None
    #: Peak Python allocation during this phase alone, in bytes. Always
    #: available, always smaller than RSS, and never a substitute for it.
    peak_traced_bytes: int


@dataclass(frozen=True, slots=True)
class PhaseResult:
    """One scan of the corpus, and everything measured about it."""

    name: str
    artifacts: int
    findings: int
    resources: ResourceUse
    cache: CacheStatistics
    #: The scan stopped recording findings at ``max_findings``. Reported because
    #: a finding count published without it reads as "this is what is there".
    findings_truncated: bool = False
    #: Discovery stopped at ``max_files``, so the corpus was not fully walked.
    discovery_truncated: bool = False

    @property
    def files_per_second(self) -> float:
        return self.artifacts / self.resources.seconds if self.resources.seconds else 0.0

    @property
    def complete(self) -> bool:
        """Whether this phase saw the whole corpus and recorded every finding."""

        return not (self.findings_truncated or self.discovery_truncated)

    def caveat(self) -> str | None:
        """Return what a reader must know before quoting this phase's counts."""

        notes = []
        if self.discovery_truncated:
            notes.append("discovery stopped at the file cap, so the corpus was not fully walked")
        if self.findings_truncated:
            notes.append("the finding budget was exhausted, so the count is a floor not a total")
        return "; ".join(notes) if notes else None


@dataclass(frozen=True, slots=True)
class DeterminismResult:
    """Whether two identical scans produced the same report."""

    identical: bool
    #: The first field whose value differed, for a failure that says where.
    first_difference: str | None = None

    def explain(self) -> str:
        if self.identical:
            return "Two identical scans produced byte-identical reports."
        return f"Reports differed at {self.first_difference}."


@dataclass(frozen=True, slots=True)
class BenchmarkResult:
    """Every phase of one benchmark run, plus the environment it ran in."""

    file_count: int
    phases: tuple[PhaseResult, ...] = ()
    determinism: DeterminismResult | None = None
    #: Whether the parallel scan produced the same report as the serial one.
    #: A speedup that changes the answer is not a speedup.
    parallel_agreement: DeterminismResult | None = None
    environment: dict[str, str] = field(default_factory=dict)

    def phase(self, name: str) -> PhaseResult | None:
        return next((item for item in self.phases if item.name == name), None)

    def to_json(self) -> str:
        payload: dict[str, Any] = {
            "file_count": self.file_count,
            "environment": self.environment,
            "phases": [
                {
                    "name": item.name,
                    "artifacts": item.artifacts,
                    "findings": item.findings,
                    "seconds": round(item.resources.seconds, 3),
                    "files_per_second": round(item.files_per_second, 1),
                    "process_peak_rss_bytes": item.resources.process_peak_rss_bytes,
                    "peak_traced_bytes": item.resources.peak_traced_bytes,
                    "cache_hits": item.cache.hits,
                    "cache_misses": item.cache.misses,
                    "cache_rejections": item.cache.rejections,
                    "cache_hit_rate": round(item.cache.hit_rate, 4),
                    "findings_truncated": item.findings_truncated,
                    "discovery_truncated": item.discovery_truncated,
                }
                for item in self.phases
            ],
        }
        for key, outcome in (
            ("determinism", self.determinism),
            ("parallel_agreement", self.parallel_agreement),
        ):
            if outcome is not None:
                payload[key] = {
                    "identical": outcome.identical,
                    "first_difference": outcome.first_difference,
                }
        return json.dumps(payload, indent=2, sort_keys=True)


# -- corpus ---------------------------------------------------------------------------


def build_corpus(root: Path, file_count: int, *, seed: int = 0, fanout: int = 100) -> int:
    """Write a seeded synthetic corpus and return how many files were created.

    Files are spread across nested directories rather than one flat directory,
    because a flat tree does not exercise the traversal and would make the
    numbers optimistic.
    """

    if file_count < 1:
        raise ValueError("A corpus needs at least one file")
    rng = random.Random(seed)
    weighted: list[tuple[str, str]] = []
    for extension, share, template in CORPUS_MIX:
        weighted.extend([(extension, template)] * share)
    root.mkdir(parents=True, exist_ok=True)
    written = 0
    for index in range(file_count):
        extension, template = weighted[rng.randrange(len(weighted))]
        directory = root / f"pkg{index // fanout:04d}" / f"part{index // (fanout * 10):03d}"
        directory.mkdir(parents=True, exist_ok=True)
        name = f"item{index:06d}"
        path = directory / f"{name}.{extension}"
        path.write_text(template.format(name=name, index=index), encoding="utf-8")
        written += 1
    return written


# -- measurement ----------------------------------------------------------------------


#: The largest peak this process has ever reported. Linux is the reason it
#: exists: since 6.2 the kernel keeps RSS in per-CPU counters and derives VmHWM
#: as ``max(stored_high_water, approximate_current_rss)``, where the second term
#: is a deliberately racy read. So two consecutive reads can go *down* by a
#: fraction of a percent, and a field this module documents as never falling
#: starts falling. Clamping here keeps the published contract true on every
#: platform instead of making each caller discover the exception.
_OBSERVED_PEAK_RSS_BYTES = 0


def _peak_rss_bytes() -> int | None:
    """Return the peak resident set size in bytes, or None where it is unknown.

    Monotonic for the life of the process, which is what "high-water mark" means
    and what the reported field promises.
    """

    global _OBSERVED_PEAK_RSS_BYTES
    reading = _read_peak_rss_bytes()
    if reading is None:
        return None
    _OBSERVED_PEAK_RSS_BYTES = max(_OBSERVED_PEAK_RSS_BYTES, reading)
    return _OBSERVED_PEAK_RSS_BYTES


def _read_peak_rss_bytes() -> int | None:
    """Ask the operating system, without smoothing what it says."""

    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class _Counters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = _Counters()
        counters.cb = ctypes.sizeof(_Counters)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        # Pinned signatures: the pseudo-handle is -1, which overflows an
        # unannotated ctypes int argument.
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        kernel32.GetCurrentProcess.argtypes = []
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_Counters),
            wintypes.DWORD,
        ]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        if not psapi.GetProcessMemoryInfo(
            kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb
        ):
            return None
        return int(counters.PeakWorkingSetSize)
    if sys.platform == "linux":
        try:
            for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
                if line.startswith("VmHWM:"):
                    return int(line.split()[1]) * 1024
        except (OSError, ValueError, IndexError):
            return None
        return None
    try:
        import resource

        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except (ImportError, OSError):
        return None
    # macOS reports bytes; other BSDs report kilobytes.
    return int(peak) if sys.platform == "darwin" else int(peak) * 1024


@contextmanager
def measured() -> Iterator[list[ResourceUse]]:
    """Measure wall time, the process RSS high-water mark, and this block's
    Python allocation peak."""

    collected: list[ResourceUse] = []
    already_tracing = tracemalloc.is_tracing()
    if already_tracing:
        # The caller's session stays open; the peak is rebased to what is live
        # now, so a spike that happened before this block and was freed does not
        # get charged to it. Memory still held from outside does count, because
        # it is still allocated while the block runs.
        tracemalloc.reset_peak()
    else:
        tracemalloc.start()
    started = time.perf_counter()
    try:
        yield collected
    finally:
        elapsed = time.perf_counter() - started
        _, traced_peak = tracemalloc.get_traced_memory()
        if not already_tracing:
            tracemalloc.stop()
        collected.append(
            ResourceUse(
                seconds=elapsed,
                process_peak_rss_bytes=_peak_rss_bytes(),
                peak_traced_bytes=traced_peak,
            )
        )


# -- determinism ----------------------------------------------------------------------


def comparable_report(report: ScanReport) -> dict[str, Any]:
    """Return a report with only the fields expected to vary removed."""

    payload = report.model_dump(mode="json")
    for name in VOLATILE_REPORT_FIELDS:
        payload.pop(name, None)
    return payload


def report_fingerprint(report: ScanReport) -> dict[str, str]:
    """Return a digest per top-level report field.

    Field-by-field rather than one digest over the whole report, so a mismatch
    still says *where*.  Digests rather than values, so the caller can hold the
    result of a 100,000-file scan without holding the scan.
    """

    return {
        name: hashlib.sha256(canonical_json_bytes(value)).hexdigest()
        for name, value in comparable_report(report).items()
    }


def compare_reports(
    first: ScanReport | dict[str, str], second: ScanReport | dict[str, str]
) -> DeterminismResult:
    """Compare two reports, or two fingerprints, and name the field that differs."""

    left = first if isinstance(first, dict) else report_fingerprint(first)
    right = second if isinstance(second, dict) else report_fingerprint(second)
    if left == right:
        return DeterminismResult(identical=True)
    for key in sorted(set(left) | set(right)):
        if left.get(key) != right.get(key):
            return DeterminismResult(identical=False, first_difference=key)
    return DeterminismResult(identical=False, first_difference="<unknown>")


# -- the benchmark --------------------------------------------------------------------


def _truncation(report: ScanReport) -> tuple[bool, bool]:
    """Return whether findings and discovery were cut short.

    Read from the report's own diagnostics rather than by comparing counts
    against the limits, so the benchmark and the scanner cannot disagree about
    whether a run was complete.
    """

    codes = {diagnostic.code for diagnostic in report.diagnostics}
    return ("finding_limit_exceeded" in codes, "discovery_truncated" in codes)


def _environment() -> dict[str, str]:
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor() or "unknown",
    }


def run_benchmark(
    corpus: Path,
    *,
    cache_directory: Path | None = None,
    options: ScanOptions | None = None,
    engine_factory: Callable[[], TrueAIEngine] | None = None,
    check_determinism: bool = True,
    workers: int = 8,
    on_phase: Callable[[PhaseResult], None] | None = None,
) -> BenchmarkResult:
    """Scan a corpus cold, warm, and in parallel, and report what each cost.

    The warm phase reuses the same cache directory, so its hit rate is the real
    question a repeated scan asks: how much of the previous run was reusable.
    The parallel phase runs without a cache, so its time is comparable to the
    cold one rather than to a run that skipped the work.

    ``on_phase`` is called as each phase finishes.  A hundred-thousand-file run
    takes the better part of an hour, and a harness that prints nothing until it
    is done is indistinguishable from one that has hung.
    """

    factory = engine_factory or (lambda: TrueAIEngine.default(discover_plugins=False))
    base = options or ScanOptions()
    phases: list[PhaseResult] = []

    scan_options = (
        base.model_copy(update={"cache_directory": cache_directory})
        if cache_directory is not None
        else base
    )

    # Only fingerprints are carried between phases. Holding the reports would
    # make the harness, not the scanner, the thing that runs out of memory.
    cold_fingerprint: dict[str, str] | None = None
    for name in ("cold", "warm"):
        cache = ScanCache(cache_directory) if cache_directory is not None else None
        engine = factory()
        with measured() as usage:
            report = engine.scan(corpus, options=scan_options, cache=cache)
        if name == "cold" and check_determinism:
            cold_fingerprint = report_fingerprint(report)
        findings_cut, discovery_cut = _truncation(report)
        phases.append(
            PhaseResult(
                name=name,
                artifacts=len(report.artifacts),
                findings=len(report.findings),
                resources=usage[0],
                cache=cache.statistics() if cache is not None else CacheStatistics(),
                findings_truncated=findings_cut,
                discovery_truncated=discovery_cut,
            )
        )
        del report
        if on_phase is not None:
            on_phase(phases[-1])

    parallel_options = base.model_copy(update={"max_workers": workers})
    with measured() as usage:
        parallel_report = factory().scan(corpus, options=parallel_options, cache=None)
    findings_cut, discovery_cut = _truncation(parallel_report)
    phases.append(
        PhaseResult(
            name=f"parallel({workers})",
            artifacts=len(parallel_report.artifacts),
            findings=len(parallel_report.findings),
            resources=usage[0],
            cache=CacheStatistics(),
            findings_truncated=findings_cut,
            discovery_truncated=discovery_cut,
        )
    )
    parallel_fingerprint = report_fingerprint(parallel_report) if check_determinism else None
    del parallel_report
    if on_phase is not None:
        on_phase(phases[-1])

    determinism = None
    parallel_agreement = None
    if check_determinism and cold_fingerprint is not None:
        repeat = factory().scan(corpus, options=scan_options, cache=None)
        determinism = compare_reports(cold_fingerprint, report_fingerprint(repeat))
        del repeat
        # A parallel scan that is faster and disagrees is not faster.
        if parallel_fingerprint is not None:
            parallel_agreement = compare_reports(cold_fingerprint, parallel_fingerprint)

    return BenchmarkResult(
        file_count=phases[0].artifacts if phases else 0,
        phases=tuple(phases),
        determinism=determinism,
        parallel_agreement=parallel_agreement,
        environment=_environment(),
    )


__all__ = [
    "CORPUS_MIX",
    "VOLATILE_REPORT_FIELDS",
    "BenchmarkResult",
    "DeterminismResult",
    "PhaseResult",
    "ResourceUse",
    "build_corpus",
    "comparable_report",
    "compare_reports",
    "measured",
    "report_fingerprint",
    "run_benchmark",
]
