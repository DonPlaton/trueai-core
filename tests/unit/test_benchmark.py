"""The benchmark harness, and whether its checks can actually fail.

A determinism check that passes on a non-deterministic report is worse than no
check, so the interesting tests here are the ones that break something on
purpose and confirm the harness notices.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from trueai.core.benchmark import (
    VOLATILE_REPORT_FIELDS,
    build_corpus,
    comparable_report,
    compare_reports,
    measured,
    run_benchmark,
)
from trueai.core.cache import CachedArtifactResult, CacheStatistics, ScanCache
from trueai.core.models import ScanOptions

SMALL = 60


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    root = tmp_path / "corpus"
    build_corpus(root, SMALL, seed=7)
    return root


# -- the corpus ----------------------------------------------------------------------


def test_a_seeded_corpus_is_reproducible(tmp_path: Path) -> None:
    """A benchmark number is worthless if the inputs differ between runs."""

    first, second = tmp_path / "a", tmp_path / "b"
    build_corpus(first, SMALL, seed=7)
    build_corpus(second, SMALL, seed=7)

    left = {
        p.relative_to(first).as_posix(): p.read_bytes() for p in first.rglob("*") if p.is_file()
    }
    right = {
        p.relative_to(second).as_posix(): p.read_bytes() for p in second.rglob("*") if p.is_file()
    }

    assert left == right


def test_different_seeds_produce_different_corpora(tmp_path: Path) -> None:
    build_corpus(tmp_path / "a", SMALL, seed=7)
    build_corpus(tmp_path / "b", SMALL, seed=8)

    left = sorted(p.name for p in (tmp_path / "a").rglob("*") if p.is_file())
    right = sorted(p.name for p in (tmp_path / "b").rglob("*") if p.is_file())

    assert left != right


def test_the_corpus_is_nested_rather_than_flat(corpus: Path) -> None:
    """A flat tree would not exercise traversal and would flatter the numbers."""

    depths = {len(path.relative_to(corpus).parts) for path in corpus.rglob("*") if path.is_file()}

    assert depths == {3}


def test_an_empty_corpus_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="at least one file"):
        build_corpus(tmp_path / "empty", 0)


# -- measurement ---------------------------------------------------------------------


def test_measurement_reports_time_and_both_memory_peaks() -> None:
    with measured() as collected:
        held = [bytearray(200_000) for _ in range(5)]
        assert len(held) == 5

    usage = collected[0]

    assert usage.seconds > 0
    assert usage.peak_traced_bytes >= 1_000_000
    assert usage.process_peak_rss_bytes is None or usage.process_peak_rss_bytes > 0


def test_the_rss_high_water_mark_never_falls_between_phases() -> None:
    """It is an OS high-water mark, and the reported field says so."""

    with measured() as first:
        held = [bytearray(2_000_000) for _ in range(8)]
        assert len(held) == 8
    del held
    with measured() as second:
        pass

    if first[0].process_peak_rss_bytes is not None:
        assert second[0].process_peak_rss_bytes is not None
        assert second[0].process_peak_rss_bytes >= first[0].process_peak_rss_bytes


def test_a_nested_measurement_does_not_inherit_an_earlier_transient_peak() -> None:
    """A spike that happened before the block, and was freed, is not its cost.

    Live memory held from outside still counts, because it is still allocated
    while the block runs. What the peak reset removes is the ghost of something
    already released.
    """

    import tracemalloc

    tracemalloc.start()
    try:
        transient = bytearray(8_000_000)
        del transient
        with measured() as inner:
            pass
        assert inner[0].peak_traced_bytes < 4_000_000
    finally:
        tracemalloc.stop()


def test_measurement_does_not_disturb_an_outer_tracer() -> None:
    """Nesting must not stop a tracemalloc session the caller started."""

    import tracemalloc

    tracemalloc.start()
    try:
        with measured():
            pass
        assert tracemalloc.is_tracing()
    finally:
        tracemalloc.stop()


# -- determinism, and whether the check has teeth ------------------------------------


def test_two_scans_of_the_same_corpus_agree(corpus: Path) -> None:
    result = run_benchmark(corpus, workers=2)

    assert result.determinism is not None
    assert result.determinism.identical, result.determinism.explain()


def test_a_parallel_scan_agrees_with_a_serial_one(corpus: Path) -> None:
    """A speedup that changes the answer is not a speedup."""

    result = run_benchmark(corpus, workers=4)

    assert result.parallel_agreement is not None
    assert result.parallel_agreement.identical, result.parallel_agreement.explain()


def test_the_comparison_ignores_only_the_fields_expected_to_vary(corpus: Path) -> None:
    from trueai import TrueAIEngine

    report = TrueAIEngine.default(discover_plugins=False).scan(corpus)
    trimmed = comparable_report(report)

    assert {"scan_id", "generated_at"} == VOLATILE_REPORT_FIELDS
    assert not VOLATILE_REPORT_FIELDS & set(trimmed)
    for field in ("findings", "artifacts", "summary", "detectors_run", "integrity"):
        assert field in trimmed, "the comparison must still cover the interesting fields"


def test_a_changed_finding_is_caught_by_the_comparison(corpus: Path) -> None:
    """Deliberately break one report and confirm the check fails."""

    from trueai import TrueAIEngine

    engine = TrueAIEngine.default(discover_plugins=False)
    first = engine.scan(corpus)
    second = first.model_copy(update={"findings": first.findings[:-1]})

    outcome = compare_reports(first, second)

    assert not outcome.identical
    assert outcome.first_difference == "findings"
    assert "findings" in outcome.explain()


def test_a_changed_scan_id_alone_is_not_a_difference(corpus: Path) -> None:
    from uuid import uuid4

    from trueai import TrueAIEngine

    first = TrueAIEngine.default(discover_plugins=False).scan(corpus)
    second = first.model_copy(update={"scan_id": uuid4()})

    assert compare_reports(first, second).identical


# -- cache statistics ----------------------------------------------------------------


def test_a_cold_run_misses_and_a_warm_run_hits(corpus: Path, tmp_path: Path) -> None:
    result = run_benchmark(corpus, cache_directory=tmp_path / "cache", workers=2)

    cold = result.phase("cold")
    warm = result.phase("warm")

    assert cold is not None and warm is not None
    assert cold.cache.hits == 0
    assert cold.cache.stores == cold.cache.misses
    assert warm.cache.hit_rate == 1.0
    assert warm.cache.misses == 0


def test_the_parallel_phase_runs_without_a_cache(corpus: Path, tmp_path: Path) -> None:
    """Otherwise its time would measure a run that skipped the work."""

    result = run_benchmark(corpus, cache_directory=tmp_path / "cache", workers=2)
    parallel = result.phase("parallel(2)")

    assert parallel is not None
    assert parallel.cache.lookups == 0
    assert parallel.findings == result.phases[0].findings


def test_a_damaged_entry_is_counted_apart_from_a_cold_miss(tmp_path: Path) -> None:
    """ "The cache did not help" and "the cache is damaged" are different facts."""

    cache = ScanCache(tmp_path / "cache")
    key = "b" * 64
    cache.store(key, CachedArtifactResult(findings=(), diagnostics=(), detectors_run=("x",)))
    assert cache.load(key) is not None

    entry = tmp_path / "cache" / key[:2] / f"{key}.json"
    entry.write_text("{ truncated", encoding="utf-8")

    assert cache.load(key) is None
    statistics = cache.statistics()
    assert statistics.hits == 1
    assert statistics.rejections == 1
    assert statistics.misses == 0


def test_a_key_that_was_never_stored_is_a_miss(tmp_path: Path) -> None:
    cache = ScanCache(tmp_path / "cache")

    assert cache.load("c" * 64) is None

    assert cache.statistics() == CacheStatistics(misses=1)


def test_an_entry_written_for_another_key_is_a_rejection(tmp_path: Path) -> None:
    cache = ScanCache(tmp_path / "cache")
    key, other = "d" * 64, "e" * 64
    cache.store(other, CachedArtifactResult(findings=(), diagnostics=(), detectors_run=()))
    source = tmp_path / "cache" / other[:2] / f"{other}.json"
    target = tmp_path / "cache" / key[:2] / f"{key}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(source.read_bytes())

    assert cache.load(key) is None
    assert cache.statistics().rejections == 1


def test_an_oversized_payload_is_a_store_failure(tmp_path: Path, monkeypatch) -> None:
    import trueai.core.cache as cache_module

    monkeypatch.setattr(cache_module, "MAX_ENTRY_BYTES", 8)
    cache = ScanCache(tmp_path / "cache")

    cache.store("f" * 64, CachedArtifactResult(findings=(), diagnostics=(), detectors_run=("x",)))

    assert cache.statistics().store_failures == 1
    assert cache.statistics().stores == 0


def test_statistics_explain_themselves() -> None:
    assert CacheStatistics().explain() == "No cache lookups."
    assert "50.0%" in CacheStatistics(hits=1, misses=1, stores=1).explain()
    assert "unusable" in CacheStatistics(hits=1, rejections=2).explain()
    assert CacheStatistics(hits=3, misses=1).hit_rate == 0.75
    assert CacheStatistics().hit_rate == 0.0


# -- the caller-supplied cache -------------------------------------------------------


def test_a_supplied_cache_is_used_instead_of_one_built_from_options(
    corpus: Path, tmp_path: Path
) -> None:
    """Otherwise the statistics would be created and discarded inside the scan."""

    from trueai import TrueAIEngine

    supplied = ScanCache(tmp_path / "supplied")
    options = ScanOptions(cache_directory=tmp_path / "ignored")

    TrueAIEngine.default(discover_plugins=False).scan(corpus, options=options, cache=supplied)

    assert supplied.statistics().stores > 0
    assert not (tmp_path / "ignored").exists()


# -- the result --------------------------------------------------------------------


def test_the_result_serializes_every_measured_number(corpus: Path, tmp_path: Path) -> None:
    import json

    result = run_benchmark(corpus, cache_directory=tmp_path / "cache", workers=2)
    payload = json.loads(result.to_json())

    assert payload["file_count"] == result.phases[0].artifacts
    assert {phase["name"] for phase in payload["phases"]} == {"cold", "warm", "parallel(2)"}
    for phase in payload["phases"]:
        for key in ("seconds", "files_per_second", "peak_traced_bytes", "cache_hit_rate"):
            assert key in phase
        for key in ("process_peak_rss_bytes", "cache_rejections"):
            assert key in phase
    assert payload["determinism"]["identical"] is True
    assert payload["parallel_agreement"]["identical"] is True
    assert set(payload["environment"]) == {"python", "platform", "processor"}


def test_an_unknown_phase_name_returns_nothing(corpus: Path) -> None:
    assert run_benchmark(corpus, check_determinism=False, workers=2).phase("absent") is None


# -- fingerprints instead of whole reports -------------------------------------------


def test_a_fingerprint_covers_every_field_the_comparison_compares(corpus: Path) -> None:
    from trueai import TrueAIEngine
    from trueai.core.benchmark import report_fingerprint

    report = TrueAIEngine.default(discover_plugins=False).scan(corpus)

    assert set(report_fingerprint(report)) == set(comparable_report(report))


def test_a_fingerprint_is_small_enough_to_hold(corpus: Path) -> None:
    """The point: a benchmark must not need three whole reports in memory."""

    from trueai import TrueAIEngine
    from trueai.core.benchmark import report_fingerprint

    report = TrueAIEngine.default(discover_plugins=False).scan(corpus)
    fingerprint = report_fingerprint(report)

    assert all(len(value) == 64 for value in fingerprint.values())


def test_comparing_fingerprints_finds_the_same_difference_as_comparing_reports(
    corpus: Path,
) -> None:
    from trueai import TrueAIEngine
    from trueai.core.benchmark import report_fingerprint

    first = TrueAIEngine.default(discover_plugins=False).scan(corpus)
    second = first.model_copy(update={"findings": first.findings[:-1]})

    by_report = compare_reports(first, second)
    by_fingerprint = compare_reports(report_fingerprint(first), report_fingerprint(second))

    assert by_report == by_fingerprint
    assert by_fingerprint.first_difference == "findings"


def test_each_phase_is_announced_as_it_finishes(corpus: Path, tmp_path: Path) -> None:
    """A run that prints nothing for an hour is indistinguishable from a hang."""

    announced: list[str] = []
    run_benchmark(
        corpus,
        cache_directory=tmp_path / "cache",
        workers=2,
        check_determinism=False,
        on_phase=lambda phase: announced.append(phase.name),
    )

    assert announced == ["cold", "warm", "parallel(2)"]


# -- a cap that is not reported is a number nobody can use ---------------------------


def test_a_finding_budget_that_ran_out_is_reported_not_hidden(corpus: Path) -> None:
    result = run_benchmark(
        corpus,
        options=ScanOptions(max_findings=5),
        workers=2,
        check_determinism=False,
    )
    cold = result.phase("cold")

    assert cold is not None
    assert cold.findings_truncated
    assert not cold.complete
    assert "floor not a total" in (cold.caveat() or "")


def test_a_discovery_cap_that_was_hit_is_reported(corpus: Path) -> None:
    result = run_benchmark(
        corpus,
        options=ScanOptions(max_files=5),
        workers=2,
        check_determinism=False,
    )
    cold = result.phase("cold")

    assert cold is not None
    assert cold.discovery_truncated
    assert "not fully walked" in (cold.caveat() or "")


def test_a_complete_phase_carries_no_caveat(corpus: Path) -> None:
    result = run_benchmark(corpus, workers=2, check_determinism=False)

    for phase in result.phases:
        assert phase.complete
        assert phase.caveat() is None


def test_truncation_flags_reach_the_serialized_result(corpus: Path) -> None:
    import json

    result = run_benchmark(
        corpus, options=ScanOptions(max_findings=5), workers=2, check_determinism=False
    )
    payload = json.loads(result.to_json())

    assert all(phase["findings_truncated"] for phase in payload["phases"])
