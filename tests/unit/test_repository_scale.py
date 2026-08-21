"""Nested ignore semantics, deterministic parallelism, and incremental caching."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from trueai import TrueAIEngine
from trueai.core.artifact import Artifact
from trueai.core.cache import CACHE_FORMAT_VERSION, ScanCache, options_fingerprint
from trueai.core.models import (
    ArtifactType,
    ConfidenceType,
    EvidenceType,
    Finding,
    FindingCategory,
    ScanContext,
    ScanOptions,
    Severity,
)
from trueai.core.registry import DetectorRegistry
from trueai.detectors import create_default_registry
from trueai.detectors.base import BaseDetector

ATTRIBUTION = "Generated with ChatGPT\n"


def scanned_paths(root: Path, options: ScanOptions | None = None) -> set[str]:
    """Return the logical paths a scan actually discovered."""

    report = TrueAIEngine.default(discover_plugins=False).scan(root, options=options)
    return {descriptor.path for descriptor in report.artifacts}


# -- nested ignore rules -------------------------------------------------------------


def test_nested_ignore_file_applies_only_beneath_its_own_directory(tmp_path: Path) -> None:
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "kept.md").write_text(ATTRIBUTION, encoding="utf-8")
    package = tmp_path / "package"
    (package / "build").mkdir(parents=True)
    (package / ".gitignore").write_text("build/\n", encoding="utf-8")
    (package / "build" / "hidden.md").write_text(ATTRIBUTION, encoding="utf-8")
    (package / "kept.md").write_text(ATTRIBUTION, encoding="utf-8")

    paths = scanned_paths(tmp_path)

    assert "build/kept.md" in paths, "a nested rule must not reach a sibling directory"
    assert "package/kept.md" in paths
    assert "package/build/hidden.md" not in paths


def test_nested_negation_overrides_a_parent_ignore_rule(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("*.log\n", encoding="utf-8")
    (tmp_path / "root.log").write_text(ATTRIBUTION, encoding="utf-8")
    audited = tmp_path / "audited"
    audited.mkdir()
    (audited / ".gitignore").write_text("!important.log\n", encoding="utf-8")
    (audited / "important.log").write_text(ATTRIBUTION, encoding="utf-8")
    (audited / "other.log").write_text(ATTRIBUTION, encoding="utf-8")

    paths = scanned_paths(tmp_path)

    assert "root.log" not in paths
    assert "audited/important.log" in paths, "the closest rule must win"
    assert "audited/other.log" not in paths


def test_ignored_directory_is_not_descended_into(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("vendor/\n", encoding="utf-8")
    vendor = tmp_path / "vendor" / "deep" / "deeper"
    vendor.mkdir(parents=True)
    (vendor / "residue.md").write_text(ATTRIBUTION, encoding="utf-8")
    (tmp_path / "kept.md").write_text(ATTRIBUTION, encoding="utf-8")

    paths = scanned_paths(tmp_path)

    assert paths == {".", "kept.md", ".gitignore"}


def test_trueaiignore_is_honoured_at_any_depth(tmp_path: Path) -> None:
    private = tmp_path / "client" / "private"
    private.mkdir(parents=True)
    (tmp_path / "client" / ".trueaiignore").write_text("private/\n", encoding="utf-8")
    (private / "contract.md").write_text(ATTRIBUTION, encoding="utf-8")
    (tmp_path / "client" / "public.md").write_text(ATTRIBUTION, encoding="utf-8")

    paths = scanned_paths(tmp_path)

    assert "client/public.md" in paths
    assert "client/private/contract.md" not in paths


def test_a_nested_rule_cannot_reach_above_its_own_directory(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / ".gitignore").write_text("/top.md\n", encoding="utf-8")
    (tmp_path / "top.md").write_text(ATTRIBUTION, encoding="utf-8")
    (nested / "top.md").write_text(ATTRIBUTION, encoding="utf-8")

    paths = scanned_paths(tmp_path)

    assert "top.md" in paths
    assert "nested/top.md" not in paths


# -- deterministic parallelism -------------------------------------------------------


def build_tree(root: Path, file_count: int) -> None:
    """Create a small tree with residue in several formats."""

    for index in range(file_count):
        directory = root / f"module{index % 4}"
        directory.mkdir(exist_ok=True)
        (directory / f"note{index}.md").write_text(
            f"# Heading {index}\n\n{ATTRIBUTION}", encoding="utf-8"
        )
        (directory / f"code{index}.py").write_text(
            f"# Generated with Claude\nvalue = {index}\n", encoding="utf-8"
        )


def test_parallel_scan_produces_an_identical_report(tmp_path: Path) -> None:
    build_tree(tmp_path, 12)
    engine = TrueAIEngine.default(discover_plugins=False)

    sequential = engine.scan(tmp_path, options=ScanOptions(max_workers=1))
    parallel = engine.scan(tmp_path, options=ScanOptions(max_workers=8))

    assert [finding.id for finding in parallel.findings] == [
        finding.id for finding in sequential.findings
    ]
    assert parallel.summary.model_dump() == sequential.summary.model_dump()
    assert [item.path for item in parallel.artifacts] == [
        item.path for item in sequential.artifacts
    ]
    assert parallel.detectors_run == sequential.detectors_run
    assert [item.code for item in parallel.diagnostics] == [
        item.code for item in sequential.diagnostics
    ]


def test_parallel_scan_repeats_deterministically(tmp_path: Path) -> None:
    build_tree(tmp_path, 8)
    engine = TrueAIEngine.default(discover_plugins=False)
    options = ScanOptions(max_workers=8)

    first = engine.scan(tmp_path, options=options)
    second = engine.scan(tmp_path, options=options)

    assert [finding.id for finding in first.findings] == [finding.id for finding in second.findings]


def test_finding_budget_is_global_across_workers(tmp_path: Path) -> None:
    build_tree(tmp_path, 12)
    engine = TrueAIEngine.default(discover_plugins=False)

    report = engine.scan(tmp_path, options=ScanOptions(max_workers=8, max_findings=5))

    assert len(report.findings) <= 5
    assert any(item.code == "finding_limit_exceeded" for item in report.diagnostics)


def test_parallel_scan_reports_a_detector_failure_without_crashing(tmp_path: Path) -> None:
    build_tree(tmp_path, 6)

    class FailingDetector(BaseDetector):
        id = "test.failing.v1"
        supported_types = frozenset({ArtifactType.MARKDOWN})
        categories = frozenset({FindingCategory.TOOLING_RESIDUE})

        def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
            raise RuntimeError("detector exploded")

    registry = create_default_registry(discover_plugins=False)
    registry.register(FailingDetector())

    report = TrueAIEngine(registry).scan(tmp_path, options=ScanOptions(max_workers=4))

    failures = [item for item in report.diagnostics if item.code == "detector_failure"]
    assert failures
    assert all(item.severity == Severity.HIGH for item in failures)


# -- incremental caching -------------------------------------------------------------


class CountingDetector(BaseDetector):
    """Records how many artifacts it was asked to inspect."""

    id = "test.counting.v1"
    supported_types = frozenset({ArtifactType.MARKDOWN, ArtifactType.TEXT})
    categories = frozenset({FindingCategory.TOOLING_RESIDUE})

    def __init__(self) -> None:
        self.calls = 0

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        self.calls += 1
        return [
            self.finding(
                artifact=artifact,
                category=FindingCategory.TOOLING_RESIDUE,
                confidence=1.0,
                confidence_type=ConfidenceType.DETERMINISTIC,
                severity=Severity.INFO,
                evidence_type=EvidenceType.STRUCTURAL,
                title="Counted artifact",
                description="Synthetic finding used to observe cache behaviour.",
                evidence={"size": artifact.size},
            )
        ]


def counting_engine() -> tuple[TrueAIEngine, CountingDetector]:
    """Return an engine whose only detector counts its invocations."""

    detector = CountingDetector()
    registry = DetectorRegistry()
    registry.register(detector)
    return TrueAIEngine(registry), detector


def test_second_scan_reuses_cached_results_for_unchanged_content(tmp_path: Path) -> None:
    source = tmp_path / "notes.md"
    source.write_text(ATTRIBUTION, encoding="utf-8")
    cache_directory = tmp_path / "cache"
    options = ScanOptions(cache_directory=cache_directory)
    engine, detector = counting_engine()

    first = engine.scan(source, options=options)
    calls_after_first = detector.calls
    second = engine.scan(source, options=options)

    assert calls_after_first == 1
    assert detector.calls == 1, "unchanged content must not be re-inspected"
    assert [item.id for item in second.findings] == [item.id for item in first.findings]
    assert second.detectors_run == first.detectors_run


def test_changed_content_invalidates_its_cache_entry(tmp_path: Path) -> None:
    source = tmp_path / "notes.md"
    source.write_text(ATTRIBUTION, encoding="utf-8")
    options = ScanOptions(cache_directory=tmp_path / "cache")
    engine, detector = counting_engine()

    engine.scan(source, options=options)
    source.write_text(f"{ATTRIBUTION}An added line.\n", encoding="utf-8")
    engine.scan(source, options=options)

    assert detector.calls == 2


def test_changed_options_invalidate_the_cache(tmp_path: Path) -> None:
    source = tmp_path / "notes.md"
    source.write_text(ATTRIBUTION, encoding="utf-8")
    cache_directory = tmp_path / "cache"
    engine, detector = counting_engine()

    engine.scan(source, options=ScanOptions(cache_directory=cache_directory))
    engine.scan(
        source,
        options=ScanOptions(cache_directory=cache_directory, include_experimental=True),
    )

    assert detector.calls == 2


def test_worker_count_alone_does_not_invalidate_the_cache(tmp_path: Path) -> None:
    source = tmp_path / "notes.md"
    source.write_text(ATTRIBUTION, encoding="utf-8")
    cache_directory = tmp_path / "cache"
    engine, detector = counting_engine()

    engine.scan(source, options=ScanOptions(cache_directory=cache_directory))
    engine.scan(source, options=ScanOptions(cache_directory=cache_directory, max_workers=4))

    assert detector.calls == 1


def test_cached_directory_scan_matches_an_uncached_one(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    build_tree(root, 10)
    engine = TrueAIEngine.default(discover_plugins=False)
    cache_directory = tmp_path / "cache"

    uncached = engine.scan(root)
    engine.scan(root, options=ScanOptions(cache_directory=cache_directory))
    cached = engine.scan(root, options=ScanOptions(cache_directory=cache_directory))

    assert [finding.id for finding in cached.findings] == [
        finding.id for finding in uncached.findings
    ]


def test_the_default_cache_location_is_never_scanned_as_an_artifact(tmp_path: Path) -> None:
    """The cache lives inside the tree it describes, so it must stay invisible."""

    build_tree(tmp_path, 4)
    engine = TrueAIEngine.default(discover_plugins=False)
    cache_directory = tmp_path / ".trueai" / "cache"

    uncached = engine.scan(tmp_path)
    engine.scan(tmp_path, options=ScanOptions(cache_directory=cache_directory))
    second = engine.scan(tmp_path, options=ScanOptions(cache_directory=cache_directory))

    assert list(cache_directory.rglob("*.json")), "the cache must have been written"
    assert [item.path for item in second.artifacts] == [item.path for item in uncached.artifacts]
    assert [finding.id for finding in second.findings] == [
        finding.id for finding in uncached.findings
    ]


def test_a_corrupt_cache_entry_is_treated_as_a_miss(tmp_path: Path) -> None:
    source = tmp_path / "notes.md"
    source.write_text(ATTRIBUTION, encoding="utf-8")
    cache_directory = tmp_path / "cache"
    options = ScanOptions(cache_directory=cache_directory)
    engine, detector = counting_engine()
    engine.scan(source, options=options)

    for entry in cache_directory.rglob("*.json"):
        entry.write_text("{not json", encoding="utf-8")

    report = engine.scan(source, options=options)

    assert detector.calls == 2
    assert report.findings


def test_a_failed_scan_is_not_cached(tmp_path: Path) -> None:
    broken = tmp_path / "broken.docx"
    broken.write_bytes(b"PK\x03\x04 not a real package")
    cache_directory = tmp_path / "cache"
    options = ScanOptions(cache_directory=cache_directory)
    engine = TrueAIEngine.default(discover_plugins=False)

    first = engine.scan(broken, options=options)
    second = engine.scan(broken, options=options)

    assert any(item.severity == Severity.HIGH for item in first.diagnostics)
    assert [item.code for item in second.diagnostics] == [item.code for item in first.diagnostics]
    assert not list(cache_directory.rglob("*.json")), "a failed scan must not be reusable"


def test_cache_entries_are_scoped_to_the_logical_path(tmp_path: Path) -> None:
    """Identical bytes at different paths carry different finding identities."""

    root = tmp_path / "repository"
    root.mkdir()
    (root / "first.md").write_text(ATTRIBUTION, encoding="utf-8")
    (root / "second.md").write_text(ATTRIBUTION, encoding="utf-8")
    options = ScanOptions(cache_directory=tmp_path / "cache")

    report = TrueAIEngine.default(discover_plugins=False).scan(root, options=options)
    cached = TrueAIEngine.default(discover_plugins=False).scan(root, options=options)

    paths = {finding.artifact_path for finding in cached.findings}
    assert {"first.md", "second.md"} <= paths
    assert [item.id for item in cached.findings] == [item.id for item in report.findings]


def test_cache_clear_removes_every_entry(tmp_path: Path) -> None:
    source = tmp_path / "notes.md"
    source.write_text(ATTRIBUTION, encoding="utf-8")
    cache_directory = tmp_path / "cache"
    engine, _ = counting_engine()
    engine.scan(source, options=ScanOptions(cache_directory=cache_directory))
    cache = ScanCache(cache_directory)

    removed = cache.clear()

    assert removed >= 1
    assert not list(cache_directory.rglob("*.json"))


def test_cache_key_covers_format_version_and_configuration(tmp_path: Path) -> None:
    cache = ScanCache(tmp_path / "cache")
    digest = "a" * 64
    base = {
        "content_sha256": digest,
        "logical_path": "notes.md",
        "artifact_type": ArtifactType.MARKDOWN,
        "detector_ids": ("one.v1", "two.v1"),
        "options_digest": options_fingerprint(ScanOptions()),
    }

    same = cache.key(**base) == cache.key(**{**base, "detector_ids": ("two.v1", "one.v1")})
    different_path = cache.key(**{**base, "logical_path": "other.md"})
    different_detectors = cache.key(**{**base, "detector_ids": ("one.v1",)})

    assert same, "detector order must not change the key"
    assert different_path != cache.key(**base)
    assert different_detectors != cache.key(**base)
    assert CACHE_FORMAT_VERSION == "1"


def test_stored_entry_records_the_key_it_was_written_for(tmp_path: Path) -> None:
    source = tmp_path / "notes.md"
    source.write_text(ATTRIBUTION, encoding="utf-8")
    cache_directory = tmp_path / "cache"
    engine, _ = counting_engine()
    engine.scan(source, options=ScanOptions(cache_directory=cache_directory))

    entries = list(cache_directory.rglob("*.json"))

    assert entries
    payload = json.loads(entries[0].read_text(encoding="utf-8"))
    assert payload["key"] == entries[0].stem
    assert payload["findings"]


@pytest.mark.parametrize("workers", [1, 4])
def test_cache_and_parallelism_compose(tmp_path: Path, workers: int) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    build_tree(root, 8)
    cache_directory = tmp_path / "cache"
    engine = TrueAIEngine.default(discover_plugins=False)
    reference = engine.scan(root)

    engine.scan(root, options=ScanOptions(cache_directory=cache_directory))
    result = engine.scan(
        root,
        options=ScanOptions(cache_directory=cache_directory, max_workers=workers),
    )

    assert [finding.id for finding in result.findings] == [
        finding.id for finding in reference.findings
    ]
