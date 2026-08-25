"""A bounded cache: what it evicts, in what order, and what it refuses to delete.

The property under test is not "the cache gets smaller". It is that the *same*
inventory, budget, and run produce the *same* victims — never an order that
depends on how a filesystem happens to enumerate a directory or on a timestamp
whose resolution differs between platforms.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from trueai._version import PACKAGE_VERSION, SCHEMA_VERSION
from trueai.cli.app import app
from trueai.core.cache import (
    CACHE_FORMAT_VERSION,
    DEFAULT_MAX_CACHE_BYTES,
    MAX_ENTRY_BYTES,
    SEQUENCE_FILENAME,
    CachedArtifactResult,
    CacheEntry,
    CacheInventory,
    ScanCache,
)

runner = CliRunner()

EMPTY = CachedArtifactResult(findings=(), diagnostics=(), detectors_run=("example.v1",))


def key(prefix: str) -> str:
    return (prefix * 64)[:64]


def stored(cache: ScanCache, *prefixes: str) -> None:
    for prefix in prefixes:
        cache.store(key(prefix), EMPTY)


# -- generations ---------------------------------------------------------------------


def test_one_generation_is_taken_per_instance_not_per_entry(tmp_path: Path) -> None:
    """A counter advanced per entry would cost a read-modify-write per store."""

    cache = ScanCache(tmp_path / "cache")
    stored(cache, "a", "b", "c")

    generations = {entry.generation for entry in cache.inspect().entries}

    assert generations == {cache.generation()}


def test_a_later_instance_takes_a_later_generation(tmp_path: Path) -> None:
    directory = tmp_path / "cache"
    first = ScanCache(directory)
    stored(first, "a")
    second = ScanCache(directory)
    stored(second, "b")

    assert second.generation() == first.generation() + 1


def test_an_instance_that_never_writes_never_advances_the_counter(tmp_path: Path) -> None:
    directory = tmp_path / "cache"
    stored(ScanCache(directory), "a")
    before = (directory / SEQUENCE_FILENAME).read_text(encoding="ascii")

    ScanCache(directory).load(key("z"))

    assert (directory / SEQUENCE_FILENAME).read_text(encoding="ascii") == before


def test_a_corrupt_counter_does_not_stop_the_cache(tmp_path: Path) -> None:
    directory = tmp_path / "cache"
    directory.mkdir()
    (directory / SEQUENCE_FILENAME).write_text("not a number", encoding="ascii")
    cache = ScanCache(directory)

    stored(cache, "a")

    assert cache.generation() == 1
    assert len(cache.inspect().entries) == 1


# -- inspection ----------------------------------------------------------------------


def test_inspection_reports_size_generation_and_versions(tmp_path: Path) -> None:
    cache = ScanCache(tmp_path / "cache")
    stored(cache, "a")

    entry = cache.inspect().entries[0]

    assert entry.key == key("a")
    assert entry.size_bytes > 0
    assert entry.package_version == PACKAGE_VERSION
    assert entry.schema_version == SCHEMA_VERSION
    assert entry.format_version == CACHE_FORMAT_VERSION
    assert entry.reachable()


def test_an_entry_from_another_build_is_reported_as_unreachable(tmp_path: Path) -> None:
    """Its key can never be produced again, so keeping it costs space for nothing."""

    cache = ScanCache(tmp_path / "cache")
    stored(cache, "a")
    path = cache.inspect().entries[0].path
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["package_version"] = "0.0.1-ancient"
    path.write_text(json.dumps(payload), encoding="utf-8")

    inventory = ScanCache(tmp_path / "cache").inspect()

    assert len(inventory.unreachable) == 1
    assert "unreachable" in inventory.explain()


def test_a_damaged_entry_is_named_rather_than_counted_as_a_result(tmp_path: Path) -> None:
    cache = ScanCache(tmp_path / "cache")
    stored(cache, "a")
    cache.inspect().entries[0].path.write_text("{ truncated", encoding="utf-8")

    inventory = ScanCache(tmp_path / "cache").inspect()

    assert inventory.entries == ()
    assert inventory.damaged == [f"{key('a')[:2]}/{key('a')}.json"] or inventory.damaged == (
        f"{key('a')[:2]}/{key('a')}.json",
    )


def test_a_file_the_cache_did_not_write_is_reported_not_removed(tmp_path: Path) -> None:
    directory = tmp_path / "cache"
    directory.mkdir()
    (directory / "notes.txt").write_text("someone else put this here\n", encoding="utf-8")

    inventory = ScanCache(directory).inspect()

    assert inventory.foreign == ("notes.txt",)
    assert "not removed" in inventory.explain()
    assert (directory / "notes.txt").is_file()


def test_a_json_file_in_the_wrong_shard_is_not_treated_as_an_entry(tmp_path: Path) -> None:
    """The shard must match the key, or a path could be anything at all."""

    directory = tmp_path / "cache"
    (directory / "zz").mkdir(parents=True)
    (directory / "zz" / f"{key('a')}.json").write_text("{}", encoding="utf-8")

    inventory = ScanCache(directory).inspect()

    assert inventory.entries == ()
    assert inventory.foreign == (f"zz/{key('a')}.json",)


def test_an_empty_directory_inspects_cleanly(tmp_path: Path) -> None:
    inventory = ScanCache(tmp_path / "absent").inspect()

    assert inventory == CacheInventory()
    assert inventory.total_bytes == 0
    assert "0 entries" in inventory.explain()


# -- eviction order ------------------------------------------------------------------


def aged(cache: ScanCache, prefix: str, generation: int, *, build: str = PACKAGE_VERSION) -> None:
    """Write an entry and rewrite its recorded generation and build."""

    cache.store(key(prefix), EMPTY)
    path = cache.inspect().entries[-1].path
    for entry in cache.inspect().entries:
        if entry.key == key(prefix):
            path = entry.path
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["generation"] = generation
    payload["package_version"] = build
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_unreachable_entries_go_first_whatever_their_age(tmp_path: Path) -> None:
    cache = ScanCache(tmp_path / "cache")
    aged(cache, "a", 1)
    aged(cache, "b", 99, build="0.0.1-ancient")

    order = [entry.key for entry in cache.eviction_order()]

    assert order == [key("b"), key("a")]


def test_untouched_entries_go_before_ones_used_this_run(tmp_path: Path) -> None:
    cache = ScanCache(tmp_path / "cache")
    aged(cache, "a", 1)
    aged(cache, "b", 9)
    cache.load(key("a"))  # used this run despite being older

    order = [entry.key for entry in cache.eviction_order()]

    assert order == [key("b"), key("a")]


def test_within_a_group_the_oldest_generation_goes_first(tmp_path: Path) -> None:
    cache = ScanCache(tmp_path / "cache")
    aged(cache, "c", 3)
    aged(cache, "a", 1)
    aged(cache, "b", 2)

    order = [entry.key for entry in cache.eviction_order()]

    assert order == [key("a"), key("b"), key("c")]


def test_the_key_breaks_a_tie_so_the_order_is_never_ambiguous(tmp_path: Path) -> None:
    """Two entries from one scan share a generation; something must decide."""

    cache = ScanCache(tmp_path / "cache")
    stored(cache, "d", "b", "c", "a")

    order = [entry.key for entry in cache.eviction_order()]

    assert order == sorted(order)


def test_the_order_does_not_depend_on_how_the_directory_is_enumerated(tmp_path: Path) -> None:
    cache = ScanCache(tmp_path / "cache")
    aged(cache, "a", 2)
    aged(cache, "b", 1)
    aged(cache, "c", 2)

    first = [entry.key for entry in cache.eviction_order()]
    shuffled = CacheInventory(entries=tuple(reversed(cache.inspect().entries)))
    second = [entry.key for entry in cache.eviction_order(shuffled)]

    assert first == second


# -- budget --------------------------------------------------------------------------


def test_a_cache_inside_its_budget_evicts_nothing(tmp_path: Path) -> None:
    cache = ScanCache(tmp_path / "cache")
    stored(cache, "a", "b")

    result = cache.enforce_budget()

    assert result.removed == ()
    assert result.remaining_bytes == cache.inspect().total_bytes


def test_a_cache_over_budget_evicts_until_it_fits(tmp_path: Path) -> None:
    cache = ScanCache(tmp_path / "cache", max_bytes=MAX_ENTRY_BYTES)
    for index, prefix in enumerate("abcde"):
        aged(cache, prefix, index)
    inventory = cache.inspect()
    budget = inventory.entries[0].size_bytes * 2
    bounded = ScanCache(tmp_path / "cache", max_bytes=max(budget, MAX_ENTRY_BYTES))
    bounded.max_bytes = budget  # type: ignore[misc]

    result = bounded.enforce_budget()

    assert bounded.inspect().total_bytes <= budget
    assert len(result.removed) == 3
    assert result.bytes_reclaimed > 0


def test_eviction_removes_the_entries_the_published_order_named(tmp_path: Path) -> None:
    cache = ScanCache(tmp_path / "cache")
    for index, prefix in enumerate("abcd"):
        aged(cache, prefix, index)
    inventory = cache.inspect()
    expected = [entry.key for entry in cache.eviction_order(inventory)[:2]]
    cache.max_bytes = inventory.entries[0].size_bytes * 2  # type: ignore[misc]

    result = cache.enforce_budget()

    assert [name.split("/")[-1][: -len(".json")] for name in result.removed] == sorted(expected)


def test_a_budget_smaller_than_one_entry_is_refused(tmp_path: Path) -> None:
    """It could never hold anything, so it is a configuration error not a policy."""

    with pytest.raises(ValueError, match="could never hold anything"):
        ScanCache(tmp_path / "cache", max_bytes=1024)


def test_the_default_budget_is_stated_rather_than_unbounded(tmp_path: Path) -> None:
    assert ScanCache(tmp_path / "cache").max_bytes == DEFAULT_MAX_CACHE_BYTES


def test_the_size_check_does_not_parse_every_entry(tmp_path: Path) -> None:
    """At a hundred thousand entries, parsing to add up sizes costs more than the
    cache saves."""

    cache = ScanCache(tmp_path / "cache")
    stored(cache, "a", "b")
    cache.inspect().entries[0].path.write_text("{ not parseable", encoding="utf-8")

    assert cache.stored_bytes() > 0


def test_evictions_are_counted_in_the_statistics(tmp_path: Path) -> None:
    cache = ScanCache(tmp_path / "cache")
    for index, prefix in enumerate("abc"):
        aged(cache, prefix, index)
    cache.max_bytes = cache.inspect().entries[0].size_bytes  # type: ignore[misc]

    cache.enforce_budget()

    assert cache.statistics().evictions >= 2
    assert "evicted" in cache.statistics().explain()


# -- pruning -------------------------------------------------------------------------


def test_a_prune_with_no_rule_removes_nothing(tmp_path: Path) -> None:
    """A prune that defaulted to deleting everything would make a typo destructive."""

    cache = ScanCache(tmp_path / "cache")
    stored(cache, "a", "b")

    result = cache.prune()

    assert result.removed == ()
    assert len(cache.inspect().entries) == 2


def test_pruning_unreachable_entries_leaves_the_reachable_ones(tmp_path: Path) -> None:
    cache = ScanCache(tmp_path / "cache")
    aged(cache, "a", 1)
    aged(cache, "b", 1, build="0.0.1-ancient")

    result = cache.prune(unreachable_only=True)

    assert len(result.removed) == 1
    assert [entry.key for entry in cache.inspect().entries] == [key("a")]


def test_pruning_by_generation_removes_only_what_is_older(tmp_path: Path) -> None:
    cache = ScanCache(tmp_path / "cache")
    aged(cache, "a", 1)
    aged(cache, "b", 5)

    cache.prune(older_than_generation=5)

    assert [entry.key for entry in cache.inspect().entries] == [key("b")]


def test_pruning_to_fit_uses_the_same_order_as_eviction(tmp_path: Path) -> None:
    cache = ScanCache(tmp_path / "cache")
    for index, prefix in enumerate("abcd"):
        aged(cache, prefix, index)
    inventory = cache.inspect()
    target = inventory.entries[0].size_bytes * 2

    cache.prune(to_fit=target)

    assert cache.inspect().total_bytes <= target


def test_two_rules_together_do_not_double_count(tmp_path: Path) -> None:
    cache = ScanCache(tmp_path / "cache")
    aged(cache, "a", 1, build="0.0.1-ancient")
    aged(cache, "b", 2)

    result = cache.prune(unreachable_only=True, older_than_generation=2)

    assert len(result.removed) == 1
    assert result.bytes_reclaimed > 0


def test_pruning_refuses_a_path_that_became_a_link(tmp_path: Path) -> None:
    """Re-checked at deletion time: a delete that follows a link leaves the cache."""

    from tests.support import create_symlink

    cache = ScanCache(tmp_path / "cache")
    aged(cache, "a", 1, build="0.0.1-ancient")
    entry = cache.inspect().entries[0]
    outside = tmp_path / "precious.json"
    outside.write_text("do not delete me\n", encoding="utf-8")
    entry.path.unlink()
    # The cache entry becomes the link; `outside` is what it points at. Swapped,
    # this asked to create a link *at* a file that already exists, and the
    # FileExistsError read as "this platform has no symlinks".
    create_symlink(entry.path, outside)

    result = cache.prune(unreachable_only=True)

    assert result.removed == ()
    assert outside.is_file()


def test_pruning_never_touches_a_file_the_cache_did_not_write(tmp_path: Path) -> None:
    directory = tmp_path / "cache"
    cache = ScanCache(directory)
    stored(cache, "a")
    (directory / "README.txt").write_text("keep\n", encoding="utf-8")

    cache.prune(to_fit=0)

    assert (directory / "README.txt").is_file()
    assert cache.inspect().entries == ()


def test_a_prune_explains_what_it_did(tmp_path: Path) -> None:
    cache = ScanCache(tmp_path / "cache")
    aged(cache, "a", 1, build="0.0.1-ancient")

    result = cache.prune(unreachable_only=True)

    assert "Removed 1 entries" in result.explain()


# -- the command line ----------------------------------------------------------------


def scanned(tmp_path: Path) -> Path:
    target = tmp_path / "project"
    target.mkdir()
    (target / "note.md").write_text("Generated with ChatGPT\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(target), "--cache"])
    assert result.exit_code in {0, 1}, result.output
    return target


def test_the_cli_reports_what_the_cache_holds(tmp_path: Path) -> None:
    target = scanned(tmp_path)

    result = runner.invoke(app, ["cache", "inspect", str(target), "--entries", "5"])

    assert result.exit_code == 0
    assert "entries" in result.output
    assert "Budget" in result.output
    assert "Eviction order" in result.output


def test_the_cli_refuses_to_prune_without_a_rule(tmp_path: Path) -> None:
    target = scanned(tmp_path)

    result = runner.invoke(app, ["cache", "prune", str(target), "--yes"])

    assert result.exit_code == 2
    assert "Nothing selected" in result.output


def test_the_cli_refuses_to_prune_without_explicit_consent(tmp_path: Path) -> None:
    target = scanned(tmp_path)

    result = runner.invoke(app, ["cache", "prune", str(target), "--unreachable"])

    assert result.exit_code == 2
    assert "--yes" in result.output


def test_the_cli_prunes_when_told_exactly_what_to_do(tmp_path: Path) -> None:
    target = scanned(tmp_path)

    result = runner.invoke(app, ["cache", "prune", str(target), "--to-fit", "0", "--yes"])

    assert result.exit_code == 0
    assert "Removed" in result.output


def test_the_cli_names_files_it_will_not_remove(tmp_path: Path) -> None:
    target = scanned(tmp_path)
    directory = target / ".trueai" / "cache"
    (directory / "stray.log").write_text("not ours\n", encoding="utf-8")

    result = runner.invoke(app, ["cache", "inspect", str(target)])

    assert "left in place" in result.output
    assert (directory / "stray.log").is_file()


# -- the engine keeps the bound ------------------------------------------------------


def test_a_scan_leaves_the_cache_inside_its_budget(tmp_path: Path) -> None:
    from trueai import TrueAIEngine
    from trueai.core.models import ScanOptions

    corpus = tmp_path / "corpus"
    corpus.mkdir()
    for index in range(12):
        (corpus / f"note{index}.md").write_text(
            f"Generated with ChatGPT number {index}\n", encoding="utf-8"
        )
    directory = tmp_path / "cache"
    seed = ScanCache(directory)
    TrueAIEngine.default(discover_plugins=False).scan(
        corpus, options=ScanOptions(cache_directory=directory), cache=seed
    )
    one_entry = seed.inspect().entries[0].size_bytes

    bounded = ScanCache(directory)
    bounded.max_bytes = one_entry * 3  # type: ignore[misc]
    TrueAIEngine.default(discover_plugins=False).scan(
        corpus, options=ScanOptions(cache_directory=directory), cache=bounded
    )

    assert bounded.inspect().total_bytes <= one_entry * 3


def test_a_cache_entry_records_what_eviction_needs(tmp_path: Path) -> None:
    """Everything eviction sorts on comes from the entry, not from the filesystem."""

    cache = ScanCache(tmp_path / "cache")
    stored(cache, "a")
    payload = json.loads(cache.inspect().entries[0].path.read_text(encoding="utf-8"))

    assert {"generation", "package_version", "schema_version", "format_version"} <= set(payload)


def test_an_entry_is_unreachable_when_any_version_moved(tmp_path: Path) -> None:
    """All three versions are part of the key, so any one of them ends the entry."""

    import dataclasses

    entry = CacheEntry(
        key=key("a"),
        path=tmp_path / "x.json",
        size_bytes=10,
        generation=1,
        package_version=PACKAGE_VERSION,
        schema_version=SCHEMA_VERSION,
        format_version=CACHE_FORMAT_VERSION,
    )

    assert entry.reachable()
    for field in ("package_version", "schema_version", "format_version"):
        assert not dataclasses.replace(entry, **{field: "moved-on"}).reachable()
