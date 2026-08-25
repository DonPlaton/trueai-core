"""The parser fuzzer, run short in the suite and proven able to fail.

A fuzz harness nobody runs is a file. This runs a small number of inputs against
every parsing boundary on each test run, so a regression that makes a parser
raise `TypeError` on a truncated header fails the build rather than waiting for
somebody to remember the nightly job.

The more important tests here are the ones that break something on purpose. A
fuzzer that cannot report a failure passes everything, and passing everything is
indistinguishable from working.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[2]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from scripts.fuzz_parsers import (  # noqa: E402
    ALLOWED_REFUSALS,
    FORBIDDEN,
    TARGETS,
    Coverage,
    Target,
    _attempt,
    mutate,
    run,
    self_check,
)

# -- the harness can fail --------------------------------------------------------------


def test_the_self_check_passes() -> None:
    """It asserts the harness reports a broken invariant and an unguarded error."""

    assert self_check() == 0


def test_a_broken_invariant_is_reported(tmp_path: Path) -> None:
    def broken(data: bytes, workspace: Path) -> None:
        raise AssertionError("the parser accepted something it should not have")

    detail = _attempt(Target("x", (b"",), broken), b"", tmp_path)

    assert detail is not None
    assert "invariant broken" in detail


def test_an_unguarded_type_error_is_reported(tmp_path: Path) -> None:
    """The whole point: a parser that assumed structure, not one that refused."""

    def unguarded(data: bytes, workspace: Path) -> None:
        raise TypeError("'NoneType' object is not subscriptable")

    detail = _attempt(Target("x", (b"",), unguarded), b"", tmp_path)

    assert detail is not None
    assert "unguarded TypeError" in detail


def test_a_refusal_is_not_a_failure(tmp_path: Path) -> None:
    def refusing(data: bytes, workspace: Path) -> None:
        raise ValueError("that is not a valid header")

    assert _attempt(Target("x", (b"",), refusing), b"", tmp_path) is None


def test_an_undeclared_exception_is_reported(tmp_path: Path) -> None:
    """A parser may refuse; it may not surprise."""

    class Surprising(Exception):
        pass

    def surprising(data: bytes, workspace: Path) -> None:
        raise Surprising("nobody declared this")

    detail = _attempt(Target("x", (b"",), surprising), b"", tmp_path)

    assert detail is not None
    assert "undeclared Surprising" in detail


def test_the_forbidden_list_does_not_overlap_the_allowed_one() -> None:
    """An exception in both lists would make the classification meaningless."""

    for forbidden in FORBIDDEN:
        assert not issubclass(forbidden, ALLOWED_REFUSALS)


# -- mutation --------------------------------------------------------------------------


def test_mutation_is_reproducible_from_a_seed() -> None:
    """A failure reported from a nightly run has to replay."""

    import random

    first = [mutate(random.Random(4), b"%PDF-1.4\ntrailer\n") for _ in range(20)]
    second = [mutate(random.Random(4), b"%PDF-1.4\ntrailer\n") for _ in range(20)]

    assert first == second


def test_mutation_stays_within_the_size_bound() -> None:
    import random

    from scripts.fuzz_parsers import MAX_INPUT_BYTES

    rng = random.Random(0)
    data = b"x" * 1000
    for _ in range(200):
        data = mutate(rng, data)
        assert len(data) <= MAX_INPUT_BYTES


def test_mutation_of_nothing_still_produces_something() -> None:
    import random

    assert mutate(random.Random(0), b"")


def test_mutation_actually_changes_the_input() -> None:
    import random

    rng = random.Random(1)
    seed = b"%PDF-1.4\ntrailer\nstartxref\n0\n%%EOF\n"
    changed = sum(1 for _ in range(50) if mutate(rng, seed) != seed)

    assert changed >= 45


# -- coverage --------------------------------------------------------------------------


def test_coverage_records_lines_inside_the_package_only() -> None:
    coverage = Coverage(REPOSITORY / "trueai")

    with coverage.measure() as batch:
        from trueai.core.ebml import EbmlError, model_ebml

        # A refusal still executes lines, which is what is being measured.
        with pytest.raises(EbmlError):
            model_ebml(b"\x1a\x45\xdf\xa3\x84\x42\x86\x81\x01")

    assert batch
    assert all(str(REPOSITORY / "trueai") in filename for filename, _ in batch)


def test_coverage_reports_whether_an_input_reached_anything_new() -> None:
    coverage = Coverage(REPOSITORY / "trueai")
    batch = {("f", 1), ("f", 2)}

    assert coverage.absorb(set(batch))
    assert not coverage.absorb(set(batch))
    assert coverage.absorb({("f", 3)})


def test_measuring_leaves_the_monitoring_tool_free() -> None:
    """Otherwise a second run would fail to acquire the tool id."""

    coverage = Coverage(REPOSITORY / "trueai")
    with coverage.measure():
        pass
    with coverage.measure():
        pass

    assert sys.monitoring.get_tool(Coverage.TOOL_ID) is None


# -- every boundary is actually fuzzed -------------------------------------------------


def test_every_named_boundary_has_a_target() -> None:
    """The backlog names ten; a missing one would be an untested parser."""

    assert set(TARGETS) == {
        "opc",
        "xml",
        "pdf",
        "iso_bmff",
        "ebml",
        "cache",
        "policy_bundle",
        "certificate",
        "report",
        "git_scope",
    }


def test_every_target_starts_from_a_seed_that_is_not_empty() -> None:
    """A seed that fails on its first field never reaches the interesting code."""

    for name, target in TARGETS.items():
        assert target.seeds, name
        assert all(seed for seed in target.seeds), name


@pytest.mark.parametrize("name", sorted(TARGETS))
def test_a_short_run_of_each_boundary_finds_nothing(name: str, tmp_path: Path) -> None:
    """Short on purpose: this is a regression gate, not the nightly run."""

    findings, _ = run(seed=20260825, iterations=60, targets=(name,), workspace=tmp_path)

    assert findings == [], [item.render(20260825) for item in findings]


def test_the_seeds_themselves_pass_every_target(tmp_path: Path) -> None:
    """A seed that already fails would report a finding on every run."""

    for name, target in TARGETS.items():
        for index, seed in enumerate(target.seeds):
            case = tmp_path / f"{name}{index}"
            case.mkdir(parents=True, exist_ok=True)
            assert _attempt(target, seed, case) is None, name


def test_an_unknown_target_is_refused() -> None:
    with pytest.raises(SystemExit, match="Unknown target"):
        run(seed=1, iterations=1, targets=("not-a-boundary",))


def test_coverage_is_measured_in_both_modes_so_they_are_comparable(tmp_path: Path) -> None:
    """The claim in the docstring is a measurement, so both sides must be measured."""

    _, guided = run(seed=7, iterations=40, targets=("ebml",), workspace=tmp_path, guided=True)
    _, blind = run(seed=7, iterations=40, targets=("ebml",), workspace=tmp_path, guided=False)

    assert guided > 0
    assert blind > 0
