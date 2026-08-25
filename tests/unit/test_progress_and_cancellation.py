"""Progress events and cancellation, and what the core is not allowed to import.

The design claim is that a scanner can report where it is and stop when asked
without the engine knowing what a UI is. Two properties carry that claim: the
core imports nothing from a console library or an event loop, and a caller's
observer cannot break a scan by raising.

The other claim is about honesty. A cancelled scan raises rather than returning
a shorter report, because a shorter report reads exactly like a clean one to
whoever opens it next.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from trueai import TrueAIEngine
from trueai.core.artifact import Artifact
from trueai.core.models import (
    ArtifactType,
    FindingCategory,
    ScanContext,
    ScanOptions,
    Severity,
)
from trueai.core.progress import (
    NEVER_CANCELLED,
    CancellationToken,
    ProgressChannel,
    ProgressEvent,
    ScanCancelled,
    ScanPhase,
)
from trueai.core.registry import DetectorRegistry
from trueai.detectors.base import BaseDetector

ATTRIBUTION = "Generated with ChatGPT\n"


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    root = tmp_path / "corpus"
    root.mkdir()
    for index in range(6):
        (root / f"note{index}.md").write_text(f"{ATTRIBUTION}{index}\n", encoding="utf-8")
    return root


def collected(root: Path, **extra: object) -> tuple[list[ProgressEvent], object]:
    events: list[ProgressEvent] = []
    report = TrueAIEngine.default(discover_plugins=False).scan(
        root, progress=events.append, **extra
    )
    return events, report


# -- the shape of an event -----------------------------------------------------------


def test_a_fraction_is_none_while_the_total_is_unknown() -> None:
    """Inventing a percentage is worse than showing an indeterminate bar."""

    assert ProgressEvent(phase=ScanPhase.DISCOVERY, completed=3).fraction is None
    assert ProgressEvent(phase=ScanPhase.DETECTION, completed=3, total=0).fraction is None


def test_a_fraction_is_bounded_at_one() -> None:
    event = ProgressEvent(phase=ScanPhase.DETECTION, completed=9, total=4)

    assert event.fraction == 1.0


def test_an_event_describes_itself_for_a_log() -> None:
    event = ProgressEvent(
        phase=ScanPhase.DETECTION, completed=2, total=4, artifact_path="a/b.md", findings=1
    )

    described = event.describe()

    assert "detection" in described
    assert "2/4" in described
    assert "50%" in described
    assert "a/b.md" in described


def test_an_event_with_an_unknown_total_says_so() -> None:
    assert "3/?" in ProgressEvent(phase=ScanPhase.DISCOVERY, completed=3).describe()


# -- what a scan reports -------------------------------------------------------------


def test_every_artifact_is_reported_once_in_order(corpus: Path) -> None:
    events, _ = collected(corpus)

    detection = [event for event in events if event.phase is ScanPhase.DETECTION]

    assert [event.completed for event in detection] == list(range(1, len(detection) + 1))
    assert all(event.total == detection[0].total for event in detection)


def test_events_name_the_artifact_and_what_was_found(corpus: Path) -> None:
    events, report = collected(corpus)

    detection = [event for event in events if event.phase is ScanPhase.DETECTION]

    assert {event.artifact_path for event in detection} == {
        descriptor.path for descriptor in report.artifacts
    }
    assert sum(event.findings for event in detection) == len(report.findings)


def test_discovery_and_integrity_are_reported_as_their_own_phases(corpus: Path) -> None:
    events, _ = collected(corpus)

    phases = [event.phase for event in events]

    assert phases[0] is ScanPhase.DISCOVERY
    assert ScanPhase.INTEGRITY in phases
    assert phases[-1] is ScanPhase.INTEGRITY


def test_parallel_detection_still_reports_in_artifact_order(corpus: Path) -> None:
    """Events are emitted from the assembling thread, so no caller needs a lock."""

    events, _ = collected(corpus, options=ScanOptions(max_workers=4))

    detection = [event for event in events if event.phase is ScanPhase.DETECTION]

    assert [event.completed for event in detection] == list(range(1, len(detection) + 1))


def test_events_arrive_one_at_a_time_even_under_parallelism(corpus: Path) -> None:
    concurrent: list[int] = []
    live = 0
    lock = threading.Lock()

    def observe(event: ProgressEvent) -> None:
        nonlocal live
        with lock:
            live += 1
            concurrent.append(live)
        with lock:
            live -= 1

    TrueAIEngine.default(discover_plugins=False).scan(
        corpus, options=ScanOptions(max_workers=4), progress=observe
    )

    assert max(concurrent) == 1


def test_a_scan_without_an_observer_costs_nothing(corpus: Path) -> None:
    report = TrueAIEngine.default(discover_plugins=False).scan(corpus)

    assert report.findings


# -- an observer that misbehaves -----------------------------------------------------


def test_an_observer_that_raises_does_not_fail_the_scan(corpus: Path) -> None:
    """A formatting bug in an interface must not abort a forensic run."""

    def hostile(event: ProgressEvent) -> None:
        raise RuntimeError("the caller's widget exploded")

    report = TrueAIEngine.default(discover_plugins=False).scan(corpus, progress=hostile)

    assert report.findings
    assert any(item.code == "progress_observer_failed" for item in report.diagnostics)


def test_the_failure_is_recorded_rather_than_swallowed(corpus: Path) -> None:
    def hostile(event: ProgressEvent) -> None:
        raise ValueError("bad format string")

    report = TrueAIEngine.default(discover_plugins=False).scan(corpus, progress=hostile)
    diagnostic = next(
        item for item in report.diagnostics if item.code == "progress_observer_failed"
    )

    assert "ValueError" in diagnostic.message
    assert "bad format string" in diagnostic.message
    assert diagnostic.severity is Severity.MEDIUM


def test_a_failing_observer_is_dropped_rather_than_called_again() -> None:
    calls: list[int] = []

    def hostile(event: ProgressEvent) -> None:
        calls.append(1)
        raise RuntimeError("once is enough")

    channel = ProgressChannel(hostile)
    for index in range(5):
        channel.emit(ScanPhase.DETECTION, index)

    assert calls == [1]
    assert channel.failure is not None


def test_a_clean_observer_leaves_no_failure_recorded(corpus: Path) -> None:
    events, report = collected(corpus)

    assert events
    assert not [item for item in report.diagnostics if item.code == "progress_observer_failed"]


# -- cancellation --------------------------------------------------------------------


def test_a_cancelled_scan_raises_rather_than_returning_a_short_report(corpus: Path) -> None:
    """A shorter report is indistinguishable from a clean one to its reader."""

    token = CancellationToken()
    token.cancel("the operator closed the window")

    with pytest.raises(ScanCancelled) as raised:
        TrueAIEngine.default(discover_plugins=False).scan(corpus, cancellation=token)

    assert raised.value.completed == 0
    assert "the operator closed the window" in str(raised.value)


def test_the_exception_says_how_far_the_scan_got(corpus: Path) -> None:
    token = CancellationToken()
    seen: list[str] = []

    def observe(event: ProgressEvent) -> None:
        if event.phase is ScanPhase.DETECTION:
            seen.append(event.artifact_path or "")
            if len(seen) == 2:
                token.cancel("enough")

    with pytest.raises(ScanCancelled) as raised:
        TrueAIEngine.default(discover_plugins=False).scan(
            corpus, progress=observe, cancellation=token
        )

    assert raised.value.completed == 2
    assert raised.value.total >= len(seen)


def test_the_exception_carries_no_findings(corpus: Path) -> None:
    """A partial result handed back through an exception becomes a report."""

    token = CancellationToken()
    token.cancel()

    with pytest.raises(ScanCancelled) as raised:
        TrueAIEngine.default(discover_plugins=False).scan(corpus, cancellation=token)

    assert not hasattr(raised.value, "findings")
    assert not hasattr(raised.value, "report")


def test_cancellation_works_under_parallelism(corpus: Path) -> None:
    token = CancellationToken()
    seen = 0

    def observe(event: ProgressEvent) -> None:
        nonlocal seen
        if event.phase is ScanPhase.DETECTION:
            seen += 1
            if seen == 1:
                token.cancel("stop")

    with pytest.raises(ScanCancelled):
        TrueAIEngine.default(discover_plugins=False).scan(
            corpus, options=ScanOptions(max_workers=4), progress=observe, cancellation=token
        )


def test_a_token_can_be_set_from_another_thread(corpus: Path) -> None:
    token = CancellationToken()
    started = threading.Event()

    def observe(event: ProgressEvent) -> None:
        started.set()

    def canceller() -> None:
        started.wait(timeout=5)
        token.cancel("from another thread")

    worker = threading.Thread(target=canceller)
    worker.start()
    try:
        with pytest.raises(ScanCancelled, match="from another thread"):
            for _ in range(200):
                TrueAIEngine.default(discover_plugins=False).scan(
                    corpus, progress=observe, cancellation=token
                )
    finally:
        worker.join(timeout=5)


def test_a_token_keeps_the_first_reason(corpus: Path) -> None:
    token = CancellationToken()
    token.cancel("first")
    token.cancel("second")

    assert token.reason == "first"
    assert token.cancelled()


def test_a_fresh_token_is_not_cancelled() -> None:
    assert not CancellationToken().cancelled()
    assert not NEVER_CANCELLED.cancelled()


def test_cancellation_is_checked_between_detectors_not_only_between_files(
    tmp_path: Path,
) -> None:
    """One large document can hold a worker a long time; a late cancel is no cancel."""

    token = CancellationToken()
    target = tmp_path / "one.md"
    target.write_text(ATTRIBUTION, encoding="utf-8")

    class Slow(BaseDetector):
        id = "example.slow.v1"
        supported_types = frozenset({ArtifactType.MARKDOWN})
        categories = frozenset({FindingCategory.STRUCTURAL_SIGNAL})

        def scan(self, artifact: Artifact, context: ScanContext) -> list:
            token.cancel("mid-document")
            return []

    registry = DetectorRegistry()
    registry.register(Slow())
    registry.register(Slow2())

    with pytest.raises(ScanCancelled, match="mid-document"):
        TrueAIEngine(registry).scan(target, cancellation=token)


class Slow2(BaseDetector):
    """A second detector, so there is a gap between two of them to stop in."""

    id = "example.slow2.v1"
    supported_types = frozenset({ArtifactType.MARKDOWN})
    categories = frozenset({FindingCategory.STRUCTURAL_SIGNAL})

    def scan(self, artifact: Artifact, context: ScanContext) -> list:
        raise AssertionError("the scan should have stopped before this detector ran")


# -- an interface-free core ----------------------------------------------------------


def test_the_progress_module_imports_no_interface_library() -> None:
    """The whole point: a CI run must not depend on a console library."""

    source = (Path(__file__).resolve().parents[2] / "trueai" / "core" / "progress.py").read_text(
        encoding="utf-8"
    )

    for forbidden in ("rich", "asyncio", "trio", "curses", "tkinter", "PyQt"):
        assert f"import {forbidden}" not in source


def test_the_engine_imports_no_interface_library() -> None:
    source = (Path(__file__).resolve().parents[2] / "trueai" / "core" / "engine.py").read_text(
        encoding="utf-8"
    )

    for forbidden in ("rich", "asyncio", "trio"):
        assert f"import {forbidden}" not in source


def test_cancellation_is_one_method_so_any_framework_can_supply_it(corpus: Path) -> None:
    """An asyncio or trio caller passes its own object, not a threading.Event."""

    class OwnCancellation:
        def __init__(self) -> None:
            self.asked = 0

        def cancelled(self) -> bool:
            self.asked += 1
            return self.asked > 3

    own = OwnCancellation()

    with pytest.raises(ScanCancelled):
        TrueAIEngine.default(discover_plugins=False).scan(corpus, cancellation=own)


def test_a_cancellation_without_a_reason_is_accepted(corpus: Path) -> None:
    class Bare:
        def cancelled(self) -> bool:
            return True

    with pytest.raises(ScanCancelled) as raised:
        TrueAIEngine.default(discover_plugins=False).scan(corpus, cancellation=Bare())

    assert "artifacts" in str(raised.value)
