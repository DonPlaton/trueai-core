"""Progress and cancellation, without the core learning what a UI is.

A scanner that runs for twenty minutes on a large repository has to be able to
say where it is and to stop when asked.  Both are easy to build in a way that
drags a console library, a widget toolkit, or an event loop into the middle of
the engine, and then a headless CI run depends on Rich and an async caller
depends on threads.

So both are protocols with a plain implementation attached:

* **Progress** is one callable taking one frozen :class:`ProgressEvent`.  Not a
  multi-method observer, because every method is one more thing a caller must
  implement and one more place a UI can break a scan.  Events arrive on the
  thread that assembles the report, in artifact order, one at a time, even when
  detectors run in parallel — a caller never needs a lock.
* **Cancellation** is one predicate.  :class:`CancellationToken` implements it
  with :class:`threading.Event`, which is safe to set from any thread; an
  asyncio or trio caller supplies its own object instead.

A cancelled scan **raises**.  It does not return a shorter report, because a
shorter report is indistinguishable from a clean one at the point where it
matters — someone reads it and concludes the repository is fine.  A caller that
wants partial results collects them from the progress events, where they are
partial by construction and cannot be mistaken for anything else.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

from trueai.core.errors import TrueAIError


class ScanPhase(StrEnum):
    """Which part of a scan an event came from."""

    DISCOVERY = "discovery"
    DETECTION = "detection"
    #: The end-of-scan sweep that re-hashes artifacts and re-lists paths.
    INTEGRITY = "integrity"
    #: Policy evaluation and report assembly.
    REPORT = "report"


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    """One thing that finished, and how much of the scan that leaves."""

    phase: ScanPhase
    completed: int
    #: ``None`` while the size of the work is not yet known — during discovery,
    #: nothing can honestly report a percentage, and inventing one is worse than
    #: showing an indeterminate bar.
    total: int | None = None
    artifact_path: str | None = None
    findings: int = 0

    @property
    def fraction(self) -> float | None:
        """Return progress in [0, 1], or ``None`` when the total is unknown."""

        if self.total is None or self.total <= 0:
            return None
        return min(1.0, self.completed / self.total)

    def describe(self) -> str:
        share = "" if self.fraction is None else f" ({self.fraction:.0%})"
        where = f" {self.artifact_path}" if self.artifact_path else ""
        total = "?" if self.total is None else str(self.total)
        return f"{self.phase.value}: {self.completed}/{total}{share}{where}"


class ProgressObserver(Protocol):
    """Anything that can be called with an event."""

    def __call__(self, event: ProgressEvent, /) -> None: ...


class Cancellation(Protocol):
    """Anything that can say whether the caller has asked the scan to stop."""

    def cancelled(self) -> bool: ...


class ScanCancelled(TrueAIError):
    """Raised when a caller stopped a scan before it finished.

    Carries how far it got so an interface can say so, and deliberately carries
    no findings: a partial result handed back through an exception is a partial
    result someone will eventually treat as a report.
    """

    def __init__(self, completed: int, total: int, reason: str = "") -> None:
        detail = f": {reason}" if reason else ""
        super().__init__(f"Scan cancelled after {completed} of {total} artifacts{detail}")
        self.completed = completed
        self.total = total
        self.reason = reason


class CancellationToken:
    """A cancellation flag that is safe to set from another thread."""

    __slots__ = ("_event", "_reason")

    def __init__(self) -> None:
        self._event = threading.Event()
        self._reason = ""

    def cancel(self, reason: str = "") -> None:
        """Ask the scan to stop. Idempotent; the first reason is kept."""

        if not self._event.is_set():
            self._reason = reason
        self._event.set()

    def cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> str:
        return self._reason


#: A cancellation that never fires, so the engine needs no ``if`` around it.
class _NeverCancelled:
    __slots__ = ()

    def cancelled(self) -> bool:
        return False


NEVER_CANCELLED: Final[Cancellation] = _NeverCancelled()


class ProgressChannel:
    """Delivers events to one observer and survives an observer that raises.

    A progress callback belongs to the caller's interface, and interfaces have
    bugs.  One raising inside a scan would abort a forensic run over a
    formatting error, so the first failure is captured, the observer is dropped,
    and the scan records that its progress reporting stopped — visible, and not
    fatal.
    """

    __slots__ = ("_failure", "_observer")

    def __init__(self, observer: ProgressObserver | None = None) -> None:
        self._observer = observer
        self._failure: str | None = None

    def emit(
        self,
        phase: ScanPhase,
        completed: int,
        total: int | None = None,
        *,
        artifact_path: str | None = None,
        findings: int = 0,
    ) -> None:
        if self._observer is None:
            return
        event = ProgressEvent(
            phase=phase,
            completed=completed,
            total=total,
            artifact_path=artifact_path,
            findings=findings,
        )
        try:
            self._observer(event)
        except Exception as exc:  # a caller's interface, not this code
            self._failure = f"{type(exc).__name__}: {exc}"
            self._observer = None

    @property
    def failure(self) -> str | None:
        """The error that stopped progress reporting, if one did."""

        return self._failure


__all__ = [
    "NEVER_CANCELLED",
    "Cancellation",
    "CancellationToken",
    "ProgressChannel",
    "ProgressEvent",
    "ProgressObserver",
    "ScanCancelled",
    "ScanPhase",
]
