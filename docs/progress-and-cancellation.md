# Progress and cancellation, without the core learning what a UI is

A scan of a large repository runs for minutes. It has to be able to say where it
is and to stop when asked. Both are easy to build in a way that drags a console
library, a widget toolkit, or an event loop into the middle of the engine — and
then a headless CI run depends on Rich and an async caller depends on threads.

So both are protocols, each with one member, and a plain implementation attached.

## Progress is one callable

```python
from trueai.core.progress import ProgressEvent, ScanPhase

def observe(event: ProgressEvent) -> None:
    print(event.describe())

report = engine.scan(path, progress=observe)
```

Not a multi-method observer: every method is one more thing a caller must
implement and one more place an interface can break a scan.

A `ProgressEvent` is frozen and carries a phase (`discovery`, `detection`,
`integrity`, `report`), how many units are done, the total when it is known, the
artifact just finished, and how many findings it produced.

`fraction` is `None` while the total is unknown. During discovery nothing can
honestly report a percentage, and inventing one is worse than showing an
indeterminate bar.

### Two guarantees a caller can rely on

**Events arrive in artifact order**, even with `--jobs 8`. They are emitted from
the thread that assembles the report, not from the worker that did the scanning.

**Events arrive one at a time.** A caller never needs a lock inside an observer.

### An observer that raises does not fail the scan

A progress callback belongs to the caller's interface, and interfaces have bugs.
One raising inside a scan would abort a forensic run over a formatting error, so
the first failure is captured, the observer is dropped, and the report carries a
`progress_observer_failed` diagnostic naming the exception. Visible, and not
fatal.

## Cancellation is one predicate

```python
from trueai.core.progress import CancellationToken, ScanCancelled

token = CancellationToken()          # threading.Event inside; set it from anywhere
try:
    report = engine.scan(path, cancellation=token)
except ScanCancelled as stopped:
    print(f"stopped after {stopped.completed} of {stopped.total}")
```

`Cancellation` is a protocol with a single `cancelled()` method, so an asyncio or
trio caller supplies its own object rather than being handed a `threading.Event`.
A reason is optional and read only if the object has one.

The token is polled **between artifacts and between detectors**. One large
document can occupy a worker for a long time, and a cancel that only takes effect
at the next file is not a cancel.

### A cancelled scan raises

It does not return a shorter report. A shorter report is indistinguishable from a
clean one at the point where it matters: someone opens it and concludes the
repository is fine. `ScanCancelled` carries how far the scan got and deliberately
carries **no findings** — a partial result handed back through an exception is a
partial result someone will eventually treat as a report.

A caller that wants partial results collects them from the progress events, where
they are partial by construction and cannot be mistaken for anything else.

## On the command line

`trueai scan` shows a progress bar when standard error is a terminal, and does
not when output is redirected — progress written into a pipe is noise in a log
and breaks anything parsing the stream. `--no-progress` turns it off explicitly.

Ctrl-C sets the token rather than raising through the middle of a scan, so an
interrupted run reports how far it got and exits `130` instead of printing a
traceback.

Rich lives in the CLI layer and nowhere near the engine. That is the whole point:
the core emits frozen events and polls a one-method predicate, and a CI run, a
desktop client, and this terminal each render them their own way.
