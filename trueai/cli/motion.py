"""The terminal's moving parts: a palette, easing curves, and a prism.

Everything here is decoration, and decoration in a forensic tool has to earn its
place under four rules.

It never claims anything. A bar reports the fraction the engine actually
reported, and when the engine does not yet know the total the bar says so by
drawing an empty track rather than by inventing a percentage. The prism's
spectrum is the proportion of checks that passed, computed from the table it is
printed under, so the picture cannot disagree with the numbers above it.

It never reaches a pipe. Animation is written only when the stream is a
terminal, so a redirected run, a CI log, and the documentation gate all see
exactly the bytes they saw before this module existed.

It never gets in the way. An animation either plays once and settles, or it runs
while real work is happening and stops when the work does. Nothing loops forever
in a still terminal, and the only animation that costs a command any time at all
is the entrance on a bare `trueai`, which has nothing else to do and is capped
at under half a second.

It never breaks a console that cannot draw it. Every glyph has an ASCII twin,
selected by asking the output encoding whether it can represent the drawn one,
because a Windows console under a legacy code page raises rather than degrades.

The motion itself is a function of elapsed time rather than of a frame counter.
A frame counter ties the speed of the animation to how often the engine happens
to call back, which on a fast directory is a blur and on a large PDF is a
stutter. Time-based phase looks the same either way, and it makes every curve
here a pure function that a test can evaluate without a terminal.
"""

from __future__ import annotations

import math
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from rich.console import Console
from rich.progress import ProgressColumn, Task
from rich.text import Text

#: Five stops, a cool blue-violet sweeping to a soft orchid, all matte.  The set
#: is the answer to four constraints rather than a preference, and
#: `tests/unit/test_cli_motion.py` asserts every one of them.
#:
#: Each stop keeps at least 3:1 against white, black, `#1E1E1E`, `#FDF6E3` and
#: `#0C0C0C`, so the palette survives a light terminal as well as a dark one.
#: The ceiling there is the light solarized ground rather than white: it puts
#: relative luminance at 0.274, which is why the lightest stop is no lighter.
#:
#: Each stop stays at least 30 CIE76 units from every colour this program spends
#: on a verdict, because a decoration that looks like a verdict is a lie told in
#: paint.  That distance is what stops the cool end where it does: a true
#: turquoise lands within 15 units of the cyan that means "marker present", and
#: a muted sea-green lands within 28 of the green that means "passed".  Hue 212
#: is as far toward turquoise as the constraint allows.
#:
#: Relative luminance rises across the set so the ramp reads as a ramp, and the
#: five land on five different indices when a 256-colour terminal quantises
#: them.
RAMP: Final[tuple[str, ...]] = (
    "#427EC2",
    "#6D7CCA",
    "#867BD1",
    "#9C79CD",
    "#B972D5",
)

#: The middle of the ramp, for the product's own name and for headings.
BRAND: Final = "#867BD1"

#: A cool slate for text that is present but not the point.  Above 3:1 on every
#: background in the list above, which ordinary `dim` is not.
MUTED: Final = "#6E7A94"

#: How long the one entrance animation is allowed to take.  Short enough that a
#: person who typed `trueai` to read the help does not notice waiting.
ENTRANCE_SECONDS: Final = 0.45

#: About twelve frames a second. Enough for a sweep to read as motion, few
#: enough that the renderer is never the reason a scan is slow.
FRAME_SECONDS: Final = 0.08

#: The share of an entrance the beam gets before the spectrum starts opening.
#: The picture is an argument about order, so the order has to be visible.
BEAM_SHARE: Final = 0.25


def ease_in_out_sine(fraction: float) -> float:
    """Ease a 0..1 fraction along a raised cosine.

    A scanning head that moves at a constant rate and then reverses looks like a
    cursor with a bug. Real heads accelerate away from a turn and decelerate into
    the next one. Any round trip has to stop somewhere in order to reverse, so
    the question is how long that stop lasts: on a seven-cell track at twelve
    frames a second, this curve holds the end column for four frames and a cubic
    ease holds it for six. A third of a second reads as a turn; half a second
    reads as a hung process.
    """

    return (1.0 - math.cos(math.pi * _clamp(fraction))) / 2.0


def ease_out_expo(fraction: float) -> float:
    """Ease a 0..1 fraction so most of the distance is covered early.

    For an entrance: the element arrives quickly and settles, which reads as
    responsive. Linear entrances read as slow at any duration.
    """

    fraction = _clamp(fraction)
    return 1.0 if fraction >= 1.0 else 1.0 - pow(2.0, -10.0 * fraction)


def pulse(phase: float) -> float:
    """Return a 0..1 brightness for a breathing highlight.

    A sine rather than a triangle, so the highlight has no corner at its
    brightest point. Corners are what make a pulse look like a blink.
    """

    return (1.0 - math.cos(2.0 * math.pi * (phase % 1.0))) / 2.0


def stagger(phase: float, index: int, count: int, overlap: float = 0.55) -> float:
    """Return one element's own progress inside a staggered group.

    Elements that all start together arrive as a block, which reads as a screen
    being painted. Offsetting each one and letting the offsets overlap reads as
    one movement with parts, which is what a spectrum leaving a prism is.
    """

    if count <= 1:
        return _clamp(phase)
    span = 1.0 / (count - (count - 1) * overlap)
    start = index * span * (1.0 - overlap)
    return _clamp((phase - start) / span)


def _clamp(value: float) -> float:
    return 0.0 if value < 0.0 else 1.0 if value > 1.0 else value


@dataclass(frozen=True, slots=True)
class Glyphs:
    """One character set, either the drawn one or its ASCII twin."""

    head: str
    trail: str
    track: str
    fill: str
    beam: str
    ray: str
    #: The prism, row by row, as an indent and the solid glyph at it. Indents
    #: differ per row, and that is what gives the spectrum its fan: each ray
    #: starts where its own row of the body ends.
    prism: tuple[tuple[int, str], ...]


#: The drawn set. The body is built from quadrant blocks rather than from box
#: outlines, because an outline made of thin lines reads as several objects with
#: seams between them and a filled shape reads as one.
UNICODE_GLYPHS: Final = Glyphs(
    head="◆",
    trail="◇",
    track="─",
    fill="━",
    beam="─",
    ray="━",
    prism=((5, "▟█▙"), (4, "▟███▙"), (3, "▟█████▙"), (3, "▀▀▀▀▀▀▀")),
)

#: The twin, for a console whose encoding cannot represent the set above.
ASCII_GLYPHS: Final = Glyphs(
    head="*",
    trail="o",
    track="-",
    fill="=",
    beam="-",
    ray="=",
    prism=((5, "/\\"), (4, "/##\\"), (3, "/####\\"), (3, "------")),
)


def glyphs_for(console: Console) -> Glyphs:
    """Pick the character set this console can actually write.

    Asking the stream rather than guessing from the platform: a Windows terminal
    in UTF-8 draws the full set, and the same machine's console under code page
    1251 raises `UnicodeEncodeError` on the first quadrant block.
    """

    encoding = getattr(console.file, "encoding", None) or "ascii"
    probe = (
        UNICODE_GLYPHS.head
        + UNICODE_GLYPHS.ray
        + "".join(glyph for _, glyph in UNICODE_GLYPHS.prism)
    )
    try:
        probe.encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return ASCII_GLYPHS
    return UNICODE_GLYPHS


def motion_wanted(console: Console, *, requested: bool = True) -> bool:
    """Answer whether this run should move anything at all.

    Four ways to say no, in the order a user would expect them to win: the
    command's own flag, `TRUEAI_NO_MOTION` for a shell profile that wants every
    invocation still, `TERM=dumb` for a terminal that cannot address the cursor,
    and finally the stream itself not being a terminal. `NO_COLOR` is
    deliberately not on the list: it is a statement about colour, which Rich
    already honours, and a user who wants plain text still benefits from knowing
    the scan is alive.
    """

    if not requested:
        return False
    if os.environ.get("TRUEAI_NO_MOTION"):
        return False
    if os.environ.get("TERM", "").lower() == "dumb":
        return False
    return bool(console.is_terminal)


def sweep_position(elapsed: float, *, cells: int, period: float = 1.6) -> float:
    """Return where the scanning head sits, as a 0..1 position across the track.

    One period is one round trip. The triangle turns elapsed time into an
    out-and-back, and the ease turns the out-and-back into something that
    accelerates off each turn.
    """

    if cells <= 1 or period <= 0.0:
        return 0.0
    phase = (elapsed % period) / period
    triangle = phase * 2.0 if phase < 0.5 else 2.0 - phase * 2.0
    return ease_in_out_sine(triangle)


def scan_strip(elapsed: float, glyphs: Glyphs, *, cells: int = 7, period: float = 1.6) -> Text:
    """Render the scanning head and the tail it drags behind it.

    The tail is what makes the movement read as movement rather than as a
    character being redrawn in a new column. Cells behind the head take
    successively earlier stops from the ramp, so the strip carries a short
    gradient that points the way the head is travelling.
    """

    strip = Text()
    position = sweep_position(elapsed, cells=cells, period=period)
    head = round(position * (cells - 1))
    forward = (elapsed % period) / period < 0.5
    for index in range(cells):
        distance = (head - index) if forward else (index - head)
        if index == head:
            strip.append(glyphs.head, style=f"bold {RAMP[-1]}")
        elif 0 < distance <= 2:
            strip.append(glyphs.trail, style=RAMP[len(RAMP) - 1 - distance])
        else:
            strip.append(glyphs.track, style=MUTED)
    return strip


def gradient_bar(
    fraction: float, glyphs: Glyphs, *, width: int = 24, elapsed: float | None = None
) -> Text:
    """Render a determinate bar whose fill is the exact fraction given.

    The gradient runs across the filled part only, so the colour says how far
    along the bar the eye is, never how far along the work is. Rounding is toward
    the floor: a bar that rounds up reports a cell of progress that has not
    happened, which is a small lie of the kind this program exists to find.

    ``elapsed`` makes the leading edge breathe. It is the one part of the bar
    that moves without the number changing, and it is what distinguishes a scan
    that is working slowly from one that has stopped.
    """

    fraction = _clamp(fraction)
    filled = int(fraction * width)
    bar = Text()
    for index in range(width):
        if index < filled:
            stop = RAMP[min(len(RAMP) - 1, index * len(RAMP) // max(width, 1))]
            leading = index == filled - 1
            if leading and elapsed is not None:
                bright = pulse(elapsed / 1.2) > 0.5
                bar.append(glyphs.head, style=f"bold {RAMP[-1]}" if bright else stop)
            elif leading:
                bar.append(glyphs.head, style=f"bold {stop}")
            else:
                bar.append(glyphs.fill, style=stop)
        else:
            bar.append(glyphs.track, style=MUTED)
    return bar


def prism(glyphs: Glyphs, *, phase: float = 1.0, rays: int = 4, reach: int = 18) -> Text:
    """Render the prism, a beam arriving, and the spectrum leaving it.

    The shape is the product's argument in one picture: one thing goes in, and
    what comes out is separated into parts that are not interchangeable. That is
    what the engine does to an artifact, and it is why the report keeps its
    evidence classes apart instead of averaging them into a score.

    ``phase`` drives the entrance. The beam arrives first, then each ray extends,
    staggered and overlapping, so the spectrum opens rather than appearing.
    ``rays`` draws fewer than four when fewer than four are true.
    """

    art = Text()
    for index in range(len(glyphs.prism)):
        art.append_text(_prism_row(glyphs, index, phase=phase, rays=rays, reach=reach))
        art.append("\n")
    return art


def _prism_row(glyphs: Glyphs, index: int, *, phase: float, rays: int, reach: int) -> Text:
    """Render one row: the beam if this row carries it, the body, and its ray."""

    indent, glyph = glyphs.prism[index]
    line = Text()
    if index == len(glyphs.prism) - 2:
        arrived = int(indent * ease_out_expo(min(1.0, phase * 2.2)))
        line.append(glyphs.beam * arrived, style=MUTED)
        line.append(" " * (indent - arrived))
    else:
        line.append(" " * indent)
    line.append(glyph, style=RAMP[min(index + 1, len(RAMP) - 1)])
    if index < rays:
        opening = stagger(
            _clamp((phase - BEAM_SHARE) / (1.0 - BEAM_SHARE)), index, len(glyphs.prism)
        )
        extent = int(reach * ease_out_expo(opening))
        line.append(glyphs.ray * extent, style=RAMP[len(glyphs.prism) - 1 - index])
    return line


#: What the banner says beside the prism. Claims kept to what the program can
#: back up, and checked by a test that refuses the ones it cannot.
BANNER_LINES: Final = (
    "Local forensic scanning for AI-tooling residue",
    "Evidence and a confidence class on every finding",
    "Offline by construction: no telemetry, no scan-time network",
)


def banner(version: str, glyphs: Glyphs, *, phase: float = 1.0, reach: int = 14) -> Text:
    """Render the prism with the product's name and what it actually does.

    The text arrives after the spectrum has opened, so the eye follows the beam
    through the prism and out to the words rather than being handed both at once.
    """

    art = Text()
    rows = glyphs.prism
    beside = [f"TrueAI Core {version}", *BANNER_LINES]
    column = max(indent + len(glyph) for indent, glyph in rows) + reach + 2
    for index in range(len(rows)):
        line = _prism_row(glyphs, index, phase=phase, rays=len(rows), reach=reach)
        art.append_text(line)
        text = beside[index] if index < len(beside) else ""
        if text and phase >= 0.55:
            art.append(" " * max(1, column - len(line.plain)))
            art.append(text, style=f"bold {BRAND}" if index == 0 else MUTED)
        art.append("\n")
    return art


def spectrum(passed: int, total: int, glyphs: Glyphs, *, phase: float = 1.0) -> Text:
    """Render the prism with one ray per portion of the checks that passed.

    Read from the table it is printed under rather than from an argument
    somebody chose, so the picture cannot disagree with the numbers above it. A
    run where nothing passed draws the beam arriving and nothing leaving, which
    is the honest image for a tool that cannot separate anything.
    """

    if total <= 0:
        return prism(glyphs, phase=phase, rays=0)
    # Rounded down, for the same reason the progress bar is: rounding up draws a
    # ray for a check that did not pass. It also means the full spectrum appears
    # only when everything passed, so one failure is visible.
    rays = int(len(glyphs.prism) * passed / total)
    return prism(glyphs, phase=phase, rays=rays)


def play(console: Console, render: Callable[[float], Text], *, seconds: float) -> None:
    """Run a one-shot entrance and leave the settled frame on screen.

    Blocking, deliberately: this is only ever called where the command has
    nothing else to do. Anything that happens while real work is running is
    driven by the engine's own callbacks instead, so it costs the scan nothing.

    The final frame is printed normally rather than left inside the live region,
    so the art stays in the scrollback after the animation ends.
    """

    from rich.live import Live

    started = time.monotonic()
    with Live(render(0.0), console=console, refresh_per_second=int(1 / FRAME_SECONDS)) as live:
        while True:
            remaining = seconds - (time.monotonic() - started)
            if remaining <= 0.0:
                break
            live.update(render(1.0 - remaining / seconds))
            # Never sleep past the budget: overshooting by a frame is time the
            # command spent on decoration after the decoration had finished.
            time.sleep(min(FRAME_SECONDS, remaining))
        live.update(render(1.0))


class ScanHeadColumn(ProgressColumn):
    """The head that keeps moving whether or not a total is known.

    Liveness and progress are different claims. A scan that has found no total
    yet is still working, and the head says so without implying a fraction.
    """

    max_refresh = FRAME_SECONDS

    def __init__(self, glyphs: Glyphs) -> None:
        super().__init__()
        self.glyphs = glyphs

    def render(self, task: Task) -> Text:
        if task.finished:
            return Text(self.glyphs.head, style=f"bold {RAMP[-1]}")
        return scan_strip(task.elapsed or 0.0, self.glyphs)


class ScanBarColumn(ProgressColumn):
    """The determinate bar, which stays empty until there is a total to divide by.

    Rich's own bar animates a "pulse" when the total is unknown, which looks like
    progress. This one draws the empty track instead, because the sweeping head
    beside it is already saying the only thing that is true so far.
    """

    max_refresh = FRAME_SECONDS

    def __init__(self, glyphs: Glyphs, *, width: int = 24) -> None:
        super().__init__()
        self.glyphs = glyphs
        self.width = width

    def render(self, task: Task) -> Text:
        if not task.total:
            return Text(self.glyphs.track * self.width, style=MUTED)
        return gradient_bar(
            task.completed / task.total,
            self.glyphs,
            width=self.width,
            elapsed=task.elapsed or 0.0,
        )
