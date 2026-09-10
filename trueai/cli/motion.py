"""The terminal's moving parts: a palette, easing curves, and a mascot.

Everything here is decoration, and decoration in a forensic tool has to earn
its place under three rules.

It never claims anything. A bar reports the fraction the engine actually
reported and nothing else, and when the engine does not yet know the total the
bar says so by sweeping rather than by inventing a percentage. The mascot has
poses for a clear result, a result needing review, and a refusal, and each pose
is chosen from the exit code rather than from a guess about what the user
probably wants to see.

It never reaches a pipe. Animation is written to stderr and only when stderr is
a terminal, so a redirected run, a CI log, and the documentation gate all see
exactly the bytes they saw before this module existed.

It never breaks a console that cannot draw it. Every glyph has an ASCII twin,
selected by asking the output encoding whether it can represent the Unicode one,
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
from dataclasses import dataclass
from typing import Final

from rich.console import Console
from rich.progress import ProgressColumn, Task
from rich.text import Text

#: Five stops from blue through indigo to orchid.  The constraints are narrow
#: enough that the set is close to forced: every stop keeps at least 3:1 against
#: white, black, `#1E1E1E`, `#FDF6E3` and `#0C0C0C`, so the palette survives a
#: light terminal and a dark one; the relative luminances rise monotonically so
#: the ramp reads as a ramp rather than as five unrelated colours; and the five
#: land on five different indices when a 256-colour terminal quantises them.
#: The hues avoid green, yellow, red, and cyan because this program already
#: spends those on verdicts, and a decorative colour that looks like a verdict
#: is a lie told in paint.
RAMP: Final[tuple[str, ...]] = (
    "#5B54EA",
    "#6366F1",
    "#8B5CF6",
    "#A855F7",
    "#C05BE8",
)

#: The middle of the ramp, for the product's own name and for headings.
BRAND: Final = "#8B5CF6"

#: Slate, for text that is present but not the point.  Also above 3:1 on every
#: background in the list above, which ordinary `dim` is not.
MUTED: Final = "#64748B"


def ease_in_out_sine(fraction: float) -> float:
    """Ease a 0..1 fraction along a raised cosine.

    A scanning head that moves at a constant rate and then reverses looks like
    a cursor with a bug. Real heads accelerate away from a turn and decelerate
    into the next one. Any round trip has to stop somewhere to reverse, so the
    question is how long that stop lasts: on a seven-cell track at twelve
    frames a second, this curve holds the end column for four frames and a
    cubic ease holds it for six. A third of a second reads as a turn; half a
    second reads as a hung process.
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


def _clamp(value: float) -> float:
    return 0.0 if value < 0.0 else 1.0 if value > 1.0 else value


@dataclass(frozen=True, slots=True)
class Glyphs:
    """One character set, either the drawn one or its ASCII twin."""

    head: str
    trail: str
    track: str
    fill: str
    lens: tuple[str, ...]
    iris: dict[str, str]


#: The drawn set. Box drawing is East Asian Ambiguous, as is every character
#: Rich itself uses for a table, so a terminal that renders these at double
#: width already renders this program's tables wrong; the set below adds no new
#: risk to what the project already ships.
UNICODE_GLYPHS: Final = Glyphs(
    head="◉",
    trail="○",
    track="─",
    fill="━",
    lens=(
        "   ╭───────╮   ",
        "  ╱ ┌─────┐ ╲  ",
        " │  │{iris}│  │ ",
        "  ╲ └─────┘ ╱  ",
        "   ╰──┬─┬──╯   ",
        "      ╰─╯      ",
    ),
    iris={
        "idle": "  ◉  ",
        "clear": "  ◡  ",
        "review": "  ◔  ",
        "refused": "  ◌  ",
    },
)

#: The twin, for a console whose encoding cannot represent the set above.
ASCII_GLYPHS: Final = Glyphs(
    head="O",
    trail="o",
    track="-",
    fill="=",
    lens=(
        "   .-------.   ",
        "  / +-----+ \\  ",
        " |  |{iris}|  | ",
        "  \\ +-----+ /  ",
        "   '--+-+--'   ",
        "      '-'      ",
    ),
    iris={
        "idle": "  O  ",
        "clear": "  u  ",
        "review": "  c  ",
        "refused": "  x  ",
    },
)


def glyphs_for(console: Console) -> Glyphs:
    """Pick the character set this console can actually write.

    Asking the stream rather than guessing from the platform: a Windows
    terminal in UTF-8 draws the full set, and the same machine's console under
    code page 1251 raises `UnicodeEncodeError` on the first box corner.
    """

    encoding = getattr(console.file, "encoding", None) or "ascii"
    probe = UNICODE_GLYPHS.head + UNICODE_GLYPHS.lens[0] + UNICODE_GLYPHS.iris["clear"]
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


def gradient_bar(fraction: float, glyphs: Glyphs, *, width: int = 24) -> Text:
    """Render a determinate bar whose fill is the exact fraction given.

    The gradient runs across the filled part only, so the colour says how far
    along the bar the eye is, never how far along the work is. Rounding is
    toward the floor: a bar that rounds up reports a cell of progress that has
    not happened, which is a small lie of the kind this program exists to find.
    """

    fraction = _clamp(fraction)
    filled = int(fraction * width)
    bar = Text()
    for index in range(width):
        if index < filled:
            stop = RAMP[min(len(RAMP) - 1, index * len(RAMP) // max(width, 1))]
            leading = index == filled - 1
            bar.append(
                glyphs.head if leading else glyphs.fill, style=f"bold {stop}" if leading else stop
            )
        else:
            bar.append(glyphs.track, style=MUTED)
    return bar


def mascot(pose: str, glyphs: Glyphs, *, iris_offset: int | None = None) -> Text:
    """Render the lens in one of its poses.

    The body never changes between poses, only the iris. That is what makes it
    a character rather than four unrelated drawings, and it means the animated
    pose can move the iris inside a body that stays still, which is the part
    that reads as alive.
    """

    window = glyphs.iris.get(pose, glyphs.iris["idle"])
    if iris_offset is not None:
        span = len(window)
        column = max(0, min(span - 1, iris_offset))
        window = "".join(glyphs.head if i == column else " " for i in range(span))
    art = Text()
    for line, template in enumerate(glyphs.lens):
        style = RAMP[min(line, len(RAMP) - 1)]
        art.append(template.format(iris=window), style=style)
        art.append("\n")
    return art


class ScanHeadColumn(ProgressColumn):
    """The head that keeps moving whether or not a total is known.

    Liveness and progress are different claims. A scan that has found no total
    yet is still working, and the head says so without implying a fraction.
    """

    max_refresh = 0.08  # about twelve frames a second, which is enough for a sweep

    def __init__(self, glyphs: Glyphs) -> None:
        super().__init__()
        self.glyphs = glyphs

    def render(self, task: Task) -> Text:
        if task.finished:
            return Text(self.glyphs.head, style=f"bold {RAMP[-1]}")
        return scan_strip(task.elapsed or 0.0, self.glyphs)


class ScanBarColumn(ProgressColumn):
    """The determinate bar, which stays empty until there is a total to divide by.

    Rich's own bar animates a "pulse" when the total is unknown, which looks
    like progress. This one draws the empty track instead, because the sweeping
    head beside it is already saying the only thing that is true so far.
    """

    def __init__(self, glyphs: Glyphs, *, width: int = 24) -> None:
        super().__init__()
        self.glyphs = glyphs
        self.width = width

    def render(self, task: Task) -> Text:
        if not task.total:
            return Text(self.glyphs.track * self.width, style=MUTED)
        return gradient_bar(task.completed / task.total, self.glyphs, width=self.width)


#: What the banner says beside the lens. Four lines because the art is six and
#: two of them are the stand; claims are kept to what the program can back up.
BANNER_LINES: Final = (
    "Local forensic scanning for AI-tooling residue",
    "Evidence and a confidence class on every finding",
    "Offline by construction: no telemetry, no scan-time network",
)


def banner(version: str, glyphs: Glyphs) -> Text:
    """Render the lens with the product's name and what it actually does.

    Printed only to a terminal, so no script ever has to parse around it.
    """

    art = Text()
    body = list(glyphs.lens)
    beside = ["", f"TrueAI Core {version}", *BANNER_LINES, ""]
    for index, template in enumerate(body):
        art.append(template.format(iris=glyphs.iris["idle"]), style=RAMP[min(index, len(RAMP) - 1)])
        text = beside[index] if index < len(beside) else ""
        if text:
            art.append("  ")
            art.append(text, style=f"bold {BRAND}" if index == 1 else MUTED)
        art.append("\n")
    return art


def pose_for_exit(code: int) -> str:
    """Map an exit code to a pose.

    Read from the code the program is about to return rather than from a count
    of findings, so the face and the exit status can never disagree.
    """

    return {0: "clear", 1: "review", 2: "refused"}.get(code, "idle")
