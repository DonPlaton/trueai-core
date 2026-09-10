# The terminal surface

What this program draws, why it draws it that way, and how to turn it off.

Everything described here is decoration. None of it changes a finding, an exit
code, a report field, or a byte written to a file, and all of it is skipped when
output is not going to a terminal.

## Turning it off

| How | Effect |
| --- | --- |
| `trueai scan PATH --no-progress` | No progress display for that run |
| `TRUEAI_NO_MOTION=1` | No progress display, no banner, no mascot, for every run |
| `TERM=dumb` | The same, for a terminal that cannot address the cursor |
| Redirecting output | The same, automatically |
| `NO_COLOR=1` | Colour off, motion unaffected |

`NO_COLOR` is deliberately not a motion switch. It is a statement about colour,
which Rich honours on its own, and somebody who wants plain text still benefits
from knowing a long scan is alive.

## The palette

Five stops, blue through indigo to orchid, in `trueai/cli/motion.py`:

```
#5B54EA  #6366F1  #8B5CF6  #A855F7  #C05BE8
```

Three constraints picked them, and
[`tests/unit/test_cli_motion.py`](../tests/unit/test_cli_motion.py) asserts all
three so that a later edit cannot quietly drop one.

**Legible on a light terminal and a dark one.** Every stop keeps at least 3:1
contrast against white, black, `#1E1E1E`, `#FDF6E3`, and `#0C0C0C`. That band is
narrow: it rules out both the bright cyans that vanish on white and the deep
indigos that vanish on black.

**Distinct after quantisation.** A 256-colour terminal maps the five to five
different indices, so the ramp still reads as a ramp where truecolor is
unavailable.

**Clear of the hues that carry meaning.** Green, yellow, red, and cyan already
say something in this program's output: valid, unknown, invalid, marker present.
A decorative colour in one of those hues reads as a verdict, so the brand sits
in the blue-to-violet arc, between 220 and 320 degrees of hue, away from all
four. It is also nowhere near the orange that other terminal tools use, which
matters only in that a screenshot should not be mistaken for one of them.

## The motion

Phase is a function of elapsed time rather than of a frame counter. A frame
counter ties the speed of the animation to how often the engine happens to call
back, which is a blur on a directory of small files and a stutter on one large
PDF. Time-based phase looks the same either way, and it makes every curve a pure
function that a test can evaluate without a terminal.

The scanning head sweeps a seven-cell track on a raised cosine. Any round trip
has to stop somewhere in order to reverse, so the question is how long that stop
lasts: at twelve frames a second this curve holds the end column for four
frames, and the cubic ease it replaced held it for six. A third of a second
reads as a turn. Half a second reads as a hung process.

Two or three cells behind the head take earlier stops from the ramp. The tail is
what makes the movement read as movement rather than as a character being
redrawn one column over, and it flips to the other side of the head at each
turn, which is the part that says which way the head is going.

## What the bar is allowed to claim

The engine does not know how many artifacts there are until discovery finishes.
Until then Rich's own bar animates a pulse across the full width, which looks
like progress. This one draws the empty track instead and lets the sweeping head
beside it carry the only true statement available, which is that the scan is
running.

Once a total exists the fill is the exact fraction, rounded down. A bar that
rounds up reports a cell of progress that has not happened. That is a small lie,
but it is the same kind of lie this program exists to find in other people's
documents.

## The mascot

A lens, in four poses. The body is identical in all four and only the iris
changes, which is what makes it one character rather than four drawings.

| Pose | Where it appears |
| --- | --- |
| Idle | Beside the banner on a bare `trueai` |
| Clear | Under a `trueai doctor` table with no failures |
| Review | Under a `trueai doctor` table with any failure |
| Refused | Reserved for exit code 2 |

`doctor` reads its own printed table to choose between clear and review rather
than being told which to show, so the face cannot end up smiling over a failed
check.

## Consoles that cannot draw it

Every glyph has an ASCII twin, and the two sets have identical line lengths so
the art keeps its shape either way. The choice is made by asking the output
stream's encoding whether it can represent the drawn set, not by guessing from
the platform: the same Windows machine draws the full set in a UTF-8 terminal
and raises `UnicodeEncodeError` on the first box corner under code page 1251.

The drawn set uses box-drawing characters, which Unicode classifies as East
Asian Ambiguous. So does every character Rich uses for a table, so a terminal
that renders these at double width already renders this program's tables wrong;
the mascot adds no new risk to what the project already ships.
