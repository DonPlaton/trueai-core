# The terminal surface

What this program draws, why it draws it that way, and how to turn it off.

Everything described here is decoration. None of it changes a finding, an exit
code, a report field, or a byte written to a file, and all of it is skipped when
output is not going to a terminal.

## Turning it off

| How | Effect |
| --- | --- |
| `trueai scan PATH --no-progress` | No progress display for that run |
| `TRUEAI_NO_MOTION=1` | No progress display, no banner, no spectrum, for every run |
| `TERM=dumb` | The same, for a terminal that cannot address the cursor |
| Redirecting output | The same, automatically |
| `NO_COLOR=1` | Colour off, motion unaffected |

`NO_COLOR` is deliberately not a motion switch. It is a statement about colour,
which Rich honours on its own, and somebody who wants plain text still benefits
from knowing a long scan is alive.

## The prism

One thing goes in and what comes out is separated into parts that are not
interchangeable. That is what the engine does to an artifact, and it is why the
report keeps deterministic observations, verified provenance, watermark results
and style measurements apart instead of averaging them into a score. The shape
is the argument.

```
     ▟█▙━━━━━━━━━━━━━━    TrueAI Core 0.1.0
    ▟███▙━━━━━━━━━━━━━━   Local forensic scanning for AI-tooling residue
───▟█████▙━━━━━━━━━━━━━━  Evidence and a confidence class on every finding
   ▀▀▀▀▀▀▀━━━━━━━━━━━━━━  Offline by construction: no telemetry, no scan-time network
```

The body is built from filled quadrant blocks rather than from box-drawing
outlines. An outline made of thin lines reads as several objects with seams
between them; a filled shape reads as one. Each ray leaves from the row of the
body it belongs to, so the fan comes from the geometry rather than from
arbitrary indentation.

## The spectrum is data, not decoration

`trueai doctor` draws one ray per quarter of its checks that passed, counted
from the table it is printed under rather than passed in as an argument. The
count rounds down, for the same reason the progress bar does: rounding up draws
a ray for a check that did not pass. A consequence worth stating, because it is
the point: the full spectrum appears only when everything passed, so a single
failure is visible in the picture and the picture cannot disagree with the rows
above it. A run where nothing passed draws the beam arriving and nothing
leaving.

## The palette

Five stops, in `trueai/cli/motion.py`:

```
#427EC2  #6D7CCA  #867BD1  #9C79CD  #B972D5
```

Four constraints picked them, and
[`tests/unit/test_cli_motion.py`](../tests/unit/test_cli_motion.py) asserts all
four so that a later edit cannot quietly drop one.

**Legible on a light terminal and a dark one.** Every stop keeps at least 3:1
against white, black, `#1E1E1E`, `#FDF6E3`, and `#0C0C0C`. The binding
background is the light solarized ground rather than white: it puts the ceiling
on relative luminance at 0.274, which is exactly why the lightest stop is no
lighter than it is.

**Matte rather than saturated.** Mean HSL saturation is 0.49, against 0.84 for
the first version of this palette. Saturation is most of what makes a colour
read as a default rather than a choice, and the test holds a ceiling rather than
a target so that a later edit cannot reach for a more vivid version of the same
hue.

**Far from anything that carries a verdict.** Green, yellow, red and cyan
already mean something in this program's output: passed, unknown, failed, marker
present. Every stop stays at least 30 CIE76 units from all of them.

That last constraint is what decides where the cool end of the ramp stops. A
true turquoise lands within 15 units of the cyan that means "marker present",
and a muted sea-green within 28 of the green that means "passed", so neither can
be used however well it would look. Hue 212 is as far toward turquoise as the
constraint allows, and that is where the ramp begins.

This replaced an earlier rule that named an allowed range of hues. The range was
a proxy for the thing that actually matters and was wrong at the edges: it
admitted colours that were far away in hue and close in appearance.

**Distinct after quantisation.** A 256-colour terminal maps the five to five
different indices, so the ramp still reads as a ramp where truecolor is
unavailable.

## The motion

Phase is a function of elapsed time rather than of a frame counter. A frame
counter ties the speed of the animation to how often the engine happens to call
back, which is a blur on a directory of small files and a stutter on one large
PDF. Time-based phase looks the same either way, and it makes every curve a pure
function that a test can evaluate without a terminal.

| Where | What moves | When it stops |
| --- | --- | --- |
| Bare `trueai` | The beam arrives, then the spectrum opens, then the text | After 450ms, settled |
| `trueai doctor` | The same, with the ray count the checks earned | After 450ms, settled |
| During a scan | A head sweeps a seven-cell track, dragging a tail | When the scan ends |
| During a scan | The bar's leading edge breathes | When the scan ends |
| During a scan | The bar fills as the engine reports | When the scan ends |

Three curves drive all of it. A raised cosine for the sweep, an exponential
ease-out for anything arriving, and a sine for anything breathing.

**Nothing loops forever in a still terminal.** Every animation is either a
one-time entrance that settles, or tied to work that is actually happening. An
animation that runs while nothing is happening is a thing to look at instead of
a thing to read.

**Only one animation costs a command any time**, the entrance, and only where
the command has nothing else to do: a bare invocation, and `doctor` after its
checks have already run. It is capped at 450ms and measured at 451ms, and it
never sleeps past its own budget. Everything during a scan is driven by the
engine's existing progress callbacks and adds nothing to the scan's duration.

### The sweep

The scanning head sweeps a seven-cell track on a raised cosine. Any round trip
has to stop somewhere to reverse, so the question is how long that stop lasts:
at twelve frames a second this curve holds the end column for four frames, and
the cubic ease it replaced held it for six. A third of a second reads as a turn.
Half a second reads as a hung process.

Two cells behind the head take earlier stops from the ramp. The tail is what
makes the movement read as movement rather than as a character being redrawn one
column over, and it flips to the other side of the head at each turn, which is
the part that says which way the head is going.

### The stagger

The rays of an entrance do not start together. Each one is offset, and the
offsets overlap, so that partway through more than one is in flight. Elements
that all start together arrive as a block, which reads as a screen being
painted; elements that wait their turn read as a list being filled in. Only the
overlap reads as one movement with parts.

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

The leading cell breathes while the scan runs. It is the one part of the bar
that moves without the number changing, and it is what separates a scan that is
working slowly from one that has stopped.

## Consoles that cannot draw it

Every glyph has an ASCII twin, and the two sets keep the same indents and the
same widening, so the fan still fans. The choice is made by asking the output
stream's encoding whether it can represent the drawn set, not by guessing from
the platform: the same Windows machine draws the full set in a UTF-8 terminal
and raises `UnicodeEncodeError` on the first quadrant block under code page
1251.

```
     /\==============    TrueAI Core 0.1.0
    /##\==============   Local forensic scanning for AI-tooling residue
---/####\==============  Evidence and a confidence class on every finding
   ------==============  Offline by construction: no telemetry, no scan-time network
```

The drawn set uses quadrant blocks and heavy rules, which Unicode classifies as
East Asian Ambiguous. So does every character Rich uses for a table, so a
terminal that renders these at double width already renders this program's
tables wrong; the prism adds no new risk to what the project already ships.
