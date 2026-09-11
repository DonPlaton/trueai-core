"""The terminal's decoration, held to the same rules as everything else.

Four kinds of claim are tested here. That the curves are curves, which is what
separates motion somebody designed from a character being redrawn in a new
column. That the palette still satisfies the constraints it was chosen under,
because a later edit that picks a prettier colour has no other way of finding
out it broke the light-terminal case or drifted into a verdict colour. That
none of it can overstate: a bar with no total draws no progress, a bar never
rounds a fraction up, and the prism's spectrum is computed from the checks
rather than chosen. And that none of it gets in the way: nothing moves when the
output is going somewhere other than a terminal, and the one animation that
blocks is bounded.
"""

from __future__ import annotations

import io
import time
from collections.abc import Callable
from itertools import groupby

import pytest
from rich.console import Console
from rich.progress import Progress

from trueai.cli import motion

#: How the colours this program spends on verdicts actually render, taken from
#: the Campbell scheme that Windows Terminal and VS Code both ship.
VERDICT_COLOURS = {
    "green": "#0DBC79",
    "bright green": "#23D18B",
    "yellow": "#E5E510",
    "red": "#CD3131",
    "bright red": "#F14C4C",
    "cyan": "#11A8CD",
    "bright cyan": "#29B8DB",
}

BACKGROUNDS = ("#FFFFFF", "#000000", "#1E1E1E", "#FDF6E3", "#0C0C0C")


def _channels(colour: str) -> list[float]:
    raw = colour.lstrip("#")
    return [int(raw[index : index + 2], 16) / 255 for index in (0, 2, 4)]


def _linear(value: float) -> float:
    return value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4


def _relative_luminance(colour: str) -> float:
    red, green, blue = (_linear(value) for value in _channels(colour))
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def _contrast(one: str, other: str) -> float:
    first, second = _relative_luminance(one), _relative_luminance(other)
    return (max(first, second) + 0.05) / (min(first, second) + 0.05)


def _lab(colour: str) -> tuple[float, float, float]:
    red, green, blue = (_linear(value) for value in _channels(colour))
    x = (0.4124 * red + 0.3576 * green + 0.1805 * blue) / 0.95047
    y = 0.2126 * red + 0.7152 * green + 0.0722 * blue
    z = (0.0193 * red + 0.1192 * green + 0.9505 * blue) / 1.08883

    def f(value: float) -> float:
        return value ** (1 / 3) if value > 0.008856 else 7.787 * value + 16 / 116

    fx, fy, fz = f(x), f(y), f(z)
    return (116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz))


def _difference(one: str, other: str) -> float:
    """CIE76 colour difference. Rough, and far more than rough enough here."""

    return sum((a - b) ** 2 for a, b in zip(_lab(one), _lab(other), strict=True)) ** 0.5


class TestTheCurves:
    def test_every_curve_stays_inside_its_range(self) -> None:
        for step in range(0, 101):
            fraction = step / 100
            assert 0.0 <= motion.ease_in_out_sine(fraction) <= 1.0
            assert 0.0 <= motion.ease_out_expo(fraction) <= 1.0
            assert 0.0 <= motion.pulse(fraction) <= 1.0

    def test_a_fraction_outside_the_range_is_clamped_rather_than_extrapolated(self) -> None:
        assert motion.ease_in_out_sine(-5.0) == 0.0
        assert motion.ease_in_out_sine(9.0) == 1.0
        assert motion.ease_out_expo(-1.0) == 0.0
        assert motion.ease_out_expo(2.0) == 1.0

    def test_the_ease_rises_without_ever_going_backwards(self) -> None:
        values = [motion.ease_in_out_sine(step / 200) for step in range(201)]
        assert values == sorted(values)
        assert values[0] == 0.0
        assert values[-1] == 1.0

    def test_the_head_pauses_to_turn_rather_than_stalling(self) -> None:
        """Measured where it matters: consecutive frames landing on one column.

        A round trip has to stop somewhere to reverse, so the question is not
        whether the head ever pauses but for how long. At twelve frames a second
        over a 1.6 second period the sine ease holds a column for at most four
        frames, a third of a second, which reads as a turn. A cubic ease holds
        it for six, half a second, which reads as a hung process.
        """

        def dwell(ease: Callable[[float], float]) -> int:
            columns = []
            for frame in range(64):
                phase = ((frame / 12.0) % 1.6) / 1.6
                triangle = phase * 2 if phase < 0.5 else 2 - phase * 2
                columns.append(round(ease(triangle) * 6))
            return max(len(list(group)) for _, group in groupby(columns))

        def cubic(fraction: float) -> float:
            return 4 * fraction**3 if fraction < 0.5 else 1 - (-2 * fraction + 2) ** 3 / 2

        assert dwell(motion.ease_in_out_sine) <= 4
        assert dwell(motion.ease_in_out_sine) < dwell(cubic)

    def test_the_entrance_ease_front_loads_its_travel(self) -> None:
        """Half the duration has to have covered well over half the distance.

        That is the difference between an element that arrives and settles and
        one that slides in at a constant rate, which reads as slow whatever the
        duration is.
        """

        assert motion.ease_out_expo(0.5) > 0.9
        assert motion.ease_out_expo(0.25) > 0.8

    def test_the_ease_is_symmetric_about_its_middle(self) -> None:
        for step in range(51):
            fraction = step / 100
            mirrored = motion.ease_in_out_sine(1.0 - fraction)
            assert mirrored == pytest.approx(1.0 - motion.ease_in_out_sine(fraction))

    def test_the_pulse_has_no_corner_at_its_brightest(self) -> None:
        assert motion.pulse(0.5) == pytest.approx(1.0)
        assert abs(motion.pulse(0.5) - motion.pulse(0.49)) < 0.01

    def test_the_pulse_repeats_every_whole_phase(self) -> None:
        assert motion.pulse(0.25) == pytest.approx(motion.pulse(1.25))
        assert motion.pulse(0.0) == pytest.approx(motion.pulse(3.0))


class TestTheStagger:
    def test_the_first_element_leads_and_the_last_one_trails(self) -> None:
        early = [motion.stagger(0.3, index, 4) for index in range(4)]
        assert early == sorted(early, reverse=True)

    def test_everything_has_arrived_by_the_end(self) -> None:
        assert [motion.stagger(1.0, index, 4) for index in range(4)] == [1.0, 1.0, 1.0, 1.0]

    def test_nothing_has_started_at_the_beginning(self) -> None:
        assert [motion.stagger(0.0, index, 4) for index in range(4)] == [0.0, 0.0, 0.0, 0.0]

    def test_the_offsets_overlap_rather_than_queueing(self) -> None:
        """Elements that wait their turn read as a list being filled in.

        Overlapping means that partway through, more than one is in flight.
        """

        moving = [index for index in range(4) if 0.0 < motion.stagger(0.45, index, 4) < 1.0]
        assert len(moving) >= 2

    def test_a_group_of_one_is_just_the_phase(self) -> None:
        assert motion.stagger(0.37, 0, 1) == pytest.approx(0.37)


class TestThePaletteConstraints:
    """The palette answers four constraints; a later edit has to keep them."""

    def test_every_stop_is_legible_on_a_light_and_a_dark_terminal(self) -> None:
        for stop in (*motion.RAMP, motion.BRAND, motion.MUTED):
            for background in BACKGROUNDS:
                ratio = _contrast(stop, background)
                assert ratio >= 3.0, f"{stop} on {background} is {ratio:.2f}:1"

    def test_no_stop_can_be_mistaken_for_a_verdict(self) -> None:
        """Green, yellow, red and cyan mean something in this program's output.

        A decoration in one of those colours reads as a verdict, so every brand
        colour stays a clear perceptual distance from all of them. This replaced
        a rule about hue ranges, which was a proxy for the thing that actually
        matters and was wrong at the edges: it admitted colours that were far in
        hue and close in appearance.
        """

        for stop in (*motion.RAMP, motion.BRAND, motion.MUTED):
            for name, verdict in VERDICT_COLOURS.items():
                difference = _difference(stop, verdict)
                assert difference >= 30, f"{stop} is {difference:.0f} from {name}"

    def test_the_ramp_gets_lighter_in_one_direction(self) -> None:
        luminances = [_relative_luminance(stop) for stop in motion.RAMP]
        assert luminances == sorted(luminances)

    def test_the_stops_survive_a_256_colour_terminal_as_separate_colours(self) -> None:
        from rich.color import Color

        quantised = {Color.parse(stop).downgrade(2).number for stop in motion.RAMP}
        assert len(quantised) == len(motion.RAMP)

    def test_the_palette_is_matte_rather_than_saturated(self) -> None:
        """The first palette was neon, which is what makes a colour read as generic.

        Held as a ceiling rather than a target: anything under this is a matte
        colour, and the bound is what stops a later edit reaching for a more
        vivid version of the same hue.
        """

        import colorsys

        saturations = [colorsys.rgb_to_hls(*_channels(stop))[2] for stop in motion.RAMP]
        assert max(saturations) <= 0.60, f"most saturated stop is {max(saturations):.2f}"
        assert sum(saturations) / len(saturations) <= 0.55

    def test_the_brand_colour_is_one_of_the_ramp_stops(self) -> None:
        assert motion.BRAND in motion.RAMP


class TestTheSweep:
    def test_one_period_is_one_round_trip(self) -> None:
        assert motion.sweep_position(0.0, cells=7, period=1.6) == pytest.approx(0.0)
        assert motion.sweep_position(0.8, cells=7, period=1.6) == pytest.approx(1.0)
        assert motion.sweep_position(1.6, cells=7, period=1.6) == pytest.approx(0.0)

    def test_a_degenerate_track_or_period_does_not_divide_by_zero(self) -> None:
        assert motion.sweep_position(3.0, cells=1, period=1.6) == 0.0
        assert motion.sweep_position(3.0, cells=7, period=0.0) == 0.0

    def test_the_head_covers_every_column_of_the_track(self) -> None:
        seen = {
            round(motion.sweep_position(step * 1.6 / 400, cells=7, period=1.6) * 6)
            for step in range(400)
        }
        assert seen == set(range(7))

    def test_the_strip_shows_exactly_one_head(self) -> None:
        glyphs = motion.UNICODE_GLYPHS
        for step in range(64):
            strip = motion.scan_strip(step * 1.6 / 64, glyphs, cells=7).plain
            assert strip.count(glyphs.head) == 1
            assert len(strip) == 7

    def test_the_tail_follows_the_head_and_changes_side_at_the_turn(self) -> None:
        glyphs = motion.UNICODE_GLYPHS
        outward = motion.scan_strip(0.4, glyphs, cells=7).plain
        back = motion.scan_strip(1.2, glyphs, cells=7).plain
        assert outward.index(glyphs.head) > outward.index(glyphs.trail)
        assert back.index(glyphs.head) < back.index(glyphs.trail)

    def test_the_strip_is_coloured_from_the_ramp_and_nothing_else(self) -> None:
        strip = motion.scan_strip(0.5, motion.UNICODE_GLYPHS, cells=7)
        allowed = {*motion.RAMP, motion.MUTED}
        for span in strip.spans:
            assert str(span.style).replace("bold ", "") in allowed


class TestTheBarNeverOverstates:
    def test_an_empty_bar_has_no_fill(self) -> None:
        glyphs = motion.UNICODE_GLYPHS
        assert motion.gradient_bar(0.0, glyphs, width=24).plain == glyphs.track * 24

    def test_a_full_bar_has_no_track_left(self) -> None:
        glyphs = motion.UNICODE_GLYPHS
        assert glyphs.track not in motion.gradient_bar(1.0, glyphs, width=24).plain

    def test_a_fraction_short_of_the_end_never_rounds_up_to_full(self) -> None:
        glyphs = motion.UNICODE_GLYPHS
        for fraction in (0.9, 0.95, 0.99, 0.999):
            bar = motion.gradient_bar(fraction, glyphs, width=24).plain
            assert glyphs.track in bar, f"{fraction} drew a full bar"

    def test_the_fill_grows_with_the_fraction_and_never_shrinks(self) -> None:
        glyphs = motion.UNICODE_GLYPHS
        widths = [
            len(motion.gradient_bar(step / 50, glyphs, width=24).plain.replace(glyphs.track, ""))
            for step in range(51)
        ]
        assert widths == sorted(widths)

    def test_a_fraction_outside_the_range_is_clamped(self) -> None:
        glyphs = motion.UNICODE_GLYPHS
        assert motion.gradient_bar(-2.0, glyphs, width=8).plain == glyphs.track * 8
        assert glyphs.track not in motion.gradient_bar(4.0, glyphs, width=8).plain

    def test_the_leading_edge_breathes_without_the_number_moving(self) -> None:
        """What distinguishes a slow scan from a stopped one.

        The fill length is identical in both frames, so nothing about the
        reported fraction changed; only the colour of the leading cell did.
        """

        glyphs = motion.UNICODE_GLYPHS
        dim = motion.gradient_bar(0.5, glyphs, width=24, elapsed=0.0)
        bright = motion.gradient_bar(0.5, glyphs, width=24, elapsed=0.6)

        assert dim.plain == bright.plain
        assert [str(span.style) for span in dim.spans] != [str(span.style) for span in bright.spans]

    def test_a_task_with_no_total_draws_an_empty_track_rather_than_a_pulse(self) -> None:
        glyphs = motion.UNICODE_GLYPHS
        column = motion.ScanBarColumn(glyphs, width=12)
        progress = Progress(column)
        task_id = progress.add_task("scanning", total=None)

        assert column.render(progress.tasks[0]).plain == glyphs.track * 12
        progress.update(task_id, total=10, completed=5)
        assert glyphs.fill in column.render(progress.tasks[0]).plain

    def test_the_head_keeps_moving_while_the_total_is_unknown(self) -> None:
        glyphs = motion.UNICODE_GLYPHS
        column = motion.ScanHeadColumn(glyphs)
        progress = Progress(column)
        progress.add_task("scanning", total=None)
        assert glyphs.head in column.render(progress.tasks[0]).plain


class TestThePrism:
    def test_the_body_is_the_same_whatever_the_spectrum_does(self) -> None:
        """One object in several states, not several drawings that rhyme."""

        glyphs = motion.UNICODE_GLYPHS
        bodies = {
            motion.prism(glyphs, rays=rays).plain.replace(glyphs.ray, "").rstrip()
            for rays in range(len(glyphs.prism) + 1)
        }
        assert len(bodies) == 1

    def test_the_body_is_solid_rather_than_an_outline(self) -> None:
        """The complaint that started this: thin outlines read as loose parts.

        Every row of the drawn body is made of filled blocks, so the shape has
        no interior edges for the eye to read as seams.
        """

        solid = set("▟█▙▀")
        for _, glyph in motion.UNICODE_GLYPHS.prism:
            assert set(glyph) <= solid, glyph

    def test_each_ray_leaves_from_its_own_row_of_the_body(self) -> None:
        """That offset is the fan. Rays starting in one column read as a bar."""

        glyphs = motion.UNICODE_GLYPHS
        starts = []
        for line in motion.prism(glyphs).plain.rstrip("\n").split("\n"):
            assert glyphs.ray in line
            starts.append(line.index(glyphs.ray))
        assert len(set(starts)) > 1

    def test_the_spectrum_counts_the_checks_that_passed(self) -> None:
        glyphs = motion.UNICODE_GLYPHS

        full = motion.spectrum(12, 12, glyphs).plain
        none = motion.spectrum(0, 12, glyphs).plain
        half = motion.spectrum(6, 12, glyphs).plain

        assert full.count(glyphs.ray) > 0
        assert none.count(glyphs.ray) == 0
        assert 0 < half.count(glyphs.ray) < full.count(glyphs.ray)
        assert full.count("\n") == len(glyphs.prism)

    def test_a_run_with_nothing_to_divide_by_draws_no_spectrum(self) -> None:
        glyphs = motion.UNICODE_GLYPHS
        assert motion.spectrum(0, 0, glyphs).plain.count(glyphs.ray) == 0

    def test_one_failed_check_visibly_costs_a_ray(self) -> None:
        glyphs = motion.UNICODE_GLYPHS
        perfect = motion.spectrum(12, 12, glyphs).plain.count(glyphs.ray)
        flawed = motion.spectrum(11, 12, glyphs).plain.count(glyphs.ray)
        assert flawed < perfect

    def test_the_entrance_only_ever_opens(self) -> None:
        glyphs = motion.UNICODE_GLYPHS
        lengths = [
            motion.prism(glyphs, phase=step / 40).plain.count(glyphs.ray) for step in range(41)
        ]
        assert lengths == sorted(lengths)
        assert lengths[0] == 0
        assert lengths[-1] > 0

    def test_the_beam_arrives_before_the_spectrum_opens(self) -> None:
        glyphs = motion.UNICODE_GLYPHS
        early = motion.prism(glyphs, phase=0.2).plain
        assert glyphs.beam in early
        assert glyphs.ray not in early


class TestTheCharacterSets:
    def test_the_ascii_twin_has_a_row_for_every_drawn_row(self) -> None:
        assert len(motion.UNICODE_GLYPHS.prism) == len(motion.ASCII_GLYPHS.prism)

    def test_the_ascii_twin_keeps_the_shape(self) -> None:
        """Same indents and the same widening, so the fan still fans."""

        drawn = [(indent, len(glyph)) for indent, glyph in motion.UNICODE_GLYPHS.prism]
        plain = [(indent, len(glyph)) for indent, glyph in motion.ASCII_GLYPHS.prism]
        assert [indent for indent, _ in drawn] == [indent for indent, _ in plain]
        assert [width for _, width in drawn] == sorted(width for _, width in drawn)
        assert [width for _, width in plain] == sorted(width for _, width in plain)

    def test_a_console_that_cannot_encode_the_art_gets_the_ascii_twin(self) -> None:
        legacy = Console(file=io.TextIOWrapper(io.BytesIO(), encoding="cp1251"))
        assert motion.glyphs_for(legacy) is motion.ASCII_GLYPHS

    def test_a_utf8_console_gets_the_drawn_set(self) -> None:
        modern = Console(file=io.TextIOWrapper(io.BytesIO(), encoding="utf-8"))
        assert motion.glyphs_for(modern) is motion.UNICODE_GLYPHS

    def test_an_unknown_encoding_falls_back_rather_than_raising(self) -> None:
        class Stream(io.StringIO):
            encoding = "not-a-real-codec"

        assert motion.glyphs_for(Console(file=Stream())) is motion.ASCII_GLYPHS

    def test_the_ascii_set_is_writable_through_a_legacy_code_page(self) -> None:
        """The point of the twin: it has to survive the console that needed it."""

        glyphs = motion.ASCII_GLYPHS
        for _, glyph in glyphs.prism:
            glyph.encode("cp1251")
        for glyph in (glyphs.head, glyphs.trail, glyphs.track, glyphs.fill, glyphs.ray):
            glyph.encode("cp1251")

    def test_the_banner_renders_in_both_sets(self) -> None:
        for glyphs in (motion.UNICODE_GLYPHS, motion.ASCII_GLYPHS):
            rendered = motion.banner("9.9.9", glyphs).plain
            assert "TrueAI Core 9.9.9" in rendered
            assert all(line in rendered for line in motion.BANNER_LINES)


class TestNothingMovesWhereItShouldNot:
    def test_a_redirected_stream_gets_no_motion(self) -> None:
        assert motion.motion_wanted(Console(file=io.StringIO())) is False

    def test_the_flag_wins_over_a_real_terminal(self) -> None:
        assert motion.motion_wanted(Console(force_terminal=True), requested=False) is False

    def test_the_environment_can_turn_it_off_for_every_invocation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRUEAI_NO_MOTION", "1")
        assert motion.motion_wanted(Console(force_terminal=True)) is False

    def test_a_terminal_that_cannot_address_the_cursor_gets_no_motion(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TERM", "dumb")
        assert motion.motion_wanted(Console(force_terminal=True)) is False

    def test_a_terminal_gets_motion(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TRUEAI_NO_MOTION", raising=False)
        monkeypatch.setenv("TERM", "xterm-256color")
        assert motion.motion_wanted(Console(force_terminal=True)) is True

    def test_no_color_alone_does_not_stop_the_motion(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """NO_COLOR is a statement about colour, which Rich already honours."""

        monkeypatch.delenv("TRUEAI_NO_MOTION", raising=False)
        monkeypatch.setenv("TERM", "xterm-256color")
        monkeypatch.setenv("NO_COLOR", "1")
        assert motion.motion_wanted(Console(force_terminal=True)) is True


class TestTheEntranceIsBounded:
    def test_the_budget_is_short_enough_not_to_be_noticed(self) -> None:
        assert motion.ENTRANCE_SECONDS <= 0.5

    def test_it_returns_inside_its_budget(self) -> None:
        """The one animation that blocks has to stay out of the way.

        A generous ceiling, because a loaded CI machine is slow, but a ceiling:
        an entrance that overruns is an entrance that costs the command time.
        """

        console = Console(file=io.StringIO(), force_terminal=True, width=100)
        started = time.monotonic()
        motion.play(
            console,
            lambda phase: motion.banner("0.0.0", motion.ASCII_GLYPHS, phase=phase),
            seconds=0.12,
        )
        assert time.monotonic() - started < 1.0

    def test_it_leaves_the_settled_frame_behind(self) -> None:
        stream = io.StringIO()
        console = Console(file=stream, force_terminal=True, width=100)

        motion.play(
            console,
            lambda phase: motion.banner("7.7.7", motion.ASCII_GLYPHS, phase=phase),
            seconds=0.05,
        )

        assert "TrueAI Core 7.7.7" in stream.getvalue()

    def test_a_zero_length_entrance_still_renders_the_settled_frame(self) -> None:
        stream = io.StringIO()
        console = Console(file=stream, force_terminal=True, width=100)

        motion.play(
            console,
            lambda phase: motion.banner("1.2.3", motion.ASCII_GLYPHS, phase=phase),
            seconds=0.0,
        )

        assert "TrueAI Core 1.2.3" in stream.getvalue()


class TestTheBannerClaims:
    def test_the_banner_claims_only_what_the_program_does(self) -> None:
        """No line here may promise a verdict; the product refuses to give one."""

        forbidden = ("ai-generated", "detects ai", "guarantee", "proof of human", "accuracy")
        text = " ".join(motion.BANNER_LINES).lower()
        assert not any(claim in text for claim in forbidden)

    def test_the_banner_names_the_version_it_was_given(self) -> None:
        assert "TrueAI Core 9.9.9" in motion.banner("9.9.9", motion.ASCII_GLYPHS).plain
