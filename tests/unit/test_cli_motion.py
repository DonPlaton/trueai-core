"""The terminal's decoration, held to the same rules as everything else.

Three kinds of claim are tested here. That the curves are curves, which is what
separates motion somebody designed from a character being redrawn in a new
column. That the palette still satisfies the constraints it was chosen under,
because a later edit that picks a prettier colour has no other way of finding
out it broke the light-terminal case. And that none of it can overstate: a bar
with no total draws no progress, a bar never rounds a fraction up, and nothing
moves when the output is going somewhere other than a terminal.
"""

from __future__ import annotations

import io
import math
from collections.abc import Callable
from itertools import groupby

import pytest
from rich.console import Console
from rich.progress import Progress

from trueai.cli import motion


def _relative_luminance(colour: str) -> float:
    channels = [int(colour.lstrip("#")[index : index + 2], 16) / 255 for index in (0, 2, 4)]
    linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast(one: str, other: str) -> float:
    first, second = _relative_luminance(one), _relative_luminance(other)
    return (max(first, second) + 0.05) / (min(first, second) + 0.05)


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
        whether the head ever pauses but for how long. At twelve frames a
        second over a 1.6 second period the sine ease holds a column for at
        most four frames, a third of a second, which reads as a turn. A cubic
        ease holds it for six, half a second, which reads as a hung process.
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

    def test_the_ease_is_symmetric_about_its_middle(self) -> None:
        for step in range(51):
            fraction = step / 100
            mirrored = motion.ease_in_out_sine(1.0 - fraction)
            assert mirrored == pytest.approx(1.0 - motion.ease_in_out_sine(fraction))

    def test_the_pulse_has_no_corner_at_its_brightest(self) -> None:
        peak = motion.pulse(0.5)
        assert peak == pytest.approx(1.0)
        # Either side of the peak the change is small, which is what a corner is not.
        assert abs(motion.pulse(0.5) - motion.pulse(0.49)) < 0.01

    def test_the_pulse_repeats_every_whole_phase(self) -> None:
        assert motion.pulse(0.25) == pytest.approx(motion.pulse(1.25))
        assert motion.pulse(0.0) == pytest.approx(motion.pulse(3.0))


class TestTheSweep:
    def test_one_period_is_one_round_trip(self) -> None:
        assert motion.sweep_position(0.0, cells=7, period=1.6) == pytest.approx(0.0)
        assert motion.sweep_position(0.8, cells=7, period=1.6) == pytest.approx(1.0)
        assert motion.sweep_position(1.6, cells=7, period=1.6) == pytest.approx(0.0)

    def test_a_degenerate_track_or_period_does_not_divide_by_zero(self) -> None:
        assert motion.sweep_position(3.0, cells=1, period=1.6) == 0.0
        assert motion.sweep_position(3.0, cells=7, period=0.0) == 0.0

    def test_the_head_covers_every_column_of_the_track(self) -> None:
        seen = set()
        for step in range(400):
            elapsed = step * 1.6 / 400
            position = motion.sweep_position(elapsed, cells=7, period=1.6)
            seen.add(round(position * 6))
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

    def test_a_task_with_no_total_draws_an_empty_track_rather_than_a_pulse(self) -> None:
        """The engine does not know the total until discovery finishes.

        Rich's own bar animates in that state, which looks like progress. This
        one has to draw nothing, because nothing is what is known.
        """

        glyphs = motion.UNICODE_GLYPHS
        column = motion.ScanBarColumn(glyphs, width=12)
        progress = Progress(column)
        task_id = progress.add_task("scanning", total=None)
        rendered = column.render(progress.tasks[0])
        assert rendered.plain == glyphs.track * 12
        progress.update(task_id, total=10, completed=5)
        assert glyphs.fill in column.render(progress.tasks[0]).plain

    def test_the_head_keeps_moving_while_the_total_is_unknown(self) -> None:
        glyphs = motion.UNICODE_GLYPHS
        column = motion.ScanHeadColumn(glyphs)
        progress = Progress(column)
        progress.add_task("scanning", total=None)
        assert glyphs.head in column.render(progress.tasks[0]).plain


class TestTheCharacterSets:
    def test_the_ascii_twin_lines_up_with_the_drawn_one(self) -> None:
        for drawn, plain in zip(motion.UNICODE_GLYPHS.lens, motion.ASCII_GLYPHS.lens, strict=True):
            assert len(drawn) == len(plain)

    def test_every_pose_exists_in_both_sets_and_is_the_same_width(self) -> None:
        assert set(motion.UNICODE_GLYPHS.iris) == set(motion.ASCII_GLYPHS.iris)
        widths = {len(art) for art in motion.UNICODE_GLYPHS.iris.values()}
        widths |= {len(art) for art in motion.ASCII_GLYPHS.iris.values()}
        assert widths == {5}

    def test_the_body_is_the_same_in_every_pose(self) -> None:
        """One character in four moods, not four drawings that happen to rhyme."""

        glyphs = motion.UNICODE_GLYPHS
        bodies = set()
        for pose in glyphs.iris:
            lines = motion.mascot(pose, glyphs).plain.splitlines()
            bodies.add(tuple(line for index, line in enumerate(lines) if index != 2))
        assert len(bodies) == 1

    def test_every_pose_renders_the_same_shape(self) -> None:
        glyphs = motion.UNICODE_GLYPHS
        shapes = {
            tuple(len(line) for line in motion.mascot(pose, glyphs).plain.splitlines())
            for pose in glyphs.iris
        }
        assert len(shapes) == 1

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

        for line in motion.ASCII_GLYPHS.lens:
            line.format(iris=motion.ASCII_GLYPHS.iris["clear"]).encode("cp1251")
        for glyph in (motion.ASCII_GLYPHS.head, motion.ASCII_GLYPHS.fill):
            glyph.encode("cp1251")


class TestThePaletteConstraints:
    """The palette was picked under constraints; a later edit has to keep them."""

    BACKGROUNDS = ("#FFFFFF", "#000000", "#1E1E1E", "#FDF6E3", "#0C0C0C")

    def test_every_stop_is_legible_on_a_light_and_a_dark_terminal(self) -> None:
        for stop in (*motion.RAMP, motion.BRAND, motion.MUTED):
            for background in self.BACKGROUNDS:
                ratio = _contrast(stop, background)
                assert ratio >= 3.0, f"{stop} on {background} is {ratio:.2f}:1"

    def test_the_ramp_gets_lighter_in_one_direction(self) -> None:
        luminances = [_relative_luminance(stop) for stop in motion.RAMP]
        assert luminances == sorted(luminances)

    def test_the_stops_survive_a_256_colour_terminal_as_separate_colours(self) -> None:
        from rich.color import Color

        quantised = {Color.parse(stop).downgrade(2).number for stop in motion.RAMP}
        assert len(quantised) == len(motion.RAMP)

    def test_the_ramp_stays_clear_of_the_hues_that_carry_verdicts(self) -> None:
        """Green, yellow, red and cyan mean something in this program's output.

        A decoration in one of those hues reads as a verdict, so the brand
        colours have to sit in the blue-to-violet arc, away from all four.
        """

        for stop in (*motion.RAMP, motion.BRAND):
            red, green, blue = (int(stop.lstrip("#")[i : i + 2], 16) / 255 for i in (0, 2, 4))
            hue = (
                math.degrees(math.atan2(math.sqrt(3) * (green - blue), 2 * red - green - blue))
                % 360
            )
            assert 220 <= hue <= 320, f"{stop} sits at {hue:.0f} degrees"


class TestNothingMovesWhereItShouldNot:
    def test_a_redirected_stream_gets_no_motion(self) -> None:
        piped = Console(file=io.StringIO())
        assert motion.motion_wanted(piped) is False

    def test_the_flag_wins_over_a_real_terminal(self) -> None:
        terminal = Console(force_terminal=True)
        assert motion.motion_wanted(terminal, requested=False) is False

    def test_the_environment_can_turn_it_off_for_every_invocation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        terminal = Console(force_terminal=True)
        monkeypatch.setenv("TRUEAI_NO_MOTION", "1")
        assert motion.motion_wanted(terminal) is False

    def test_a_terminal_that_cannot_address_the_cursor_gets_no_motion(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        terminal = Console(force_terminal=True)
        monkeypatch.setenv("TERM", "dumb")
        assert motion.motion_wanted(terminal) is False

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


class TestTheFaceMatchesTheOutcome:
    def test_each_exit_code_has_its_own_pose(self) -> None:
        assert motion.pose_for_exit(0) == "clear"
        assert motion.pose_for_exit(1) == "review"
        assert motion.pose_for_exit(2) == "refused"

    def test_an_unexpected_code_does_not_claim_a_result(self) -> None:
        for code in (3, 4, 130, -1):
            assert motion.pose_for_exit(code) == "idle"

    def test_every_pose_the_exit_codes_name_actually_exists(self) -> None:
        for code in (0, 1, 2, 3):
            assert motion.pose_for_exit(code) in motion.UNICODE_GLYPHS.iris

    def test_the_banner_names_the_version_it_was_given(self) -> None:
        rendered = motion.banner("9.9.9", motion.ASCII_GLYPHS).plain
        assert "TrueAI Core 9.9.9" in rendered
        assert all(line in rendered for line in motion.BANNER_LINES)

    def test_the_banner_claims_only_what_the_program_does(self) -> None:
        """No line here may promise a verdict; the product refuses to give one."""

        forbidden = ("ai-generated", "detects ai", "guarantee", "proof of human")
        text = " ".join(motion.BANNER_LINES).lower()
        assert not any(claim in text for claim in forbidden)
