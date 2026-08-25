"""Linear scanning for delimited regions, and why a regular expression is not.

``re.finditer(r"<!--[\\s\\S]*?-->", text)`` is the obvious way to find comments
and it is quadratic on input the file gets to choose. When the closing delimiter
is missing, the engine scans to the end of the text, fails, and starts again at
the next opener; a file of 200,000 unterminated ``<!--`` makes a scanner that
reads untrusted files by design spend hours on 800 kilobytes. Bounding the span
does not fix it, because the cost is the number of restarts multiplied by the
window, and the file chooses the number of restarts.

The observation that makes this linear is small: if no closing delimiter exists
after one opener, none exists after any later opener either. So the first failed
search is the last one, and the whole scan is a sequence of forward ``find``
calls that never look at a byte twice.

Semantics match the lazy regular expression exactly -- non-overlapping,
left-to-right, the first closer after each opener, and an unterminated region is
not a region. Nothing about what counts as a comment changes; only the time it
takes to decide.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Delimiter:
    """One region shape: what opens it, and what closes it.

    ``closer=None`` means the region runs to the end of the line, which is how
    ``//`` and ``#`` comments end. A line ending is always present or the text
    has ended, so that case can never fail to terminate.
    """

    opener: str
    closer: str | None = None


def scan_delimited(text: str, delimiters: Sequence[Delimiter]) -> Iterator[tuple[int, int]]:
    """Yield ``(start, end)`` for each region, left to right, without overlaps.

    ``end`` is one past the closing delimiter, so ``text[start:end]`` is the
    whole region including both delimiters -- the same string the equivalent
    regular expression would have put in group zero.
    """

    if not delimiters:
        return
    length = len(text)
    # One cursor per delimiter, refreshed only after it is consumed or passed.
    # Recomputing all of them on every yield would reintroduce the quadratic
    # behaviour this module exists to remove.
    starts = [text.find(item.opener, 0) for item in delimiters]
    index = 0
    while index < length:
        chosen = -1
        for position, start in enumerate(starts):
            if start < 0:
                continue
            if chosen < 0 or start < starts[chosen]:
                chosen = position
            elif start == starts[chosen] and len(delimiters[position].opener) > len(
                delimiters[chosen].opener
            ):
                # A longer opener at the same offset is the more specific
                # reading. Two openers rarely tie; when they do, the alternative
                # is deciding by declaration order, which is not a reason.
                chosen = position
        if chosen < 0:
            return
        delimiter = delimiters[chosen]
        start = starts[chosen]
        if delimiter.closer is None:
            end = _line_end(text, start)
        else:
            found = text.find(delimiter.closer, start + len(delimiter.opener))
            if found < 0:
                # No closer remains after this opener, so no later opener of this
                # kind can have one. Retiring the cursor here is what keeps the
                # scan linear rather than restarting the search at every opener.
                starts[chosen] = -1
                continue
            end = found + len(delimiter.closer)
        yield start, end
        index = end
        for position, item in enumerate(delimiters):
            if 0 <= starts[position] < index:
                starts[position] = text.find(item.opener, index)


def _line_end(text: str, start: int) -> int:
    """Return the offset of the first line break at or after ``start``."""

    candidates = [
        position for position in (text.find("\r", start), text.find("\n", start)) if position >= 0
    ]
    return min(candidates) if candidates else len(text)


__all__ = ["Delimiter", "scan_delimited"]
