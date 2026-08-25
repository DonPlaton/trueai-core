"""Shared comment-span extraction for source attribution analysis."""

from __future__ import annotations

import io
import tokenize
from dataclasses import dataclass
from pathlib import Path

from trueai.core.errors import ScanLimitExceededError
from trueai.core.spans import Delimiter, scan_delimited


@dataclass(frozen=True, slots=True)
class CommentSpan:
    """A comment and its absolute source span."""

    text: str
    start: int
    end: int
    line: int
    column: int
    syntax_verified: bool


def extract_comments(
    text: str,
    path: Path | None,
    max_spans: int = 50_000,
) -> list[CommentSpan]:
    """Extract comments conservatively, using Python's tokenizer where possible."""

    if path is not None and path.suffix.casefold() == ".py":
        return _python_comments(text, max_spans)
    return _generic_comments(text, max_spans)


def _python_comments(text: str, max_spans: int) -> list[CommentSpan]:
    raw_comments: list[tuple[str, int, int]] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
        for token in tokens:
            if token.type != tokenize.COMMENT:
                continue
            if len(raw_comments) >= max_spans:
                raise ScanLimitExceededError(f"Source comment event limit {max_spans} was exceeded")
            line, zero_column = token.start
            raw_comments.append((token.string, line, zero_column))
    except (IndentationError, SyntaxError, tokenize.TokenError):
        return _generic_comments(text, max_spans)
    line_offsets = _requested_line_offsets(text, {item[1] for item in raw_comments})
    comments: list[CommentSpan] = []
    for token_text, line, zero_column in raw_comments:
        start = line_offsets[line] + zero_column
        comments.append(
            CommentSpan(
                text=token_text,
                start=start,
                end=start + len(token_text),
                line=line,
                column=zero_column + 1,
                syntax_verified=True,
            )
        )
    return comments


#: The four comment shapes this fallback recognizes, in no particular order:
#: `scan_delimited` picks whichever opens first rather than whichever is listed
#: first. `//` and `/*` cannot open at the same offset, so the order between them
#: never decides anything.
_GENERIC_COMMENTS = (
    Delimiter("//"),
    Delimiter("#"),
    Delimiter("/*", "*/"),
    Delimiter("<!--", "-->"),
)


def _generic_comments(text: str, max_spans: int) -> list[CommentSpan]:
    """Find comments in a language this module has no real lexer for.

    Scanned rather than matched. The regular expression this replaced was
    quadratic on unterminated comments -- 200,000 `<!--` with no `-->` is 800 kB
    that never finishes -- because each failed search restarted at the next
    opener. The regions it reports are the same ones.
    """

    comments: list[CommentSpan] = []
    line = 1
    previous_offset = 0
    line_start = 0
    for start, end in scan_delimited(text, _GENERIC_COMMENTS):
        _check_span_budget(comments, max_spans)
        line_breaks = text.count("\n", previous_offset, start)
        if line_breaks:
            line += line_breaks
            line_start = text.rfind("\n", previous_offset, start) + 1
        previous_offset = start
        comments.append(
            CommentSpan(
                text=text[start:end],
                start=start,
                end=end,
                line=line,
                column=start - line_start + 1,
                syntax_verified=False,
            )
        )
    return comments


def extract_css_comments(text: str, max_spans: int = 50_000) -> list[CommentSpan]:
    """Extract CSS block comments while skipping quoted string contents."""

    comments: list[CommentSpan] = []
    index = 0
    quote: str | None = None
    line = 1
    line_start = 0
    while index < len(text):
        character = text[index]
        if character == "\n":
            line += 1
            line_start = index + 1
        if quote is not None:
            if character == "\\":
                index += 2
                continue
            if character == quote:
                quote = None
            index += 1
            continue
        if character in {'"', "'"}:
            quote = character
            index += 1
            continue
        if text.startswith("/*", index):
            _check_span_budget(comments, max_spans)
            end_marker = text.find("*/", index + 2)
            end = len(text) if end_marker < 0 else end_marker + 2
            comments.append(
                CommentSpan(
                    text=text[index:end],
                    start=index,
                    end=end,
                    line=line,
                    column=index - line_start + 1,
                    syntax_verified=True,
                )
            )
            index = end
            continue
        index += 1
    return comments


def _requested_line_offsets(text: str, requested_lines: set[int]) -> dict[int, int]:
    offsets = {1: 0}
    remaining = requested_lines - {1}
    if not remaining:
        return offsets
    line = 1
    for index, character in enumerate(text):
        if character != "\n":
            continue
        line += 1
        if line in remaining:
            offsets[line] = index + 1
            remaining.remove(line)
            if not remaining:
                break
    return offsets


def _check_span_budget(comments: list[CommentSpan], max_spans: int) -> None:
    if len(comments) >= max_spans:
        raise ScanLimitExceededError(f"Source comment event limit {max_spans} was exceeded")
