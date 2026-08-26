"""Inputs a file can choose that used to make the scanner stop responding.

Seven regular expressions in the scanning path were quadratic in the length of
the artifact. Every one of them is reachable from `trueai scan <file>`, in a tool
whose entire purpose is reading files somebody else wrote, and every one of them
was inside the default 25 MB size limit at the point where it stopped finishing:

* `<!--` repeated with no `-->`, in the fallback comment reader — 800 kB did not
  finish in a minute;
* `Co-Authored-By: Claude` followed by a line of spaces, where `[^<\\r\\n]*` and a
  following `\\s*` both accept a space and the engine tries every division of the
  run between them;
* `:a(` and `[a` repeated, in the CSS selector features, where the contents of a
  bracket could contain the bracket that opens it;
* a stylesheet with no braces at all, in the hidden-rule scan, where `([^{}]+)\\{`
  reads to the end of the file once per starting position — 60 kB took
  seventeen seconds;
* `/Info <<` repeated in a PDF trailer that runs to the end of the file because
  `startxref` is missing;
* `<?` repeated in an XML prolog;
* `<path` and `<meta` with no `>`.

The budgets below are deliberately loose. The fixed code answers each of these
in well under a second, and the broken code took minutes to hours, so a
ten-second budget separates them on any machine without being a benchmark. What
is being asserted is a complexity class, not a speed.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from trueai import TrueAIEngine
from trueai.detectors import create_default_registry

#: Long enough that quadratic behaviour is unmistakable, short enough that the
#: fixed implementations stay in the milliseconds.
REPEATS = 100_000

BUDGET_SECONDS = 10.0


def elapsed(callable_) -> float:
    started = time.perf_counter()
    callable_()
    return time.perf_counter() - started


HOSTILE: tuple[tuple[str, str, str], ...] = (
    (
        "unterminated html comments in code",
        "bomb.js",
        "<!--" * REPEATS,
    ),
    (
        "unterminated block comments in code",
        "bomb.ts",
        "/*" * REPEATS,
    ),
    (
        "a co-author trailer followed by a line of spaces",
        "trailer.txt",
        "Co-Authored-By: Claude" + " " * REPEATS,
    ),
    (
        "unclosed functional pseudo-classes",
        "pseudo.css",
        "a{color:red}\n" + ":a(" * REPEATS,
    ),
    (
        "unclosed attribute selectors",
        "attributes.css",
        "a{color:red}\n" + "[a" * REPEATS,
    ),
    (
        "a stylesheet with no braces",
        "braceless.css",
        "selector," * REPEATS,
    ),
    (
        "an svg with unterminated processing instructions",
        "prolog.svg",
        "<?x" * REPEATS + '<svg xmlns="http://www.w3.org/2000/svg"/>',
    ),
    (
        "unterminated tags in html",
        "tags.html",
        "<path " * REPEATS,
    ),
    (
        "a pdf trailer with no startxref and many direct info dictionaries",
        "trailer.pdf",
        "%PDF-1.4\ntrailer\n" + "/Info <<" * REPEATS,
    ),
)


@pytest.mark.parametrize(
    ("description", "name", "content"),
    HOSTILE,
    ids=[item[0] for item in HOSTILE],
)
def test_a_hostile_artifact_does_not_stall_a_scan(
    description: str, name: str, content: str, tmp_path: Path
) -> None:
    """A scanner a file can stall is a denial of service against its own purpose."""

    artifact = tmp_path / name
    artifact.write_text(content, encoding="utf-8")
    engine = TrueAIEngine(create_default_registry())

    duration = elapsed(lambda: engine.scan(artifact))

    assert duration < BUDGET_SECONDS, (
        f"{description}: {artifact.stat().st_size} bytes took {duration:.1f}s. "
        "That is the shape of a quadratic scan, not a slow machine."
    )


def test_the_same_input_at_twice_the_length_does_not_cost_four_times_as_much(
    tmp_path: Path,
) -> None:
    """The property underneath the budgets above, stated directly.

    A budget can be met by a fast machine running quadratic code on a small
    input. Doubling the input and requiring less than a fourfold increase is what
    actually distinguishes the complexity class, with enough headroom that
    ordinary scheduling noise does not decide the result.
    """

    engine = TrueAIEngine(create_default_registry())

    def scan(repeats: int) -> float:
        artifact = tmp_path / f"bomb-{repeats}.js"
        artifact.write_text("<!--" * repeats, encoding="utf-8")
        return elapsed(lambda: engine.scan(artifact))

    small = scan(50_000)
    large = scan(100_000)

    assert large < max(small * 8, 2.0), (
        f"Doubling the input took {large / max(small, 1e-6):.1f} times as long "
        f"({small:.3f}s then {large:.3f}s), which is superlinear."
    )


def test_the_css_hidden_rule_scan_still_finds_what_it_is_for(tmp_path: Path) -> None:
    """The fix replaced a regular expression, so the behaviour needs restating."""

    artifact = tmp_path / "hidden.css"
    artifact.write_text(
        ".visible { color: red }\n"
        ".secret { display: none; color: blue }\n"
        "@media print { .print-only { visibility: hidden } }\n",
        encoding="utf-8",
    )

    report = TrueAIEngine(create_default_registry()).scan(artifact)
    hiding = [item for item in report.findings if item.category.value == "hidden_element"]

    assert {item.evidence["selector"] for item in hiding} == {".secret", ".print-only"}
    assert {item.evidence["declaration"] for item in hiding} == {
        "display: none",
        "visibility: hidden",
    }


def test_a_comment_that_never_closes_is_still_not_a_comment(tmp_path: Path) -> None:
    """The linear scanner keeps the semantics, not only the speed.

    An unterminated comment was not a comment before and is not one now. The
    alternative -- treating it as running to the end of the file -- would have
    been a cheaper fix and would have changed what the tool reports.
    """

    from trueai.detectors.code.attribution import extract_comments

    spans = extract_comments("/* Generated with ChatGPT", Path("notes.js"))

    assert spans == []


# -- the interpreter's own quadratic scan --------------------------------------------


def test_a_document_of_unclosed_tags_is_refused_rather_than_parsed(tmp_path: Path) -> None:
    """CPython's `html.parser` rescans from every `<` that never closes, up to 3.12.

    Measured there: 1,000 unclosed tags in 6 kB take 0.07 seconds, 4,000 in 24 kB
    take 2.0, and 8,000 in 48 kB take 15.6. A hundred thousand does not finish,
    which is what made the 3.12 jobs in the test matrix hang while 3.13 and 3.14
    passed in five minutes. 3.13 fixed the parser; 3.12 is a supported
    interpreter, so the input is bounded rather than the interpreter version.
    """

    artifact = tmp_path / "tags.html"
    artifact.write_text("<path " * 100_000, encoding="utf-8")

    report = TrueAIEngine(create_default_registry()).scan(artifact)

    assert [item.code for item in report.diagnostics] == ["scan_limit_exceeded"]
    assert any("never close" in item.message for item in report.diagnostics)


def test_ordinary_html_is_not_refused(tmp_path: Path) -> None:
    """The bound has to leave real documents alone or it is not a bound."""

    artifact = tmp_path / "page.html"
    artifact.write_text(
        "<!DOCTYPE html><html><body>" + "<p>Generated with ChatGPT</p>" * 20_000 + "</body></html>",
        encoding="utf-8",
    )

    report = TrueAIEngine(create_default_registry()).scan(artifact)

    assert not [item for item in report.diagnostics if item.code == "scan_limit_exceeded"]
    assert report.findings


def test_one_stray_opening_bracket_in_a_large_document_is_still_scanned(
    tmp_path: Path,
) -> None:
    """The bound is a product, because one of them is cheap and many are not.

    Kept under `max_parser_events` on purpose: that budget already refuses a
    document carrying 50,000 markup events, and a fixture tripping it would be
    measuring the wrong guard.
    """

    artifact = tmp_path / "stray.html"
    artifact.write_text("<p>x</p>" * 10_000 + "<broken ", encoding="utf-8")

    report = TrueAIEngine(create_default_registry()).scan(artifact)

    assert not [item for item in report.diagnostics if item.code == "scan_limit_exceeded"]


def test_the_counter_is_linear_in_the_length_of_the_document() -> None:
    """Searching for `>` from every `<` would be the scan this is measuring."""

    from trueai.core.spans import unclosed_tag_count

    small = elapsed(lambda: unclosed_tag_count("<path " * 200_000))
    large = elapsed(lambda: unclosed_tag_count("<path " * 400_000))

    assert large < max(small * 8, 1.0)


def test_the_counter_counts_what_it_says() -> None:
    from trueai.core.spans import unclosed_tag_count

    assert unclosed_tag_count("<a><b></b></a>") == 0
    assert unclosed_tag_count("<path <path <path ") == 3
    assert unclosed_tag_count("<a>text<b") == 1
    assert unclosed_tag_count("") == 0
    assert unclosed_tag_count("no markup at all") == 0
    # A comparison in prose, which is genuinely an unclosed opener as far as the
    # parser is concerned, and is why the bound is a product rather than a count.
    assert unclosed_tag_count("a > b < c") == 1
