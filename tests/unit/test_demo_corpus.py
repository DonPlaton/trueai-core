"""The demo corpus has to keep finding what it says it plants.

A demonstration is worth nothing unless it is executed. `examples/demo_corpus`
declares what it puts in each file; this builds the corpus and asserts the
scanner reports every declared trace, which makes the demo a recall check over
a known set rather than a screenshot that used to be true.

It is also the closest honest thing to "proof that it works" that this project
can offer. The traces here are deterministic: a byte string is present or it is
not, so finding all of them is a fact rather than a rate. Averaging results like
these into an accuracy figure would manufacture the probabilistic claim the
product exists to refuse.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from trueai.core.engine import TrueAIEngine
from trueai.core.models import ConfidenceType, ScanReport
from trueai.core.policy import PolicyStore

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "demo_corpus" / "make_corpus.py"


def _load_example() -> object:
    """Import the example the way a reader would run it, from its own path."""

    specification = importlib.util.spec_from_file_location("demo_corpus", EXAMPLE)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    sys.modules["demo_corpus"] = module
    specification.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def corpus_module() -> object:
    return _load_example()


@pytest.fixture
def scanned(corpus_module: object, tmp_path: Path) -> ScanReport:
    directory = corpus_module.build(tmp_path / "demo")  # type: ignore[attr-defined]
    return TrueAIEngine.default().scan(directory, policy=PolicyStore.get("audit"))


def test_the_example_file_is_where_the_readme_says_it_is() -> None:
    assert EXAMPLE.is_file()


def test_every_planted_trace_is_found(corpus_module: object, scanned: ScanReport) -> None:
    found = {(finding.artifact_path, finding.category.value) for finding in scanned.findings}
    missing = [
        f"{item.filename}: {item.category} ({item.description})"
        for item in corpus_module.PLANTED  # type: ignore[attr-defined]
        if (item.filename, item.category) not in found
    ]
    assert not missing, "the corpus claims traces the scan did not report: " + "; ".join(missing)


def test_the_corpus_declares_everything_it_plants(
    corpus_module: object, scanned: ScanReport
) -> None:
    """The other direction: a trace nobody wrote down is a claim nobody checks."""

    declared = {
        (item.filename, item.category)
        for item in corpus_module.PLANTED  # type: ignore[attr-defined]
    }
    undeclared = {
        (finding.artifact_path, finding.category.value)
        for finding in scanned.findings
        if finding.artifact_path != "."
    } - declared
    assert not undeclared, f"the scan reports traces the corpus does not declare: {undeclared}"


def test_the_file_typed_by_hand_produces_nothing(scanned: ScanReport) -> None:
    """A demo needs to show what a clean result looks like, or it shows nothing."""

    assert not [item for item in scanned.findings if item.artifact_path == "typed-by-hand.txt"]


def test_nothing_in_the_demo_is_a_guess(scanned: ScanReport) -> None:
    """Every planted trace is a byte string, so every finding must be deterministic.

    A probabilistic finding here would mean the demo is quietly leaning on
    stylometry to look impressive, which is the failure this project is about.
    """

    classes = {finding.confidence_type for finding in scanned.findings}
    assert classes == {ConfidenceType.DETERMINISTIC}, classes


def test_the_corpus_is_the_same_every_time(corpus_module: object, tmp_path: Path) -> None:
    """A reader has to be able to reproduce the bytes, not just the story."""

    first = corpus_module.build(tmp_path / "one")  # type: ignore[attr-defined]
    second = corpus_module.build(tmp_path / "two")  # type: ignore[attr-defined]
    for path in sorted(first.iterdir()):
        assert path.read_bytes() == (second / path.name).read_bytes(), path.name


def test_the_pdf_is_a_pdf_rather_than_a_string_that_looks_like_one(
    corpus_module: object, tmp_path: Path
) -> None:
    """The cross-reference offsets have to be right or a real reader refuses it."""

    directory = corpus_module.build(tmp_path / "demo")  # type: ignore[attr-defined]
    data = (directory / "contract.pdf").read_bytes()
    assert data.startswith(b"%PDF-")
    start = int(data.rsplit(b"startxref", 1)[1].split()[0])
    assert data[start : start + 4] == b"xref"
    for number in (1, 2, 3, 4):
        entry = data.index(b"%d 0 obj" % number)
        assert b"%010d 00000 n" % entry in data
