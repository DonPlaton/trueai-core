"""The catalogue of what TrueAI can remove, and the fixtures that must exercise it.

Two gates here. The catalogue and the code must name the same set of operations
in both directions, so a new removable field cannot ship uncatalogued and a stale
entry cannot survive a removal. And every catalogued operation must be exercised
by a test, which is what stops a removable field shipping without a fixture.

The bug this replaced is worth remembering. Safety used to be a prefix match on
the identifier, so `odf.remove-metadata-field` was classified as a content change
for as long as ODF support existed — not because anybody decided ODF metadata was
content, but because `"odf."` was never added to a tuple. It happened to fail
safe, which is why nothing noticed.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from trueai.core.models import RemediationSafety
from trueai.core.remediation import RemediationPlanner
from trueai.core.remediation_catalog import (
    CATALOGUE,
    RemediationKind,
    catalogued_ids,
    kind_for,
    safety_for,
)

REPOSITORY = Path(__file__).resolve().parents[2]
PACKAGE = REPOSITORY / "trueai"
TESTS = REPOSITORY / "tests"

#: An identifier looks like `format.verb-noun` and appears as a string literal.
IDENTIFIER = re.compile(r'"((?:docx|pptx|xlsx|odf|pdf|image|media|text|html|svg|git)\.[a-z-]+)"')


def identifiers_in(root: Path) -> set[str]:
    """Every remediation identifier written as a literal under a tree."""

    found: set[str] = set()
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        found.update(IDENTIFIER.findall(path.read_text(encoding="utf-8")))
    return found


# -- the catalogue and the code agree ------------------------------------------------


def test_every_operation_the_code_can_emit_is_catalogued() -> None:
    """An operation nobody wrote down is an operation nobody reviewed."""

    emitted = identifiers_in(PACKAGE) - {"git.rewrite-history"} | {"git.rewrite-history"}
    uncatalogued = sorted(emitted - catalogued_ids())

    assert uncatalogued == [], uncatalogued


def test_no_catalogue_entry_describes_an_operation_that_no_longer_exists() -> None:
    """A stale entry tells an operator the tool does something it does not."""

    orphaned = sorted(catalogued_ids() - identifiers_in(PACKAGE))

    assert orphaned == [], orphaned


def test_identifiers_are_unique() -> None:
    identifiers = [item.remediation_id for item in CATALOGUE]

    assert len(set(identifiers)) == len(identifiers)


def test_every_entry_says_what_it_removes_and_why_that_safety_class() -> None:
    """The `why` field is what would have caught the ODF misclassification."""

    for entry in CATALOGUE:
        assert entry.removes.strip(), entry.remediation_id
        assert entry.why.strip(), entry.remediation_id
        assert entry.format.strip(), entry.remediation_id


# -- the planner asks the catalogue --------------------------------------------------


@pytest.mark.parametrize("entry", CATALOGUE, ids=lambda entry: entry.remediation_id)
def test_the_planner_uses_the_declared_safety(entry: RemediationKind) -> None:
    assert RemediationPlanner._safety(entry.remediation_id) is entry.safety


def test_odf_metadata_is_metadata_like_every_other_package_format() -> None:
    """The bug the catalogue replaced: a prefix tuple nobody updated.

    `meta.xml` is a separate part exactly like `docProps`, so removing a field
    from it cannot change what a reader sees — the same claim OOXML already made.
    """

    for identifier in (
        "odf.remove-metadata-field",
        "docx.remove-metadata-field",
        "pdf.remove-metadata-field",
    ):
        assert safety_for(identifier) is RemediationSafety.SAFE_METADATA


def test_markup_removals_are_still_content_changes() -> None:
    """The catalogue made ODF less strict. It did not make markup less strict."""

    for identifier in (
        "svg.remove-metadata-element",
        "html.remove-generator-metadata",
        "text.remove-invisible",
    ):
        assert safety_for(identifier) is RemediationSafety.PREDICTABLE_CONTENT


def test_history_rewriting_is_the_only_destructive_operation() -> None:
    destructive = {
        item.remediation_id for item in CATALOGUE if item.safety is RemediationSafety.DESTRUCTIVE
    }

    assert destructive == {"git.rewrite-history"}
    assert kind_for("git.rewrite-history").requires_explicit_opt_in


def test_an_uncatalogued_operation_falls_back_to_the_strictest_reading() -> None:
    """A planner is not the place to fail a scan; treating it as content is safe."""

    assert (
        RemediationPlanner._safety("invented.remove-something")
        is RemediationSafety.PREDICTABLE_CONTENT
    )


def test_asking_the_catalogue_directly_refuses_an_unknown_operation() -> None:
    """Where a caller *can* handle it, guessing is the wrong answer."""

    with pytest.raises(KeyError, match="not in the remediation catalogue"):
        safety_for("invented.remove-something")


def test_only_metadata_removals_leave_visible_content_alone() -> None:
    for entry in CATALOGUE:
        expected = entry.safety is not RemediationSafety.SAFE_METADATA
        assert entry.changes_visible_content is expected, entry.remediation_id


# -- every catalogued operation has a fixture ----------------------------------------


def test_every_catalogued_operation_is_exercised_by_a_test() -> None:
    """A removable field shipping without a fixture is what this prevents."""

    exercised = identifiers_in(TESTS)
    untested = sorted(catalogued_ids() - exercised)

    assert untested == [], (
        "These removable operations have no test naming them: "
        + ", ".join(untested)
        + ". Add a synthetic fixture before shipping the field."
    )


def test_the_fixture_check_would_notice_a_missing_one() -> None:
    """A gate that cannot fail is not a gate."""

    exercised = identifiers_in(TESTS)

    assert "text.remove-invisible" in exercised
    assert "invented.remove-something" not in exercised


def test_the_catalogue_covers_every_format_the_cleaners_handle() -> None:
    formats = {entry.format for entry in CATALOGUE}

    assert {
        "docx",
        "pptx",
        "xlsx",
        "odf",
        "pdf",
        "image",
        "media",
        "text",
        "html",
        "svg",
        "git",
    } == formats
