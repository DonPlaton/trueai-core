"""Documentation that names things which do not exist.

Prose has no compiler, so it drifts in one direction: a flag is renamed, a module
moves, and the sentence keeps saying the old thing confidently. The reader who is
hurt is the one who trusts it — they run the documented command, it fails, and
they conclude the tool is broken rather than the sentence.

The gate checks whether the nouns exist. It cannot check whether the prose is
true; that needs a reader. What it can check is the part that rots first.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[2]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from scripts.check_docs import (  # noqa: E402
    DOCUMENTS,
    INVOCATION,
    check_document,
    cli_surface,
    orphaned_documents,
    run,
)


@pytest.fixture(scope="module")
def surface() -> tuple[set[str], dict[str, set[str]], set[str]]:
    return cli_surface()


# -- the repository as it stands ------------------------------------------------------


def test_the_documentation_names_only_things_that_exist() -> None:
    problems = run()

    assert problems == [], [str(item) for item in problems]


def test_every_document_the_check_expects_is_present() -> None:
    """A rename would otherwise silently shrink what is checked."""

    missing = [item for item in DOCUMENTS if not item.exists()]

    assert missing == []


def test_no_document_is_orphaned() -> None:
    """An unread document is one that quietly goes stale."""

    assert orphaned_documents() == [], [str(item) for item in orphaned_documents()]


# -- the CLI surface it checks against ------------------------------------------------


def test_the_surface_is_read_from_the_app_rather_than_from_help_text(
    surface: tuple[set[str], dict[str, set[str]], set[str]],
) -> None:
    commands, options, groups = surface

    assert "trueai scan" in commands
    assert "trueai cache prune" in commands
    assert "trueai cache" in groups
    assert "trueai scan" not in groups
    assert "--policy" in options["trueai scan"]
    assert "--yes" in options["trueai cache prune"]


def test_the_surface_covers_every_command_group(
    surface: tuple[set[str], dict[str, set[str]], set[str]],
) -> None:
    commands, _, _ = surface

    for group in ("detectors", "policies", "plugins", "cache", "attestations", "certificates"):
        assert any(name.startswith(f"trueai {group}") for name in commands), group


# -- the gate can fail ----------------------------------------------------------------


def test_a_command_that_does_not_exist_is_reported(
    tmp_path: Path, surface: tuple[set[str], dict[str, set[str]], set[str]]
) -> None:
    commands, options, groups = surface
    document = tmp_path / "guide.md"
    document.write_text("Run `trueai scna ./repo` to begin.\n", encoding="utf-8")

    problems = check_document(document, commands, options, groups)

    assert any(item.kind == "command" for item in problems)


def test_an_option_that_does_not_exist_is_reported(
    tmp_path: Path, surface: tuple[set[str], dict[str, set[str]], set[str]]
) -> None:
    """The worst of the five: a wrong flag looks exactly like a right one."""

    commands, options, groups = surface
    document = tmp_path / "guide.md"
    document.write_text("Run `trueai scan` with --polciy client-delivery.\n", encoding="utf-8")

    problems = check_document(document, commands, options, groups)

    assert any(item.kind == "option" and "--polciy" in item.detail for item in problems)


def test_a_dead_relative_link_is_reported(
    tmp_path: Path, surface: tuple[set[str], dict[str, set[str]], set[str]]
) -> None:
    commands, options, groups = surface
    document = tmp_path / "guide.md"
    document.write_text("See [the guide](nowhere.md).\n", encoding="utf-8")

    problems = check_document(document, commands, options, groups)

    assert any(item.kind == "link" for item in problems)


def test_a_real_command_and_option_pass(
    tmp_path: Path, surface: tuple[set[str], dict[str, set[str]], set[str]]
) -> None:
    """A checker that always complains is one people learn to ignore."""

    commands, options, groups = surface
    document = tmp_path / "guide.md"
    document.write_text(
        "Run `trueai scan ./repo` with --policy client-delivery.\n", encoding="utf-8"
    )

    assert check_document(document, commands, options, groups) == []


# -- the scoping that keeps it useful -------------------------------------------------


def test_another_tool_s_flags_are_not_claimed_as_ours(
    tmp_path: Path, surface: tuple[set[str], dict[str, set[str]], set[str]]
) -> None:
    """A first version reported --all-extras and --build-arg. They are pip's and docker's."""

    commands, options, groups = surface
    document = tmp_path / "guide.md"
    document.write_text(
        "python -m pip install --all-extras .\n"
        "docker build --build-arg SOURCE_DATE_EPOCH=0 -t trueai-core:audit .\n"
        "docker create --name trueai-audit trueai-core:audit\n",
        encoding="utf-8",
    )

    assert check_document(document, commands, options, groups) == []


def test_an_image_name_is_not_an_invocation() -> None:
    """`trueai-core:audit` on a docker line must not drag docker's flags in."""

    assert not INVOCATION.search("docker build -t trueai-core:audit .")
    assert not INVOCATION.search("docker create --name trueai-audit image")
    assert INVOCATION.search("trueai scan ./repo --cache")


def test_the_invocation_pattern_needs_a_word_boundary() -> None:
    """It was a literal backspace for one commit, so it matched nothing at all.

    A pattern that can never match makes the check skip every line while still
    reporting success — the same shape of failure the license gate's fallback
    exists to avoid.
    """

    assert INVOCATION.pattern.startswith("\\b")
    assert not INVOCATION.search("run mytrueai scan --whatever")


def test_a_flag_on_a_line_that_never_mentions_the_tool_is_ignored(
    tmp_path: Path, surface: tuple[set[str], dict[str, set[str]], set[str]]
) -> None:
    commands, options, groups = surface
    document = tmp_path / "guide.md"
    document.write_text("python -m build --outdir dist\n", encoding="utf-8")

    assert check_document(document, commands, options, groups) == []


# -- the skill and the backlog --------------------------------------------------------


def test_the_codex_skill_is_checked_alongside_the_documentation() -> None:
    """It gives an agent instructions; a wrong flag there is a wrong action."""

    skill = REPOSITORY / "skills" / "trueai" / "SKILL.md"

    assert skill in DOCUMENTS
    assert skill.exists()


def test_the_backlog_is_checked_too() -> None:
    """A completed item citing a renamed module describes work nobody can check."""

    assert REPOSITORY / "PROJECT_STATUS.md" in DOCUMENTS


def test_every_file_a_completed_backlog_item_names_exists() -> None:
    """Backticked paths in ticked items, which is how each one cites its work."""

    import re

    text = (REPOSITORY / "PROJECT_STATUS.md").read_text(encoding="utf-8")
    cited = set(re.findall(r"`((?:trueai|tests|scripts|docs|examples|security)/[\w./-]+)`", text))
    missing = sorted(path for path in cited if not (REPOSITORY / path).exists())

    assert missing == [], missing
