"""The repository must not make it easy to commit a key it told you to create.

`trueai certificates keygen --private-key issuer.pem` writes a private key into
whatever directory it was run from, and the README runs it from the repository
root. That is a documented instruction to put key material next to a git index,
so the ignore rules have to cover the names the documentation actually uses
rather than a list somebody guessed once.

These tests read the documentation, not a fixture. A filename added to the docs
and not to `.gitignore` fails here, which is the only way the two stay in step.

GitHub's push protection is the second line and is enabled on this repository.
It is not a reason to skip the first: relying on the platform to catch what the
project's own instructions invite is the wrong way round.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[2]

#: Where a reader is told to run things.
DOCUMENTS = ("README.md", "SECURITY.md", "CONTRIBUTING.md", "PROJECT_STATUS.md")

#: Anything with one of these suffixes is key material unless it is named as a
#: public half. The list matches the ignore rules, and a suffix added to one
#: without the other shows up as a filename this test cannot classify.
KEY_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk")

#: A public half or a trust anchor. These are meant to be shared, so they stay
#: trackable; a private key named like one of these is a mistake no ignore rule
#: can catch, and push protection is the layer for that.
PUBLIC = re.compile(r"(\.pub\.pem|-public\.pem|roots\.pem)$")

FILENAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\.(?:pem|key|p12|pfx|jks|keystore|ppk)\b")


def documented_key_filenames() -> set[str]:
    """Every key-shaped filename the documentation tells a reader to create."""

    found: set[str] = set()
    for name in DOCUMENTS:
        path = REPOSITORY / name
        if path.is_file():
            found |= set(FILENAME.findall(path.read_text(encoding="utf-8")))
    for path in sorted((REPOSITORY / "docs").glob("*.md")):
        found |= set(FILENAME.findall(path.read_text(encoding="utf-8")))
    return found


def ignored(relative: str) -> bool:
    """Ask git, rather than reimplementing its matching rules badly."""

    result = subprocess.run(
        ["git", "-C", str(REPOSITORY), "check-ignore", "-q", "--no-index", relative],
        capture_output=True,
    )
    if result.returncode not in (0, 1):
        pytest.skip(f"git could not answer: {result.stderr.decode(errors='replace').strip()}")
    return result.returncode == 0


@pytest.fixture(scope="module")
def documented() -> set[str]:
    names = documented_key_filenames()
    if not names:
        pytest.fail(
            "the documentation named no key files at all, which means the pattern "
            "stopped matching and every test below would pass without checking anything"
        )
    return names


def test_the_documentation_still_tells_people_to_make_keys(documented: set[str]) -> None:
    """Guards the others: they are only meaningful if this found something."""

    assert "issuer.pem" in documented
    assert len(documented) >= 5


def test_every_private_key_the_docs_name_is_ignored(documented: set[str]) -> None:
    exposed = sorted(name for name in documented if not PUBLIC.search(name) and not ignored(name))
    assert not exposed, (
        "the documentation tells a reader to create these and git would happily "
        f"commit them: {exposed}"
    )


def test_the_public_halves_stay_trackable(documented: set[str]) -> None:
    """Ignoring these would silently drop a trust anchor somebody meant to publish."""

    blocked = sorted(name for name in documented if PUBLIC.search(name) and ignored(name))
    assert not blocked, f"these are meant to be shareable and are ignored: {blocked}"


@pytest.mark.parametrize("suffix", KEY_SUFFIXES)
def test_every_key_suffix_is_covered_wherever_it_lands(suffix: str) -> None:
    """Not only in the root: a key written into a subdirectory is the same key."""

    for location in ("issuer", "keys/issuer", "docs/deep/nested/issuer"):
        assert ignored(f"{location}{suffix}"), f"{location}{suffix} is not ignored"


def test_an_environment_file_is_ignored() -> None:
    for name in (".env", ".env.local", ".env.production", "config/.env"):
        assert ignored(name), name


def test_nothing_key_shaped_is_tracked_right_now() -> None:
    """The rules above prevent the next one. This one checks the ones already in."""

    listing = subprocess.run(
        ["git", "-C", str(REPOSITORY), "ls-files"],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    if listing.returncode != 0:
        pytest.skip("not a git checkout")
    tracked = [
        name
        for name in listing.stdout.splitlines()
        if name.endswith(KEY_SUFFIXES) and not PUBLIC.search(name)
    ]
    assert not tracked, f"key material is committed: {tracked}"


def test_no_private_key_has_ever_been_committed() -> None:
    """Deleting a key does not remove it; it stays reachable in every clone."""

    history = subprocess.run(
        ["git", "-C", str(REPOSITORY), "log", "--all", "--name-only", "--pretty=format:"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if history.returncode != 0:
        pytest.skip("not a git checkout")
    ever = {
        name
        for name in history.stdout.splitlines()
        if name.endswith(KEY_SUFFIXES) and not PUBLIC.search(name)
    }
    assert not ever, f"key material is in the history and rewriting it is the only fix: {ever}"
