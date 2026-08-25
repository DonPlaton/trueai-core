"""The helpers the security tests lean on, and the ways they can lie.

`tests/support.py` exists so that a missing OS capability skips loudly instead of
passing quietly. That makes it the one module in the suite whose bugs are
invisible by construction: when it turns a real failure into a skip, the suite
still reports green and the security case it was guarding stops running.

One did. `create_symlink` swallowed `FileExistsError` along with every other
`OSError`, so a call with its two arguments swapped -- asking for a link *at* a
file that already existed -- reported as "symlinks are unavailable on this
platform". The cache's refusal to delete through a symlink went unexercised on
Windows and failed only once a Linux runner turned the skip into a failure.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.support import create_symlink, missing_modules, unavailable_capability


def test_a_link_over_an_existing_file_is_a_mistake_not_a_platform_gap(tmp_path: Path) -> None:
    """The distinction this whole module exists to preserve.

    A skip says "this machine cannot answer the question". Asking for a symlink
    where a file already sits is the caller getting the argument order wrong, and
    reporting it as a platform gap hides a test that never ran.
    """

    occupied = tmp_path / "already-here.txt"
    occupied.write_text("do not replace me\n", encoding="utf-8")
    target = tmp_path / "target.txt"
    target.write_text("target\n", encoding="utf-8")

    with pytest.raises(FileExistsError, match="link first and its target second"):
        create_symlink(occupied, target)

    assert occupied.read_text(encoding="utf-8") == "do not replace me\n"


def test_the_refusal_names_the_argument_order(tmp_path: Path) -> None:
    """The message has to say how to fix it, or it is just a different failure."""

    occupied = tmp_path / "occupied"
    occupied.mkdir()

    with pytest.raises(FileExistsError) as caught:
        create_symlink(occupied, tmp_path / "elsewhere")

    assert "create_symlink takes the link first" in str(caught.value)


def test_a_dangling_target_is_still_a_legitimate_link(tmp_path: Path) -> None:
    """Only the *link* must be free. Pointing at nothing is a normal symlink."""

    link = tmp_path / "link"
    create_symlink(link, tmp_path / "never-created")

    assert link.is_symlink()
    assert not link.exists()


def test_an_enforced_capability_fails_rather_than_skips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With the enforcement variable set, a skip must become a failure."""

    monkeypatch.setenv("TRUEAI_REQUIRE_PRIVILEGED_TESTS", "1")

    # pytest's own outcomes derive from BaseException so that an `except
    # Exception` in the code under test cannot swallow a skip or a failure.
    with pytest.raises(BaseException) as caught:
        unavailable_capability("Symlink creation", "no privilege")

    assert "must run here" in str(caught.value)


def test_an_unenforced_capability_skips_with_the_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("TRUEAI_REQUIRE_PRIVILEGED_TESTS", raising=False)

    with pytest.raises(BaseException) as caught:
        unavailable_capability("Symlink creation", "no privilege")

    assert "no privilege" in str(caught.value)


def test_missing_modules_reports_only_what_is_absent() -> None:
    assert missing_modules("json", "pathlib") == []
    assert missing_modules("json", "trueai_module_that_does_not_exist") == [
        "trueai_module_that_does_not_exist"
    ]
