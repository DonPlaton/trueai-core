"""What the README's capability table says about containers, checked against the code.

The table's cleanup column said `Inspection only` for M4A, MP4, MOV, and WebM
while the paragraph a hundred lines below it described the mechanism in detail —
same-length `free` padding, so nothing moves and no offset needs correcting. Both
could not be right.

The code is what settles it: the cleaner exists, it is surgical, and it is gated
on the seven container invariants. What is true is narrower and belongs in the
table: **no built-in policy selects it.** `media_metadata` is `review` in every
cleaning profile and `error` under `strict`, so `trueai clean` leaves a container
alone until an operator writes a policy that says otherwise.

These tests hold both halves of that statement, because a change to either one
turns the README into a false claim in one direction or the other.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tests.unit.test_iso_bmff_invariants import build_mp4
from trueai.core.models import PolicyAction
from trueai.core.policy import PolicyStore

BUILT_IN_PROFILES = ("audit", "safe-clean", "privacy", "client-delivery", "strict")


@pytest.mark.parametrize("profile", BUILT_IN_PROFILES)
def test_no_built_in_policy_removes_container_metadata(profile: str) -> None:
    policy = PolicyStore.get(profile)
    rules = {name: action for name, action in policy.rules.items()}

    assert rules.get("media_metadata") != PolicyAction.REMOVE


def test_an_explicit_policy_does_clean_a_container(tmp_path: Path) -> None:
    """The other half: the capability is real and reachable, not aspirational."""

    from typer.testing import CliRunner

    from trueai.cli.app import app

    clip = tmp_path / "clip.mp4"
    original = build_mp4()
    clip.write_bytes(original)
    policy = tmp_path / "media.yaml"
    policy.write_text(
        yaml.safe_dump(
            {
                "policy": "media-clean",
                "default_action": "report",
                "rules": {"media_metadata": "remove", "c2pa_provenance": "preserve"},
            }
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["clean", str(clip), "--policy", str(policy)])

    cleaned = tmp_path / "clip.cleaned.mp4"
    assert cleaned.exists(), result.output
    # Same length is the whole design: a shorter file would have moved every
    # sample offset stored in `stco`.
    assert cleaned.stat().st_size == len(original)
    assert cleaned.read_bytes() != original
    assert "invariants held" in result.output, result.output
