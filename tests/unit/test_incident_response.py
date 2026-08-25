"""The incident processes, checked for the parts that get left out.

A document describing what to do in an incident is worth having only if it names
the mechanisms that exist. The failure it guards is a runbook that tells somebody
to revoke a thing the tool cannot revoke, at three in the morning.

The other thing checked is the half that gets left out of every advisory: what
already-issued evidence is worth. A forensic tool's reports stay in circulation
after the failure that produced them.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[2]
RUNBOOK = REPOSITORY / "docs" / "incident-response.md"
SECURITY = REPOSITORY / "SECURITY.md"


@pytest.fixture(scope="module")
def runbook() -> str:
    return RUNBOOK.read_text(encoding="utf-8")


# -- all five incidents are covered ---------------------------------------------------


@pytest.mark.parametrize(
    "incident",
    [
        "vulnerability report",
        "plugin incident",
        "trust store compromise",
        "certificate misissuance",
        "release that has to be rolled back",
    ],
)
def test_every_named_incident_has_a_section(incident: str, runbook: str) -> None:
    assert incident.lower() in runbook.lower(), incident


def test_the_security_policy_points_at_all_five(runbook: str) -> None:
    text = SECURITY.read_text(encoding="utf-8")

    assert "docs/incident-response.md" in text
    assert text.count("incident-response.md") >= 5


# -- the mechanisms each process names actually exist ---------------------------------


def test_the_plugin_process_names_a_revocation_that_exists(runbook: str) -> None:
    """A runbook telling somebody to revoke a thing the tool cannot revoke is worse
    than none, because it is read at three in the morning."""

    from trueai.plugins.distribution import DistributionRevocation

    assert "DistributionRevocation" in runbook
    assert DistributionRevocation is not None


def test_the_plugin_process_names_the_diagnostics_the_engine_emits(runbook: str) -> None:
    for code in ("detector_mutation", "plugin_rejected"):
        assert code in runbook, code


def test_the_diagnostic_codes_it_names_are_the_ones_the_engine_uses() -> None:
    """Named rather than paraphrased, so a reader can grep a report for them."""

    source = (REPOSITORY / "trueai" / "core" / "engine.py").read_text(encoding="utf-8")

    for code in ("detector_mutation", "plugin_rejected"):
        assert f'code="{code}"' in source, code


def test_the_trust_store_process_relies_on_the_one_sequence_rule(runbook: str) -> None:
    """It is the property that makes a revocation impossible to skip."""

    from trueai.core.trust_store import TrustStoreUpdate

    assert "Do not skip a sequence" in runbook
    assert TrustStoreUpdate is not None


def test_the_trust_store_process_separates_signature_from_signer_trust(runbook: str) -> None:
    """A compromised anchor breaks signer trust, not the signature.

    Saying "provenance verification was broken" overstates it, and an
    overstatement is what gets a correction printed later.
    """

    assert "only *signer trust* was wrong" in runbook
    assert "overstates" in runbook


def test_the_certificate_process_names_the_command_that_revokes(runbook: str) -> None:
    import typer

    from trueai.cli.app import app

    assert "trueai certificates revoke" in runbook
    command = typer.main.get_command(app)
    certificates = command.commands["certificates"]  # type: ignore[attr-defined]
    assert "revoke" in certificates.commands


def test_the_certificate_process_restates_what_a_certificate_never_claimed(
    runbook: str,
) -> None:
    """Otherwise the advisory makes the original overclaim on the project's behalf."""

    assert "never certified human authorship" in runbook
    assert "never certified that AI was not used" in runbook


def test_a_compromised_key_revokes_everything_it_signed(runbook: str) -> None:
    """A partial revocation invites relying parties to trust the remainder."""

    assert "revoke every certificate that key signed" in runbook
    assert "not only" in runbook


def test_the_rollback_process_yanks_rather_than_deletes(runbook: str) -> None:
    """A deleted release breaks lockfiles belonging to people the bug never touched."""

    assert "Yank rather than delete" in runbook
    assert "lockfile" in runbook


def test_the_rollback_process_re_runs_the_release_gates(runbook: str) -> None:
    assert "supply chain" in runbook
    assert "reproducible" in runbook


# -- the half that gets left out ------------------------------------------------------


def test_every_process_says_what_already_issued_evidence_is_worth(runbook: str) -> None:
    """The second half of all five, and the half that gets dropped."""

    assert runbook.lower().count("already-issued") >= 2
    assert "still in circulation" in runbook or "stay in circulation" in runbook


def test_the_runbook_warns_against_overstating_the_blast_radius(runbook: str) -> None:
    """Precision is not a courtesy here; it keeps the channel usable."""

    assert "Do not overstate the blast radius" in runbook
    assert "discount the next advisory" in runbook


def test_the_runbook_requires_a_regression_fixture_before_a_replacement_ships(
    runbook: str,
) -> None:
    """A bug without a committed fixture comes back."""

    assert "regression fixture before the replacement ships" in runbook
    assert "synthetic fixture" in runbook


def test_every_incident_names_who_has_to_be_told(runbook: str) -> None:
    """Different blast radii mean different people, and the table says which."""

    for audience in ("Reporter", "publisher", "fleet", "relying parties"):
        assert audience.lower() in runbook.lower(), audience


def test_the_plugin_process_tells_the_publisher_before_the_operators(runbook: str) -> None:
    """Operators can only stop using it; publishers can ship a fix."""

    assert "Tell the publisher first" in runbook


# -- the documents themselves ----------------------------------------------------------


def test_the_runbook_is_linked_and_not_an_orphan() -> None:
    from scripts.check_docs import orphaned_documents

    orphans = {problem.document for problem in orphaned_documents()}

    assert "docs/incident-response.md" not in orphans


def test_the_runbook_links_only_to_documents_that_exist() -> None:
    from scripts.check_docs import check_document, cli_surface

    commands, options, groups = cli_surface()

    assert check_document(RUNBOOK, commands, options, groups) == []
