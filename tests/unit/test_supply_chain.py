"""Supply-chain gates, and the neglect each one is supposed to catch.

The advisory gate is the unusual one. `pip-audit` fails when a CVE appears; this
fails when *nobody has looked*, which is the failure that actually happens. So
most of what follows drives the clock forward and checks the gate notices.
"""

from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[2]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from scripts.check_advisories import (  # noqa: E402
    LEDGER_PATH,
    _absence_is_expected,
    check,
    installed_closure,
    load_ledger,
)
from scripts.check_licenses import (  # noqa: E402
    ALLOWED_LICENSES,
    license_is_allowed,
    read_licenses_directly,
    runtime_distribution_names,
)
from scripts.check_supply_chain import GATES  # noqa: E402
from scripts.generate_sbom import (  # noqa: E402
    Component,
    build_document,
    collect,
    incompleteness,
)
from scripts.generate_sbom import main as sbom_main  # noqa: E402

TODAY = date(2026, 8, 25)


def ledger(**meta: object) -> dict[str, object]:
    base: dict[str, object] = {
        "meta": {
            "reviewed_at": "2026-08-25",
            "reviewed_by": "someone",
            "max_age_days": 90,
            "sources": ["https://osv.dev/"],
        },
        "component": [
            {
                "name": "pydantic",
                "kind": "dependency",
                "why": "Validates every model.",
                "reviewed_at": "2026-08-25",
            },
            {
                "name": "cpython:zipfile",
                "kind": "stdlib-parser",
                "why": "Every OPC package.",
                "reviewed_at": "2026-08-25",
            },
        ],
    }
    assert isinstance(base["meta"], dict)
    base["meta"].update(meta)
    return base


INSTALLED = frozenset({"pydantic"})


# -- the gate fails when nobody has looked -------------------------------------------


def test_a_ledger_reviewed_recently_passes() -> None:
    assert check(ledger(), installed=INSTALLED, today=TODAY) == []


def test_a_stale_ledger_fails() -> None:
    """The failure that matters: it fires when the reviewing stops."""

    problems = check(ledger(), installed=INSTALLED, today=date(2027, 1, 1))

    assert any(item.kind == "stale" for item in problems)
    assert any("re-check the sources" in item.detail for item in problems)


def test_a_ledger_one_day_inside_its_window_still_passes() -> None:
    problems = check(ledger(), installed=INSTALLED, today=date(2026, 11, 22))

    assert not [item for item in problems if item.kind == "stale"]


def test_a_component_reviewed_long_ago_fails_even_when_the_header_is_fresh() -> None:
    """Bumping the header without re-reading the entries would otherwise pass."""

    stale = ledger()
    components = stale["component"]
    assert isinstance(components, list)
    components[0]["reviewed_at"] = "2025-01-01"

    problems = check(stale, installed=INSTALLED, today=TODAY)

    assert any(item.kind == "stale" and "pydantic" in item.detail for item in problems)


def test_a_ledger_with_no_sources_fails() -> None:
    """A handover would otherwise lose the watch list."""

    problems = check(ledger(sources=[]), installed=INSTALLED, today=TODAY)

    assert any("sources" in item.detail for item in problems)


# -- the ledger has to describe the build that exists --------------------------------


def test_an_unreviewed_dependency_fails() -> None:
    problems = check(ledger(), installed=frozenset({"pydantic", "newcomer"}), today=TODAY)

    assert any(item.kind == "unreviewed" and "newcomer" in item.detail for item in problems)


def test_a_reviewed_dependency_that_is_gone_fails() -> None:
    """Otherwise the ledger describes a build that no longer exists."""

    problems = check(ledger(), installed=frozenset(), today=TODAY)

    assert any(item.kind == "orphaned" and "pydantic" in item.detail for item in problems)


def test_an_optional_parser_may_be_absent_without_failing() -> None:
    """The extras are not installed everywhere, and that is not neglect."""

    optional = ledger()
    components = optional["component"]
    assert isinstance(components, list)
    components.append(
        {
            "name": "pikepdf",
            "kind": "optional-parser",
            "why": "PDF parsing through qpdf.",
            "reviewed_at": "2026-08-25",
        }
    )

    problems = check(optional, installed=INSTALLED, today=TODAY)

    assert not [item for item in problems if item.kind == "orphaned"]


def test_a_stdlib_parser_is_never_expected_to_be_installed() -> None:
    """It has no distribution, which is exactly why it needs an entry."""

    problems = check(ledger(), installed=INSTALLED, today=TODAY)

    assert not [item for item in problems if "zipfile" in item.detail]


def test_a_component_without_a_reason_fails() -> None:
    """An entry nobody can justify is an entry nobody reviewed."""

    unexplained = ledger()
    components = unexplained["component"]
    assert isinstance(components, list)
    components[0]["why"] = ""

    problems = check(unexplained, installed=INSTALLED, today=TODAY)

    assert any(item.kind == "unexplained" for item in problems)


# -- an acceptance is not a decision until it has an expiry ---------------------------


def test_an_accepted_risk_without_an_expiry_fails() -> None:
    """Without one it becomes permanent by inattention rather than by decision."""

    with_acceptance = ledger()
    with_acceptance["accepted"] = [
        {
            "advisory": "GHSA-test",
            "component": "pydantic",
            "reason": "not reachable",
            "accepted_by": "maintainer",
        }
    ]

    problems = check(with_acceptance, installed=INSTALLED, today=TODAY)

    assert any(item.kind == "accepted" and "expiry" in item.detail for item in problems)


def test_an_expired_acceptance_fails() -> None:
    with_acceptance = ledger()
    with_acceptance["accepted"] = [
        {
            "advisory": "GHSA-test",
            "component": "pydantic",
            "reason": "not reachable",
            "accepted_by": "maintainer",
            "expires_at": "2026-01-01",
        }
    ]

    problems = check(with_acceptance, installed=INSTALLED, today=TODAY)

    assert any(item.kind == "expired" for item in problems)


def test_a_live_acceptance_passes() -> None:
    with_acceptance = ledger()
    with_acceptance["accepted"] = [
        {
            "advisory": "GHSA-test",
            "component": "pydantic",
            "reason": "not reachable",
            "accepted_by": "maintainer",
            "expires_at": "2027-01-01",
        }
    ]

    assert check(with_acceptance, installed=INSTALLED, today=TODAY) == []


def test_an_acceptance_without_a_reason_fails() -> None:
    with_acceptance = ledger()
    with_acceptance["accepted"] = [
        {"advisory": "GHSA-test", "component": "pydantic", "expires_at": "2027-01-01"}
    ]

    problems = check(with_acceptance, installed=INSTALLED, today=TODAY)

    assert len([item for item in problems if item.kind == "accepted"]) == 2


# -- the real ledger ------------------------------------------------------------------


def test_the_committed_ledger_describes_this_environment() -> None:
    """The gate on the actual repository, at a pinned date.

    Pinned so this test checks the *ledger* rather than the calendar. Whether the
    review has gone stale is checked separately, and deliberately does move with
    the calendar.
    """

    problems = check(load_ledger(LEDGER_PATH), installed=installed_closure(), today=TODAY)

    assert problems == [], [str(item) for item in problems]


def test_the_advisory_review_is_not_overdue() -> None:
    """This one is allowed to start failing as time passes. That is the point.

    A suite that never tells anybody the review lapsed is a suite that lets it
    lapse. When this fails, re-read the sources in `security/advisories.toml` and
    move the dates — the fix is doing the review, not editing the test.
    """

    problems = check(load_ledger(LEDGER_PATH), installed=installed_closure(), today=date.today())
    stale = [item for item in problems if item.kind == "stale"]

    assert stale == [], (
        "The advisory review is overdue: "
        + "; ".join(item.detail for item in stale)
        + ". Re-check the sources listed in security/advisories.toml and move the dates."
    )


def test_the_ledger_covers_the_standard_library_parsers_a_dependency_audit_misses() -> None:
    """The reason this file exists at all."""

    raw = load_ledger(LEDGER_PATH)
    components = raw["component"]
    assert isinstance(components, list)
    stdlib = {
        entry["name"]
        for entry in components
        if isinstance(entry, dict) and entry.get("kind") == "stdlib-parser"
    }

    assert {"cpython:zipfile", "cpython:xml.etree", "cpython:zlib", "cpython:json"} <= stdlib


# -- the SBOM has to answer the questions it is requested for ------------------------


def test_a_component_with_no_version_is_an_incomplete_sbom() -> None:
    """A document that passes "do you have an SBOM" and answers nothing."""

    problems = incompleteness(
        [Component(name="x", version="", license_id="MIT", purl="pkg:pypi/x@")]
    )

    assert any("no version" in item for item in problems)


def test_a_component_with_no_license_is_an_incomplete_sbom() -> None:
    problems = incompleteness(
        [Component(name="x", version="1", license_id="", purl="pkg:pypi/x@1")]
    )

    assert any("no license" in item for item in problems)


def test_two_components_sharing_a_reference_is_an_incomplete_sbom() -> None:
    same = Component(name="x", version="1", license_id="MIT", purl="pkg:pypi/x@1")

    problems = incompleteness([same, same])

    assert any("share a bom-ref" in item for item in problems)


def test_an_empty_sbom_is_reported_rather_than_passing() -> None:
    assert incompleteness([]) == ["the SBOM lists no components at all"]


def test_the_real_closure_produces_a_complete_sbom() -> None:
    assert incompleteness(collect(runtime_distribution_names())) == []


def test_the_document_is_cyclonedx_and_names_the_application() -> None:
    document = build_document(
        [Component(name="x", version="1", license_id="MIT", purl="pkg:pypi/x@1")]
    )

    assert document["bomFormat"] == "CycloneDX"
    assert document["metadata"]["component"]["name"] == "trueai-core"
    assert document["components"][0]["licenses"][0]["license"]["name"] == "MIT"


def test_the_timestamp_can_be_pinned_for_a_reproducible_build() -> None:
    """A document that differs between two builds of one source proves nothing."""

    from datetime import UTC, datetime

    moment = datetime(2026, 1, 1, tzinfo=UTC)
    first = build_document([], timestamp=moment)
    second = build_document([], timestamp=moment)

    assert first == second


def test_the_sbom_cli_accepts_a_reproducible_timestamp(tmp_path: Path) -> None:
    output = tmp_path / "sbom.json"

    assert sbom_main(["--output", str(output), "--timestamp", "1767225600"]) == 0

    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["metadata"]["timestamp"] == "2026-01-01T00:00:00+00:00"


# -- licenses -------------------------------------------------------------------------


def test_the_license_gate_runs_without_pip_licenses_installed() -> None:
    """A gate that only runs in one CI provider cannot be run before pushing."""

    packages = read_licenses_directly(runtime_distribution_names())

    assert packages
    assert all(item["Name"] and item["Version"] for item in packages)


def test_every_installed_license_is_allowlisted_under_either_spelling() -> None:
    """Two readers disagree about which metadata field to believe."""

    unexpected = [
        (item["Name"], item["License"])
        for item in read_licenses_directly(runtime_distribution_names())
        if not license_is_allowed(item["License"])
    ]

    assert unexpected == []


def test_the_allowlist_carries_both_spellings_of_the_licenses_that_have_two() -> None:
    for pair in (("ISC License (ISCL)", "ISC License"), ("PSF-2.0", "PSFL")):
        assert set(pair) <= ALLOWED_LICENSES


def test_a_copyleft_license_is_still_refused() -> None:
    """The allowlist got longer; it did not get weaker."""

    for refused in ("GPL-3.0", "AGPL-3.0", "GNU General Public License v3 (GPLv3)"):
        assert not license_is_allowed(refused)


# -- the combined gate ----------------------------------------------------------------


def test_the_release_gate_runs_all_four_checks() -> None:
    assert {gate.name for gate in GATES} == {"licenses", "advisories", "sbom", "manifest"}


def test_every_gate_states_the_question_it_answers() -> None:
    for gate in GATES:
        assert gate.question.endswith("?"), gate.name


@pytest.mark.parametrize("gate", GATES, ids=lambda gate: gate.name)
def test_each_gate_passes_on_this_working_tree(gate) -> None:
    assert gate.run() == 0


# -- a dependency that exists on one platform and not another --------------------------


def _platform_component(**overrides: object) -> dict[str, object]:
    entry: dict[str, object] = {
        "name": "colorama",
        "kind": "dependency",
        "why": "Behind rich on Windows; terminal escapes only.",
        "platforms": ["win32"],
        "reviewed_at": "2026-08-25",
    }
    entry.update(overrides)
    return entry


def test_a_windows_only_dependency_may_be_absent_on_linux() -> None:
    """It is in the lock and installs nowhere else, which is not neglect.

    Reported as orphaned it invites the fix that loses information: deleting a
    reviewed entry for a package that really does ship, on one platform, and
    really does need a recorded decision about what it parses.
    """

    conditional = ledger()
    components = conditional["component"]
    assert isinstance(components, list)
    components.append(_platform_component())

    problems = check(conditional, installed=INSTALLED, today=TODAY, platform="linux")

    assert not [item for item in problems if item.kind == "orphaned"]


def test_the_same_windows_only_dependency_is_reported_missing_on_windows() -> None:
    """Declaring a platform excuses absence there and nowhere else."""

    conditional = ledger()
    components = conditional["component"]
    assert isinstance(components, list)
    components.append(_platform_component())

    problems = check(conditional, installed=INSTALLED, today=TODAY, platform="win32")

    assert [item for item in problems if item.kind == "orphaned" and "colorama" in item.detail]


def test_the_same_dependency_missing_on_its_own_platform_is_still_reported() -> None:
    """Declaring a platform excuses absence there and nowhere else."""

    components = [_platform_component()]

    assert _absence_is_expected(components, "colorama", "linux")
    assert not _absence_is_expected(components, "colorama", "win32")


def test_a_dependency_with_no_platforms_is_expected_everywhere() -> None:
    components = [_platform_component(name="pathspec", platforms=None)]
    del components[0]["platforms"]

    assert not _absence_is_expected(components, "pathspec", "linux")
    assert not _absence_is_expected(components, "pathspec", "win32")


@pytest.mark.parametrize("value", [[], "win32", ["win32", ""], [1], {}])
def test_an_unreadable_platform_list_is_a_ledger_error(value: object) -> None:
    """An unparseable field must not quietly excuse a real absence."""

    broken = ledger()
    components = broken["component"]
    assert isinstance(components, list)
    components.append(_platform_component(platforms=value))

    problems = check(broken, installed=INSTALLED, today=TODAY)

    assert [item for item in problems if item.kind == "ledger" and "platforms" in item.detail]


def test_the_committed_ledger_declares_the_platform_for_its_conditional_entry() -> None:
    """colorama is the one entry whose presence depends on the operating system."""

    components = load_ledger(LEDGER_PATH)["component"]
    assert isinstance(components, list)
    entry = next(item for item in components if item.get("name") == "colorama")

    assert entry["platforms"] == ["win32"]
