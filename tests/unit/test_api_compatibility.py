"""The published Python API is a contract, so its rules are executable."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from trueai.api import (
    API_SNAPSHOT_PATH,
    API_VERSION,
    PUBLIC_MODULES,
    SDK_CONTRACT,
    breaking_api_changes,
    canonical_api_json,
    compare_api_surfaces,
    public_api_surface,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PUBLISHED = REPOSITORY_ROOT / "api" / "published" / API_SNAPSHOT_PATH.name


def load_published() -> dict[str, Any]:
    """Read the frozen surface that consumers were given."""

    raw = json.loads(PUBLISHED.read_text(encoding="utf-8"))
    assert isinstance(raw, dict)
    return raw


def mutate(surface: dict[str, Any]) -> dict[str, Any]:
    """Return a deep copy that a test can safely edit."""

    return json.loads(json.dumps(surface))


def test_published_api_snapshot_exists() -> None:
    assert PUBLISHED.is_file(), f"The frozen contract for API {API_VERSION} is missing: {PUBLISHED}"


def test_current_surface_is_backward_compatible_with_the_published_contract() -> None:
    published = load_published()

    violations = breaking_api_changes(published, public_api_surface())

    assert not violations, (
        "The current code breaks the published API contract:\n"
        + "\n".join(f"  {change}" for change in violations)
        + "\nA breaking change requires a new API version and a new published file; "
        "see docs/api-compatibility.md."
    )


def test_committed_snapshot_matches_the_emitted_surface() -> None:
    snapshot = REPOSITORY_ROOT / API_SNAPSHOT_PATH
    if not snapshot.is_file():  # pragma: no cover - only when running from a wheel
        pytest.skip(f"API snapshot is not present in this checkout: {snapshot}")

    committed = json.loads(snapshot.read_text(encoding="utf-8"))

    assert committed == json.loads(canonical_api_json(public_api_surface())), (
        "Regenerate with: python scripts/check_api_snapshot.py --write"
    )


def test_every_declared_public_module_is_importable() -> None:
    surface = public_api_surface()

    assert set(surface["modules"]) == set(PUBLIC_MODULES)
    for module_name, exported in surface["modules"].items():
        assert exported, f"{module_name} exports nothing, so listing it is misleading"


def test_the_package_version_is_not_part_of_the_contract() -> None:
    """A release bump must not make every snapshot stale."""

    rendered = json.loads(canonical_api_json(public_api_surface()))

    assert "package_version" not in rendered
    assert rendered["api_version"] == API_VERSION


# -- classification --------------------------------------------------------------


def test_a_new_optional_parameter_is_additive() -> None:
    published = load_published()
    candidate = mutate(published)
    candidate["modules"]["trueai.core.policy"]["PolicyStore"]["methods"]["get"][
        "parameters"
    ].append({"name": "strict", "kind": "KEYWORD_ONLY", "required": False})

    changes = compare_api_surfaces(published, candidate)

    assert [change.kind for change in changes] == ["added_parameter"]
    assert not breaking_api_changes(published, candidate)


def test_a_new_required_parameter_is_breaking() -> None:
    published = load_published()
    candidate = mutate(published)
    candidate["modules"]["trueai.core.policy"]["PolicyStore"]["methods"]["get"][
        "parameters"
    ].append({"name": "mandatory", "kind": "KEYWORD_ONLY", "required": True})

    violations = breaking_api_changes(published, candidate)

    assert [change.kind for change in violations] == ["added_parameter"]


def test_removing_a_public_name_is_breaking() -> None:
    published = load_published()
    candidate = mutate(published)
    del candidate["modules"]["trueai"]["TrueAIEngine"]

    violations = breaking_api_changes(published, candidate)

    assert [change.kind for change in violations] == ["removed_name"]


def test_removing_a_public_module_is_breaking() -> None:
    published = load_published()
    candidate = mutate(published)
    del candidate["modules"]["trueai.reporters"]

    violations = breaking_api_changes(published, candidate)

    assert [change.kind for change in violations] == ["removed_module"]


def test_adding_a_public_module_is_additive() -> None:
    published = load_published()
    candidate = mutate(published)
    candidate["modules"]["trueai.future"] = {"Thing": {"kind": "value", "type": "int"}}

    changes = compare_api_surfaces(published, candidate)

    assert [change.kind for change in changes] == ["added_module"]
    assert not breaking_api_changes(published, candidate)


def test_removing_an_enum_member_is_breaking() -> None:
    published = load_published()
    candidate = mutate(published)
    candidate["modules"]["trueai.core.models"]["Severity"]["members"].remove("critical")

    violations = breaking_api_changes(published, candidate)

    assert [change.kind for change in violations] == ["removed_enum_member"]


def test_adding_an_enum_member_is_additive() -> None:
    published = load_published()
    candidate = mutate(published)
    candidate["modules"]["trueai.core.models"]["Severity"]["members"].append("catastrophic")

    assert not breaking_api_changes(published, candidate)


def test_removing_a_model_field_is_breaking() -> None:
    published = load_published()
    candidate = mutate(published)
    del candidate["modules"]["trueai.core.models"]["Finding"]["model_fields"]["confidence"]

    violations = breaking_api_changes(published, candidate)

    assert [change.kind for change in violations] == ["removed_model_field"]


def test_making_a_model_field_required_is_breaking() -> None:
    published = load_published()
    candidate = mutate(published)
    candidate["modules"]["trueai.core.models"]["Finding"]["model_fields"]["tags"]["required"] = True

    violations = breaking_api_changes(published, candidate)

    assert [change.kind for change in violations] == ["changed_model_field_requirement"]


def test_reordering_positional_parameters_is_breaking() -> None:
    published = load_published()
    candidate = mutate(published)
    parameters = candidate["modules"]["trueai.core.remediation"]["RemediationService"]["methods"][
        "apply"
    ]["parameters"]
    positional = [
        item for item in parameters if item["kind"] in {"POSITIONAL_ONLY", "POSITIONAL_OR_KEYWORD"}
    ]
    assert len(positional) >= 2, "the fixture needs two positional parameters to swap"
    first, second = positional[0]["name"], positional[1]["name"]
    for item in parameters:
        if item["name"] == first:
            item["name"] = second
        elif item["name"] == second:
            item["name"] = first

    violations = breaking_api_changes(published, candidate)

    assert any(change.kind == "reordered_parameters" for change in violations)


def test_changing_a_name_from_class_to_callable_is_breaking() -> None:
    published = load_published()
    candidate = mutate(published)
    candidate["modules"]["trueai.core.models"]["Finding"] = {
        "kind": "callable",
        "signature": {"parameters": [], "introspectable": True},
    }

    violations = breaking_api_changes(published, candidate)

    assert [change.kind for change in violations] == ["changed_name_kind"]


# -- the SDK rule: abstractness is part of what a subclass depends on ----------------


def surface_with(described: dict[str, Any]) -> dict[str, Any]:
    """Build a one-class surface so a rule can be tested in isolation."""

    return {
        "api_version": API_VERSION,
        "modules": {"trueai.detectors.base": {"BaseDetector": described}},
    }


def detector_class(*, methods: dict[str, Any], abstract: list[str]) -> dict[str, Any]:
    return {
        "kind": "class",
        "bases": [],
        "methods": {name: {"parameters": [], "introspectable": True} for name in methods},
        "attributes": [],
        "abstract_methods": abstract,
    }


def test_a_new_abstract_method_is_breaking_even_though_it_is_an_addition() -> None:
    """Every existing third-party detector stops being instantiable."""

    before = surface_with(detector_class(methods={"scan": {}}, abstract=["scan"]))
    after = surface_with(
        detector_class(methods={"scan": {}, "prepare": {}}, abstract=["scan", "prepare"])
    )

    changes = compare_api_surfaces(before, after)

    assert [change.kind for change in changes] == ["added_abstract_method"]
    assert changes[0].breaking
    assert "subclass" in changes[0].detail


def test_a_new_concrete_method_is_still_an_addition() -> None:
    before = surface_with(detector_class(methods={"scan": {}}, abstract=["scan"]))
    after = surface_with(detector_class(methods={"scan": {}, "helper": {}}, abstract=["scan"]))

    changes = compare_api_surfaces(before, after)

    assert [change.kind for change in changes] == ["added_method"]
    assert not changes[0].breaking


def test_an_existing_method_becoming_abstract_is_breaking() -> None:
    """Same consequence, arrived at without adding a name."""

    before = surface_with(detector_class(methods={"scan": {}, "supports": {}}, abstract=["scan"]))
    after = surface_with(
        detector_class(methods={"scan": {}, "supports": {}}, abstract=["scan", "supports"])
    )

    changes = breaking_api_changes(before, after)

    assert [change.kind for change in changes] == ["added_abstract_method"]


def test_relaxing_a_requirement_on_subclasses_is_not_breaking() -> None:
    before = surface_with(detector_class(methods={"scan": {}}, abstract=["scan"]))
    after = surface_with(detector_class(methods={"scan": {}}, abstract=[]))

    changes = compare_api_surfaces(before, after)

    assert [change.kind for change in changes] == ["removed_abstract_method"]
    assert not changes[0].breaking


def test_the_detector_base_class_still_asks_subclasses_for_exactly_one_method() -> None:
    """A promise the examples and the docs both make; here it is, checked."""

    described = public_api_surface()["modules"]["trueai.detectors.base"]["BaseDetector"]

    assert described["abstract_methods"] == ["scan"]


def test_every_sdk_name_is_in_the_frozen_surface() -> None:
    surface = public_api_surface()["modules"]
    missing = [
        f"{module}.{name}"
        for module, name in SDK_CONTRACT
        if module not in surface or name not in surface[module]
    ]

    assert missing == []


def test_the_sdk_contract_names_no_module_outside_the_public_list() -> None:
    assert {module for module, _ in SDK_CONTRACT} <= set(PUBLIC_MODULES)


def test_a_contract_published_before_the_field_existed_reports_no_false_break() -> None:
    """A descriptive addition must not retroactively invent a breaking change.

    The standing hazard whenever a frozen contract gains a field: absent data is
    not evidence that the answer was empty.
    """

    older = surface_with(
        {
            "kind": "class",
            "bases": [],
            "methods": {"scan": {"parameters": [], "introspectable": True}},
            "attributes": [],
        }
    )
    current = surface_with(detector_class(methods={"scan": {}}, abstract=["scan"]))

    assert breaking_api_changes(older, current) == ()
