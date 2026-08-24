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
