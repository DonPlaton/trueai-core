"""The published report schema is a contract, so its rules are executable."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from trueai._version import SCHEMA_VERSION
from trueai.reporters import JSONReporter
from trueai.schema import (
    SCHEMA_SNAPSHOT_PATH,
    breaking_changes,
    canonical_schema_json,
    compare_report_schemas,
    report_schema,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PUBLISHED_SCHEMA = REPOSITORY_ROOT / "schema" / "published" / SCHEMA_SNAPSHOT_PATH.name


def load_published() -> dict[str, object]:
    """Read the frozen contract that consumers were given."""

    raw = json.loads(PUBLISHED_SCHEMA.read_text(encoding="utf-8"))
    assert isinstance(raw, dict)
    return raw


def test_published_schema_snapshot_exists() -> None:
    assert PUBLISHED_SCHEMA.is_file(), (
        f"The frozen contract for schema {SCHEMA_VERSION} is missing: {PUBLISHED_SCHEMA}"
    )


def test_current_schema_is_backward_compatible_with_the_published_contract() -> None:
    published = load_published()

    violations = breaking_changes(published, report_schema())

    assert not violations, (
        "The current models break the published schema contract:\n"
        + "\n".join(f"  {change}" for change in violations)
        + "\nA breaking change requires a new schema_version and a new published file; "
        "see docs/schema-compatibility.md."
    )


def test_schema_version_is_unchanged_since_publication() -> None:
    published = load_published()
    properties = published["properties"]
    assert isinstance(properties, dict)
    version_field = properties["schema_version"]
    assert isinstance(version_field, dict)

    assert version_field["const"] == SCHEMA_VERSION


def test_reporter_schema_matches_the_schema_module() -> None:
    assert JSONReporter.schema() == report_schema()


def test_canonical_serialization_is_deterministic_and_newline_terminated() -> None:
    rendered = canonical_schema_json(report_schema())

    assert rendered.endswith("\n")
    assert rendered == canonical_schema_json(report_schema())
    assert json.loads(rendered) == report_schema()


def test_committed_snapshot_matches_the_emitted_schema() -> None:
    snapshot = REPOSITORY_ROOT / SCHEMA_SNAPSHOT_PATH
    if not snapshot.is_file():  # pragma: no cover - only when running from a wheel
        pytest.skip(f"Schema snapshot is not present in this checkout: {snapshot}")

    committed = json.loads(snapshot.read_text(encoding="utf-8"))

    assert committed == report_schema(), (
        f"Regenerate with: trueai schema --output {SCHEMA_SNAPSHOT_PATH}"
    )


def test_added_optional_property_is_additive_not_breaking() -> None:
    published = load_published()
    candidate = json.loads(json.dumps(published))
    candidate["$defs"]["Finding"]["properties"]["new_optional"] = {"type": "string"}

    changes = compare_report_schemas(published, candidate)

    assert [change.kind for change in changes] == ["added_property"]
    assert not breaking_changes(published, candidate)


def test_added_enum_member_is_additive_not_breaking() -> None:
    published = load_published()
    candidate = json.loads(json.dumps(published))
    candidate["$defs"]["Severity"]["enum"].append("catastrophic")

    assert not breaking_changes(published, candidate)


def test_removed_property_is_reported_as_breaking() -> None:
    published = load_published()
    candidate = json.loads(json.dumps(published))
    del candidate["$defs"]["Finding"]["properties"]["confidence_type"]

    violations = breaking_changes(published, candidate)

    assert [change.kind for change in violations] == ["removed_property"]
    assert "Finding.confidence_type" in violations[0].location


def test_removed_enum_member_is_reported_as_breaking() -> None:
    published = load_published()
    candidate = json.loads(json.dumps(published))
    candidate["$defs"]["ConfidenceType"]["enum"].remove("heuristic")

    violations = breaking_changes(published, candidate)

    assert [change.kind for change in violations] == ["removed_enum_member"]


def test_changed_property_type_is_reported_as_breaking() -> None:
    published = load_published()
    candidate = json.loads(json.dumps(published))
    candidate["$defs"]["Finding"]["properties"]["confidence"] = {"type": "string"}

    violations = breaking_changes(published, candidate)

    assert [change.kind for change in violations] == ["changed_property_type"]


def test_new_required_property_is_reported_as_breaking() -> None:
    published = load_published()
    candidate = json.loads(json.dumps(published))
    candidate["$defs"]["Finding"]["properties"]["mandatory"] = {"type": "string"}
    candidate["$defs"]["Finding"]["required"].append("mandatory")

    violations = breaking_changes(published, candidate)

    assert [change.kind for change in violations] == ["added_property"]


def test_removed_definition_is_reported_as_breaking() -> None:
    published = load_published()
    candidate = json.loads(json.dumps(published))
    del candidate["$defs"]["IntegrityReport"]

    violations = breaking_changes(published, candidate)

    assert "removed_definition" in {change.kind for change in violations}


def test_reworded_description_is_not_a_change_in_the_contract() -> None:
    published = load_published()
    candidate = json.loads(json.dumps(published))
    candidate["$defs"]["Finding"]["properties"]["confidence"]["description"] = "Reworded."
    candidate["$defs"]["Finding"]["description"] = "Reworded."

    assert not compare_report_schemas(published, candidate)
