"""Public report-schema surface and the frozen 0.1 compatibility contract.

Desktop, CI, and IDE consumers read TrueAI reports as data. Once a schema version
is published, the shape they parse against must not change underneath them, so
this module makes the contract executable instead of documentary:

* :func:`report_schema` emits the JSON Schema for the current report version.
* :func:`canonical_schema_json` serializes it deterministically for snapshotting.
* :func:`compare_report_schemas` classifies every difference between a published
  snapshot and the current code, separating additive changes from breaking ones.

The compatibility rules for a single schema version are:

* adding an optional property is compatible; consumers ignore unknown keys;
* adding an enum member is compatible; consumers must tolerate unknown members
  and fall back to their own default handling;
* removing a property, removing an enum member, renaming either, changing a
  property type, or changing whether a property is required is breaking and
  requires a new ``schema_version``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from trueai._version import SCHEMA_VERSION

__all__ = [
    "SCHEMA_SNAPSHOT_FILENAME",
    "SCHEMA_SNAPSHOT_PATH",
    "SCHEMA_VERSION",
    "SchemaChange",
    "breaking_changes",
    "canonical_schema_json",
    "compare_report_schemas",
    "report_schema",
]

SCHEMA_SNAPSHOT_FILENAME = f"trueai-report-{SCHEMA_VERSION}.schema.json"
"""File name of the published snapshot for the current schema version."""

SCHEMA_SNAPSHOT_PATH = PurePosixPath("schema") / SCHEMA_SNAPSHOT_FILENAME
"""Repository-relative location of the published snapshot."""

# Annotations that describe a field for humans without constraining the wire
# format. They are excluded from type signatures so that a reworded docstring is
# not reported as a breaking change.
_NON_CONTRACT_KEYS = frozenset({"default", "description", "examples", "title"})


@dataclass(frozen=True, slots=True)
class SchemaChange:
    """One classified difference between two versions of the report schema."""

    kind: str
    location: str
    detail: str
    breaking: bool

    def __str__(self) -> str:
        marker = "BREAKING" if self.breaking else "additive"
        return f"[{marker}] {self.kind} at {self.location}: {self.detail}"


def report_schema() -> dict[str, Any]:
    """Return the JSON Schema of the public scan report."""

    from trueai.core.models import ScanReport

    return ScanReport.model_json_schema(mode="serialization")


def canonical_schema_json(schema: Mapping[str, Any] | None = None) -> str:
    """Serialize a schema deterministically so snapshots diff cleanly."""

    payload = dict(schema) if schema is not None else report_schema()
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def load_snapshot(path: str | Path) -> dict[str, Any]:
    """Read a published schema snapshot from disk."""

    raw: Any = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"Schema snapshot must contain a JSON object: {path}")
    return raw


def compare_report_schemas(
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> tuple[SchemaChange, ...]:
    """Classify every difference between a published schema and a candidate one."""

    changes: list[SchemaChange] = []
    baseline_objects = _objects(baseline)
    candidate_objects = _objects(candidate)

    for name in sorted(set(baseline_objects) - set(candidate_objects)):
        changes.append(
            SchemaChange(
                kind="removed_definition",
                location=name,
                detail="the definition no longer exists",
                breaking=True,
            )
        )
    for name in sorted(set(candidate_objects) - set(baseline_objects)):
        changes.append(
            SchemaChange(
                kind="added_definition",
                location=name,
                detail="a new definition was introduced",
                breaking=False,
            )
        )

    for name in sorted(set(baseline_objects) & set(candidate_objects)):
        changes.extend(_compare_object(name, baseline_objects[name], candidate_objects[name]))

    baseline_version = _schema_version(baseline)
    candidate_version = _schema_version(candidate)
    if baseline_version != candidate_version:
        changes.append(
            SchemaChange(
                kind="changed_schema_version",
                location="ScanReport.schema_version",
                detail=f"{baseline_version!r} became {candidate_version!r}",
                breaking=False,
            )
        )
    return tuple(changes)


def breaking_changes(
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> tuple[SchemaChange, ...]:
    """Return only the differences that require a new schema version."""

    return tuple(
        change for change in compare_report_schemas(baseline, candidate) if change.breaking
    )


def _objects(schema: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    """Return the root object plus every named definition, keyed by name."""

    result: dict[str, Mapping[str, Any]] = {}
    root_name = str(schema.get("title", "ScanReport"))
    result[root_name] = schema
    definitions = schema.get("$defs", {})
    if isinstance(definitions, Mapping):
        for name, definition in definitions.items():
            if isinstance(definition, Mapping):
                result[str(name)] = definition
    return result


def _schema_version(schema: Mapping[str, Any]) -> str | None:
    properties = schema.get("properties")
    if not isinstance(properties, Mapping):
        return None
    field = properties.get("schema_version")
    if not isinstance(field, Mapping):
        return None
    value = field.get("const")
    return None if value is None else str(value)


def _compare_object(
    name: str,
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> list[SchemaChange]:
    changes: list[SchemaChange] = []
    changes.extend(_compare_enum(name, baseline, candidate))

    baseline_properties = _properties(baseline)
    candidate_properties = _properties(candidate)
    baseline_required = _required(baseline)
    candidate_required = _required(candidate)

    for field in sorted(set(baseline_properties) - set(candidate_properties)):
        changes.append(
            SchemaChange(
                kind="removed_property",
                location=f"{name}.{field}",
                detail="consumers reading this field would break",
                breaking=True,
            )
        )
    for field in sorted(set(candidate_properties) - set(baseline_properties)):
        changes.append(
            SchemaChange(
                kind="added_property",
                location=f"{name}.{field}",
                detail=(
                    "a new required property forces consumers to handle it"
                    if field in candidate_required
                    else "a new optional property; consumers ignore unknown keys"
                ),
                breaking=field in candidate_required,
            )
        )
    for field in sorted(set(baseline_properties) & set(candidate_properties)):
        before = _type_signature(baseline_properties[field])
        after = _type_signature(candidate_properties[field])
        if before != after:
            changes.append(
                SchemaChange(
                    kind="changed_property_type",
                    location=f"{name}.{field}",
                    detail=f"{before} became {after}",
                    breaking=True,
                )
            )
        was_required = field in baseline_required
        is_required = field in candidate_required
        if was_required != is_required:
            changes.append(
                SchemaChange(
                    kind="changed_property_requirement",
                    location=f"{name}.{field}",
                    detail=(
                        "an optional property became required"
                        if is_required
                        else "a required property became optional"
                    ),
                    breaking=True,
                )
            )
    return changes


def _compare_enum(
    name: str,
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> list[SchemaChange]:
    baseline_members = _enum_members(baseline)
    candidate_members = _enum_members(candidate)
    if baseline_members is None and candidate_members is None:
        return []
    before = baseline_members or frozenset()
    after = candidate_members or frozenset()
    changes: list[SchemaChange] = []
    for member in sorted(before - after):
        changes.append(
            SchemaChange(
                kind="removed_enum_member",
                location=name,
                detail=f"{member!r} is no longer emitted but may exist in stored reports",
                breaking=True,
            )
        )
    for member in sorted(after - before):
        changes.append(
            SchemaChange(
                kind="added_enum_member",
                location=name,
                detail=f"{member!r} was added; consumers must tolerate unknown members",
                breaking=False,
            )
        )
    return changes


def _enum_members(definition: Mapping[str, Any]) -> frozenset[str] | None:
    members = definition.get("enum")
    if not isinstance(members, list):
        return None
    return frozenset(str(member) for member in members)


def _properties(definition: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    properties = definition.get("properties")
    if not isinstance(properties, Mapping):
        return {}
    return {str(field): value for field, value in properties.items() if isinstance(value, Mapping)}


def _required(definition: Mapping[str, Any]) -> frozenset[str]:
    required = definition.get("required")
    if not isinstance(required, list):
        return frozenset()
    return frozenset(str(field) for field in required)


def _type_signature(field_schema: Mapping[str, Any]) -> str:
    """Return a stable signature that ignores human-facing annotations."""

    return json.dumps(_strip_annotations(field_schema), sort_keys=True, ensure_ascii=False)


def _strip_annotations(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: _strip_annotations(item)
            for key, item in value.items()
            if key not in _NON_CONTRACT_KEYS
        }
    if isinstance(value, list):
        return [_strip_annotations(item) for item in value]
    return value
