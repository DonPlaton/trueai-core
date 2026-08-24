"""The public Python API surface and the rules for changing it.

The report schema is already an executable contract. The Python API is the other
half of what a consumer depends on: a desktop client, a CI integration, or a
third-party detector imports names, calls functions, and reads model fields. If
those move, the schema being stable does not help.

This module describes the surface the way :mod:`trueai.schema` describes the
report: it enumerates what is public, serializes it deterministically, and
classifies every difference between two versions as additive or breaking. The
enumeration is deliberately explicit — :data:`PUBLIC_MODULES` is the contract,
not a heuristic over whatever happens to be importable.

The rules for a single API version are:

* adding a module, a name, a model field with a default, or a keyword parameter
  with a default is compatible;
* removing or renaming any of them is breaking;
* changing a parameter's kind or position, making an optional parameter or model
  field required, or removing an enum member is breaking.
"""

from __future__ import annotations

import enum
import importlib
import inspect
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from trueai._version import PACKAGE_VERSION

__all__ = [
    "API_SNAPSHOT_PATH",
    "API_VERSION",
    "PUBLIC_MODULES",
    "ApiChange",
    "breaking_api_changes",
    "canonical_api_json",
    "compare_api_surfaces",
    "public_api_surface",
]

#: The API contract version. It tracks the report schema version deliberately:
#: a consumer pins one pair, not two independent numbers.
API_VERSION = "0.1"

API_SNAPSHOT_FILENAME = f"trueai-api-{API_VERSION}.json"
API_SNAPSHOT_PATH = PurePosixPath("api") / API_SNAPSHOT_FILENAME

#: Every module a consumer is invited to import. Anything not listed is internal
#: and may change without notice, which is only a fair rule if the list is
#: written down rather than inferred.
PUBLIC_MODULES: tuple[str, ...] = (
    "trueai",
    "trueai.api",
    "trueai.schema",
    "trueai.core.artifact",
    "trueai.core.engine",
    "trueai.core.errors",
    "trueai.core.models",
    "trueai.core.policy",
    "trueai.core.remediation",
    "trueai.detectors.base",
    "trueai.plugins",
    "trueai.reporters",
)

#: Parameters whose presence is an implementation detail of instance methods.
_IMPLICIT_PARAMETERS = frozenset({"self", "cls"})


@dataclass(frozen=True, slots=True)
class ApiChange:
    """One classified difference between two versions of the public API."""

    kind: str
    location: str
    detail: str
    breaking: bool

    def __str__(self) -> str:
        marker = "BREAKING" if self.breaking else "additive"
        return f"[{marker}] {self.kind} at {self.location}: {self.detail}"


def public_api_surface() -> dict[str, Any]:
    """Return a serializable description of every public module and name."""

    modules: dict[str, Any] = {}
    for module_name in PUBLIC_MODULES:
        module = importlib.import_module(module_name)
        exported = getattr(module, "__all__", None)
        if exported is None:
            names = sorted(
                name
                for name, value in vars(module).items()
                if not name.startswith("_") and _belongs_to(value, module_name)
            )
        else:
            names = sorted(str(name) for name in exported)
        modules[module_name] = {
            name: _describe(getattr(module, name)) for name in names if hasattr(module, name)
        }
    return {
        "api_version": API_VERSION,
        "package_version": PACKAGE_VERSION,
        "modules": modules,
    }


def canonical_api_json(surface: Mapping[str, Any] | None = None) -> str:
    """Serialize a surface deterministically so snapshots diff cleanly."""

    payload = dict(surface) if surface is not None else public_api_surface()
    # The package version moves every release and would make every snapshot
    # stale. The contract is the shape, not the version that produced it.
    payload.pop("package_version", None)
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def compare_api_surfaces(
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> tuple[ApiChange, ...]:
    """Classify every difference between a published surface and a candidate one."""

    changes: list[ApiChange] = []
    baseline_modules = _modules(baseline)
    candidate_modules = _modules(candidate)

    for name in sorted(set(baseline_modules) - set(candidate_modules)):
        changes.append(
            ApiChange(
                kind="removed_module",
                location=name,
                detail="consumers importing this module would break",
                breaking=True,
            )
        )
    for name in sorted(set(candidate_modules) - set(baseline_modules)):
        changes.append(
            ApiChange(
                kind="added_module",
                location=name,
                detail="a new public module was introduced",
                breaking=False,
            )
        )
    for module_name in sorted(set(baseline_modules) & set(candidate_modules)):
        changes.extend(
            _compare_module(
                module_name, baseline_modules[module_name], candidate_modules[module_name]
            )
        )
    return tuple(changes)


def breaking_api_changes(
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> tuple[ApiChange, ...]:
    """Return only the differences that require a new API version."""

    return tuple(change for change in compare_api_surfaces(baseline, candidate) if change.breaking)


# -- description -------------------------------------------------------------------


def _belongs_to(value: object, module_name: str) -> bool:
    origin = getattr(value, "__module__", None)
    return isinstance(origin, str) and origin.startswith(module_name.split(".")[0])


def _describe(value: object) -> dict[str, Any]:
    """Describe one exported name in terms a consumer can depend on."""

    if isinstance(value, type) and issubclass(value, enum.Enum):
        return {
            "kind": "enum",
            "members": sorted(str(member.value) for member in value),
        }
    if isinstance(value, type):
        described: dict[str, Any] = {"kind": "class", "bases": _base_names(value)}
        fields = getattr(value, "model_fields", None)
        if isinstance(fields, dict):
            described["model_fields"] = {
                str(name): {"required": bool(getattr(field, "is_required", lambda: False)())}
                for name, field in sorted(fields.items())
            }
        methods, attributes = _class_members(value)
        described["methods"] = methods
        described["attributes"] = attributes
        return described
    if callable(value):
        return {"kind": "callable", "signature": _signature(value)}
    return {"kind": "value", "type": type(value).__name__}


def _class_members(value: type) -> tuple[dict[str, Any], list[str]]:
    """Split a class's public members into callables and readable attributes.

    Classmethods and staticmethods are unwrapped first. A bare ``classmethod``
    object is not callable on modern Python, so treating it as an attribute would
    hide exactly the signatures consumers call — ``PolicyStore.get`` and
    ``TrueAIEngine.default`` among them.
    """

    methods: dict[str, Any] = {}
    attributes: list[str] = []
    for name, member in sorted(vars(value).items()):
        if name.startswith("_"):
            continue
        if isinstance(member, property):
            # Consumers read a property; its signature is not part of the call.
            attributes.append(name)
            continue
        target = member.__func__ if isinstance(member, (classmethod, staticmethod)) else member
        if callable(target):
            methods[name] = _signature(target)
        else:
            attributes.append(name)
    return methods, sorted(attributes)


def _base_names(value: type) -> list[str]:
    return [
        f"{base.__module__}.{base.__qualname__}" for base in value.__bases__ if base is not object
    ]


def _signature(value: object) -> dict[str, Any]:
    """Describe a callable's parameters without pinning their annotations.

    Annotations are recorded as text because a consumer depends on how a
    function is *called*, and a widened annotation should not read as a breaking
    change.
    """

    try:
        signature = inspect.signature(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):  # pragma: no cover - builtins without signatures
        return {"parameters": [], "introspectable": False}
    parameters = []
    for name, parameter in signature.parameters.items():
        if name in _IMPLICIT_PARAMETERS:
            continue
        parameters.append(
            {
                "name": name,
                "kind": parameter.kind.name,
                "required": parameter.default is inspect.Parameter.empty
                and parameter.kind
                not in {
                    inspect.Parameter.VAR_POSITIONAL,
                    inspect.Parameter.VAR_KEYWORD,
                },
            }
        )
    return {"parameters": parameters, "introspectable": True}


# -- comparison --------------------------------------------------------------------


def _modules(surface: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    modules = surface.get("modules")
    if not isinstance(modules, Mapping):
        return {}
    return {str(name): value for name, value in modules.items() if isinstance(value, Mapping)}


def _compare_module(
    module_name: str,
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> list[ApiChange]:
    changes: list[ApiChange] = []
    for name in sorted(set(baseline) - set(candidate)):
        changes.append(
            ApiChange(
                kind="removed_name",
                location=f"{module_name}.{name}",
                detail="consumers importing this name would break",
                breaking=True,
            )
        )
    for name in sorted(set(candidate) - set(baseline)):
        changes.append(
            ApiChange(
                kind="added_name",
                location=f"{module_name}.{name}",
                detail="a new public name was introduced",
                breaking=False,
            )
        )
    for name in sorted(set(baseline) & set(candidate)):
        before, after = baseline[name], candidate[name]
        if not isinstance(before, Mapping) or not isinstance(after, Mapping):
            continue
        changes.extend(_compare_name(f"{module_name}.{name}", before, after))
    return changes


def _compare_name(
    location: str,
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> list[ApiChange]:
    changes: list[ApiChange] = []
    if baseline.get("kind") != candidate.get("kind"):
        return [
            ApiChange(
                kind="changed_name_kind",
                location=location,
                detail=f"{baseline.get('kind')} became {candidate.get('kind')}",
                breaking=True,
            )
        ]
    kind = baseline.get("kind")
    if kind == "enum":
        changes.extend(_compare_enum_members(location, baseline, candidate))
    elif kind == "callable":
        changes.extend(
            _compare_signature(location, baseline.get("signature"), candidate.get("signature"))
        )
    elif kind == "class":
        changes.extend(_compare_class(location, baseline, candidate))
    return changes


def _compare_enum_members(
    location: str,
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> list[ApiChange]:
    before = set(baseline.get("members", []))
    after = set(candidate.get("members", []))
    changes: list[ApiChange] = []
    for member in sorted(before - after):
        changes.append(
            ApiChange(
                kind="removed_enum_member",
                location=location,
                detail=f"{member!r} is no longer defined",
                breaking=True,
            )
        )
    for member in sorted(after - before):
        changes.append(
            ApiChange(
                kind="added_enum_member",
                location=location,
                detail=f"{member!r} was added",
                breaking=False,
            )
        )
    return changes


def _compare_class(
    location: str,
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
) -> list[ApiChange]:
    changes: list[ApiChange] = []
    changes.extend(
        _compare_model_fields(
            location, baseline.get("model_fields", {}), candidate.get("model_fields", {})
        )
    )
    before_methods = baseline.get("methods", {})
    after_methods = candidate.get("methods", {})
    if isinstance(before_methods, Mapping) and isinstance(after_methods, Mapping):
        for name in sorted(set(before_methods) - set(after_methods)):
            changes.append(
                ApiChange(
                    kind="removed_method",
                    location=f"{location}.{name}",
                    detail="consumers calling this method would break",
                    breaking=True,
                )
            )
        for name in sorted(set(after_methods) - set(before_methods)):
            changes.append(
                ApiChange(
                    kind="added_method",
                    location=f"{location}.{name}",
                    detail="a new method was introduced",
                    breaking=False,
                )
            )
        for name in sorted(set(before_methods) & set(after_methods)):
            changes.extend(
                _compare_signature(f"{location}.{name}", before_methods[name], after_methods[name])
            )
    before_attributes = set(baseline.get("attributes", []))
    after_attributes = set(candidate.get("attributes", []))
    for name in sorted(before_attributes - after_attributes):
        changes.append(
            ApiChange(
                kind="removed_attribute",
                location=f"{location}.{name}",
                detail="consumers reading this attribute would break",
                breaking=True,
            )
        )
    for name in sorted(after_attributes - before_attributes):
        changes.append(
            ApiChange(
                kind="added_attribute",
                location=f"{location}.{name}",
                detail="a new attribute was introduced",
                breaking=False,
            )
        )
    return changes


def _compare_model_fields(
    location: str,
    baseline: Any,
    candidate: Any,
) -> list[ApiChange]:
    if not isinstance(baseline, Mapping) or not isinstance(candidate, Mapping):
        return []
    changes: list[ApiChange] = []
    for name in sorted(set(baseline) - set(candidate)):
        changes.append(
            ApiChange(
                kind="removed_model_field",
                location=f"{location}.{name}",
                detail="consumers reading this field would break",
                breaking=True,
            )
        )
    for name in sorted(set(candidate) - set(baseline)):
        required = (
            bool(candidate[name].get("required")) if isinstance(candidate[name], Mapping) else False
        )
        changes.append(
            ApiChange(
                kind="added_model_field",
                location=f"{location}.{name}",
                detail=(
                    "a new required field forces every constructor call to change"
                    if required
                    else "a new optional field"
                ),
                breaking=required,
            )
        )
    for name in sorted(set(baseline) & set(candidate)):
        before, after = baseline[name], candidate[name]
        if not isinstance(before, Mapping) or not isinstance(after, Mapping):
            continue
        if not before.get("required") and after.get("required"):
            changes.append(
                ApiChange(
                    kind="changed_model_field_requirement",
                    location=f"{location}.{name}",
                    detail="an optional field became required",
                    breaking=True,
                )
            )
    return changes


def _compare_signature(location: str, baseline: Any, candidate: Any) -> list[ApiChange]:
    if not isinstance(baseline, Mapping) or not isinstance(candidate, Mapping):
        return []
    before = [item for item in baseline.get("parameters", []) if isinstance(item, Mapping)]
    after = [item for item in candidate.get("parameters", []) if isinstance(item, Mapping)]
    before_by_name = {str(item["name"]): item for item in before}
    after_by_name = {str(item["name"]): item for item in after}
    changes: list[ApiChange] = []

    for name in sorted(set(before_by_name) - set(after_by_name)):
        changes.append(
            ApiChange(
                kind="removed_parameter",
                location=f"{location}({name})",
                detail="callers passing this argument would break",
                breaking=True,
            )
        )
    for name in sorted(set(after_by_name) - set(before_by_name)):
        parameter = after_by_name[name]
        changes.append(
            ApiChange(
                kind="added_parameter",
                location=f"{location}({name})",
                detail=(
                    "a new required parameter forces every caller to change"
                    if parameter.get("required")
                    else "a new optional parameter"
                ),
                breaking=bool(parameter.get("required")),
            )
        )
    for name in sorted(set(before_by_name) & set(after_by_name)):
        first, second = before_by_name[name], after_by_name[name]
        if first.get("kind") != second.get("kind"):
            changes.append(
                ApiChange(
                    kind="changed_parameter_kind",
                    location=f"{location}({name})",
                    detail=f"{first.get('kind')} became {second.get('kind')}",
                    breaking=True,
                )
            )
        if not first.get("required") and second.get("required"):
            changes.append(
                ApiChange(
                    kind="changed_parameter_requirement",
                    location=f"{location}({name})",
                    detail="an optional parameter became required",
                    breaking=True,
                )
            )

    positional = [
        inspect.Parameter.POSITIONAL_ONLY.name,
        inspect.Parameter.POSITIONAL_OR_KEYWORD.name,
    ]
    before_order = [str(item["name"]) for item in before if item.get("kind") in positional]
    after_order = [str(item["name"]) for item in after if item.get("kind") in positional]
    shared = [name for name in before_order if name in set(after_order)]
    if shared != [name for name in after_order if name in set(before_order)]:
        changes.append(
            ApiChange(
                kind="reordered_parameters",
                location=location,
                detail="positional arguments would bind to different parameters",
                breaking=True,
            )
        )
    return changes
