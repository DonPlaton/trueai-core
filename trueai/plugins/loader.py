"""Resolution of ``module:attribute`` entry-point targets, shared by host and worker."""

from __future__ import annotations

import importlib
from typing import Any

from trueai.core.errors import DetectorRegistrationError
from trueai.core.models import ArtifactType, FindingCategory
from trueai.plugins.manifest import PluginManifest, PluginRegistration


def resolve_target(value: str) -> Any:
    """Import and return the object an entry-point value names."""

    module_name, separator, attribute_path = value.partition(":")
    if not module_name or not separator or not attribute_path:
        raise DetectorRegistrationError(f"Entry point must be 'module:attribute', got {value!r}")
    target: Any = importlib.import_module(module_name)
    for part in attribute_path.split("."):
        target = getattr(target, part)
    return target


def load_entry_point(value: str) -> Any:
    """Return a detector instance for an entry-point value.

    The target may be a detector, a factory returning one, or a
    :class:`~trueai.plugins.manifest.PluginRegistration` carrying a manifest.
    """

    target = resolve_target(value)
    return instantiate(target)


def instantiate(target: Any) -> Any:
    """Turn an entry-point target into a detector instance."""

    if isinstance(target, PluginRegistration):
        return target.build()
    return target() if callable(target) else target


def manifest_for(target: Any, detector: Any) -> PluginManifest:
    """Return the plugin's declared manifest, or a conservative synthesized one."""

    declared = None
    if isinstance(target, PluginRegistration):
        declared = target.manifest
    else:
        candidate = getattr(detector, "manifest", None)
        if isinstance(candidate, PluginManifest):
            declared = candidate
    detector_id = str(getattr(detector, "id", "unknown"))
    if declared is None:
        return PluginManifest.synthesize(detector_id)
    if declared.detector_id != detector_id:
        raise DetectorRegistrationError(
            f"Manifest declares detector {declared.detector_id!r} but the plugin "
            f"provides {detector_id!r}"
        )
    return declared


def describe_target(target: Any) -> tuple[PluginManifest, Any | None]:
    """Return a plugin's manifest and, only if unavoidable, the built detector.

    A registration carries its manifest, and a detector class exposes its id and
    supported types as class attributes, so in both cases the host can decide
    whether the plugin may run before constructing it. A bare factory function is
    the exception: its identity is only knowable by calling it, so it is built
    first and the caller discards the instance if the policy refuses. Shipping a
    :class:`PluginRegistration` is what lets an operator keep that from happening.
    """

    if isinstance(target, PluginRegistration):
        manifest = target.manifest
        declared_id = manifest.detector_id
        if not declared_id:
            raise DetectorRegistrationError("Plugin registration declares no detector id")
        return manifest, None

    identity = getattr(target, "id", None)
    if isinstance(identity, str) and identity:
        candidate = getattr(target, "manifest", None)
        manifest = (
            candidate
            if isinstance(candidate, PluginManifest)
            else PluginManifest.synthesize(identity)
        )
        if manifest.detector_id != identity:
            raise DetectorRegistrationError(
                f"Manifest declares detector {manifest.detector_id!r} but the plugin "
                f"provides {identity!r}"
            )
        return manifest, None

    detector = instantiate(target)
    return manifest_for(target, detector), detector


def enrich_manifest(manifest: PluginManifest, source: Any) -> PluginManifest:
    """Fill declared detector types/categories without changing capabilities."""

    supported: frozenset[ArtifactType] = getattr(source, "supported_types", frozenset())
    categories: frozenset[FindingCategory] = getattr(source, "categories", frozenset())
    updates: dict[str, object] = {}
    if not manifest.supported_types and supported:
        updates["supported_types"] = supported
    if not manifest.categories and categories:
        updates["categories"] = categories
    return manifest.model_copy(update=updates) if updates else manifest
