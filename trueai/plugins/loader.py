"""Resolution of ``module:attribute`` entry-point targets, shared by host and worker."""

from __future__ import annotations

import importlib
from typing import Any

from trueai.core.errors import DetectorRegistrationError
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
