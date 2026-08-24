"""Wire format shared by the plugin host and its worker process.

Keeping the request and response shapes in one place means the host and the
worker cannot drift apart, and it makes the trust boundary explicit: everything
in :class:`WorkerResponse` arrived from code the host does not trust and must be
re-validated before it reaches a report.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from trueai.core.models import ArtifactType, ScanOptions
from trueai.plugins.manifest import PluginCapability
from trueai.plugins.resources import PluginResourceLimits

PROTOCOL_VERSION: Literal["1"] = "1"


class WorkerArtifact(BaseModel):
    """The artifact description a worker rebuilds before scanning."""

    model_config = ConfigDict(extra="forbid")

    artifact_type: ArtifactType
    path: str
    logical_path: str
    size: int | None = None
    media_type: str | None = None
    sha256: str


class WorkerRequest(BaseModel):
    """Everything a worker needs to run exactly one detector once."""

    model_config = ConfigDict(extra="forbid")

    protocol_version: Literal["1"] = PROTOCOL_VERSION
    entry_point: str
    detector_id: str
    granted_capabilities: frozenset[PluginCapability]
    resource_limits: PluginResourceLimits = PluginResourceLimits()
    artifact: WorkerArtifact
    options: ScanOptions
    root: str | None = None


class WorkerResponse(BaseModel):
    """Untrusted worker output. Every field is re-checked by the host."""

    model_config = ConfigDict(extra="forbid")

    protocol_version: Literal["1"] = PROTOCOL_VERSION
    detector_id: str
    ok: bool
    findings: list[dict[str, Any]] = Field(default_factory=list)
    error_code: str | None = None
    error_message: str | None = None


class InspectionRequest(BaseModel):
    """Request a capability-guarded manifest inspection in a helper process."""

    model_config = ConfigDict(extra="forbid")

    protocol_version: Literal["1"] = PROTOCOL_VERSION
    entry_point: str
    fallback_detector_id: str
    resource_limits: PluginResourceLimits = PluginResourceLimits()


class InspectionResponse(BaseModel):
    """Bounded output of an untrusted plugin-manifest inspection."""

    model_config = ConfigDict(extra="forbid")

    protocol_version: Literal["1"] = PROTOCOL_VERSION
    detector_id: str
    ok: bool
    manifest: dict[str, Any] | None = None
    error_code: str | None = None
    error_message: str | None = None
