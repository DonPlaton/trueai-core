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
from trueai.plugins.broker import BrokerGrants
from trueai.plugins.confinement import ConfinementLevel, ConfinementReport
from trueai.plugins.manifest import PluginCapability
from trueai.plugins.resources import PluginResourceLimits, ResourceLimitReport

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
    #: The scoped grants the broker enforces. The capability set above is what
    #: the guards act on; these are the same decision with its scopes attached.
    grants: BrokerGrants = BrokerGrants()
    #: How hard the host insists on kernel-level confinement. `required` makes the
    #: worker refuse to import the plugin when confinement cannot be established.
    confinement: ConfinementLevel = ConfinementLevel.BEST_EFFORT
    #: Whether the host started this worker under a restricted token. A process
    #: cannot narrow its own token, so on Windows this is the only way the worker
    #: can know a restriction was applied -- and it verifies the claim by reading
    #: the token rather than repeating it.
    spawn_time_confinement: bool = False
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
    #: What the worker actually established, so the host reports the confinement
    #: that happened rather than the one it asked for.
    confinement: ConfinementReport | None = None
    #: Which process limits the kernel accepted. `None` only when the worker
    #: failed before it got that far.
    resource_limits: ResourceLimitReport | None = None
    error_code: str | None = None
    error_message: str | None = None


class InspectionRequest(BaseModel):
    """Request a capability-guarded manifest inspection in a helper process."""

    model_config = ConfigDict(extra="forbid")

    protocol_version: Literal["1"] = PROTOCOL_VERSION
    entry_point: str
    fallback_detector_id: str
    resource_limits: PluginResourceLimits = PluginResourceLimits()
    #: Mirrors the worker's own setting. `required` makes the inspector refuse
    #: rather than import a plugin under limits the platform would not install.
    confinement: ConfinementLevel = ConfinementLevel.BEST_EFFORT


class InspectionResponse(BaseModel):
    """Bounded output of an untrusted plugin-manifest inspection."""

    model_config = ConfigDict(extra="forbid")

    protocol_version: Literal["1"] = PROTOCOL_VERSION
    detector_id: str
    ok: bool
    manifest: dict[str, Any] | None = None
    #: Which process limits the inspector ran under, for the same reason the
    #: worker reports its own: an unenforced limit has to be visible somewhere.
    resource_limits: ResourceLimitReport | None = None
    error_code: str | None = None
    error_message: str | None = None
