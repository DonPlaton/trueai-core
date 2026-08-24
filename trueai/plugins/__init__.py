"""Third-party detector hosting: capability manifests and process isolation."""

from trueai.plugins.broker import (
    ArtifactGrant,
    BrokerGrants,
    CapabilityBroker,
    CapabilityDeniedError,
    NativeLibraryGrant,
    NetworkGrant,
    SubprocessGrant,
    TemporaryOutputGrant,
    WorkspaceGrant,
    grants_for,
)
from trueai.plugins.host import (
    DEFAULT_TIMEOUT_SECONDS,
    ENTRY_POINT_GROUP,
    DiscoveryResult,
    IsolatedDetector,
    PluginExecutionError,
    PluginHost,
    PluginIsolation,
    PluginRejection,
)
from trueai.plugins.manifest import (
    DEFAULT_CAPABILITIES,
    DEFAULT_GRANTED_CAPABILITIES,
    CapabilityDecision,
    CapabilityPolicy,
    PluginCapability,
    PluginManifest,
    PluginRegistration,
)
from trueai.plugins.resources import PluginResourceLimits

__all__ = [
    "DEFAULT_CAPABILITIES",
    "DEFAULT_GRANTED_CAPABILITIES",
    "DEFAULT_TIMEOUT_SECONDS",
    "ENTRY_POINT_GROUP",
    "ArtifactGrant",
    "BrokerGrants",
    "CapabilityBroker",
    "CapabilityDecision",
    "CapabilityDeniedError",
    "CapabilityPolicy",
    "DiscoveryResult",
    "IsolatedDetector",
    "NativeLibraryGrant",
    "NetworkGrant",
    "PluginCapability",
    "PluginExecutionError",
    "PluginHost",
    "PluginIsolation",
    "PluginManifest",
    "PluginRegistration",
    "PluginRejection",
    "PluginResourceLimits",
    "SubprocessGrant",
    "TemporaryOutputGrant",
    "WorkspaceGrant",
    "grants_for",
]
