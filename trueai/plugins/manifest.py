"""Capability manifests and the host policy that decides what a plugin may do.

A third-party detector is ordinary Python running inside a forensic tool, which
is exactly the position an attacker would like to be in. The manifest makes the
plugin state its intentions up front, and the policy lets an operator decide
which of those intentions are acceptable before the detector is constructed or
run. Reading the manifest still imports the plugin's module, because an entry
point is an import path; module-level code is outside what a policy can gate.

Nothing here is a sandbox on its own. The manifest is the declaration, the policy
is the decision, and :mod:`trueai.plugins.host` is the enforcement point.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from trueai._version import PACKAGE_VERSION, SCHEMA_VERSION
from trueai.core.models import ArtifactType, FindingCategory, FrozenModel


class PluginCapability(StrEnum):
    """Something a plugin may need that the host would otherwise deny."""

    #: Read the artifact under inspection. Every detector needs this.
    READ_ARTIFACT = "read_artifact"
    #: Read files near the artifact, such as sibling parts of a package.
    READ_WORKSPACE = "read_workspace"
    #: Write anywhere on the filesystem.
    WRITE_FILESYSTEM = "write_filesystem"
    #: Start other processes.
    RUN_SUBPROCESS = "run_subprocess"
    #: Open network connections.
    NETWORK = "network"


#: What a detector gets when it asks for nothing in particular.
DEFAULT_CAPABILITIES = frozenset({PluginCapability.READ_ARTIFACT})

#: What a host grants unless an operator widens or narrows it. Detection is a
#: read-only activity, so mutation, process spawning, and network access are all
#: denied by default even to a plugin that asks for them.
DEFAULT_GRANTED_CAPABILITIES = frozenset(
    {PluginCapability.READ_ARTIFACT, PluginCapability.READ_WORKSPACE}
)


class PluginManifest(FrozenModel):
    """What a plugin says it is and what it says it needs."""

    detector_id: str = Field(min_length=3, max_length=120)
    name: str = Field(min_length=1, max_length=120)
    version: str = Field(min_length=1, max_length=40)
    description: str = ""
    vendor: str | None = None
    capabilities: frozenset[PluginCapability] = DEFAULT_CAPABILITIES
    supported_types: frozenset[ArtifactType] = frozenset()
    categories: frozenset[FindingCategory] = frozenset()
    #: Report schema versions this plugin is known to produce findings for.
    compatible_schema_versions: frozenset[str] = frozenset({SCHEMA_VERSION})
    #: Lowest TrueAI Core version the plugin was tested against, informational.
    minimum_core_version: str | None = None
    #: True when the plugin actually shipped a manifest. A synthesized manifest is
    #: an assumption about an undeclared plugin, not a statement by its author.
    declared: bool = True

    def is_schema_compatible(self, schema_version: str = SCHEMA_VERSION) -> bool:
        """Return whether the plugin declares support for a report schema version."""

        return schema_version in self.compatible_schema_versions

    @classmethod
    def synthesize(cls, detector_id: str) -> PluginManifest:
        """Describe an undeclared plugin conservatively."""

        return cls(
            detector_id=detector_id,
            name=detector_id,
            version="unknown",
            description=(
                "This plugin ships no capability manifest. It is treated as requesting "
                "read-only artifact access."
            ),
            declared=False,
        )


class CapabilityDecision(FrozenModel):
    """The host's decision about one plugin."""

    detector_id: str
    allowed: bool
    reason: str
    granted: frozenset[PluginCapability] = frozenset()
    denied: frozenset[PluginCapability] = frozenset()


class CapabilityPolicy(FrozenModel):
    """Operator decision about which plugins may run and with what.

    ``require_manifest`` is the enterprise posture: a plugin that will not say
    what it needs does not run at all.
    """

    granted: frozenset[PluginCapability] = DEFAULT_GRANTED_CAPABILITIES
    require_manifest: bool = False
    require_schema_compatibility: bool = True
    allowed_detector_ids: frozenset[str] | None = None
    blocked_detector_ids: frozenset[str] = frozenset()

    def evaluate(
        self,
        manifest: PluginManifest,
        *,
        schema_version: str = SCHEMA_VERSION,
    ) -> CapabilityDecision:
        """Decide whether a plugin may run, before it is constructed or invoked."""

        detector_id = manifest.detector_id
        if detector_id in self.blocked_detector_ids:
            return CapabilityDecision(
                detector_id=detector_id,
                allowed=False,
                reason="The detector is on the host block list.",
                denied=manifest.capabilities,
            )
        if self.allowed_detector_ids is not None and detector_id not in self.allowed_detector_ids:
            return CapabilityDecision(
                detector_id=detector_id,
                allowed=False,
                reason="The detector is not on the host allow list.",
                denied=manifest.capabilities,
            )
        if self.require_manifest and not manifest.declared:
            return CapabilityDecision(
                detector_id=detector_id,
                allowed=False,
                reason=(
                    "The host requires a capability manifest and this plugin does not ship one."
                ),
                denied=manifest.capabilities,
            )
        if self.require_schema_compatibility and not manifest.is_schema_compatible(schema_version):
            declared = ", ".join(sorted(manifest.compatible_schema_versions)) or "none"
            return CapabilityDecision(
                detector_id=detector_id,
                allowed=False,
                reason=(
                    f"The plugin declares schema compatibility with {declared}, "
                    f"but this host emits schema {schema_version}."
                ),
                denied=manifest.capabilities,
            )
        denied = frozenset(manifest.capabilities) - self.granted
        if denied:
            names = ", ".join(sorted(capability.value for capability in denied))
            return CapabilityDecision(
                detector_id=detector_id,
                allowed=False,
                reason=f"The host does not grant: {names}.",
                granted=frozenset(manifest.capabilities) & self.granted,
                denied=denied,
            )
        return CapabilityDecision(
            detector_id=detector_id,
            allowed=True,
            reason="Every declared capability is granted by the host policy.",
            granted=frozenset(manifest.capabilities),
        )


class PluginRegistration(FrozenModel):
    """What an entry point may return instead of a bare detector.

    Returning a registration is how a plugin declares its manifest without the
    host having to import and instantiate the detector first.
    """

    model_config = FrozenModel.model_config | {"arbitrary_types_allowed": True}

    manifest: PluginManifest
    factory: object

    def build(self) -> object:
        """Instantiate the detector this registration describes."""

        factory = self.factory
        return factory() if callable(factory) else factory


def core_version() -> str:
    """Return the running core version, for manifest compatibility reporting."""

    return PACKAGE_VERSION
