"""Capability manifests, host policy, and process-isolated plugin execution."""

from __future__ import annotations

import sys
from importlib.metadata import EntryPoint
from pathlib import Path

import pytest

import trueai.plugins.host as host_module
from tests.plugin_examples import WellBehavedPlugin
from trueai import TrueAIEngine
from trueai.core.artifact import ArtifactDiscovery
from trueai.core.models import ScanOptions, Severity
from trueai.core.registry import DetectorRegistry
from trueai.detectors import create_default_registry
from trueai.plugins import (
    CapabilityPolicy,
    PluginCapability,
    PluginExecutionError,
    PluginHost,
    PluginIsolation,
    PluginManifest,
)

REPOSITORY_ROOT = str(Path(__file__).resolve().parents[2])
EXAMPLES = "tests.plugin_examples"


def entry_point(name: str, attribute: str) -> EntryPoint:
    """Build a real entry point pointing at one of the example plugins."""

    return EntryPoint(
        name=name, value=f"{EXAMPLES}:{attribute}", group=host_module.ENTRY_POINT_GROUP
    )


@pytest.fixture
def install_plugins(monkeypatch: pytest.MonkeyPatch):
    """Replace installed entry points with a controlled set."""

    def install(*points: EntryPoint) -> None:
        monkeypatch.setattr(host_module, "entry_points", lambda *, group: list(points))

    return install


@pytest.fixture
def text_artifact(tmp_path: Path) -> Path:
    path = tmp_path / "notes.txt"
    path.write_text("Ordinary content.\n", encoding="utf-8")
    return path


# -- manifests and policy ------------------------------------------------------------


def test_a_plugin_without_a_manifest_is_described_conservatively() -> None:
    manifest = PluginManifest.synthesize("vendor.detector.v1")

    assert manifest.declared is False
    assert manifest.capabilities == frozenset({PluginCapability.READ_ARTIFACT})


def test_default_policy_denies_network_subprocess_and_writes() -> None:
    policy = CapabilityPolicy()

    for capability in (
        PluginCapability.NETWORK,
        PluginCapability.RUN_SUBPROCESS,
        PluginCapability.WRITE_FILESYSTEM,
    ):
        assert capability not in policy.granted


def test_a_plugin_asking_for_an_ungranted_capability_is_refused() -> None:
    manifest = PluginManifest(
        detector_id="vendor.detector.v1",
        name="Vendor",
        version="1.0",
        capabilities=frozenset({PluginCapability.READ_ARTIFACT, PluginCapability.NETWORK}),
    )

    decision = CapabilityPolicy().evaluate(manifest)

    assert not decision.allowed
    assert PluginCapability.NETWORK in decision.denied
    assert "network" in decision.reason


def test_requiring_a_manifest_refuses_undeclared_plugins() -> None:
    decision = CapabilityPolicy(require_manifest=True).evaluate(
        PluginManifest.synthesize("vendor.detector.v1")
    )

    assert not decision.allowed
    assert "capability manifest" in decision.reason


def test_an_incompatible_schema_version_is_refused() -> None:
    manifest = PluginManifest(
        detector_id="vendor.detector.v1",
        name="Vendor",
        version="1.0",
        compatible_schema_versions=frozenset({"9.9"}),
    )

    decision = CapabilityPolicy().evaluate(manifest)

    assert not decision.allowed
    assert "schema" in decision.reason


def test_allow_and_block_lists_are_honoured() -> None:
    manifest = PluginManifest(detector_id="vendor.detector.v1", name="Vendor", version="1.0")

    blocked = CapabilityPolicy(blocked_detector_ids=frozenset({"vendor.detector.v1"})).evaluate(
        manifest
    )
    not_allowed = CapabilityPolicy(allowed_detector_ids=frozenset({"other.v1"})).evaluate(manifest)
    allowed = CapabilityPolicy(allowed_detector_ids=frozenset({"vendor.detector.v1"})).evaluate(
        manifest
    )

    assert not blocked.allowed
    assert not not_allowed.allowed
    assert allowed.allowed


# -- discovery -----------------------------------------------------------------------


def test_discovery_reads_a_declared_manifest(install_plugins) -> None:
    install_plugins(entry_point("declared", "DECLARED_REGISTRATION"))

    result = PluginHost().discover()

    assert [manifest.detector_id for manifest in result.manifests] == ["example.well-behaved.v1"]
    assert result.manifests[0].declared is True
    assert result.manifests[0].vendor == "example"
    assert not result.rejections


def test_discovery_synthesizes_a_manifest_for_a_bare_detector(install_plugins) -> None:
    install_plugins(entry_point("bare", "WellBehavedPlugin"))

    result = PluginHost().discover()

    assert result.manifests[0].declared is False
    # The host still learns what the detector supports, from the detector itself.
    assert result.manifests[0].supported_types


def test_a_greedy_plugin_is_rejected_and_reported(install_plugins) -> None:
    install_plugins(entry_point("greedy", "GREEDY_REGISTRATION"))

    result = PluginHost().discover()

    assert not result.detectors
    assert [rejection.detector_id for rejection in result.rejections] == ["example.network.v1"]
    assert "network" in result.rejections[0].reason


def test_a_plugin_that_fails_to_load_is_rejected_not_fatal(install_plugins) -> None:
    install_plugins(entry_point("broken", "broken_factory"))

    result = PluginHost().discover()

    assert not result.detectors
    assert "could not be loaded" in result.rejections[0].reason


def test_a_future_schema_plugin_is_rejected(install_plugins) -> None:
    install_plugins(entry_point("future", "FUTURE_SCHEMA_REGISTRATION"))

    result = PluginHost().discover()

    assert not result.detectors
    assert "schema" in result.rejections[0].reason


def test_disabled_isolation_loads_nothing(install_plugins) -> None:
    install_plugins(entry_point("declared", "DECLARED_REGISTRATION"))

    result = PluginHost(isolation=PluginIsolation.DISABLED).discover()

    assert not result.detectors
    assert not result.manifests


def test_a_rejected_plugin_appears_in_the_scan_report(install_plugins, text_artifact: Path) -> None:
    install_plugins(entry_point("greedy", "GREEDY_REGISTRATION"))
    registry = DetectorRegistry()
    registry.discover()

    report = TrueAIEngine(registry).scan(text_artifact)

    rejected = [item for item in report.diagnostics if item.code == "plugin_rejected"]
    assert rejected
    assert rejected[0].severity == Severity.MEDIUM
    assert "example.network.v1" in rejected[0].message


# -- isolated execution --------------------------------------------------------------


def isolated_registry(*points: EntryPoint, timeout: float = 60.0) -> DetectorRegistry:
    """Build a registry whose plugins run in worker processes."""

    registry = DetectorRegistry()
    registry.discover(
        isolation=PluginIsolation.SUBPROCESS,
        timeout=timeout,
        search_path=(REPOSITORY_ROOT,),
    )
    return registry


def test_an_isolated_plugin_produces_findings(install_plugins, text_artifact: Path) -> None:
    install_plugins(entry_point("declared", "DECLARED_REGISTRATION"))
    registry = isolated_registry()

    report = TrueAIEngine(registry).scan(text_artifact)

    plugin_findings = [
        finding for finding in report.findings if finding.detector_id == "example.well-behaved.v1"
    ]
    assert plugin_findings
    assert plugin_findings[0].title == "Plugin observation"
    assert "example.well-behaved.v1" in report.detectors_run


def test_a_crashing_plugin_becomes_a_diagnostic(install_plugins, text_artifact: Path) -> None:
    install_plugins(entry_point("crashing", "CrashingPlugin"))
    registry = isolated_registry()

    report = TrueAIEngine(registry).scan(text_artifact)

    failures = [item for item in report.diagnostics if item.code == "plugin_failed"]
    assert failures
    assert "this plugin is broken" in failures[0].message


def test_a_hanging_plugin_is_killed_at_the_deadline(install_plugins, text_artifact: Path) -> None:
    install_plugins(entry_point("hanging", "HangingPlugin"))
    registry = isolated_registry(timeout=3.0)

    report = TrueAIEngine(registry).scan(text_artifact)

    timeouts = [item for item in report.diagnostics if item.code == "plugin_timeout"]
    assert timeouts
    assert "3 seconds" in timeouts[0].message


def test_a_forged_finding_identity_is_rejected(install_plugins, text_artifact: Path) -> None:
    install_plugins(entry_point("forging", "ForgingPlugin"))
    registry = isolated_registry()

    report = TrueAIEngine(registry).scan(text_artifact)

    assert not [item for item in report.findings if item.detector_id == "example.forging.v1"]
    assert any(item.code == "plugin_forged_finding_id" for item in report.diagnostics)


def test_a_plugin_cannot_attribute_findings_to_another_detector(
    install_plugins, text_artifact: Path
) -> None:
    install_plugins(entry_point("impersonating", "ImpersonatingPlugin"))
    registry = isolated_registry()

    report = TrueAIEngine(registry).scan(text_artifact)

    assert not [item for item in report.findings if item.detector_id == "text.unicode-forensics.v1"]
    assert any(item.code == "plugin_impersonation" for item in report.diagnostics)


@pytest.mark.parametrize(
    ("attribute", "capability"),
    [
        ("NetworkPlugin", "network"),
        ("WritingPlugin", "write_filesystem"),
        ("SubprocessPlugin", "run_subprocess"),
    ],
)
def test_ungranted_capabilities_are_denied_inside_the_worker(
    install_plugins, text_artifact: Path, attribute: str, capability: str
) -> None:
    install_plugins(entry_point("guarded", attribute))
    registry = isolated_registry()

    report = TrueAIEngine(registry).scan(text_artifact)

    failures = [item for item in report.diagnostics if item.code == "plugin_failed"]
    assert failures, [item.model_dump() for item in report.diagnostics]
    assert "CapabilityDenied" in failures[0].message
    assert capability in failures[0].message
    if attribute == "WritingPlugin":
        assert not (text_artifact.parent / "written-by-plugin.txt").exists()


def test_the_host_does_not_rewrite_a_plugin_finding_it_accepts(
    install_plugins, text_artifact: Path
) -> None:
    """Accepting a finding means reporting it as observed, not editing it."""

    install_plugins(entry_point("loud", "LoudPlugin"))
    registry = isolated_registry()

    report = TrueAIEngine(registry).scan(text_artifact)

    loud = next(item for item in report.findings if item.detector_id == "example.loud.v1")
    assert loud.severity == Severity.CRITICAL
    assert loud.title == "Critical plugin observation"


def test_a_refused_plugin_is_never_constructed(install_plugins) -> None:
    """A block list that runs the constructor first is not a block list."""

    from tests.plugin_examples import CONSTRUCTIONS

    install_plugins(entry_point("recorded", "ConstructionRecordingPlugin"))
    CONSTRUCTIONS.clear()
    policy = CapabilityPolicy(blocked_detector_ids=frozenset({"example.constructed.v1"}))

    result = PluginHost(policy=policy).discover()

    assert not result.detectors
    assert CONSTRUCTIONS == []
    assert "block list" in result.rejections[0].reason


def test_an_allowed_plugin_is_constructed_once(install_plugins) -> None:
    from tests.plugin_examples import CONSTRUCTIONS

    install_plugins(entry_point("recorded", "ConstructionRecordingPlugin"))
    CONSTRUCTIONS.clear()

    result = PluginHost().discover()

    assert len(result.detectors) == 1
    assert CONSTRUCTIONS == ["example.constructed.v1"]


def test_subprocess_isolation_never_constructs_a_plugin_in_the_host(
    install_plugins,
) -> None:
    from tests.plugin_examples import CONSTRUCTIONS

    install_plugins(entry_point("recorded", "ConstructionRecordingPlugin"))
    CONSTRUCTIONS.clear()

    result = PluginHost(isolation=PluginIsolation.SUBPROCESS).discover()

    assert len(result.detectors) == 1
    assert CONSTRUCTIONS == [], "the worker owns the detector, not the host"


def test_a_duplicate_detector_id_is_refused_without_aborting_discovery(
    install_plugins, text_artifact: Path
) -> None:
    """A third-party package must not be able to stop the tool from starting."""

    install_plugins(
        entry_point("first", "WellBehavedPlugin"),
        entry_point("second", "WellBehavedPlugin"),
    )
    registry = DetectorRegistry()

    loaded = registry.discover()

    assert loaded == ["example.well-behaved.v1"]
    assert any(
        "already uses this id" in rejection.reason
        for rejection in registry.plugin_discovery.rejections
    )
    report = TrueAIEngine(registry).scan(text_artifact)
    assert report.findings


def test_a_plugin_cannot_take_over_a_built_in_detector_id(
    install_plugins, text_artifact: Path
) -> None:
    install_plugins(entry_point("collide", "WellBehavedPlugin"))
    registry = create_default_registry(discover_plugins=False)
    registry.register(WellBehavedPlugin())

    loaded = registry.discover()

    assert loaded == []
    assert any(
        "already uses this id" in rejection.reason
        for rejection in registry.plugin_discovery.rejections
    )


def test_import_time_capability_use_is_denied_in_the_worker(
    text_artifact: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Guards must be installed before the worker executes the plugin module.

    The detector is built directly rather than through discovery, because
    discovery imports the module in the host to read its manifest. This test is
    about the worker boundary, which is where the guarantee actually holds.
    """

    from trueai.core.models import ScanContext
    from trueai.plugins.host import IsolatedDetector
    from trueai.plugins.manifest import CapabilityDecision, PluginCapability, PluginManifest

    target = tmp_path / "written-at-import.txt"
    monkeypatch.setenv("TRUEAI_TEST_IMPORT_TARGET", str(target))
    manifest = PluginManifest.synthesize("example.import-writer.v1")
    detector = IsolatedDetector(
        entry_point="tests.plugin_import_side_effect:ImportTimeWriterPlugin",
        manifest=manifest,
        decision=CapabilityDecision(
            detector_id=manifest.detector_id,
            allowed=True,
            reason="test",
            granted=frozenset({PluginCapability.READ_ARTIFACT}),
        ),
        search_path=(REPOSITORY_ROOT,),
    )
    artifact = ArtifactDiscovery().identify(text_artifact)

    with pytest.raises(PluginExecutionError) as failure:
        detector.scan(artifact, ScanContext(options=ScanOptions()))

    assert not target.exists(), "the import-time write must be denied"
    assert failure.value.code == "plugin_load_failed"
    assert "write_filesystem" in str(failure.value)


def test_reading_a_manifest_still_imports_the_plugin_module(
    install_plugins, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The documented limit: an entry point is an import path, so discovery imports it.

    Policy runs before the detector is constructed, not before its module is
    executed. Pinning that here keeps the documentation honest.
    """

    target = tmp_path / "written-at-import.txt"
    monkeypatch.setenv("TRUEAI_TEST_IMPORT_TARGET", str(target))
    monkeypatch.delitem(sys.modules, "tests.plugin_import_side_effect", raising=False)
    install_plugins(
        EntryPoint(
            name="import-writer",
            value="tests.plugin_import_side_effect:ImportTimeWriterPlugin",
            group=host_module.ENTRY_POINT_GROUP,
        )
    )

    PluginHost(
        policy=CapabilityPolicy(blocked_detector_ids=frozenset({"example.import-writer.v1"}))
    ).discover()

    assert target.exists(), "host-side discovery imports the module; the docs say so"


def test_path_open_is_guarded_like_the_builtin(install_plugins, text_artifact: Path) -> None:
    install_plugins(entry_point("path-writer", "PathOpenWriterPlugin"))
    registry = isolated_registry()

    report = TrueAIEngine(registry).scan(text_artifact)

    failures = [item for item in report.diagnostics if item.code == "plugin_failed"]
    assert failures
    assert "write_filesystem" in failures[0].message
    assert not (text_artifact.parent / "written-via-path-open.txt").exists()


def test_the_isolated_host_reports_its_own_limits_in_the_module_docstring() -> None:
    """The docstring is the honest statement about what isolation does not do."""

    assert "not: an operating-system sandbox" in (host_module.__doc__ or "")


def test_plugin_execution_errors_carry_a_stable_code() -> None:
    error = PluginExecutionError("plugin_timeout", "took too long")

    assert error.code == "plugin_timeout"
    assert "took too long" in str(error)


def test_isolated_plugins_respect_the_scan_finding_budget(
    install_plugins, text_artifact: Path
) -> None:
    install_plugins(entry_point("declared", "DECLARED_REGISTRATION"))
    registry = isolated_registry()

    report = TrueAIEngine(registry).scan(
        text_artifact, options=ScanOptions(max_findings=1, max_workers=1)
    )

    assert len(report.findings) <= 1
