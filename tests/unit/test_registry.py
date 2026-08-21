from importlib.metadata import EntryPoint
from pathlib import Path

import pytest

import trueai.plugins.host as host_module
from tests.plugin_examples import WellBehavedPlugin
from trueai import TrueAIEngine
from trueai.core.artifact import Artifact
from trueai.core.errors import DetectorRegistrationError
from trueai.core.models import (
    ArtifactType,
    Finding,
    FindingCategory,
    IntegrityStatus,
    ScanContext,
    ScanOptions,
)
from trueai.core.registry import DetectorRegistry
from trueai.detectors import create_default_registry
from trueai.detectors.base import BaseDetector


class ExampleDetector(BaseDetector):
    id = "example.detector.v1"
    provider = "example"
    supported_types = frozenset({ArtifactType.TEXT})
    categories = frozenset({FindingCategory.STRUCTURAL_SIGNAL})

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        del artifact, context
        return []


def test_registry_enable_disable_and_group_filters() -> None:
    registry = DetectorRegistry()
    detector = ExampleDetector()
    registry.register(detector)

    assert registry.get(detector.id) is detector
    assert registry.detectors(provider="example") == (detector,)
    assert registry.detectors(category=FindingCategory.STRUCTURAL_SIGNAL) == (detector,)

    registry.disable(detector.id)
    assert not registry.is_enabled(detector.id)
    assert registry.detectors() == ()
    assert registry.detectors(include_disabled=True) == (detector,)

    registry.enable(detector.id)
    with pytest.raises(DetectorRegistrationError, match="already registered"):
        registry.register(ExampleDetector())


EXAMPLE_ENTRY_POINT = EntryPoint(
    name="example",
    value="tests.plugin_examples:WellBehavedPlugin",
    group="trueai.detectors",
)


def install_example_plugin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pretend the example detector is installed as a third-party plugin."""

    def fake_entry_points(*, group: str) -> list[EntryPoint]:
        assert group == "trueai.detectors"
        return [EXAMPLE_ENTRY_POINT]

    monkeypatch.setattr(host_module, "entry_points", fake_entry_points)


def test_entry_point_discovery_registers_protocol_compatible_detector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_example_plugin(monkeypatch)
    registry = DetectorRegistry()

    assert registry.discover() == [WellBehavedPlugin.id]
    assert isinstance(registry.get(WellBehavedPlugin.id), WellBehavedPlugin)
    assert not registry.plugin_discovery.rejections


def test_default_registry_discovers_entry_point_plugins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_example_plugin(monkeypatch)

    registry = create_default_registry()

    assert isinstance(registry.get(WellBehavedPlugin.id), WellBehavedPlugin)


def test_discovery_records_a_synthesized_manifest_for_an_undeclared_plugin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_example_plugin(monkeypatch)
    registry = DetectorRegistry()

    registry.discover()

    manifest = registry.plugin_discovery.manifests[0]
    assert manifest.detector_id == WellBehavedPlugin.id
    assert manifest.declared is False


def test_registry_detector_does_not_require_a_filesystem_path() -> None:
    artifact = Artifact.from_text("content")

    assert ExampleDetector().supports(artifact)
    assert artifact.path is None


def test_engine_detects_in_process_detector_mutation(tmp_path: Path) -> None:
    path = tmp_path / "source.txt"
    path.write_text("original\n", encoding="utf-8")

    class MutatingDetector(ExampleDetector):
        id = "example.mutating.v1"

        def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
            del context
            assert artifact.path is not None
            artifact.path.write_text("mutated\n", encoding="utf-8")
            return []

    registry = DetectorRegistry()
    registry.register(MutatingDetector())

    report = TrueAIEngine(registry).scan(path)

    assert report.integrity.status == IntegrityStatus.FAIL
    assert any(diagnostic.code == "detector_mutation" for diagnostic in report.diagnostics)


def test_unicode_finding_budget_fails_closed() -> None:
    report = TrueAIEngine.default().scan_text(
        "a\u200b\u200b",
        options=ScanOptions(max_findings=1),
    )

    assert any(diagnostic.code == "scan_limit_exceeded" for diagnostic in report.diagnostics)


def test_engine_rechecks_earlier_artifacts_after_later_plugin_runs(tmp_path: Path) -> None:
    first = tmp_path / "a.txt"
    second = tmp_path / "b.txt"
    first.write_text("first\n", encoding="utf-8")
    second.write_text("second\n", encoding="utf-8")

    class CrossArtifactMutator(ExampleDetector):
        id = "example.cross-artifact-mutator.v1"

        def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
            del context
            if artifact.path == second:
                first.write_text("mutated later\n", encoding="utf-8")
            return []

    registry = DetectorRegistry()
    registry.register(CrossArtifactMutator())

    report = TrueAIEngine(registry).scan(tmp_path)

    assert report.integrity.status == IntegrityStatus.FAIL
    assert any(
        diagnostic.code == "detector_mutation" and diagnostic.artifact_path == "a.txt"
        for diagnostic in report.diagnostics
    )


def test_engine_detects_new_file_created_by_directory_plugin(tmp_path: Path) -> None:
    (tmp_path / "source.txt").write_text("original\n", encoding="utf-8")

    class DirectoryMutator(BaseDetector):
        id = "example.directory-mutator.v1"
        supported_types = frozenset({ArtifactType.DIRECTORY})
        categories = frozenset({FindingCategory.STRUCTURAL_SIGNAL})

        def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
            del context
            assert artifact.path is not None
            (artifact.path / "created-by-plugin.txt").write_text("new\n", encoding="utf-8")
            return []

    registry = DetectorRegistry()
    registry.register(DirectoryMutator())

    report = TrueAIEngine(registry).scan(tmp_path)

    assert report.integrity.status == IntegrityStatus.FAIL
    assert any(
        diagnostic.code == "detector_mutation" and "created-by-plugin.txt" in diagnostic.message
        for diagnostic in report.diagnostics
    )
