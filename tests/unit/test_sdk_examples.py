"""The published example, checked rather than described.

An example that drifts is worse than no example: someone copies it, it works
locally, and it breaks on the next upgrade with the compatibility gate silent
because the example was never part of what the gate covers. So the example is
loaded, run, signed, and — the part that matters — inspected to prove every
import in it comes from a module TrueAI has actually frozen.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from trueai import TrueAIEngine
from trueai.api import PUBLIC_MODULES, SDK_CONTRACT, public_api_surface
from trueai.core.models import (
    ConfidenceType,
    EvidenceType,
    FindingCategory,
    ProvenanceClass,
    Severity,
)
from trueai.core.registry import DetectorRegistry

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"
DETECTOR_PACKAGE = EXAMPLES / "acme_ticket_detector" / "acme_ticket_detector"
NOW = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def example():
    """Import the example package from its own directory, not from the tree."""

    location = DETECTOR_PACKAGE / "__init__.py"
    spec = importlib.util.spec_from_file_location("acme_ticket_detector", location)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["acme_ticket_detector"] = module
    spec.loader.exec_module(module)
    try:
        yield module
    finally:
        sys.modules.pop("acme_ticket_detector", None)


# -- it actually works ---------------------------------------------------------------


def test_the_example_detector_finds_what_it_claims(example, tmp_path: Path) -> None:
    target = tmp_path / "notes.md"
    target.write_text("Fixed in ACME-1234 and ACME-7.\n", encoding="utf-8")
    registry = DetectorRegistry()
    registry.register(example.AcmeTicketDetector())

    report = TrueAIEngine(registry).scan(target)

    tickets = sorted(finding.evidence["ticket"] for finding in report.findings)
    assert tickets == ["ACME-1234", "ACME-7"]


def test_the_example_reports_the_same_finding_id_every_run(example, tmp_path: Path) -> None:
    """A detector whose ids move cannot be diffed between two scans."""

    target = tmp_path / "notes.md"
    target.write_text("See ACME-1234.\n", encoding="utf-8")
    registry = DetectorRegistry()
    registry.register(example.AcmeTicketDetector())

    first = TrueAIEngine(registry).scan(target)
    second = TrueAIEngine(registry).scan(target)

    assert [item.id for item in first.findings] == [item.id for item in second.findings]


def test_the_example_reports_a_ticket_as_an_observation_not_as_provenance(
    example, tmp_path: Path
) -> None:
    """A lexical hit says what is in the file, never who wrote it."""

    target = tmp_path / "notes.md"
    target.write_text("See ACME-1234.\n", encoding="utf-8")
    registry = DetectorRegistry()
    registry.register(example.AcmeTicketDetector())

    finding = TrueAIEngine(registry).scan(target).findings[0]

    assert finding.provenance_class is ProvenanceClass.NONE
    assert finding.confidence_type is ConfidenceType.DETERMINISTIC
    assert finding.evidence_type is EvidenceType.TEXT
    assert finding.severity is Severity.LOW
    assert finding.category is FindingCategory.TOOLING_RESIDUE


def test_the_example_reports_each_ticket_once(example, tmp_path: Path) -> None:
    target = tmp_path / "notes.md"
    target.write_text("ACME-1 ACME-1 ACME-1\n", encoding="utf-8")
    registry = DetectorRegistry()
    registry.register(example.AcmeTicketDetector())

    assert len(TrueAIEngine(registry).scan(target).findings) == 1


def test_the_example_bounds_a_pathological_file(example, tmp_path: Path) -> None:
    """Fifty findings from one file is already a report nobody reads."""

    target = tmp_path / "notes.md"
    target.write_text(" ".join(f"ACME-{index}" for index in range(500)), encoding="utf-8")
    registry = DetectorRegistry()
    registry.register(example.AcmeTicketDetector())

    findings = TrueAIEngine(registry).scan(target).findings

    assert len(findings) == example.MAX_FINDINGS_PER_ARTIFACT


def test_the_example_leaves_the_artifact_untouched(example, tmp_path: Path) -> None:
    target = tmp_path / "notes.md"
    target.write_text("ACME-1234\n", encoding="utf-8")
    before = target.read_bytes()
    registry = DetectorRegistry()
    registry.register(example.AcmeTicketDetector())

    report = TrueAIEngine(registry).scan(target)

    assert target.read_bytes() == before
    assert not [item for item in report.diagnostics if item.code == "detector_mutation"]


# -- it stays inside the public surface ----------------------------------------------


def imported_modules(path: Path) -> set[str]:
    """Return every module the file imports, by name."""

    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def test_the_example_imports_only_frozen_modules() -> None:
    """The guarantee, checked. Anything else may change in any release."""

    used = {
        name
        for name in imported_modules(DETECTOR_PACKAGE / "__init__.py")
        if name == "trueai" or name.startswith("trueai.")
    }

    assert used
    assert used <= set(PUBLIC_MODULES), sorted(used - set(PUBLIC_MODULES))


def test_the_sdk_contract_is_reachable_through_public_modules() -> None:
    """`SDK_CONTRACT` is a claim; this is the check behind it."""

    surface = public_api_surface()["modules"]
    missing = [
        f"{module}.{name}"
        for module, name in SDK_CONTRACT
        if module not in surface or name not in surface[module]
    ]

    assert missing == []


def test_the_example_declares_the_entry_point_group_the_host_reads() -> None:
    from trueai.plugins import ENTRY_POINT_GROUP

    manifest = (EXAMPLES / "acme_ticket_detector" / "pyproject.toml").read_text(encoding="utf-8")

    assert f'[project.entry-points."{ENTRY_POINT_GROUP}"]' in manifest


def test_the_example_pins_the_api_contract_it_was_written_against() -> None:
    from trueai.api import API_VERSION

    manifest = (EXAMPLES / "acme_ticket_detector" / "pyproject.toml").read_text(encoding="utf-8")

    assert f"trueai-core>={API_VERSION}" in manifest


# -- it declares only what it uses ---------------------------------------------------


def test_the_example_asks_for_the_narrowest_capability_set(example) -> None:
    from trueai.plugins import PluginCapability

    assert example.MANIFEST.capabilities == frozenset({PluginCapability.READ_ARTIFACT})


def test_the_registration_lets_a_host_read_the_manifest_without_instantiating(example) -> None:
    """Import time is when hostile code acts; a declaration read first is the point."""

    assert example.REGISTRATION.manifest is example.MANIFEST
    assert example.REGISTRATION.factory is example.AcmeTicketDetector
    assert isinstance(example.REGISTRATION.build(), example.AcmeTicketDetector)


# -- it can be published -------------------------------------------------------------


def test_a_signed_distribution_of_the_example_verifies(example, tmp_path: Path) -> None:
    pytest.importorskip("cryptography", reason="Signing needs the attestation extra")

    from trueai.core.certificates import generate_ed25519_keypair
    from trueai.plugins import build_distribution, sign_distribution, verify_distribution

    private, public = tmp_path / "acme.key", tmp_path / "acme.pub"
    generate_ed25519_keypair(private, public)

    distribution = sign_distribution(
        build_distribution(
            detector_id="acme.ticket.v1",
            version="1.0",
            entry_point="acme_ticket_detector:REGISTRATION",
            manifest=example.MANIFEST,
            publisher="ACME",
            root=DETECTOR_PACKAGE,
            created_at=NOW,
        ),
        signing_key=private,
    )
    result = verify_distribution(distribution, root=DETECTOR_PACKAGE, public_key=public, now=NOW)

    assert result.content_id_valid
    assert result.files_match is True
    assert result.signature == "valid"
    assert result.may_load()


def test_the_distribution_covers_the_module_bytes_not_only_the_manifest(
    example, tmp_path: Path
) -> None:
    """A declared capability set must not be contradictable by module-level code."""

    pytest.importorskip("cryptography", reason="Signing needs the attestation extra")

    from trueai.plugins import build_distribution

    distribution = build_distribution(
        detector_id="acme.ticket.v1",
        version="1.0",
        entry_point="acme_ticket_detector:REGISTRATION",
        manifest=example.MANIFEST,
        publisher="ACME",
        root=DETECTOR_PACKAGE,
        created_at=NOW,
    )

    assert {item.path for item in distribution.files} == {"__init__.py"}


# -- what the SDK guarantees when a detector misbehaves ------------------------------


def test_a_detector_that_raises_does_not_take_the_scan_with_it(tmp_path: Path) -> None:
    """The guarantee an author most needs: your bug is contained to your detector."""

    from trueai.core.artifact import Artifact
    from trueai.core.models import ArtifactType, Finding, ScanContext
    from trueai.detectors.base import BaseDetector

    class Broken(BaseDetector):
        id = "vendor.broken.v1"
        supported_types = frozenset({ArtifactType.MARKDOWN})
        categories = frozenset({FindingCategory.TOOLING_RESIDUE})

        def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
            raise ValueError("a bug in somebody's detector")

    target = tmp_path / "notes.md"
    target.write_text("ACME-1234\n", encoding="utf-8")
    registry = DetectorRegistry()
    registry.register(Broken())

    report = TrueAIEngine(registry).scan(target)

    failure = next(item for item in report.diagnostics if item.code == "detector_failure")
    assert "vendor.broken.v1" in failure.message
    assert "ValueError" in failure.message


def test_a_failing_detector_does_not_silence_a_working_one(example, tmp_path: Path) -> None:
    """A report is not quietly emptied because one third party shipped a bug."""

    from trueai.core.artifact import Artifact
    from trueai.core.models import ArtifactType, Finding, ScanContext
    from trueai.detectors.base import BaseDetector

    class Broken(BaseDetector):
        id = "vendor.broken.v1"
        supported_types = frozenset({ArtifactType.MARKDOWN})
        categories = frozenset({FindingCategory.TOOLING_RESIDUE})

        def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
            raise ValueError("a bug in somebody's detector")

    target = tmp_path / "notes.md"
    target.write_text("ACME-1234\n", encoding="utf-8")
    registry = DetectorRegistry()
    registry.register(Broken())
    registry.register(example.AcmeTicketDetector())

    report = TrueAIEngine(registry).scan(target)

    assert len(report.findings) == 1
    assert any(item.code == "detector_failure" for item in report.diagnostics)


def test_scan_is_the_only_method_a_detector_must_implement() -> None:
    """Promised by the docs and the examples; enforced by the compatibility gate."""

    from trueai.detectors.base import BaseDetector

    assert BaseDetector.__abstractmethods__ == frozenset({"scan"})
