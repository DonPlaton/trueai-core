"""The plugin fuzzer, and the evidence that it would notice a regression.

A fuzz harness that has never failed is indistinguishable from one that cannot
fail. So this file does three things: it runs a bounded campaign so a regression
is caught in an ordinary test run, it pins the specific inputs that must always
be refused, and it deliberately breaks a check to prove the fuzzer reports it.

The long campaigns live in ``scripts/fuzz_plugins.py`` and are meant to be run
continuously — a nightly ``--seconds 3600`` or a targeted ``--iterations 200000``
after a change to the trust boundary.
"""

from __future__ import annotations

import hashlib
import random
from pathlib import Path

import pytest

from scripts.fuzz_plugins import (
    TARGETS,
    fuzz_broker_paths,
    fuzz_distribution,
    fuzz_findings,
    fuzz_manifest,
    fuzz_protocol,
    fuzz_resource_limits,
    run,
)

pytest.importorskip("cryptography", reason="Distribution fuzzing needs the attestation extra")


# -- a bounded campaign, run in the ordinary suite ------------------------------------


@pytest.mark.parametrize("seed", [1, 2, 3, 17, 99])
def test_a_short_campaign_finds_nothing(seed: int, tmp_path: Path) -> None:
    """Every boundary, a few hundred cases each, at five fixed seeds."""

    failures = run(seed=seed, iterations=300, workspace=tmp_path / f"seed-{seed}")

    assert not failures, "\n".join(failure.render(seed) for failure in failures)


@pytest.mark.parametrize("target", sorted(TARGETS))
def test_every_target_is_exercised_and_clean(target: str, tmp_path: Path) -> None:
    """Named individually, so a target that silently stopped running is visible."""

    failures = run(seed=4242, iterations=200, targets=(target,), workspace=tmp_path / target)

    assert not failures, "\n".join(failure.render(4242) for failure in failures)


def test_a_campaign_replays_from_its_seed(tmp_path: Path) -> None:
    """A bug found overnight has to reproduce with one command."""

    first = run(seed=5150, iterations=250, workspace=tmp_path / "a")
    second = run(seed=5150, iterations=250, workspace=tmp_path / "b")

    assert [(item.target, item.iteration, item.payload) for item in first] == [
        (item.target, item.iteration, item.payload) for item in second
    ]


def test_an_unknown_target_is_refused_rather_than_silently_skipped() -> None:
    with pytest.raises(SystemExit, match="Unknown target"):
        run(seed=1, iterations=1, targets=("does-not-exist",))


# -- the fuzzer has teeth -------------------------------------------------------------


def test_the_finding_target_reports_a_validator_that_stopped_checking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Break the identity check and the fuzzer must notice within a short run.

    Without this, "no findings" would be equally consistent with a healthy
    boundary and with a harness that never reaches one.
    """

    import trueai.plugins.host as host_module

    monkeypatch.setattr(host_module, "finding_id_is_valid", lambda finding: True)

    found = []
    for seed in range(400):
        detail = fuzz_findings(random.Random(seed), tmp_path)
        if detail is not None:
            found.append(detail)
            break

    assert found, "the fuzzer did not notice that finding identities stopped being checked"
    assert "does not match its evidence" in found[0]


def test_the_broker_target_reports_a_confinement_that_stopped_resolving(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Make workspace_path return whatever it was asked for; the fuzzer must object."""

    from trueai.plugins import broker as broker_module

    monkeypatch.setattr(
        broker_module.CapabilityBroker,
        "workspace_path",
        lambda self, relative: Path(str(relative)).absolute(),
    )

    found = []
    for seed in range(400):
        detail = fuzz_broker_paths(random.Random(seed), tmp_path)
        if detail is not None:
            found.append(detail)
            break

    assert found, "the fuzzer did not notice that workspace confinement stopped working"
    assert "outside" in found[0]


# -- the specific inputs that must always be refused ----------------------------------


def test_a_forged_finding_identity_is_refused(tmp_path: Path) -> None:
    """The corpus case behind the whole finding target, pinned so it cannot regress."""

    from trueai.core.artifact import Artifact
    from trueai.core.models import ArtifactType, ScanContext, ScanOptions
    from trueai.plugins.host import IsolatedDetector, PluginExecutionError
    from trueai.plugins.manifest import CapabilityDecision, PluginManifest
    from trueai.plugins.protocol import WorkerResponse

    artifact_path = tmp_path / "notes.txt"
    artifact_path.write_text("Ordinary content.\n", encoding="utf-8")
    digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    manifest = PluginManifest(detector_id="example.fuzz.v1", name="fuzz", version="1.0")
    detector = IsolatedDetector(
        entry_point="unused:Detector",
        manifest=manifest,
        decision=CapabilityDecision(detector_id=manifest.detector_id, allowed=True, reason="test"),
    )
    artifact = Artifact(
        artifact_type=ArtifactType.TEXT, path=artifact_path, logical_path=artifact_path.name
    )
    forged = {
        "id": "fnd_" + "0" * 20,
        "detector_id": manifest.detector_id,
        "artifact_path": artifact.display_path,
        "category": "structural_signal",
        "severity": "critical",
        "confidence": 1.0,
        "confidence_type": "deterministic",
        "evidence_type": "structural",
        "title": "Forged",
        "description": "An identity that does not match its evidence.",
        "evidence": {"claim": "invented"},
        "provenance_class": "none",
        "tags": [],
    }

    with pytest.raises(PluginExecutionError) as raised:
        detector._validate(
            WorkerResponse(detector_id=manifest.detector_id, ok=True, findings=[forged]),
            artifact,
            digest,
            ScanContext(options=ScanOptions()),
        )

    assert raised.value.code == "plugin_forged_finding_id"


def test_a_protocol_document_with_an_unknown_field_is_refused() -> None:
    """``extra="forbid"`` is what keeps a future field from being silently ignored."""

    from pydantic import ValidationError

    from trueai.plugins.protocol import WorkerResponse

    with pytest.raises(ValidationError):
        WorkerResponse.model_validate_json('{"detector_id": "x", "ok": true, "surprise": 1}')


def test_a_resource_limit_below_the_floor_is_refused() -> None:
    from pydantic import ValidationError

    from trueai.plugins.resources import PluginResourceLimits

    with pytest.raises(ValidationError):
        PluginResourceLimits(max_memory_bytes=1024)
    with pytest.raises(ValidationError):
        PluginResourceLimits(max_cpu_seconds=0)
    with pytest.raises(ValidationError):
        PluginResourceLimits(max_cpu_seconds=10_000)


def test_a_distribution_file_path_that_escapes_is_refused() -> None:
    from trueai.plugins.distribution import DistributionFile

    for path in ("../escape.py", "/etc/passwd", "nested/../../escape.py"):
        with pytest.raises(ValueError):
            DistributionFile(path=path, sha256="a" * 64, size=1)


def test_a_manifest_with_an_unknown_capability_is_refused() -> None:
    from pydantic import ValidationError

    from trueai.plugins.manifest import PluginManifest

    with pytest.raises(ValidationError):
        PluginManifest.model_validate(
            {
                "detector_id": "acme.v1",
                "name": "ACME",
                "version": "1.0",
                "capabilities": ["become_root"],
            }
        )


# -- the targets return a description rather than raising -----------------------------


@pytest.mark.parametrize(
    "target",
    [fuzz_protocol, fuzz_manifest, fuzz_distribution, fuzz_resource_limits],
)
def test_a_target_reports_by_returning_not_by_raising(target) -> None:
    """A target that raises would abort the campaign instead of recording a case."""

    for seed in range(60):
        assert target(random.Random(seed)) is None


@pytest.mark.parametrize("target", [fuzz_findings, fuzz_broker_paths])
def test_a_workspace_target_reports_by_returning(target, tmp_path: Path) -> None:
    for seed in range(60):
        assert target(random.Random(seed), tmp_path) is None
