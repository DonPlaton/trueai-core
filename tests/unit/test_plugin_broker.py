"""The capability broker: scoped grants instead of boolean permission.

The recurring failure this module guards against is a grant that had to be widened
because it could not be narrowed. Every test here asks whether a grant does what
it says and refuses what it does not, and whether the refusal names the scope that
would have had to change.
"""

from __future__ import annotations

import hashlib
import socket
import sys
from importlib.metadata import EntryPoint
from pathlib import Path

import pytest

import trueai.plugins.host as host_module
from trueai import TrueAIEngine
from trueai.core.registry import DetectorRegistry
from trueai.plugins import (
    ArtifactGrant,
    BrokerGrants,
    CapabilityBroker,
    CapabilityDeniedError,
    NativeLibraryGrant,
    NetworkGrant,
    PluginCapability,
    PluginIsolation,
    SubprocessGrant,
    TemporaryOutputGrant,
    WorkspaceGrant,
    grants_for,
)

REPOSITORY_ROOT = str(Path(__file__).resolve().parents[2])
EXAMPLES = "tests.plugin_examples"


def entry_point(name: str, attribute: str) -> EntryPoint:
    return EntryPoint(
        name=name, value=f"{EXAMPLES}:{attribute}", group=host_module.ENTRY_POINT_GROUP
    )


@pytest.fixture
def install_plugins(monkeypatch: pytest.MonkeyPatch):
    def install(*points: EntryPoint) -> None:
        monkeypatch.setattr(host_module, "entry_points", lambda *, group: list(points))

    return install


@pytest.fixture
def artifact(tmp_path: Path) -> Path:
    path = tmp_path / "notes.txt"
    path.write_text("Ordinary content.\n", encoding="utf-8")
    return path


def artifact_grant(path: Path) -> ArtifactGrant:
    return ArtifactGrant(path=path, sha256=hashlib.sha256(path.read_bytes()).hexdigest())


# -- grants describe their scope -----------------------------------------------------


def test_a_grant_with_no_scope_is_refused_rather_than_widened() -> None:
    """ "network: yes" with no endpoints means nothing, and should not mean everything."""

    with pytest.raises(ValueError, match="grants nothing"):
        NetworkGrant()
    with pytest.raises(ValueError, match="grants nothing"):
        SubprocessGrant()


def test_a_native_library_grant_must_acknowledge_that_it_is_unmediated() -> None:
    """The broker cannot mediate native code, and must not imply that it can."""

    with pytest.raises(ValueError, match="acknowledged_unmediated"):
        NativeLibraryGrant(libraries=("libfoo.so",))

    grant = NativeLibraryGrant(libraries=("libfoo.so",), acknowledged_unmediated=True)
    assert grant.libraries == ("libfoo.so",)


def test_an_invalid_endpoint_is_refused() -> None:
    with pytest.raises(ValueError, match="Invalid network endpoint"):
        NetworkGrant(endpoints=(("example.test", 0),))


def test_grants_report_the_capability_set_they_correspond_to(
    tmp_path: Path, artifact: Path
) -> None:
    """The guards and the broker must be configured from one decision, not two."""

    grants = BrokerGrants(
        artifact=artifact_grant(artifact),
        workspace=WorkspaceGrant(root=tmp_path),
        temporary_output=TemporaryOutputGrant(directory=tmp_path / "scratch"),
    )

    assert grants.capabilities() == {
        PluginCapability.READ_ARTIFACT,
        PluginCapability.READ_WORKSPACE,
        PluginCapability.WRITE_TEMPORARY,
    }


def test_grants_describe_their_scopes_for_an_operator(tmp_path: Path, artifact: Path) -> None:
    """ "granted: read_workspace" tells an operator nothing about which directory."""

    grants = BrokerGrants(
        artifact=artifact_grant(artifact),
        workspace=WorkspaceGrant(root=tmp_path),
        network=NetworkGrant(endpoints=(("verify.example", 443),)),
    )

    described = "\n".join(grants.describe())

    assert str(tmp_path) in described
    assert "verify.example:443" in described


def test_a_capability_without_a_scope_produces_no_grant(tmp_path: Path) -> None:
    """Allowing the name and configuring nothing must grant nothing."""

    grants = grants_for(
        frozenset(
            {
                PluginCapability.READ_WORKSPACE,
                PluginCapability.NETWORK,
                PluginCapability.RUN_SUBPROCESS,
            }
        ),
        workspace_root=None,
    )

    assert grants.capabilities() == frozenset()


# -- artifact access -----------------------------------------------------------------


def test_the_broker_reads_the_artifact_it_was_granted(artifact: Path) -> None:
    broker = CapabilityBroker(BrokerGrants(artifact=artifact_grant(artifact)))

    assert broker.read_artifact() == artifact.read_bytes()
    assert broker.artifact_digest() == artifact_grant(artifact).sha256


def test_without_the_grant_reading_the_artifact_names_the_capability() -> None:
    broker = CapabilityBroker(BrokerGrants())

    with pytest.raises(CapabilityDeniedError) as raised:
        broker.read_artifact()

    assert raised.value.capability == PluginCapability.READ_ARTIFACT


def test_granted_is_answerable_without_provoking_an_exception(artifact: Path) -> None:
    """A plugin that degrades gracefully must be able to ask before it tries."""

    broker = CapabilityBroker(BrokerGrants(artifact=artifact_grant(artifact)))

    assert broker.granted(PluginCapability.READ_ARTIFACT)
    assert not broker.granted(PluginCapability.NETWORK)


# -- workspace confinement -----------------------------------------------------------


def test_a_workspace_read_stays_inside_its_root(tmp_path: Path) -> None:
    root = tmp_path / "package"
    root.mkdir()
    (root / "part.xml").write_text("<part/>", encoding="utf-8")
    broker = CapabilityBroker(BrokerGrants(workspace=WorkspaceGrant(root=root)))

    assert broker.read_workspace("part.xml") == b"<part/>"


def test_traversal_out_of_the_workspace_is_refused_by_scope(tmp_path: Path) -> None:
    """A prefix check on an unresolved path is how ../.. gets through."""

    root = tmp_path / "package"
    root.mkdir()
    (tmp_path / "secret.txt").write_text("private", encoding="utf-8")
    broker = CapabilityBroker(BrokerGrants(workspace=WorkspaceGrant(root=root)))

    with pytest.raises(CapabilityDeniedError) as raised:
        broker.workspace_path("../secret.txt")

    assert raised.value.capability == PluginCapability.READ_WORKSPACE
    assert str(root.resolve()) in raised.value.scope


def test_an_absolute_path_does_not_escape_the_workspace(tmp_path: Path) -> None:
    root = tmp_path / "package"
    root.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("private", encoding="utf-8")
    broker = CapabilityBroker(BrokerGrants(workspace=WorkspaceGrant(root=root)))

    with pytest.raises(CapabilityDeniedError):
        broker.workspace_path(str(outside))


def test_an_oversized_workspace_file_is_refused_rather_than_read(tmp_path: Path) -> None:
    root = tmp_path / "package"
    root.mkdir()
    (root / "big.bin").write_bytes(b"x" * 4096)
    broker = CapabilityBroker(
        BrokerGrants(workspace=WorkspaceGrant(root=root, max_file_bytes=1024))
    )

    with pytest.raises(CapabilityDeniedError, match="4096 bytes"):
        broker.read_workspace("big.bin")


def test_listing_the_workspace_skips_entries_that_resolve_outside_it(tmp_path: Path) -> None:
    root = tmp_path / "package"
    root.mkdir()
    (root / "a.txt").write_text("a", encoding="utf-8")
    (root / "b.txt").write_text("b", encoding="utf-8")
    broker = CapabilityBroker(BrokerGrants(workspace=WorkspaceGrant(root=root)))

    names = [path.name for path in broker.iter_workspace("*.txt")]

    assert names == ["a.txt", "b.txt"]


# -- temporary output ----------------------------------------------------------------


def test_scratch_writes_land_in_the_granted_directory(tmp_path: Path) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    broker = CapabilityBroker(
        BrokerGrants(temporary_output=TemporaryOutputGrant(directory=scratch))
    )

    with broker.open_temporary("work.bin") as handle:
        handle.write(b"payload")

    assert (scratch / "work.bin").read_bytes() == b"payload"
    assert broker.temporary_bytes_written == 7


def test_the_scratch_budget_is_charged_across_writes_not_per_file(tmp_path: Path) -> None:
    """A per-file limit is not a limit when a plugin can open more files."""

    scratch = tmp_path / "scratch"
    scratch.mkdir()
    broker = CapabilityBroker(
        BrokerGrants(temporary_output=TemporaryOutputGrant(directory=scratch, max_total_bytes=4096))
    )

    with broker.open_temporary("first.bin") as handle:
        handle.write(b"x" * 4000)
    with (
        pytest.raises(CapabilityDeniedError, match="4096 bytes"),
        broker.open_temporary("second.bin") as handle,
    ):
        handle.write(b"x" * 4000)


def test_a_refused_scratch_write_does_not_reach_the_file(tmp_path: Path) -> None:
    """A budget checked at close is a budget an attacker writes past."""

    scratch = tmp_path / "scratch"
    scratch.mkdir()
    broker = CapabilityBroker(
        BrokerGrants(temporary_output=TemporaryOutputGrant(directory=scratch, max_total_bytes=4096))
    )

    with pytest.raises(CapabilityDeniedError), broker.open_temporary("over.bin") as handle:
        handle.write(b"x" * 5000)

    assert (scratch / "over.bin").stat().st_size == 0


def test_scratch_traversal_is_refused(tmp_path: Path) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    broker = CapabilityBroker(
        BrokerGrants(temporary_output=TemporaryOutputGrant(directory=scratch))
    )

    with pytest.raises(CapabilityDeniedError):
        broker.temporary_path("../escaped.bin")


def test_without_the_grant_a_scratch_write_names_the_capability(tmp_path: Path) -> None:
    broker = CapabilityBroker(BrokerGrants())

    with pytest.raises(CapabilityDeniedError) as raised:
        broker.temporary_path("work.bin")

    assert raised.value.capability == PluginCapability.WRITE_TEMPORARY


# -- network and subprocess allowlists -----------------------------------------------


def test_an_unlisted_endpoint_is_refused_before_a_socket_is_opened() -> None:
    broker = CapabilityBroker(
        BrokerGrants(network=NetworkGrant(endpoints=(("verify.example", 443),)))
    )

    with pytest.raises(CapabilityDeniedError) as raised:
        broker.connect("evil.example", 443)

    assert raised.value.capability == PluginCapability.NETWORK
    assert "verify.example:443" in raised.value.scope


def test_the_listed_endpoint_is_the_one_that_is_attempted() -> None:
    """The allowlist decides; failing to connect afterwards is a different problem."""

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    broker = CapabilityBroker(BrokerGrants(network=NetworkGrant(endpoints=(("127.0.0.1", port),))))

    try:
        connection = broker.connect("127.0.0.1", port, timeout=5.0)
        connection.close()
    finally:
        listener.close()


def test_an_unlisted_executable_is_refused(tmp_path: Path) -> None:
    broker = CapabilityBroker(
        BrokerGrants(subprocess=SubprocessGrant(executables=(Path(sys.executable),)))
    )

    with pytest.raises(CapabilityDeniedError) as raised:
        broker.run(["/bin/sh", "-c", "echo hi"])

    assert raised.value.capability == PluginCapability.RUN_SUBPROCESS


def test_a_listed_executable_runs_without_a_shell() -> None:
    broker = CapabilityBroker(
        BrokerGrants(subprocess=SubprocessGrant(executables=(Path(sys.executable),)))
    )

    completed = broker.run([sys.executable, "-c", "print('broker')"], timeout=60.0)

    assert completed.returncode == 0
    assert b"broker" in completed.stdout


def test_without_the_grant_running_anything_names_the_capability() -> None:
    broker = CapabilityBroker(BrokerGrants())

    with pytest.raises(CapabilityDeniedError) as raised:
        broker.run([sys.executable, "-c", "pass"])

    assert raised.value.capability == PluginCapability.RUN_SUBPROCESS


def test_a_native_library_is_reported_as_granted_or_not() -> None:
    broker = CapabilityBroker(
        BrokerGrants(
            native_library=NativeLibraryGrant(
                libraries=("libexif.so",), acknowledged_unmediated=True
            )
        )
    )

    assert broker.native_library_granted("libexif.so")
    assert not broker.native_library_granted("libanything-else.so")


# -- end to end through the host -----------------------------------------------------


def isolated_registry() -> DetectorRegistry:
    registry = DetectorRegistry()
    registry.discover(
        isolation=PluginIsolation.SUBPROCESS,
        timeout=120.0,
        search_path=(REPOSITORY_ROOT,),
    )
    return registry


def test_a_broker_aware_plugin_reads_through_the_broker(install_plugins, artifact: Path) -> None:
    install_plugins(entry_point("broker", "BROKER_READER_REGISTRATION"))

    report = TrueAIEngine(isolated_registry()).scan(artifact)

    findings = [
        finding for finding in report.findings if finding.detector_id == "example.broker-reader.v1"
    ]
    assert findings, report.diagnostics
    assert findings[0].evidence["bytes"] == artifact.stat().st_size


def test_a_scratch_grant_is_usable_and_the_directory_does_not_survive(
    install_plugins, artifact: Path
) -> None:
    """A granted capability that the guards deny is a capability nobody can use."""

    install_plugins(entry_point("scratch", "BROKER_SCRATCH_REGISTRATION"))
    registry = DetectorRegistry()
    registry.discover(
        isolation=PluginIsolation.SUBPROCESS,
        timeout=120.0,
        search_path=(REPOSITORY_ROOT,),
        policy=_policy_granting(PluginCapability.WRITE_TEMPORARY),
    )

    report = TrueAIEngine(registry).scan(artifact)

    findings = [
        finding for finding in report.findings if finding.detector_id == "example.broker-scratch.v1"
    ]
    assert findings, report.diagnostics
    assert findings[0].evidence["written"] == 7
    # Nothing was left beside the artifact, and the scratch directory is gone.
    assert sorted(path.name for path in artifact.parent.iterdir()) == ["notes.txt"]


def test_a_plugin_that_escapes_its_workspace_grant_fails_visibly(
    install_plugins, tmp_path: Path
) -> None:
    directory = tmp_path / "project"
    directory.mkdir()
    (directory / "notes.txt").write_text("Ordinary content.\n", encoding="utf-8")
    install_plugins(entry_point("escape", "BROKER_ESCAPE_REGISTRATION"))

    report = TrueAIEngine(isolated_registry()).scan(directory)

    denied = [diagnostic for diagnostic in report.diagnostics if diagnostic.code == "plugin_failed"]
    assert denied, report.diagnostics
    # The diagnostic names the capability and the root, so an operator can tell a
    # too-narrow grant from a plugin reaching where it should not.
    assert "read_workspace" in denied[0].message
    assert "outside the workspace grant" in denied[0].message


def test_a_plugin_that_refuses_its_broker_is_reported_not_ignored(
    install_plugins, artifact: Path
) -> None:
    install_plugins(entry_point("rejecting", "BrokerRejectingPlugin"))

    report = TrueAIEngine(isolated_registry()).scan(artifact)

    rejected = [
        diagnostic
        for diagnostic in report.diagnostics
        if diagnostic.code == "plugin_broker_rejected"
    ]
    assert rejected, report.diagnostics
    assert "will not accept a broker" in rejected[0].message


def _policy_granting(*extra: PluginCapability):
    from trueai.plugins import DEFAULT_GRANTED_CAPABILITIES, CapabilityPolicy

    return CapabilityPolicy(granted=frozenset(DEFAULT_GRANTED_CAPABILITIES) | frozenset(extra))
