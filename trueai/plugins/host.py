"""Plugin host: manifest review, capability enforcement, and process isolation.

Running a third-party detector in the scanner's own process means a plugin crash
takes the scan down, a plugin hang never ends, a plugin's memory growth is the
host's memory growth, and a plugin can return whatever finding it likes. The
isolated host addresses each of those directly:

* the detector runs in a separate interpreter, so a crash cannot corrupt host state;
* the worker is killed at a deadline, so a hang becomes a diagnostic;
* stdout/stderr are discarded and the response is a bounded file, so plugin output
  cannot exhaust host memory;
* kernel CPU and memory limits are installed before third-party code is imported;
* every returned finding is re-validated against its own evidence, so a plugin
  cannot forge a finding identity, attribute a finding to a different artifact,
  or impersonate another detector.

What this is not: a filesystem/system-call sandbox. The worker runs with the same
user and filesystem access as the host. The in-worker guards and kernel resource
quotas do not stop malicious native code from opening files. Seccomp, AppContainer,
or container-level isolation remains future work.

Manifest inspection also happens in a guarded helper process. A refused plugin is
therefore never imported or constructed in the scanner process. Python-level
guards, process separation, and resource quotas still do not replace a platform
sandbox; operators should combine hostile native plugins with platform controls.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from enum import StrEnum
from importlib.metadata import EntryPoint, entry_points
from pathlib import Path

from trueai.core.artifact import Artifact
from trueai.core.errors import DetectorRegistrationError
from trueai.core.finding_id import finding_id_is_valid
from trueai.core.models import ArtifactType, Finding, FindingCategory, ScanContext
from trueai.plugins.loader import enrich_manifest, instantiate, manifest_for, resolve_target
from trueai.plugins.manifest import (
    CapabilityDecision,
    CapabilityPolicy,
    PluginManifest,
)
from trueai.plugins.protocol import (
    InspectionRequest,
    InspectionResponse,
    WorkerArtifact,
    WorkerRequest,
    WorkerResponse,
)
from trueai.plugins.resources import PluginResourceLimits

ENTRY_POINT_GROUP = "trueai.detectors"

#: A detector that has not answered within this many seconds is killed.
DEFAULT_TIMEOUT_SECONDS = 60.0
#: Worker responses larger than this are rejected without being parsed.
MAX_RESPONSE_BYTES = 32 * 1024 * 1024


def _read_bounded(path: Path, limit: int) -> bytes:
    """Read a worker-owned protocol file without a size-check race."""

    with path.open("rb") as handle:
        payload = handle.read(limit + 1)
    if len(payload) > limit:
        raise DetectorRegistrationError(f"Plugin protocol output exceeded {limit} bytes")
    return payload


class PluginIsolation(StrEnum):
    """How much the host trusts third-party detector code."""

    #: Load plugins into the scanner process. Fast, and fully trusting.
    IN_PROCESS = "in_process"
    #: Run each plugin in a separate interpreter with capability guards.
    SUBPROCESS = "subprocess"
    #: Do not load third-party detectors at all.
    DISABLED = "disabled"


@dataclass(frozen=True, slots=True)
class PluginRejection:
    """A plugin the host refused to run, and why."""

    detector_id: str
    entry_point: str
    reason: str


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    """Detectors the host accepted, plus the ones it refused."""

    detectors: tuple[object, ...]
    manifests: tuple[PluginManifest, ...]
    decisions: tuple[CapabilityDecision, ...]
    rejections: tuple[PluginRejection, ...]


class IsolatedDetector:
    """Detector-shaped proxy that runs the real plugin in a worker process."""

    experimental = False

    def __init__(
        self,
        *,
        entry_point: str,
        manifest: PluginManifest,
        decision: CapabilityDecision,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        search_path: tuple[str, ...] = (),
        resource_limits: PluginResourceLimits | None = None,
    ) -> None:
        self.id = manifest.detector_id
        self.entry_point = entry_point
        self.manifest = manifest
        self.decision = decision
        self.timeout = timeout
        self.search_path = search_path
        self.resource_limits = resource_limits or PluginResourceLimits()
        self.provider: str | None = manifest.vendor
        self.supported_types: frozenset[ArtifactType] = manifest.supported_types
        self.categories: frozenset[FindingCategory] = manifest.categories

    def supports(self, artifact: Artifact) -> bool:
        """Return whether the plugin declared support for this artifact type.

        An isolated plugin only ever sees artifacts with content to hash, because
        the worker is handed a digest it must still match on return. Directories
        and in-memory streams therefore reach in-process plugins only.
        """

        if artifact.path is None or not artifact.path.is_file():
            return False
        if not self.supported_types:
            # A plugin that declared no types is offered every file.
            return True
        return artifact.artifact_type in self.supported_types

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        """Run the plugin out of process and return only findings that validate."""

        if artifact.path is None:
            return []
        digest = artifact.sha256(context.options.max_file_size)
        if digest is None:
            return []
        request = WorkerRequest(
            entry_point=self.entry_point,
            detector_id=self.id,
            granted_capabilities=frozenset(self.decision.granted),
            resource_limits=self.resource_limits,
            artifact=WorkerArtifact(
                artifact_type=artifact.artifact_type,
                path=str(artifact.path),
                logical_path=artifact.display_path,
                size=artifact.size,
                media_type=artifact.media_type,
                sha256=digest,
            ),
            options=context.options,
            root=str(context.root) if context.root else None,
        )
        response = self._run_worker(request)
        return self._validate(response, artifact, digest, context)

    # -- worker lifecycle -------------------------------------------------------------

    def _run_worker(self, request: WorkerRequest) -> WorkerResponse:
        workspace = Path(tempfile.mkdtemp(prefix="trueai-plugin-"))
        request_path = workspace / "request.json"
        response_path = workspace / "response.json"
        try:
            request_path.write_text(request.model_dump_json(), encoding="utf-8")
            environment = dict(os.environ)
            if self.search_path:
                existing = environment.get("PYTHONPATH", "")
                entries = [*self.search_path, existing] if existing else list(self.search_path)
                environment["PYTHONPATH"] = os.pathsep.join(entries)
            try:
                completed = subprocess.run(
                    # The worker deliberately runs in the host's own interpreter
                    # and import environment. Trimming its module search path
                    # would make a plugin's dependencies resolve in the host and
                    # fail in the worker, which is a difference that would show
                    # up as a mysterious plugin failure rather than a security
                    # improvement.
                    [
                        sys.executable,
                        "-m",
                        "trueai.plugins.worker",
                        str(request_path),
                        str(response_path),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=self.timeout,
                    env=environment,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return WorkerResponse(
                    detector_id=self.id,
                    ok=False,
                    error_code="plugin_timeout",
                    error_message=(
                        f"The plugin did not finish within {self.timeout:g} seconds and was "
                        "terminated."
                    ),
                )
            if not response_path.is_file():
                return WorkerResponse(
                    detector_id=self.id,
                    ok=False,
                    error_code="plugin_crashed",
                    error_message=(
                        f"The worker exited with code {completed.returncode} without a "
                        "response. Plugin-controlled stdout and stderr were discarded."
                    ),
                )
            try:
                payload = _read_bounded(response_path, MAX_RESPONSE_BYTES)
                return WorkerResponse.model_validate_json(payload)
            except DetectorRegistrationError as exc:
                return WorkerResponse(
                    detector_id=self.id,
                    ok=False,
                    error_code="plugin_output_too_large",
                    error_message=str(exc),
                )
            except Exception as exc:
                return WorkerResponse(
                    detector_id=self.id,
                    ok=False,
                    error_code="plugin_output_invalid",
                    error_message=f"{type(exc).__name__}: {exc}",
                )
        finally:
            for path in (request_path, response_path):
                with contextlib.suppress(OSError):
                    path.unlink(missing_ok=True)
            with contextlib.suppress(OSError):
                workspace.rmdir()

    def _validate(
        self,
        response: WorkerResponse,
        artifact: Artifact,
        digest: str,
        context: ScanContext,
    ) -> list[Finding]:
        """Re-derive every finding so a plugin cannot assert one into existence."""

        if not response.ok:
            raise PluginExecutionError(
                response.error_code or "plugin_failed",
                response.error_message or "The plugin failed without an explanation.",
            )
        if response.detector_id != self.id:
            raise PluginExecutionError(
                "detector_identity_mismatch",
                f"The worker answered for detector {response.detector_id!r}.",
            )
        after = artifact.sha256(context.options.max_file_size)
        if after != digest:
            raise PluginExecutionError(
                "plugin_mutated_artifact",
                "The artifact changed while the plugin was running.",
            )
        findings: list[Finding] = []
        for payload in response.findings[: context.options.max_findings]:
            try:
                finding = Finding.model_validate(payload)
            except Exception as exc:
                raise PluginExecutionError(
                    "plugin_output_invalid",
                    f"A returned finding is not a valid Finding: {exc}",
                ) from exc
            if finding.detector_id != self.id:
                raise PluginExecutionError(
                    "plugin_impersonation",
                    f"A finding claims detector {finding.detector_id!r}.",
                )
            if finding.artifact_path != artifact.display_path:
                raise PluginExecutionError(
                    "plugin_artifact_mismatch",
                    f"A finding claims artifact {finding.artifact_path!r}.",
                )
            if not finding_id_is_valid(finding):
                raise PluginExecutionError(
                    "plugin_forged_finding_id",
                    f"Finding {finding.id} does not match its own evidence.",
                )
            findings.append(finding)
        return findings


class PluginExecutionError(DetectorRegistrationError):
    """Raised when an isolated plugin fails, times out, or returns bad data."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class PluginHost:
    """Discover, review, and wrap third-party detectors."""

    def __init__(
        self,
        *,
        policy: CapabilityPolicy | None = None,
        isolation: PluginIsolation = PluginIsolation.SUBPROCESS,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        search_path: tuple[str, ...] = (),
        resource_limits: PluginResourceLimits | None = None,
    ) -> None:
        self.policy = policy or CapabilityPolicy()
        self.isolation = isolation
        self.timeout = timeout
        self.search_path = search_path
        self.resource_limits = resource_limits or PluginResourceLimits()

    def discover(self) -> DiscoveryResult:
        """Review every registered plugin and return the ones the policy allows."""

        if self.isolation == PluginIsolation.DISABLED:
            return DiscoveryResult((), (), (), ())
        detectors: list[object] = []
        manifests: list[PluginManifest] = []
        decisions: list[CapabilityDecision] = []
        rejections: list[PluginRejection] = []
        for entry_point in sorted(
            entry_points(group=ENTRY_POINT_GROUP), key=lambda item: item.name
        ):
            try:
                manifest = self._inspect(entry_point)
            except Exception as exc:
                rejections.append(
                    PluginRejection(
                        detector_id=entry_point.name,
                        entry_point=entry_point.value,
                        reason=f"The plugin could not be loaded: {type(exc).__name__}: {exc}",
                    )
                )
                continue
            # The decision comes before the detector is built, so a blocked or
            # undeclared plugin does not get to run its constructor.
            decision = self.policy.evaluate(manifest)
            decisions.append(decision)
            if not decision.allowed:
                rejections.append(
                    PluginRejection(
                        detector_id=manifest.detector_id,
                        entry_point=entry_point.value,
                        reason=decision.reason,
                    )
                )
                continue
            if self.isolation == PluginIsolation.SUBPROCESS:
                # Nothing is constructed in the host at all; the worker owns it.
                detectors.append(
                    IsolatedDetector(
                        entry_point=entry_point.value,
                        manifest=manifest,
                        decision=decision,
                        timeout=self.timeout,
                        search_path=self.search_path,
                        resource_limits=self.resource_limits,
                    )
                )
            else:
                try:
                    target = resolve_target(entry_point.value)
                    detector = instantiate(target)
                    runtime_manifest = enrich_manifest(manifest_for(target, detector), detector)
                    runtime_id = str(getattr(detector, "id", "unknown"))
                    if runtime_id != manifest.detector_id:
                        raise DetectorRegistrationError(
                            f"Inspected detector {manifest.detector_id!r} became {runtime_id!r}"
                        )
                    if runtime_manifest != manifest:
                        raise DetectorRegistrationError(
                            "The plugin manifest changed between inspection and construction"
                        )
                except Exception as exc:
                    rejections.append(
                        PluginRejection(
                            detector_id=manifest.detector_id,
                            entry_point=entry_point.value,
                            reason=(
                                f"The plugin could not be constructed: {type(exc).__name__}: {exc}"
                            ),
                        )
                    )
                    continue
                detectors.append(detector)
            manifests.append(manifest)
        return DiscoveryResult(
            detectors=tuple(detectors),
            manifests=tuple(manifests),
            decisions=tuple(decisions),
            rejections=tuple(rejections),
        )

    def _inspect(self, entry_point: EntryPoint) -> PluginManifest:
        """Inspect a plugin manifest without importing the module in this process."""

        workspace = Path(tempfile.mkdtemp(prefix="trueai-plugin-inspection-"))
        request_path = workspace / "request.json"
        response_path = workspace / "response.json"
        try:
            request = InspectionRequest(
                entry_point=entry_point.value,
                fallback_detector_id=entry_point.name,
                resource_limits=self.resource_limits,
            )
            request_path.write_text(request.model_dump_json(), encoding="utf-8")
            environment = dict(os.environ)
            if self.search_path:
                existing = environment.get("PYTHONPATH", "")
                entries = [*self.search_path, existing] if existing else list(self.search_path)
                environment["PYTHONPATH"] = os.pathsep.join(entries)
            try:
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "trueai.plugins.inspector",
                        str(request_path),
                        str(response_path),
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=self.timeout,
                    env=environment,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise DetectorRegistrationError(
                    f"Plugin manifest inspection exceeded {self.timeout:g} seconds"
                ) from exc
            if not response_path.is_file():
                raise DetectorRegistrationError(
                    f"Manifest inspector exited with {completed.returncode} without a response"
                )
            response = InspectionResponse.model_validate_json(
                _read_bounded(response_path, MAX_RESPONSE_BYTES)
            )
            if not response.ok or response.manifest is None:
                raise DetectorRegistrationError(
                    response.error_message or "Plugin manifest inspection failed"
                )
            manifest = PluginManifest.model_validate(response.manifest)
            if response.detector_id != manifest.detector_id:
                raise DetectorRegistrationError("Plugin manifest inspection identity mismatch")
            return manifest
        finally:
            for path in (request_path, response_path):
                with contextlib.suppress(OSError):
                    path.unlink(missing_ok=True)
            with contextlib.suppress(OSError):
                workspace.rmdir()
