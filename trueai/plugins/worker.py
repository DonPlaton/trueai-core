"""Worker process that runs exactly one third-party detector, once.

Invoked as ``python -m trueai.plugins.worker <request-file> <response-file>``.
The worker installs the guards implied by its granted capabilities before it
imports the plugin, runs the detector, and writes a JSON response. Import time is
when a hostile plugin would act, so guarding only the ``scan`` call would guard
the wrong moment. A plugin that legitimately needs a denied capability while
importing fails with a message naming that capability.

The worker never writes to stdout on the success path, so a plugin that prints
does not corrupt the protocol.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_RESPONSE_BYTES = 32 * 1024 * 1024

# Captured before any guard is installed. The filesystem guard replaces every
# open() spelling, including os.open, so the worker keeps its own references to
# write the response it owes the host.
_RAW_OPEN = os.open
_RAW_WRITE = os.write
_RAW_CLOSE = os.close


def _fail(response_path: Path, detector_id: str, code: str, message: str) -> int:
    from trueai.plugins.protocol import WorkerResponse

    response = WorkerResponse(
        detector_id=detector_id,
        ok=False,
        error_code=code,
        error_message=message[:4000],
    )
    _write(response_path, response)
    return 1


def _write(response_path: Path, response: Any) -> None:
    payload = response.model_dump_json()
    encoded = payload.encode("utf-8")
    if len(encoded) > MAX_RESPONSE_BYTES:
        from trueai.plugins.protocol import WorkerResponse

        encoded = (
            WorkerResponse(
                detector_id=response.detector_id,
                ok=False,
                error_code="response_too_large",
                error_message=(
                    f"The detector produced {len(encoded)} bytes, above the "
                    f"{MAX_RESPONSE_BYTES} byte worker limit."
                ),
            )
            .model_dump_json()
            .encode("utf-8")
        )
    # Written through the descriptor functions captured before the guards, because
    # the filesystem guard replaces every open() the plugin could reach.
    descriptor = _RAW_OPEN(str(response_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        remaining = memoryview(encoded)
        while remaining:
            written = _RAW_WRITE(descriptor, remaining)
            if written <= 0:
                raise OSError("Unable to write plugin response")
            remaining = remaining[written:]
    finally:
        _RAW_CLOSE(descriptor)


def main(argv: list[str]) -> int:
    """Run one detector against one artifact and write the response file."""

    if len(argv) != 2:
        print("usage: python -m trueai.plugins.worker <request> <response>", file=sys.stderr)
        return 2
    request_path, response_path = Path(argv[0]), Path(argv[1])

    from trueai.plugins.protocol import WorkerRequest, WorkerResponse

    try:
        if request_path.stat().st_size > MAX_REQUEST_BYTES:
            return _fail(response_path, "unknown", "request_too_large", "Request file too large.")
        request = WorkerRequest.model_validate_json(request_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return _fail(response_path, "unknown", "invalid_request", f"{type(exc).__name__}: {exc}")

    from trueai.core.artifact import Artifact
    from trueai.core.models import ScanContext
    from trueai.plugins.guards import apply_guards
    from trueai.plugins.loader import load_entry_point
    from trueai.plugins.resources import apply_process_resource_limits

    try:
        # Strictness travels with the budget rather than with the confinement
        # level. A limit the platform refuses is reported and not fatal unless
        # the budget says otherwise, because refusing to scan is a worse answer
        # than scanning with a CPU ceiling and saying the memory ceiling is
        # missing -- and macOS refuses `RLIMIT_AS` on every machine.
        resource_limits = apply_process_resource_limits(request.resource_limits)
    except Exception as exc:
        return _fail(
            response_path,
            request.detector_id,
            "plugin_resource_limits_unavailable",
            f"{type(exc).__name__}: {exc}",
        )

    from trueai.plugins.broker import CapabilityBroker
    from trueai.plugins.confinement import ConfinementUnavailableError, apply_confinement

    # Confinement comes first. Guards replace Python functions; this asks the
    # kernel, and asking after the plugin is imported would be asking too late.
    try:
        confinement = apply_confinement(
            request.grants,
            request.confinement,
            spawn_time_applied=request.spawn_time_confinement,
            # The response file is how the worker answers the host. A confinement
            # that makes it unwritable produces a crash report instead of a
            # verdict, which is worse than no confinement.
            writable_paths=(response_path.parent,),
        )
    except ConfinementUnavailableError as exc:
        return _fail(
            response_path,
            request.detector_id,
            "plugin_confinement_unavailable",
            f"{exc}. The host requires operating-system confinement, so the plugin was "
            "not imported.",
        )

    # Guards go up before the plugin is imported. Everything the plugin runs,
    # including module-level code and its constructor, is subject to them. The
    # scratch directory is passed through so a granted write_temporary stays
    # usable rather than being denied by the guard that protects everywhere else.
    scratch = request.grants.temporary_output
    apply_guards(
        frozenset(request.granted_capabilities),
        writable_root=scratch.directory if scratch is not None else None,
    )
    broker = CapabilityBroker(request.grants)

    try:
        detector = load_entry_point(request.entry_point)
    except Exception as exc:
        return _fail(
            response_path,
            request.detector_id,
            "plugin_load_failed",
            f"{type(exc).__name__}: {exc}",
        )

    # A plugin that wants mediated access declares bind_broker. Nothing is
    # forced on a plugin that does not: the broker is opt-in until PLUG-02 makes
    # ambient access impossible, and a detector that never asks for one behaves
    # exactly as it did before.
    binder = getattr(detector, "bind_broker", None)
    if callable(binder):
        try:
            binder(broker)
        except Exception as exc:
            return _fail(
                response_path,
                request.detector_id,
                "plugin_broker_rejected",
                f"{type(exc).__name__}: {exc}",
            )

    detector_id = getattr(detector, "id", request.detector_id)
    if detector_id != request.detector_id:
        return _fail(
            response_path,
            request.detector_id,
            "detector_identity_mismatch",
            f"The entry point produced detector {detector_id!r}.",
        )

    artifact = Artifact(
        artifact_type=request.artifact.artifact_type,
        path=Path(request.artifact.path),
        logical_path=request.artifact.logical_path,
        size=request.artifact.size,
        media_type=request.artifact.media_type,
    )
    context = ScanContext(
        options=request.options,
        root=Path(request.root) if request.root else None,
    )

    try:
        findings = detector.scan(artifact, context)
    except Exception as exc:
        return _fail(
            response_path,
            request.detector_id,
            "plugin_failed",
            f"{type(exc).__name__}: {exc}",
        )

    try:
        serialized = [finding.model_dump(mode="json") for finding in findings]
    except Exception as exc:
        return _fail(
            response_path,
            request.detector_id,
            "plugin_output_invalid",
            f"{type(exc).__name__}: {exc}",
        )

    _write(
        response_path,
        WorkerResponse(
            detector_id=request.detector_id,
            ok=True,
            findings=serialized,
            confinement=confinement,
            resource_limits=resource_limits,
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
