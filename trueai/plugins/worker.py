"""Worker process that runs exactly one third-party detector, once.

Invoked as ``python -m trueai.plugins.worker <request-file> <response-file>``.
The worker installs the guards implied by its granted capabilities *before* it
imports the plugin, runs the detector, and writes a JSON response. It never
writes to stdout on the success path, so a plugin that prints does not corrupt
the protocol.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_RESPONSE_BYTES = 32 * 1024 * 1024


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
    # Written with the raw descriptor because the filesystem guard replaces open().
    import os

    descriptor = os.open(str(response_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(descriptor, encoded)
    finally:
        os.close(descriptor)


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

    try:
        detector = load_entry_point(request.entry_point)
    except Exception as exc:
        return _fail(
            response_path,
            request.detector_id,
            "plugin_load_failed",
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

    # Guards are installed after the plugin is imported but before it runs, so a
    # plugin cannot use import time to escape them and cannot be blocked from
    # legitimately importing its own dependencies.
    apply_guards(frozenset(request.granted_capabilities))

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
        WorkerResponse(detector_id=request.detector_id, ok=True, findings=serialized),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
