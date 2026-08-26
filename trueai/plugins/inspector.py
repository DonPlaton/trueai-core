"""Capability-guarded helper that inspects one plugin manifest.

Discovery must not import third-party modules in the scanner process merely to
learn whether policy permits them. This helper installs the deny-by-default
guards first, imports the entry point, derives its manifest, and returns only a
bounded JSON document. It is containment, not an operating-system sandbox.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 256 * 1024

_RAW_OPEN = os.open
_RAW_WRITE = os.write
_RAW_CLOSE = os.close


def _write(response_path: Path, response: Any) -> None:
    from trueai.plugins.protocol import InspectionResponse

    encoded = response.model_dump_json().encode("utf-8")
    if len(encoded) > MAX_RESPONSE_BYTES:
        encoded = (
            InspectionResponse(
                detector_id=response.detector_id,
                ok=False,
                error_code="inspection_response_too_large",
                error_message="The plugin manifest exceeded the inspection response limit.",
            )
            .model_dump_json()
            .encode("utf-8")
        )
    descriptor = _RAW_OPEN(str(response_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        remaining = memoryview(encoded)
        while remaining:
            written = _RAW_WRITE(descriptor, remaining)
            if written <= 0:
                raise OSError("Unable to write plugin inspection response")
            remaining = remaining[written:]
    finally:
        _RAW_CLOSE(descriptor)


def main(argv: list[str]) -> int:
    """Inspect one entry point after installing deny-by-default guards."""

    if len(argv) != 2:
        return 2
    request_path, response_path = Path(argv[0]), Path(argv[1])

    from trueai.plugins.protocol import InspectionRequest, InspectionResponse

    try:
        if request_path.stat().st_size > MAX_REQUEST_BYTES:
            raise ValueError("Inspection request is too large")
        request = InspectionRequest.model_validate_json(request_path.read_text(encoding="utf-8"))
    except Exception as exc:
        _write(
            response_path,
            InspectionResponse(
                detector_id="unknown",
                ok=False,
                error_code="invalid_inspection_request",
                error_message=f"{type(exc).__name__}: {exc}"[:4000],
            ),
        )
        return 1

    from trueai.plugins.guards import apply_guards
    from trueai.plugins.resources import apply_process_resource_limits

    try:
        resource_limits = apply_process_resource_limits(request.resource_limits)
    except Exception as exc:
        _write(
            response_path,
            InspectionResponse(
                detector_id=request.fallback_detector_id,
                ok=False,
                error_code="plugin_resource_limits_unavailable",
                error_message=f"{type(exc).__name__}: {exc}"[:4000],
            ),
        )
        return 1

    # Manifest discovery gets no artifact, workspace, mutation, network, or process
    # capability. A plugin must keep module import and manifest declaration inert.
    apply_guards(frozenset())

    try:
        from trueai.plugins.loader import describe_target, enrich_manifest, resolve_target

        target = resolve_target(request.entry_point)
        manifest, prebuilt = describe_target(target)
        source = prebuilt if prebuilt is not None else target
        manifest = enrich_manifest(manifest, source)
        response = InspectionResponse(
            detector_id=manifest.detector_id,
            ok=True,
            manifest=manifest.model_dump(mode="json"),
            resource_limits=resource_limits,
        )
    except Exception as exc:
        response = InspectionResponse(
            detector_id=request.fallback_detector_id,
            ok=False,
            error_code="plugin_inspection_failed",
            error_message=f"{type(exc).__name__}: {exc}"[:4000],
            resource_limits=resource_limits,
        )
    _write(response_path, response)
    return 0 if response.ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
