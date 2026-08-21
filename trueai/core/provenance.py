"""Shared fail-safe recognition of provenance markers in removable containers."""

from __future__ import annotations

PROTECTED_PROVENANCE_MARKERS = (
    b"c2pa",
    b"content credentials",
    b"application/c2pa",
    b"c2pa_manifest",
)


def contains_protected_provenance_marker(value: object) -> bool:
    """Return whether a value contains a marker that built-in cleaners must preserve."""

    if isinstance(value, bytes):
        lowered = value.lower()
    else:
        lowered = str(value).casefold().encode("utf-8", errors="replace")
    return any(marker in lowered for marker in PROTECTED_PROVENANCE_MARKERS)
