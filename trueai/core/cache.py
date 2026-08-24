"""Content-addressed cache of per-artifact detector output.

Re-scanning a repository is dominated by files that did not change since the last
run. Caching by content hash rather than by path and mtime means the cache is
correct across checkouts, branch switches, and copies: the same bytes scanned with
the same detectors and the same limits always produce the same findings, so the
stored result is reusable and a changed byte can never return a stale one.

Anything that could change detector output is part of the key: the content digest,
the artifact's logical path (finding identities are path-derived), the artifact
type, the enabled detector set, the resource limits, and the package and schema
versions. A key mismatch is a miss, never a partial reuse.

The cache is local-only. Nothing is uploaded, and a corrupt or unreadable entry is
treated as a miss rather than an error, so a damaged cache degrades to a slow scan
instead of a failed one.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from trueai._version import PACKAGE_VERSION, SCHEMA_VERSION
from trueai.core.models import ArtifactType, Finding, ScanDiagnostic, ScanOptions

#: Bumped whenever the stored payload shape changes, so old entries miss instead
#: of being misread.
CACHE_FORMAT_VERSION = "1"

#: Entries larger than this are not written. A pathological artifact should not
#: be able to fill the cache directory.
MAX_ENTRY_BYTES = 4 * 1024 * 1024
_CACHE_KEY = re.compile(r"[0-9a-f]{64}\Z")

#: Option fields that do not change what a detector observes about one artifact.
_NON_KEY_OPTIONS = frozenset({"max_files", "max_workers", "cache_directory"})


@dataclass(frozen=True, slots=True)
class CachedArtifactResult:
    """Detector output for one artifact, reusable while its key still matches."""

    findings: tuple[Finding, ...]
    diagnostics: tuple[ScanDiagnostic, ...]
    detectors_run: tuple[str, ...]


def options_fingerprint(options: ScanOptions) -> str:
    """Return a stable digest of every option that can change detector output."""

    payload = options.model_dump(mode="json")
    for field in _NON_KEY_OPTIONS:
        payload.pop(field, None)
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=True, default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class ScanCache:
    """Filesystem-backed store keyed by artifact content and scan configuration."""

    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory)

    def key(
        self,
        *,
        content_sha256: str,
        logical_path: str,
        artifact_type: ArtifactType,
        detector_ids: tuple[str, ...],
        options_digest: str,
    ) -> str:
        """Build the content-addressed key for one artifact under one configuration."""

        identity = "\x00".join(
            (
                CACHE_FORMAT_VERSION,
                PACKAGE_VERSION,
                SCHEMA_VERSION,
                content_sha256,
                logical_path,
                artifact_type.value,
                ",".join(sorted(detector_ids)),
                options_digest,
            )
        )
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()

    def load(self, key: str) -> CachedArtifactResult | None:
        """Return a previously stored result, or ``None`` for any miss or damage."""

        path = self._safe_entry_path(key)
        if path is None:
            return None
        try:
            if path.stat().st_size > MAX_ENTRY_BYTES:
                return None
            with path.open("rb") as handle:
                encoded = handle.read(MAX_ENTRY_BYTES + 1)
            if len(encoded) > MAX_ENTRY_BYTES:
                return None
            raw: Any = json.loads(encoded.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(raw, dict) or raw.get("key") != key:
            return None
        try:
            findings = tuple(Finding.model_validate(item) for item in raw.get("findings", []))
            diagnostics = tuple(
                ScanDiagnostic.model_validate(item) for item in raw.get("diagnostics", [])
            )
        except (ValidationError, TypeError):
            return None
        detectors = raw.get("detectors_run", [])
        if not isinstance(detectors, list):
            return None
        return CachedArtifactResult(
            findings=findings,
            diagnostics=diagnostics,
            detectors_run=tuple(str(item) for item in detectors),
        )

    def store(self, key: str, result: CachedArtifactResult) -> None:
        """Write a result atomically, ignoring any filesystem failure."""

        payload = json.dumps(
            {
                "key": key,
                "findings": [finding.model_dump(mode="json") for finding in result.findings],
                "diagnostics": [
                    diagnostic.model_dump(mode="json") for diagnostic in result.diagnostics
                ],
                "detectors_run": list(result.detectors_run),
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
        encoded = payload.encode("utf-8")
        if len(encoded) > MAX_ENTRY_BYTES:
            return
        path = self._safe_entry_path(key, create_parent=True)
        if path is None:
            return
        try:
            descriptor, temporary_name = tempfile.mkstemp(prefix=".trueai-cache-", dir=path.parent)
            temporary = Path(temporary_name)
            try:
                with open(descriptor, "wb") as handle:
                    handle.write(encoded)
                temporary.replace(path)
            except OSError:
                temporary.unlink(missing_ok=True)
        except OSError:
            return

    def clear(self) -> int:
        """Delete every cache entry and return how many were removed."""

        removed = 0
        if not self.directory.is_dir() or self._contains_link(self.directory):
            return 0
        for entry in sorted(self.directory.rglob("*.json")):
            try:
                entry.unlink()
                removed += 1
            except OSError:
                continue
        return removed

    def _entry_path(self, key: str) -> Path:
        return self.directory / key[:2] / f"{key}.json"

    def _safe_entry_path(self, key: str, *, create_parent: bool = False) -> Path | None:
        """Resolve one cache entry without following attacker-controlled links.

        Cache contents are untrusted local state. A checkout may already contain a
        ``.trueai/cache`` symlink, or a hostile process may place a link at a hash
        prefix. In either case caching degrades to a miss instead of redirecting a
        scanner write outside the configured cache tree.
        """

        if _CACHE_KEY.fullmatch(key) is None or self._contains_link(self.directory):
            return None
        entry = self._entry_path(key)
        try:
            if create_parent:
                entry.parent.mkdir(parents=True, exist_ok=True)
            if self._contains_link(entry.parent):
                return None
            root = self.directory.resolve(strict=create_parent)
            parent = entry.parent.resolve(strict=create_parent)
            parent.relative_to(root)
            if entry.exists() and self._is_link(entry):
                return None
        except (OSError, ValueError):
            return None
        return entry

    @classmethod
    def _contains_link(cls, path: Path) -> bool:
        """Return whether any existing component is a symlink or junction."""

        absolute = Path(os.path.abspath(path))
        current = Path(absolute.anchor)
        for part in absolute.parts[1:]:
            current /= part
            try:
                if current.exists() and cls._is_link(current):
                    return True
            except OSError:
                return True
        return False

    @staticmethod
    def _is_link(path: Path) -> bool:
        junction = getattr(path, "is_junction", None)
        return path.is_symlink() or bool(junction is not None and junction())
