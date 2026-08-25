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


@dataclass(frozen=True, slots=True)
class CacheStatistics:
    """What one cache instance did during one scan.

    ``misses`` and ``rejections`` are counted apart on purpose. A miss means the
    bytes were never scanned under this key. A rejection means an entry was
    there and could not be used — truncated, corrupt, oversized, or written by a
    different version. Both make the scan slower, but only the second says the
    cache directory itself is unhealthy, and a single "hit rate" hides that.
    """

    hits: int = 0
    misses: int = 0
    rejections: int = 0
    stores: int = 0
    store_failures: int = 0

    @property
    def lookups(self) -> int:
        return self.hits + self.misses + self.rejections

    @property
    def hit_rate(self) -> float:
        """Hits as a fraction of lookups; 0.0 when nothing was looked up."""

        return self.hits / self.lookups if self.lookups else 0.0

    def explain(self) -> str:
        if not self.lookups:
            return "No cache lookups."
        note = f" {self.rejections} unusable entries." if self.rejections else ""
        return (
            f"{self.hits}/{self.lookups} lookups hit ({self.hit_rate:.1%}); "
            f"{self.stores} stored.{note}"
        )


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
        self._hits = 0
        self._misses = 0
        self._rejections = 0
        self._stores = 0
        self._store_failures = 0

    def statistics(self) -> CacheStatistics:
        """Return a snapshot of what this instance has done so far."""

        return CacheStatistics(
            hits=self._hits,
            misses=self._misses,
            rejections=self._rejections,
            stores=self._stores,
            store_failures=self._store_failures,
        )

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
        """Return a previously stored result, or ``None`` for any miss or damage.

        Every ``None`` is counted as either a miss or a rejection, because "the
        cache did not help" and "the cache is damaged" are different operational
        facts and a bare hit rate cannot tell them apart.
        """

        path = self._safe_entry_path(key)
        if path is None:
            # An unresolvable path is a refusal to follow a link, not a
            # cold key: something is wrong with the directory.
            self._rejections += 1
            return None
        try:
            if path.stat().st_size > MAX_ENTRY_BYTES:
                self._rejections += 1
                return None
            with path.open("rb") as handle:
                encoded = handle.read(MAX_ENTRY_BYTES + 1)
            if len(encoded) > MAX_ENTRY_BYTES:
                self._rejections += 1
                return None
            raw: Any = json.loads(encoded.decode("utf-8"))
        except FileNotFoundError:
            self._misses += 1
            return None
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            self._rejections += 1
            return None
        if not isinstance(raw, dict) or raw.get("key") != key:
            self._rejections += 1
            return None
        try:
            findings = tuple(Finding.model_validate(item) for item in raw.get("findings", []))
            diagnostics = tuple(
                ScanDiagnostic.model_validate(item) for item in raw.get("diagnostics", [])
            )
        except (ValidationError, TypeError):
            self._rejections += 1
            return None
        detectors = raw.get("detectors_run", [])
        if not isinstance(detectors, list):
            self._rejections += 1
            return None
        self._hits += 1
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
            self._store_failures += 1
            return
        path = self._safe_entry_path(key, create_parent=True)
        if path is None:
            self._store_failures += 1
            return
        try:
            descriptor, temporary_name = tempfile.mkstemp(prefix=".trueai-cache-", dir=path.parent)
            temporary = Path(temporary_name)
            try:
                with open(descriptor, "wb") as handle:
                    handle.write(encoded)
                temporary.replace(path)
                self._stores += 1
            except OSError:
                temporary.unlink(missing_ok=True)
                self._store_failures += 1
        except OSError:
            self._store_failures += 1
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
