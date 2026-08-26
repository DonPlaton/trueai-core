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

**Bounded, and evicted in a defined order.** An unbounded cache beside a
repository is a disk-space bug waiting for a large enough checkout. Eviction is
deterministic in the sense that matters: given the same inventory, the same
budget, and the same set of keys used in this run, the same entries are removed —
never a filesystem-dependent ordering, never a timestamp whose resolution differs
between platforms. The order is:

1. entries written under a different package, schema, or cache format version.
   Their key can never be produced again, so they are unreachable by
   construction and evicting anything else first would be strictly worse;
2. entries not used in this run, oldest generation first, then by key;
3. entries used in this run, oldest generation first, then by key.

A *generation* is one scan: an instance takes a number when it first writes, and
stamps every entry it writes with it. That costs one small read and one small
write per scan rather than one per entry, and it makes "which entries are older"
a property of recorded data rather than of file timestamps.

**Pruning only removes what this cache wrote.** A path is deleted only when it
sits at the exact shard-and-key location an entry would occupy, no component of
its path is a link, and it parses as an entry. A file that arrived some other way
is reported, never deleted, because a cache directory is not a place to be
confident about what is safe to remove.
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

#: Default ceiling for one cache directory. Chosen to hold a large repository's
#: results without becoming a surprise beside a checkout; override per instance.
DEFAULT_MAX_CACHE_BYTES = 256 * 1024 * 1024

#: Where the per-directory generation counter lives.
SEQUENCE_FILENAME = ".generation"

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
class CacheEntry:
    """One stored result, as the cache directory holds it."""

    key: str
    path: Path
    size_bytes: int
    generation: int
    package_version: str
    schema_version: str
    format_version: str

    def reachable(self) -> bool:
        """Whether a running scan could ever produce this entry's key again.

        The versions are part of the key, so an entry written by another build is
        not merely stale — it is unreachable, and holding it costs space that can
        never be repaid.
        """

        return (
            self.package_version == PACKAGE_VERSION
            and self.schema_version == SCHEMA_VERSION
            and self.format_version == CACHE_FORMAT_VERSION
        )


@dataclass(frozen=True, slots=True)
class CacheInventory:
    """What a cache directory actually contains, including what it should not."""

    entries: tuple[CacheEntry, ...] = ()
    #: Files at an entry location that could not be parsed as one.
    damaged: tuple[str, ...] = ()
    #: Files under the cache directory that this cache did not write. Reported
    #: rather than removed: a cache directory is not a place to be confident
    #: about what is safe to delete.
    foreign: tuple[str, ...] = ()

    @property
    def total_bytes(self) -> int:
        return sum(entry.size_bytes for entry in self.entries)

    @property
    def unreachable(self) -> tuple[CacheEntry, ...]:
        """Entries no running scan can hit, because the versions moved on."""

        return tuple(entry for entry in self.entries if not entry.reachable())

    def generations(self) -> tuple[int, ...]:
        return tuple(sorted({entry.generation for entry in self.entries}))

    def explain(self) -> str:
        megabytes = self.total_bytes / (1024 * 1024)
        parts = [f"{len(self.entries)} entries, {megabytes:.1f} MB"]
        if self.unreachable:
            parts.append(f"{len(self.unreachable)} unreachable (older build)")
        if self.damaged:
            parts.append(f"{len(self.damaged)} damaged")
        if self.foreign:
            parts.append(f"{len(self.foreign)} unrecognised files (not removed)")
        return "; ".join(parts)


@dataclass(frozen=True, slots=True)
class PruneResult:
    """What a prune removed, and what it left behind on purpose."""

    removed: tuple[str, ...] = ()
    bytes_reclaimed: int = 0
    #: Paths a prune declined to touch, with the reason.
    refused: tuple[tuple[str, str], ...] = ()
    remaining_bytes: int = 0

    def explain(self) -> str:
        megabytes = self.bytes_reclaimed / (1024 * 1024)
        note = f"; refused {len(self.refused)}" if self.refused else ""
        return f"Removed {len(self.removed)} entries, {megabytes:.1f} MB reclaimed{note}."


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
    #: Entries removed to keep the directory inside its budget.
    evictions: int = 0

    @property
    def lookups(self) -> int:
        return self.hits + self.misses + self.rejections

    @property
    def hit_rate(self) -> float:
        """Hits as a fraction of lookups; 0.0 when nothing was looked up."""

        return self.hits / self.lookups if self.lookups else 0.0

    def explain(self) -> str:
        note = f" {self.rejections} unusable entries." if self.rejections else ""
        # Reported even when nothing was looked up: a run that only wrote and
        # then evicted still did something an operator should be able to see.
        evicted = f" {self.evictions} evicted." if self.evictions else ""
        if not self.lookups:
            return f"No cache lookups.{note}{evicted}"
        return (
            f"{self.hits}/{self.lookups} lookups hit ({self.hit_rate:.1%}); "
            f"{self.stores} stored.{note}{evicted}"
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

    def __init__(self, directory: Path, *, max_bytes: int = DEFAULT_MAX_CACHE_BYTES) -> None:
        if max_bytes < MAX_ENTRY_BYTES:
            raise ValueError(
                f"A cache budget below one entry ({MAX_ENTRY_BYTES} bytes) could never "
                "hold anything"
            )
        self.directory = Path(directory)
        self.max_bytes = max_bytes
        self._generation: int | None = None
        self._used: set[str] = set()
        self._hits = 0
        self._misses = 0
        self._rejections = 0
        self._stores = 0
        self._store_failures = 0
        self._evictions = 0

    def statistics(self) -> CacheStatistics:
        """Return a snapshot of what this instance has done so far."""

        return CacheStatistics(
            hits=self._hits,
            misses=self._misses,
            rejections=self._rejections,
            stores=self._stores,
            store_failures=self._store_failures,
            evictions=self._evictions,
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
        # Recorded so eviction can prefer entries this run never touched. Kept in
        # memory rather than written back, because one write per hit would cost
        # about what a miss costs and undo the point of the cache.
        self._used.add(key)
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
                "generation": self.generation(),
                "package_version": PACKAGE_VERSION,
                "schema_version": SCHEMA_VERSION,
                "format_version": CACHE_FORMAT_VERSION,
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

    # -- generation ------------------------------------------------------------------

    def generation(self) -> int:
        """Return this instance's generation, taking the next one on first use.

        One number per scan rather than one per entry: the counter is read and
        advanced once, and every entry this instance writes carries it. That
        makes "which entries are older" a property of recorded data rather than
        of file timestamps, whose resolution differs between platforms and whose
        ordering a copy or a restore can destroy.
        """

        if self._generation is None:
            self._generation = self._advance_sequence()
        return self._generation

    def _sequence_path(self) -> Path | None:
        if self._contains_link(self.directory):
            return None
        candidate = self.directory / SEQUENCE_FILENAME
        return None if candidate.exists() and self._is_link(candidate) else candidate

    def _advance_sequence(self) -> int:
        """Read the stored counter, advance it, and persist the new value."""

        path = self._sequence_path()
        if path is None:
            return 0
        current = 0
        try:
            raw = path.read_text(encoding="ascii").strip()
            current = int(raw) if raw.isdigit() else 0
        except (OSError, ValueError):
            current = 0
        following = current + 1
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(str(following), encoding="ascii")
        except OSError:
            # A cache that cannot record its counter still works; every entry
            # simply shares a generation and eviction falls back to key order.
            return current
        return following

    # -- inspection ------------------------------------------------------------------

    def inspect(self) -> CacheInventory:
        """Return everything in the cache directory, entries and intruders alike."""

        if not self.directory.is_dir() or self._contains_link(self.directory):
            return CacheInventory()
        entries: list[CacheEntry] = []
        damaged: list[str] = []
        foreign: list[str] = []
        for candidate in sorted(self.directory.rglob("*")):
            if candidate.is_dir():
                continue
            relative = candidate.relative_to(self.directory).as_posix()
            if relative == SEQUENCE_FILENAME:
                continue
            key = self._key_at(candidate)
            if key is None:
                foreign.append(relative)
                continue
            entry = self._read_entry(key, candidate)
            if entry is None:
                damaged.append(relative)
            else:
                entries.append(entry)
        return CacheInventory(
            entries=tuple(sorted(entries, key=lambda item: (item.generation, item.key))),
            damaged=tuple(damaged),
            foreign=tuple(foreign),
        )

    def _key_at(self, candidate: Path) -> str | None:
        """Return the key a path would hold, or None if it is not an entry slot."""

        try:
            relative = candidate.relative_to(self.directory)
        except ValueError:
            return None
        if len(relative.parts) != 2 or not relative.name.endswith(".json"):
            return None
        shard, name = relative.parts[0], relative.name[: -len(".json")]
        if _CACHE_KEY.fullmatch(name) is None or shard != name[:2]:
            return None
        return name

    def _read_entry(self, key: str, candidate: Path) -> CacheEntry | None:
        try:
            size = candidate.stat().st_size
            if size > MAX_ENTRY_BYTES:
                return None
            raw: Any = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(raw, dict) or raw.get("key") != key:
            return None
        generation = raw.get("generation")
        return CacheEntry(
            key=key,
            path=candidate,
            size_bytes=size,
            generation=generation if isinstance(generation, int) and generation >= 0 else 0,
            package_version=str(raw.get("package_version", "")),
            schema_version=str(raw.get("schema_version", "")),
            format_version=str(raw.get("format_version", "")),
        )

    # -- eviction --------------------------------------------------------------------

    def stored_bytes(self) -> int:
        """Return the directory's size without parsing anything.

        The budget check runs after every scan, and at a hundred thousand entries
        parsing each one to add up sizes would cost more than the cache saves.
        """

        if not self.directory.is_dir() or self._contains_link(self.directory):
            return 0
        total = 0
        for candidate in self.directory.rglob("*.json"):
            try:
                total += candidate.stat().st_size
            except OSError:
                continue
        return total

    def eviction_order(self, inventory: CacheInventory | None = None) -> tuple[CacheEntry, ...]:
        """Return entries in the order they would be evicted.

        Exposed rather than kept private because "which entries would go" is a
        question an operator should be able to ask before, not after.
        """

        held = inventory if inventory is not None else self.inspect()

        def rank(entry: CacheEntry) -> tuple[int, int, int, str]:
            unreachable = 0 if not entry.reachable() else 1
            untouched = 0 if entry.key not in self._used else 1
            return (unreachable, untouched, entry.generation, entry.key)

        return tuple(sorted(held.entries, key=rank))

    def enforce_budget(self) -> PruneResult:
        """Evict, in the defined order, until the directory fits its budget."""

        cheap_total = self.stored_bytes()
        if cheap_total <= self.max_bytes:
            return PruneResult(remaining_bytes=cheap_total)
        inventory = self.inspect()
        total = inventory.total_bytes
        if total <= self.max_bytes:
            return PruneResult(remaining_bytes=total)
        victims: list[CacheEntry] = []
        for entry in self.eviction_order(inventory):
            if total <= self.max_bytes:
                break
            victims.append(entry)
            total -= entry.size_bytes
        return self._remove(victims, remaining=total)

    # -- pruning ---------------------------------------------------------------------

    def prune(
        self,
        *,
        unreachable_only: bool = False,
        older_than_generation: int | None = None,
        to_fit: int | None = None,
    ) -> PruneResult:
        """Remove entries under an explicit rule, and report what was refused.

        No rule at all removes nothing. A prune that defaulted to deleting
        everything would make a mistyped command destructive, and the cache is
        the one place where a wrong deletion is silent: the next scan is merely
        slower, so nobody notices what went missing.
        """

        inventory = self.inspect()
        selected: list[CacheEntry] = []
        if unreachable_only:
            selected.extend(inventory.unreachable)
        if older_than_generation is not None:
            selected.extend(
                entry for entry in inventory.entries if entry.generation < older_than_generation
            )
        chosen = {entry.key: entry for entry in selected}
        total = inventory.total_bytes - sum(entry.size_bytes for entry in chosen.values())
        if to_fit is not None:
            for entry in self.eviction_order(inventory):
                if total <= to_fit:
                    break
                if entry.key in chosen:
                    continue
                chosen[entry.key] = entry
                total -= entry.size_bytes
        return self._remove(list(chosen.values()), remaining=total)

    def _remove(self, victims: list[CacheEntry], *, remaining: int) -> PruneResult:
        """Delete chosen entries, refusing anything whose path stopped matching."""

        removed: list[str] = []
        refused: list[tuple[str, str]] = []
        reclaimed = 0
        for entry in sorted(victims, key=lambda item: item.key):
            relative = entry.path.relative_to(self.directory).as_posix()
            # Re-checked at deletion time, not only at inspection time: a link
            # could have been placed in between, and a delete that follows one
            # leaves the cache directory entirely.
            if self._safe_entry_path(entry.key) is None or self._is_link(entry.path):
                refused.append((relative, "the path is a link or is outside the cache"))
                continue
            try:
                entry.path.unlink()
            except OSError as exc:
                refused.append((relative, str(exc)))
                continue
            removed.append(relative)
            reclaimed += entry.size_bytes
            self._evictions += 1
        return PruneResult(
            removed=tuple(removed),
            bytes_reclaimed=reclaimed,
            refused=tuple(refused),
            remaining_bytes=max(0, remaining),
        )

    def clear(self) -> int:
        """Delete every cache entry and return how many were removed.

        Every *entry*, not every file. `prune` re-derives the key from the path
        before deleting anything, and refuses what does not resolve to a slot
        this cache writes; `clear` walked `*.json` and unlinked whatever it
        found. An operator may point `--cache-dir` at a directory the cache does
        not own, and deleting a stranger's file there is not something a scanner
        should do quietly.
        """

        removed = 0
        if not self.directory.is_dir() or self._contains_link(self.directory):
            return 0
        for candidate in sorted(self.directory.rglob("*.json")):
            if self._key_at(candidate) is None or self._is_link(candidate):
                continue
            try:
                candidate.unlink()
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
