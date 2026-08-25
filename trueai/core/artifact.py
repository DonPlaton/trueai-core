"""Safe artifact identification, bounded reads, and recursive discovery."""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from pathspec import GitIgnoreSpec

from trueai.core.errors import (
    ArtifactNotFoundError,
    ArtifactTooLargeError,
    CorruptArtifactError,
    UnsafeArtifactError,
)
from trueai.core.models import ArtifactType

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_JPEG_SIGNATURE = b"\xff\xd8\xff"
_PDF_SIGNATURE = b"%PDF-"
_FLAC_SIGNATURE = b"fLaC"
_EBML_SIGNATURE = b"\x1aE\xdf\xa3"
_ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")

_ISO_AUDIO_BRANDS = frozenset(
    {
        b"M4A ",
        b"M4B ",
        b"M4P ",
        b"F4A ",
        b"F4B ",
    }
)

# Office Open XML packages share one container format and one safety layer. The
# family is decided by the part that must exist in a valid package, not by the
# file name, because an extension is attacker-controlled.
_OOXML_MARKERS: tuple[tuple[bytes, ArtifactType, str], ...] = (
    (
        b"word/document.xml",
        ArtifactType.DOCX,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ),
    (
        b"ppt/presentation.xml",
        ArtifactType.PPTX,
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ),
    (
        b"xl/workbook.xml",
        ArtifactType.XLSX,
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ),
)
_OOXML_CONTENT_TYPES_PART = b"[Content_Types].xml"

# OpenDocument packages declare their own type in an uncompressed `mimetype`
# entry that the specification requires to come first. Reading it is how the
# family is decided; the file name is attacker-controlled.
_ODF_MIMETYPE_PREFIX = b"application/vnd.oasis.opendocument."
_ODF_MARKER = b"mimetype"
_ODF_SUFFIXES = frozenset({".odt", ".ods", ".odp", ".odg", ".odf", ".ott", ".ots", ".otp"})

# Compound File Binary header. Legacy Word, Excel, and PowerPoint all start with
# it, as do a few unrelated formats, so the signature identifies the container
# rather than the application.
_CFB_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_LEGACY_OFFICE_SUFFIXES = frozenset({".doc", ".xls", ".ppt", ".dot", ".xlt", ".pot"})
_OOXML_BY_SUFFIX: dict[str, tuple[ArtifactType, str]] = {
    ".docx": (ArtifactType.DOCX, _OOXML_MARKERS[0][2]),
    ".docm": (ArtifactType.DOCX, "application/vnd.ms-word.document.macroEnabled.12"),
    ".dotx": (
        ArtifactType.DOCX,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
    ),
    ".pptx": (ArtifactType.PPTX, _OOXML_MARKERS[1][2]),
    ".pptm": (ArtifactType.PPTX, "application/vnd.ms-powerpoint.presentation.macroEnabled.12"),
    ".potx": (
        ArtifactType.PPTX,
        "application/vnd.openxmlformats-officedocument.presentationml.template",
    ),
    ".xlsx": (ArtifactType.XLSX, _OOXML_MARKERS[2][2]),
    ".xlsm": (ArtifactType.XLSX, "application/vnd.ms-excel.sheet.macroEnabled.12"),
    ".xltx": (
        ArtifactType.XLSX,
        "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
    ),
}

_MARKDOWN_EXTENSIONS = {".md", ".markdown", ".mdx", ".rst"}
_CODE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".cu",
    ".go",
    ".h",
    ".hpp",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".lua",
    ".php",
    ".py",
    ".r",
    ".rb",
    ".rs",
    ".scala",
    ".sh",
    ".sql",
    ".swift",
    ".ts",
    ".tsx",
    ".v",
    ".vhd",
    ".vhdl",
    ".yaml",
    ".yml",
    ".toml",
    ".json",
}
_TEXT_EXTENSIONS = {".txt", ".csv", ".log", ".ini", ".cfg", ".conf"}


@dataclass(frozen=True, slots=True)
class Artifact:
    """A file, directory, repository, or in-memory text stream."""

    artifact_type: ArtifactType
    path: Path | None = None
    logical_path: str | None = None
    size: int | None = None
    media_type: str | None = None
    text_content: str | None = None

    @property
    def display_path(self) -> str:
        """Return a stable user-facing path."""

        if self.logical_path is not None:
            return self.logical_path
        if self.path is not None:
            return str(self.path)
        return "<text-stream>"

    @classmethod
    def from_text(cls, text: str, name: str = "<text-stream>") -> Artifact:
        """Construct an in-memory text artifact."""

        return cls(
            artifact_type=ArtifactType.TEXT,
            logical_path=name,
            size=len(text.encode("utf-8")),
            media_type="text/plain",
            text_content=text,
        )

    def read_bytes(self, limit: int) -> bytes:
        """Read at most ``limit`` bytes, raising instead of truncating silently."""

        if self.text_content is not None:
            data = self.text_content.encode("utf-8")
            if len(data) > limit:
                raise ArtifactTooLargeError(f"{self.display_path} exceeds {limit} bytes")
            return data
        if self.path is None or not self.path.is_file():
            raise ArtifactNotFoundError(f"No readable file for {self.display_path}")
        file_size = self.path.stat().st_size
        if file_size > limit:
            raise ArtifactTooLargeError(
                f"{self.display_path} is {file_size} bytes; limit is {limit}"
            )
        return self.path.read_bytes()

    def read_text(self, limit: int) -> str:
        """Decode a bounded textual artifact exactly, or refuse to guess.

        Substituting replacement characters would make every offset a detector
        reports refer to a string the cleaner can never reconstruct, so a span
        approved for removal would cut the wrong bytes. An artifact that cannot
        be decoded exactly is reported as corrupt instead, which fails the scan
        closed and blocks remediation rather than silently mis-editing a file.
        """

        if self.text_content is not None:
            if len(self.text_content.encode("utf-8")) > limit:
                raise ArtifactTooLargeError(f"{self.display_path} exceeds {limit} bytes")
            return self.text_content
        data = self.read_bytes(limit)
        encoding = "utf-16" if data.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8"
        try:
            return data.decode(encoding)
        except UnicodeDecodeError as exc:
            raise CorruptArtifactError(
                f"{self.display_path} is not valid {encoding}: {exc}"
            ) from exc

    def sha256(self, limit: int) -> str | None:
        """Hash file or stream content within the configured boundary."""

        if self.artifact_type in {ArtifactType.DIRECTORY, ArtifactType.GIT_REPOSITORY}:
            return None
        if self.text_content is not None:
            return hashlib.sha256(self.read_bytes(limit)).hexdigest()
        if self.path is None or not self.path.is_file():
            raise ArtifactNotFoundError(f"No readable file for {self.display_path}")
        file_size = self.path.stat().st_size
        if file_size > limit:
            raise ArtifactTooLargeError(
                f"{self.display_path} is {file_size} bytes; limit is {limit}"
            )
        digest = hashlib.sha256()
        with self.path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class DiscoveryOptions:
    """Filesystem traversal boundaries."""

    max_file_size: int = 25 * 1024 * 1024
    max_files: int = 100_000
    follow_symlinks: bool = False


@dataclass(frozen=True, slots=True)
class DiscoveryIssue:
    """A path that could not be safely included in recursive discovery."""

    path: str
    message: str


#: Applied at the scan root before any repository file is read. These are the
#: paths TrueAI must never treat as artifacts regardless of project settings.
BASE_IGNORE_LINES = (".git/", ".trueai/", "*.pyc", "__pycache__/")
IGNORE_FILE_NAMES = (".gitignore", ".trueaiignore")
_MAX_IGNORE_FILE_BYTES = 1024 * 1024
_MAX_IGNORE_FILES = 10_000


@dataclass(frozen=True, slots=True)
class _IgnoreScope:
    """One ignore file and the directory its patterns are relative to."""

    prefix: str
    spec: GitIgnoreSpec


@dataclass(frozen=True, slots=True)
class IgnoreRules:
    """Directory-relative ignore rules resolved the way Git resolves them.

    An ignore file in a subdirectory applies only beneath that directory, and a
    deeper file overrides a shallower one, including through negation. Flattening
    every pattern into one root-level spec, as a naive implementation does, both
    over-ignores (a nested "build/" rule hides an unrelated top-level "build/")
    and under-ignores (a nested "!keep" never wins).
    """

    scopes: tuple[_IgnoreScope, ...]

    @classmethod
    def root(cls, directory: Path) -> IgnoreRules:
        """Build the root scope from the built-in list plus the root ignore files."""

        lines = [*BASE_IGNORE_LINES, *_read_ignore_lines(directory)]
        return cls((_IgnoreScope("", GitIgnoreSpec.from_lines(lines)),))

    def descend(self, directory: Path, prefix: str) -> IgnoreRules:
        """Return rules extended with any ignore file in the given directory."""

        lines = _read_ignore_lines(directory)
        if not lines:
            return self
        scope = _IgnoreScope(prefix, GitIgnoreSpec.from_lines(lines))
        return IgnoreRules((*self.scopes, scope))

    def is_ignored(self, relative: str, *, is_directory: bool) -> bool:
        """Return whether a root-relative path is ignored by the closest rule."""

        for scope in reversed(self.scopes):
            if scope.prefix and not relative.startswith(scope.prefix):
                continue
            candidate = relative[len(scope.prefix) :]
            if not candidate:
                continue
            if is_directory:
                candidate = candidate + "/"
            decision = scope.spec.check_file(candidate)
            if decision.include is not None:
                return bool(decision.include)
        return False


def _read_ignore_lines(directory: Path) -> list[str]:
    """Read the bounded contents of the ignore files in one directory."""

    lines: list[str] = []
    for name in IGNORE_FILE_NAMES:
        ignore_file = directory / name
        try:
            if not ignore_file.is_file() or ignore_file.stat().st_size > _MAX_IGNORE_FILE_BYTES:
                continue
            lines.extend(ignore_file.read_text(encoding="utf-8").splitlines())
        except (OSError, UnicodeDecodeError):
            continue
    return lines


class ArtifactDiscovery:
    """Identify artifacts by signatures first and extensions second."""

    def __init__(self, options: DiscoveryOptions | None = None) -> None:
        self.options = options or DiscoveryOptions()
        self.truncated = False
        self.issues: list[DiscoveryIssue] = []

    def identify(self, path: Path) -> Artifact:
        """Identify a path without executing or fully parsing its content."""

        path = path.resolve(strict=True)
        if path.is_dir():
            artifact_type = (
                ArtifactType.GIT_REPOSITORY if (path / ".git").exists() else ArtifactType.DIRECTORY
            )
            return Artifact(artifact_type=artifact_type, path=path, logical_path=".")

        size = path.stat().st_size
        with path.open("rb") as handle:
            head = handle.read(min(8192, self.options.max_file_size + 1))
        artifact_type, media_type = self._identify_file(
            path,
            head,
            inspect_archive=size <= self.options.max_file_size,
        )
        return Artifact(
            artifact_type=artifact_type,
            path=path,
            logical_path=path.name,
            size=size,
            media_type=media_type,
        )

    def discover(self, target: str | Path | Artifact) -> list[Artifact]:
        """Discover a target and its safe recursive children in deterministic order."""

        self.truncated = False
        self.issues = []
        if isinstance(target, Artifact):
            if (
                target.artifact_type in {ArtifactType.DIRECTORY, ArtifactType.GIT_REPOSITORY}
                and target.path is not None
            ):
                # A caller-supplied container is still a recursive scan target. Treating
                # it as a one-item inventory made the post-scan mutation check rediscover
                # every pre-existing child and falsely accuse detectors of creating them.
                # Re-identification also avoids trusting a caller-provided container type.
                return self.discover(target.path)
            return [target]
        raw_path = Path(target)
        if raw_path.is_symlink() and not self.options.follow_symlinks:
            raise UnsafeArtifactError(
                f"Top-level symlink requires follow_symlinks=True: {raw_path}"
            )
        if not raw_path.exists():
            raise ArtifactNotFoundError(f"Artifact does not exist: {raw_path}")
        root_artifact = self.identify(raw_path)
        if root_artifact.artifact_type not in {
            ArtifactType.DIRECTORY,
            ArtifactType.GIT_REPOSITORY,
        }:
            return [root_artifact]

        root = root_artifact.path
        assert root is not None
        artifacts = [root_artifact]
        for path in self._walk(root, IgnoreRules.root(root)):
            if len(artifacts) - 1 >= self.options.max_files:
                self.truncated = True
                break
            try:
                artifact = self.identify(path)
            except (OSError, ArtifactNotFoundError) as exc:
                self.issues.append(
                    DiscoveryIssue(
                        path=path.relative_to(root).as_posix(),
                        message=f"Unable to identify artifact: {exc}",
                    )
                )
                continue
            artifacts.append(
                Artifact(
                    artifact_type=artifact.artifact_type,
                    path=artifact.path,
                    logical_path=path.relative_to(root).as_posix(),
                    size=artifact.size,
                    media_type=artifact.media_type,
                )
            )
        return artifacts

    def inventory(self, root: Path) -> set[str]:
        """Return the logical paths under ``root`` without identifying anything.

        The end-of-scan sweep that asks "did new files appear while detectors
        ran" needs a set of paths and nothing else.  Building it with
        :meth:`discover` meant opening and sniffing every file a second time to
        produce type information the comparison then threw away — measured at
        roughly a third of a whole-repository scan.  Traversal, ignore rules,
        symlink containment, and the file cap are the same ones
        :meth:`discover` uses, because a sweep that walked differently would
        report differences that are its own.
        """

        paths = {"."}
        for candidate in self._walk(root, IgnoreRules.root(root)):
            if len(paths) - 1 >= self.options.max_files:
                self.truncated = True
                break
            paths.add(candidate.relative_to(root).as_posix())
        return paths

    def _walk(self, root: Path, rules: IgnoreRules) -> Iterator[Path]:
        stack: list[tuple[Path, IgnoreRules]] = [(root, rules)]
        visited_directories: set[Path] = set()
        ignore_files_read = 1
        while stack:
            directory, directory_rules = stack.pop()
            try:
                resolved_directory = directory.resolve(strict=True)
                resolved_directory.relative_to(root)
            except (OSError, ValueError) as exc:
                self.issues.append(
                    DiscoveryIssue(
                        path=str(directory),
                        message=f"Directory escaped the scan root or was inaccessible: {exc}",
                    )
                )
                continue
            if resolved_directory in visited_directories:
                continue
            visited_directories.add(resolved_directory)
            try:
                entries = sorted(
                    os.scandir(directory),
                    key=lambda entry: (entry.name.casefold(), entry.name),
                )
            except OSError as exc:
                self.issues.append(
                    DiscoveryIssue(path=str(directory), message=f"Unable to list directory: {exc}")
                )
                continue
            child_directories: list[tuple[Path, IgnoreRules]] = []
            for entry in entries:
                path = Path(entry.path)
                relative = path.relative_to(root).as_posix()
                if relative == ".git" or relative.startswith(".git/"):
                    continue
                try:
                    entry_is_directory = entry.is_dir(follow_symlinks=self.options.follow_symlinks)
                except OSError as exc:
                    self.issues.append(
                        DiscoveryIssue(path=relative, message=f"Unable to inspect path: {exc}")
                    )
                    continue
                if directory_rules.is_ignored(relative, is_directory=entry_is_directory):
                    continue
                if entry.is_symlink():
                    if not self.options.follow_symlinks:
                        continue
                    try:
                        resolved = path.resolve(strict=True)
                        resolved.relative_to(root)
                    except (OSError, ValueError) as exc:
                        self.issues.append(
                            DiscoveryIssue(
                                path=relative,
                                message=f"Symlink target escaped the scan root: {exc}",
                            )
                        )
                        continue
                try:
                    if entry_is_directory:
                        child_rules = directory_rules
                        if ignore_files_read < _MAX_IGNORE_FILES:
                            child_rules = directory_rules.descend(path, relative + "/")
                            if child_rules is not directory_rules:
                                ignore_files_read += 1
                        elif ignore_files_read == _MAX_IGNORE_FILES:
                            ignore_files_read += 1
                            self.issues.append(
                                DiscoveryIssue(
                                    path=relative,
                                    message=(
                                        "Stopped reading nested ignore files after "
                                        f"{_MAX_IGNORE_FILES}; deeper rules are not applied."
                                    ),
                                )
                            )
                        child_directories.append((path, child_rules))
                    elif entry.is_file(follow_symlinks=self.options.follow_symlinks):
                        yield path
                except OSError as exc:
                    self.issues.append(
                        DiscoveryIssue(path=relative, message=f"Unable to inspect path: {exc}")
                    )
                    continue
            stack.extend(reversed(child_directories))

    @staticmethod
    def _identify_file(
        path: Path,
        head: bytes,
        *,
        inspect_archive: bool = True,
    ) -> tuple[ArtifactType, str | None]:
        suffix = path.suffix.casefold()
        if head.startswith(_PNG_SIGNATURE):
            return ArtifactType.PNG, "image/png"
        if head.startswith(_JPEG_SIGNATURE):
            return ArtifactType.JPEG, "image/jpeg"
        if head.startswith(_PDF_SIGNATURE):
            return ArtifactType.PDF, "application/pdf"
        if head.startswith(_FLAC_SIGNATURE):
            return ArtifactType.AUDIO, "audio/flac"
        if head.startswith((b"RIFF", b"RIFX")) and head[8:12] == b"WAVE":
            return ArtifactType.AUDIO, "audio/wav"
        if head.startswith(b"ID3") or (
            suffix in {".mp2", ".mp3", ".mpa"} and ArtifactDiscovery._looks_like_mp3_frame(head)
        ):
            return ArtifactType.AUDIO, "audio/mpeg"
        if len(head) >= 12 and head[4:8] == b"ftyp":
            major_brand = head[8:12]
            if major_brand in _ISO_AUDIO_BRANDS or suffix in {".m4a", ".m4b", ".m4p"}:
                return ArtifactType.AUDIO, "audio/mp4"
            media_type = "video/quicktime" if major_brand == b"qt  " else "video/mp4"
            return ArtifactType.VIDEO, media_type
        if head.startswith(_EBML_SIGNATURE):
            if suffix in {".weba", ".mka"}:
                return ArtifactType.AUDIO, "audio/webm"
            return ArtifactType.VIDEO, "video/webm"
        if head.startswith(_CFB_SIGNATURE):
            # Identified, not parsed. See docs/legacy-office.md for why cleanup
            # is refused; naming the format is what stops a skip from reading as
            # a clean result.
            return ArtifactType.LEGACY_OFFICE, "application/x-ole-storage"
        if head.startswith(_ZIP_SIGNATURES):
            # The ODF mimetype entry is stored uncompressed and required to be
            # first, so the declared type is in the opening bytes and needs no
            # archive expansion to read.
            declared = ArtifactDiscovery._sniff_odf_mimetype(head)
            if declared is not None:
                return ArtifactType.ODF, declared
            known = _OOXML_BY_SUFFIX.get(suffix)
            if known is not None:
                return known
            if inspect_archive:
                sniffed = ArtifactDiscovery._sniff_ooxml(path)
                if sniffed is not None:
                    return sniffed
            if suffix in _ODF_SUFFIXES:
                return ArtifactType.ODF, "application/vnd.oasis.opendocument.text"

        if head.startswith((b"\xff\xfe", b"\xfe\xff")):
            if suffix in _MARKDOWN_EXTENSIONS:
                return ArtifactType.MARKDOWN, "text/markdown"
            if suffix in _CODE_EXTENSIONS:
                return ArtifactType.SOURCE_CODE, "text/plain"
            if suffix in _TEXT_EXTENSIONS:
                return ArtifactType.TEXT, "text/plain"
        if b"\x00" in head:
            return ArtifactType.BINARY, "application/octet-stream"
        decoded = head.decode("utf-8", errors="ignore").lstrip("\ufeff\t\r\n ")
        lowered = decoded[:1024].casefold()
        if suffix == ".svg" or re.match(r"(?:<\?xml[^>]*>\s*)?<svg(?:\s|>)", lowered):
            return ArtifactType.SVG, "image/svg+xml"
        if lowered.startswith("<!doctype html") or lowered.startswith("<html"):
            return ArtifactType.HTML, "text/html"
        if suffix in {".html", ".htm", ".xhtml"}:
            return ArtifactType.HTML, "text/html"
        if suffix == ".css":
            return ArtifactType.CSS, "text/css"
        if suffix in _MARKDOWN_EXTENSIONS:
            return ArtifactType.MARKDOWN, "text/markdown"
        if suffix in _CODE_EXTENSIONS:
            return ArtifactType.SOURCE_CODE, "text/plain"
        if suffix in _TEXT_EXTENSIONS or ArtifactDiscovery._is_probably_text(head):
            return ArtifactType.TEXT, "text/plain"
        return ArtifactType.UNKNOWN, None

    @staticmethod
    def _sniff_odf_mimetype(head: bytes) -> str | None:
        """Return an ODF media type read from the opening bytes, or None.

        The specification requires the `mimetype` entry to be first and stored
        without compression, so its value sits in plain bytes near the start of
        the file. Reading it there means the archive is never opened during type
        identification, and a hostile package cannot be inflated by being looked
        at.
        """

        marker = head.find(_ODF_MARKER)
        if marker < 0:
            return None
        window = head[marker : marker + 256]
        start = window.find(_ODF_MIMETYPE_PREFIX)
        if start < 0:
            return None
        value = bytearray()
        for byte in window[start:]:
            if byte in b"\x00\r\nPK" or byte < 0x20:
                break
            value.append(byte)
        declared = bytes(value).decode("ascii", "replace")
        return declared or None

    @staticmethod
    def _sniff_ooxml(path: Path) -> tuple[ArtifactType, str] | None:
        """Identify an Office Open XML family by streaming for its required parts.

        The archive is never expanded here. Only literal part names are searched
        in the raw bytes, so a hostile or unbounded package cannot be inflated
        during type identification.
        """

        content_types_seen = False
        matched: tuple[ArtifactType, str] | None = None
        carry = b""
        try:
            with path.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    sample = carry + chunk
                    content_types_seen = content_types_seen or _OOXML_CONTENT_TYPES_PART in sample
                    if matched is None:
                        for marker, artifact_type, media_type in _OOXML_MARKERS:
                            if marker in sample:
                                matched = (artifact_type, media_type)
                                break
                    if content_types_seen and matched is not None:
                        return matched
                    carry = sample[-64:]
        except OSError:
            return None
        return None

    @staticmethod
    def _is_probably_text(data: bytes) -> bool:
        if not data:
            return True
        sample = data[:4096]
        try:
            sample.decode("utf-8")
            return True
        except UnicodeDecodeError:
            control_count = sum(byte < 9 or 13 < byte < 32 for byte in sample)
            return control_count / len(sample) < 0.02

    @staticmethod
    def _looks_like_mp3_frame(data: bytes) -> bool:
        """Recognize a plausible MPEG audio frame header without trusting the suffix."""

        if len(data) < 4 or data[0] != 0xFF or data[1] & 0xE0 != 0xE0:
            return False
        version = (data[1] >> 3) & 0x03
        layer = (data[1] >> 1) & 0x03
        bitrate_index = (data[2] >> 4) & 0x0F
        sample_rate_index = (data[2] >> 2) & 0x03
        return (
            version != 0x01
            and layer != 0x00
            and bitrate_index not in {0x00, 0x0F}
            and sample_rate_index != 0x03
        )
