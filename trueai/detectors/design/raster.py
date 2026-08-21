"""Bounded PNG/JPEG metadata inspection using Pillow's non-executing decoders."""

from __future__ import annotations

import warnings
from collections.abc import Iterable
from typing import Any

from PIL import ExifTags, Image, UnidentifiedImageError

from trueai.core.artifact import Artifact
from trueai.core.errors import CorruptArtifactError, UnsafeArtifactError
from trueai.core.models import (
    ArtifactType,
    ConfidenceType,
    EvidenceType,
    Finding,
    FindingCategory,
    ProvenanceClass,
    ScanContext,
    Severity,
)
from trueai.core.provenance import contains_protected_provenance_marker
from trueai.detectors.base import BaseDetector, FindingBuffer

_MAX_PIXELS = 100_000_000
_GENERATOR_FIELDS = {"software", "processingsoftware", "hostcomputer"}
_PERSONAL_FIELDS = {"artist", "author", "copyright", "cameraownername", "xp author", "xpauthor"}
_IGNORED_INFO_FIELDS = {
    "exif",
    "icc_profile",
    "transparency",
    "gamma",
    "dpi",
    "jfif",
    "jfif_version",
    "jfif_unit",
    "jfif_density",
    "progressive",
    "progression",
    "chromaticity",
    "srgb",
}
_RENDERING_CRITICAL_EXIF_TAGS = {
    274,  # Orientation
    282,  # XResolution
    283,  # YResolution
    296,  # ResolutionUnit
    40961,  # ColorSpace
}


class RasterMetadataDetector(BaseDetector):
    """Inspect standard metadata without attempting watermark removal or pixel inference."""

    id = "design.raster-metadata.v1"
    supported_types = frozenset({ArtifactType.PNG, ArtifactType.JPEG})
    categories = frozenset(
        {
            FindingCategory.IMAGE_METADATA,
            FindingCategory.PERSONAL_METADATA,
            FindingCategory.GENERATOR_METADATA,
        }
    )

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        if artifact.path is None:
            return []
        findings = FindingBuffer(context.options.max_findings, self.id)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", Image.DecompressionBombWarning)
                with Image.open(artifact.path) as image:
                    width, height = image.size
                    if width * height > _MAX_PIXELS:
                        raise UnsafeArtifactError(
                            f"Image has {width * height} pixels; safety limit is {_MAX_PIXELS}"
                        )
                    image.verify()
                with Image.open(artifact.path) as image:
                    info: dict[str, Any] = {
                        key: value for key, value in image.info.items() if isinstance(key, str)
                    }
                    findings.extend(self._info_findings(artifact, info))
                    findings.extend(self._exif_findings(artifact, image.getexif()))
        except Image.DecompressionBombWarning as exc:
            raise UnsafeArtifactError(f"Image decompression bomb warning: {exc}") from exc
        except (UnidentifiedImageError, OSError, SyntaxError, ValueError) as exc:
            raise CorruptArtifactError(f"Malformed or unsupported raster image: {exc}") from exc
        return findings

    def _info_findings(self, artifact: Artifact, info: dict[str, Any]) -> Iterable[Finding]:
        for field, raw_value in sorted(info.items(), key=lambda item: item[0].casefold()):
            field_lower = field.casefold()
            if field_lower in _IGNORED_INFO_FIELDS or raw_value is None:
                continue
            if not isinstance(raw_value, (str, bytes, int, float)):
                continue
            if raw_value == b"" or raw_value == "":
                continue
            value = self._safe_value(raw_value)
            category = self._category(field_lower)
            protected = contains_protected_provenance_marker(raw_value)
            yield self.finding(
                artifact=artifact,
                category=category,
                confidence=1.0,
                confidence_type=ConfidenceType.DETERMINISTIC,
                severity=(
                    Severity.MEDIUM
                    if category
                    in {FindingCategory.PERSONAL_METADATA, FindingCategory.GENERATOR_METADATA}
                    else Severity.LOW
                ),
                evidence_type=EvidenceType.METADATA,
                title=f"Image metadata: {field}",
                description=(
                    "A metadata field is exposed by the image container. This observation does "
                    "not inspect or remove statistical/robust watermarks."
                    + (
                        " The field contains a provenance marker and is protected from cleanup."
                        if protected
                        else ""
                    )
                ),
                evidence={
                    "container": artifact.artifact_type.value,
                    "field": field,
                    "value": value,
                },
                removable=not protected,
                remediation_id=None if protected else "image.remove-metadata",
                provenance_class=(
                    ProvenanceClass.PROVENANCE_METADATA if protected else ProvenanceClass.METADATA
                ),
                tags=("image", "metadata", field_lower)
                + (("preserve", "provenance-marker") if protected else ()),
            )

    def _exif_findings(self, artifact: Artifact, exif: Any) -> Iterable[Finding]:
        for tag_id, raw_value in exif.items():
            field = str(ExifTags.TAGS.get(tag_id, tag_id))
            field_lower = field.casefold()
            category = self._category(field_lower)
            provenance_protected = contains_protected_provenance_marker(raw_value)
            rendering_critical = int(tag_id) in _RENDERING_CRITICAL_EXIF_TAGS
            removable = not provenance_protected and not rendering_critical
            yield self.finding(
                artifact=artifact,
                category=category,
                confidence=1.0,
                confidence_type=ConfidenceType.DETERMINISTIC,
                severity=(
                    Severity.MEDIUM
                    if category
                    in {FindingCategory.PERSONAL_METADATA, FindingCategory.GENERATOR_METADATA}
                    else Severity.LOW
                ),
                evidence_type=EvidenceType.METADATA,
                title=f"EXIF metadata: {field}",
                description=(
                    "A standard EXIF tag is present in the image container."
                    + (
                        " It affects intended rendering and is preserved by built-in cleaners."
                        if rendering_critical
                        else ""
                    )
                    + (
                        " It contains a provenance marker and is protected from cleanup."
                        if provenance_protected
                        else ""
                    )
                ),
                evidence={
                    "container": "exif",
                    "field": field,
                    "tag_id": int(tag_id),
                    "value": self._safe_value(raw_value),
                    "rendering_critical": rendering_critical,
                },
                removable=removable,
                remediation_id="image.remove-metadata" if removable else None,
                provenance_class=(
                    ProvenanceClass.PROVENANCE_METADATA
                    if provenance_protected
                    else ProvenanceClass.METADATA
                ),
                tags=("image", "exif", field_lower)
                + (("preserve", "provenance-marker") if provenance_protected else ())
                + (("preserve", "rendering-critical") if rendering_critical else ()),
            )

    @staticmethod
    def _category(field: str) -> FindingCategory:
        normalized = field.replace("_", "").replace(" ", "")
        if normalized in {value.replace(" ", "") for value in _GENERATOR_FIELDS}:
            return FindingCategory.GENERATOR_METADATA
        if normalized in {value.replace(" ", "") for value in _PERSONAL_FIELDS}:
            return FindingCategory.PERSONAL_METADATA
        return FindingCategory.IMAGE_METADATA

    @staticmethod
    def _safe_value(value: Any, limit: int = 500) -> str:
        if isinstance(value, bytes):
            if len(value) > limit:
                return f"<{len(value)} bytes>"
            return value.decode("utf-8", errors="replace")
        rendered = str(value)
        return rendered if len(rendered) <= limit else f"{rendered[:limit]}…"
