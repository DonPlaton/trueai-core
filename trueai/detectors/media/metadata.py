"""Deterministic audio/video metadata findings over bounded container readers."""

from __future__ import annotations

import hashlib
import re

from trueai.core.artifact import Artifact
from trueai.core.models import (
    ArtifactType,
    ConfidenceType,
    EvidenceType,
    Finding,
    FindingCategory,
    FindingLocation,
    ProvenanceClass,
    ScanContext,
    Severity,
)
from trueai.core.provenance import contains_protected_provenance_marker
from trueai.detectors.base import BaseDetector, FindingBuffer
from trueai.detectors.media.containers import MediaMetadataEntry, parse_media_metadata
from trueai.providers import AttributionContext, attribution_rules

_GENERATOR_FIELDS = frozenset(
    {
        "software",
        "encoder",
        "encoder software",
        "encoder settings",
        "encoded by",
        "encoding tool",
        "vendor",
        "writing application",
        "muxing application",
        "host computer",
    }
)
_PERSONAL_FIELDS = frozenset(
    {
        "artist",
        "album artist",
        "author",
        "composer",
        "copyright",
        "engineer",
        "originator",
        "owner",
    }
)


class MediaMetadataDetector(BaseDetector):
    """Inspect metadata without decoding streams or claiming media authorship."""

    id = "media.container-metadata.v1"
    supported_types = frozenset({ArtifactType.AUDIO, ArtifactType.VIDEO})
    categories = frozenset(
        {
            FindingCategory.MEDIA_METADATA,
            FindingCategory.PERSONAL_METADATA,
            FindingCategory.GENERATOR_METADATA,
            FindingCategory.EXPLICIT_AI_ATTRIBUTION,
        }
    )

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        data = artifact.read_bytes(context.options.max_file_size)
        entries = parse_media_metadata(
            data,
            artifact.media_type,
            max_events=context.options.max_parser_events,
        )
        findings = FindingBuffer(context.options.max_findings, self.id)
        for entry in entries:
            findings.append(self._metadata_finding(artifact, entry))
            findings.extend(self._attribution_findings(artifact, entry))
        return findings

    def _metadata_finding(self, artifact: Artifact, entry: MediaMetadataEntry) -> Finding:
        category = self._category(entry.field)
        protected = contains_protected_provenance_marker(entry.value)
        removable = entry.remediation_safe and not protected
        severity = (
            Severity.MEDIUM
            if category in {FindingCategory.PERSONAL_METADATA, FindingCategory.GENERATOR_METADATA}
            else Severity.LOW
        )
        return self.finding(
            artifact=artifact,
            category=category,
            confidence=1.0,
            confidence_type=ConfidenceType.DETERMINISTIC,
            severity=severity,
            evidence_type=EvidenceType.METADATA,
            title=f"Media metadata: {entry.field}",
            description=(
                "A bounded container parser observed a textual audio/video metadata field. "
                "No media stream was decoded and this field alone does not establish authorship. "
                + (
                    "This field can be removed surgically while a format-specific integrity gate "
                    "proves that the audio-bearing bytes remain unchanged."
                    if removable
                    else "This container or field remains inspection-only because no safe "
                    "format-specific cleanup transform is available."
                )
                + (
                    " The value contains a provenance marker and must be preserved."
                    if protected
                    else ""
                )
            ),
            evidence={
                "container": entry.container,
                "field": entry.field,
                "raw_identifier": entry.raw_identifier,
                "value": self._display_value(entry.value),
                "value_sha256": hashlib.sha256(entry.value.encode("utf-8")).hexdigest(),
            },
            location=FindingLocation(byte_offset=entry.byte_offset),
            removable=removable,
            remediation_id="media.remove-metadata-field" if removable else None,
            provenance_class=(
                ProvenanceClass.PROVENANCE_METADATA if protected else ProvenanceClass.METADATA
            ),
            tags=("media", "metadata", self._normalize(entry.field))
            + (("preserve", "provenance-marker") if protected else ()),
        )

    def _attribution_findings(self, artifact: Artifact, entry: MediaMetadataEntry) -> list[Finding]:
        findings: list[Finding] = []
        for rule in attribution_rules():
            if AttributionContext.METADATA not in rule.contexts:
                continue
            for match in rule.finditer(entry.value):
                protected = contains_protected_provenance_marker(entry.value)
                removable = entry.remediation_safe and not protected
                findings.append(
                    self.finding(
                        artifact=artifact,
                        category=FindingCategory.EXPLICIT_AI_ATTRIBUTION,
                        confidence=rule.confidence,
                        confidence_type=ConfidenceType.DETERMINISTIC,
                        severity=Severity.MEDIUM,
                        evidence_type=EvidenceType.METADATA,
                        title="Explicit AI-tool attribution in media metadata",
                        description=(
                            f"{rule.explanation} This is literal metadata residue, not an "
                            "inference about the surrounding audio or video content. "
                            + (
                                "A container-specific cleaner can remove this exact field while "
                                "preserving audio-bearing bytes."
                                if removable
                                else "This field remains inspection-only because a safe transform "
                                "is unavailable."
                            )
                        ),
                        evidence={
                            "container": entry.container,
                            "field": entry.field,
                            "match": match.group(0),
                            "rule_id": rule.id,
                            "value": self._display_value(entry.value),
                            "raw_identifier": entry.raw_identifier,
                            "value_sha256": hashlib.sha256(entry.value.encode("utf-8")).hexdigest(),
                        },
                        location=FindingLocation(byte_offset=entry.byte_offset),
                        provider=rule.provider,
                        removable=removable,
                        remediation_id="media.remove-metadata-field" if removable else None,
                        provenance_class=(
                            ProvenanceClass.PROVENANCE_METADATA
                            if protected
                            else ProvenanceClass.ATTRIBUTION
                        ),
                        tags=("attribution", "literal", "media", rule.provider),
                    )
                )
        return findings

    @classmethod
    def _category(cls, field: str) -> FindingCategory:
        normalized = cls._normalize(field)
        if normalized in _GENERATOR_FIELDS or any(
            token in normalized for token in ("encoder", "software", "muxing application")
        ):
            return FindingCategory.GENERATOR_METADATA
        if normalized in _PERSONAL_FIELDS:
            return FindingCategory.PERSONAL_METADATA
        return FindingCategory.MEDIA_METADATA

    @staticmethod
    def _normalize(field: str) -> str:
        value = re.sub(r"^com\.apple\.quicktime\.", "", field, flags=re.IGNORECASE)
        value = re.sub(r"[_\-.]+", " ", value)
        return " ".join(value.casefold().split())

    @staticmethod
    def _display_value(value: str, limit: int = 500) -> str:
        return value if len(value) <= limit else f"{value[:limit]}…"


__all__ = ["MediaMetadataDetector"]
