"""Stable finding fingerprint construction and validation."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

from pydantic import JsonValue

from trueai.core.models import Finding, FindingCategory, FindingLocation


def build_finding_id(
    *,
    artifact_path: str,
    category: FindingCategory,
    detector_id: str,
    evidence: Mapping[str, JsonValue],
    location: FindingLocation | None,
    provider: str | None,
) -> str:
    """Build a deterministic ID from all evidence-bearing identity fields."""

    identity = {
        "artifact": artifact_path,
        "category": category.value,
        "detector": detector_id,
        "evidence": dict(evidence),
        "location": location.model_dump(mode="json") if location else None,
        "provider": provider,
    }
    digest = hashlib.sha256(
        json.dumps(identity, sort_keys=True, ensure_ascii=True, default=str).encode("utf-8")
    ).hexdigest()[:20]
    return f"fnd_{digest}"


def finding_id_is_valid(finding: Finding) -> bool:
    """Detect shallow mutation of a finding's nested evidence after validation."""

    return finding.id == build_finding_id(
        artifact_path=finding.artifact_path,
        category=finding.category,
        detector_id=finding.detector_id,
        evidence=finding.evidence,
        location=finding.location,
        provider=finding.provider,
    )
