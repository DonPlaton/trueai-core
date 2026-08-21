from pathlib import Path

from PIL import Image, PngImagePlugin

from trueai import Artifact, TrueAIEngine
from trueai.core.models import (
    ConfidenceType,
    FindingCategory,
    ProvenanceClass,
    WatermarkSupportStatus,
)
from trueai.core.policy import PolicyStore
from trueai.core.remediation import RemediationPlanner
from trueai.providers import watermark_adapters


def test_c2pa_marker_is_reported_as_unverified_and_not_removable(tmp_path: Path) -> None:
    path = tmp_path / "credentialed.png"
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("Content Credentials", "c2pa manifest marker")
    Image.new("RGB", (2, 2), "white").save(path, pnginfo=metadata)

    report = TrueAIEngine.default().scan(path)
    finding = next(
        item for item in report.findings if item.category == FindingCategory.C2PA_PROVENANCE
    )

    assert finding.confidence_type == ConfidenceType.DETERMINISTIC
    assert finding.provenance_class == ProvenanceClass.PROVENANCE_METADATA
    assert finding.evidence["authenticated"] is False
    assert finding.removable is False

    metadata_finding = next(
        item
        for item in report.findings
        if item.category == FindingCategory.IMAGE_METADATA
        and item.evidence.get("field") == "Content Credentials"
    )
    assert metadata_finding.removable is False
    assert metadata_finding.provenance_class == ProvenanceClass.PROVENANCE_METADATA

    policy = PolicyStore.get("client-delivery")
    policy_report = TrueAIEngine.default().scan(path, policy=policy)
    plan = RemediationPlanner().plan(policy_report, policy)
    assert metadata_finding.id in plan.blocked_findings
    assert not plan.remediations


def test_provider_adapters_report_support_status_without_inventing_verification(
    tmp_path: Path,
) -> None:
    path = tmp_path / "text.txt"
    path.write_text("ordinary text", encoding="utf-8")
    artifact = Artifact.from_text(path.read_text(encoding="utf-8"), name=path.name)
    adapters = watermark_adapters()
    statuses = {adapter.provider: adapter.status for adapter in adapters}
    results = [adapter.verify(artifact) for adapter in adapters]

    assert statuses["anthropic"] == WatermarkSupportStatus.VERIFICATION_UNAVAILABLE
    assert statuses["openai"] == WatermarkSupportStatus.VERIFICATION_UNAVAILABLE
    assert statuses["google"] == WatermarkSupportStatus.VERIFICATION_UNAVAILABLE
    assert statuses["generic"] == WatermarkSupportStatus.NOT_SUPPORTED
    assert all(result.verified is False for result in results)
    assert all("No watermark algorithm" in result.explanation for result in results)


def test_jpeg_provenance_marker_blocks_cleanup_of_other_comment_segments(
    tmp_path: Path,
) -> None:
    path = tmp_path / "credentialed.jpg"
    base_path = tmp_path / "base.jpg"
    Image.new("RGB", (2, 2), "white").save(base_path)
    base = base_path.read_bytes()

    def comment_segment(value: bytes) -> bytes:
        return b"\xff\xfe" + (len(value) + 2).to_bytes(2, "big") + value

    path.write_bytes(
        base[:2] + comment_segment(b"c2pa manifest") + comment_segment(b"ordinary note") + base[2:]
    )
    policy = PolicyStore.get("client-delivery")
    report = TrueAIEngine.default().scan(path, policy=policy)
    plan = RemediationPlanner().plan(report, policy)

    assert any(finding.category == FindingCategory.C2PA_PROVENANCE for finding in report.findings)
    assert not plan.remediations
    assert plan.blocked_findings


def test_compressed_png_provenance_text_is_preserved(tmp_path: Path) -> None:
    path = tmp_path / "compressed-credential.png"
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("Comment", "c2pa Content Credentials manifest", zip=True)
    metadata.add_text("Author", "Alice")
    Image.new("RGB", (2, 2), "white").save(path, pnginfo=metadata)
    policy = PolicyStore.get("client-delivery")

    report = TrueAIEngine.default().scan(path, policy=policy)
    plan = RemediationPlanner().plan(report, policy)
    protected = next(
        finding for finding in report.findings if finding.evidence.get("field") == "Comment"
    )

    assert protected.provenance_class == ProvenanceClass.PROVENANCE_METADATA
    assert protected.removable is False
    assert protected.id in plan.blocked_findings
    assert not plan.remediations
