"""Signed enterprise policy controls remain auditable and provenance-safe."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from PIL import Image, PngImagePlugin

from trueai import PolicyStore, TrueAIEngine
from trueai.core.certificates import generate_ed25519_keypair
from trueai.core.errors import PolicyValidationError
from trueai.core.models import FindingCategory, PolicyAction
from trueai.core.policy_bundle import (
    FindingSelector,
    PolicyBundleControls,
    PolicyException,
    PolicySuppression,
    apply_policy_bundle,
    issue_policy_bundle,
    policy_bundle_schema_json,
    verify_policy_bundle,
)
from trueai.core.remediation import RemediationPlanner


@pytest.fixture
def signing_keys(tmp_path: Path) -> tuple[Path, Path]:
    private = tmp_path / "policy-private.pem"
    public = tmp_path / "policy-public.pem"
    generate_ed25519_keypair(private, public)
    return private, public


def _control_expiry() -> datetime:
    return datetime.now(UTC) + timedelta(days=7)


def test_signed_suppression_changes_only_the_decision_and_records_audit(
    signing_keys: tuple[Path, Path],
) -> None:
    private, public = signing_keys
    report = TrueAIEngine.default(discover_plugins=False).scan_text(
        "Generated with ChatGPT\n",
        policy=PolicyStore.get("strict"),
    )
    controls = PolicyBundleControls(
        suppressions=(
            PolicySuppression(
                id="approved.chatgpt-attribution",
                selector=FindingSelector(category=FindingCategory.EXPLICIT_AI_ATTRIBUTION),
                reason="Reviewed legacy attribution in the approved delivery baseline.",
                approved_by="security@example.test",
                expires_at=_control_expiry(),
            ),
        )
    )
    bundle = issue_policy_bundle(
        PolicyStore.get("strict"),
        issuer="Example Security",
        signing_key=private,
        controls=controls,
    )

    evaluated = apply_policy_bundle(report, bundle, public_key=public)

    assert evaluated.findings == report.findings
    assert evaluated.policy_bundle_id == bundle.bundle_id
    assert evaluated.policy_decisions[0].action == PolicyAction.IGNORE
    assert evaluated.summary.violation_count == 0
    assert evaluated.policy_audit[0].source == "suppression"
    assert verify_policy_bundle(bundle, public_key=public).valid


def test_tampered_or_expired_bundle_is_rejected(
    signing_keys: tuple[Path, Path],
) -> None:
    private, public = signing_keys
    issued = datetime.now(UTC)
    bundle = issue_policy_bundle(
        PolicyStore.get("audit"),
        issuer="Example Security",
        signing_key=private,
        issued_at=issued,
        expires_in=timedelta(hours=1),
    )
    tampered = bundle.model_copy(update={"issuer": "Unknown issuer"})

    assert not verify_policy_bundle(tampered, public_key=public).valid
    assert not verify_policy_bundle(
        bundle,
        public_key=public,
        at_time=issued + timedelta(hours=2),
    ).valid
    report = TrueAIEngine.default(discover_plugins=False).scan_text("ordinary text")
    with pytest.raises(PolicyValidationError, match="verification failed"):
        apply_policy_bundle(report, tampered, public_key=public)


def test_exception_can_select_predictable_remediation_and_planner_uses_it(
    signing_keys: tuple[Path, Path],
) -> None:
    private, public = signing_keys
    profile = PolicyStore.get("strict")
    report = TrueAIEngine.default(discover_plugins=False).scan_text(
        "Generated with ChatGPT\n",
        policy=profile,
    )
    controls = PolicyBundleControls(
        exceptions=(
            PolicyException(
                id="remove.reviewed-attribution",
                selector=FindingSelector(category=FindingCategory.EXPLICIT_AI_ATTRIBUTION),
                action=PolicyAction.REMOVE,
                reason="Approved removal of explicit generator boilerplate.",
                approved_by="delivery@example.test",
                expires_at=_control_expiry(),
            ),
        )
    )
    bundle = issue_policy_bundle(
        profile,
        issuer="Example Delivery",
        signing_key=private,
        controls=controls,
    )

    evaluated = apply_policy_bundle(report, bundle, public_key=public)
    plan = RemediationPlanner().plan(evaluated, profile)

    assert evaluated.policy_decisions[0].action == PolicyAction.REMOVE
    assert plan.remediations
    assert plan.remediations[0].remediation_id == "text.remove-attribution-line"


def test_protected_provenance_cannot_be_suppressed(
    tmp_path: Path,
    signing_keys: tuple[Path, Path],
) -> None:
    private, public = signing_keys
    image_path = tmp_path / "credential.png"
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("c2pa", "manifest marker")
    Image.new("RGB", (1, 1), "white").save(image_path, pnginfo=metadata)
    report = TrueAIEngine.default(discover_plugins=False).scan(
        image_path,
        policy=PolicyStore.get("audit"),
    )
    controls = PolicyBundleControls(
        suppressions=(
            PolicySuppression(
                id="never.hide-provenance",
                selector=FindingSelector(category=FindingCategory.C2PA_PROVENANCE),
                reason="Attempted acknowledgement for regression coverage.",
                approved_by="security@example.test",
                expires_at=_control_expiry(),
            ),
        )
    )
    bundle = issue_policy_bundle(
        PolicyStore.get("audit"),
        issuer="Example Security",
        signing_key=private,
        controls=controls,
    )

    evaluated = apply_policy_bundle(report, bundle, public_key=public)
    provenance_ids = {
        finding.id
        for finding in evaluated.findings
        if finding.category == FindingCategory.C2PA_PROVENANCE
    }
    decisions = {decision.finding_id: decision.action for decision in evaluated.policy_decisions}

    assert provenance_ids
    assert all(decisions[item] == PolicyAction.PRESERVE for item in provenance_ids)
    assert any(entry.source == "protected" for entry in evaluated.policy_audit)


def test_policy_bundle_schema_snapshot_matches_the_public_model() -> None:
    snapshot = (
        Path(__file__).resolve().parents[2] / "schema" / "trueai-policy-bundle-0.1.schema.json"
    )

    assert json.loads(snapshot.read_text(encoding="utf-8")) == json.loads(
        policy_bundle_schema_json()
    )
