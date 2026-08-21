import pytest

from trueai import TrueAIEngine
from trueai.core.errors import PolicyValidationError
from trueai.core.models import FindingCategory, PolicyAction
from trueai.core.policy import PolicyProfile, PolicyStore
from trueai.core.remediation import RemediationPlanner


def test_builtin_client_delivery_preserves_provenance() -> None:
    policy = PolicyStore.get("client-delivery")

    assert policy.rules[FindingCategory.EXPLICIT_AI_ATTRIBUTION] == PolicyAction.REMOVE
    assert policy.rules[FindingCategory.C2PA_PROVENANCE] == PolicyAction.PRESERVE
    assert policy.rules[FindingCategory.PROVIDER_WATERMARK] == PolicyAction.PRESERVE


def test_policy_rejects_provenance_removal() -> None:
    with pytest.raises(PolicyValidationError, match="Protected provenance"):
        PolicyProfile.from_yaml(
            """
policy: unsafe
rules:
  c2pa_provenance: remove
"""
        )


def test_planner_separates_review_and_removal() -> None:
    policy = PolicyStore.get("client-delivery")
    report = TrueAIEngine.default().scan_text("Text\u200b\nGenerated with ChatGPT\n", policy=policy)
    plan = RemediationPlanner().plan(report, policy)

    assert any(item.remediation_id == "text.remove-attribution-line" for item in plan.remediations)
    assert plan.review_findings


def test_policy_rejects_default_remove_without_explicit_provenance_preservation() -> None:
    with pytest.raises(PolicyValidationError, match="default_action REMOVE"):
        PolicyProfile.from_yaml("policy: unsafe-default\ndefault_action: remove\n")


def test_policy_rules_and_public_evidence_are_recursively_immutable() -> None:
    policy = PolicyStore.get("client-delivery")
    report = TrueAIEngine.default().scan_text("Text\u200b")

    with pytest.raises(TypeError, match="immutable"):
        policy.rules[FindingCategory.C2PA_PROVENANCE] = PolicyAction.REMOVE
    with pytest.raises(TypeError, match="immutable"):
        report.findings[0].evidence["code_point"] = "U+0000"
    with pytest.raises(TypeError, match="immutable"):
        report.summary.by_category["forged"] = 1
