"""Validated policy profiles kept separate from detection and remediation."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, ValidationError, field_validator, model_validator

from trueai.core.errors import PolicyValidationError
from trueai.core.models import (
    Finding,
    FindingCategory,
    FrozenModel,
    PolicyAction,
    PolicyDecision,
)

_PROTECTED_CATEGORIES = {
    FindingCategory.C2PA_PROVENANCE,
    FindingCategory.PROVIDER_WATERMARK,
}


class PolicyProfile(FrozenModel):
    """A named mapping from finding categories to operational actions."""

    policy: str = Field(min_length=1, max_length=80, pattern=r"^[a-z0-9][a-z0-9-]*$")
    default_action: PolicyAction = PolicyAction.REPORT
    rules: dict[FindingCategory, PolicyAction] = Field(default_factory=dict)

    @field_validator("rules")
    @classmethod
    def protect_provenance(
        cls, rules: dict[FindingCategory, PolicyAction]
    ) -> dict[FindingCategory, PolicyAction]:
        """Reject policies that request watermark or authenticated provenance removal."""

        unsafe = [
            category.value
            for category in _PROTECTED_CATEGORIES
            if rules.get(category) == PolicyAction.REMOVE
        ]
        if unsafe:
            joined = ", ".join(sorted(unsafe))
            raise ValueError(f"Protected provenance categories cannot use REMOVE: {joined}")
        return rules

    @model_validator(mode="after")
    def protect_default_action(self) -> PolicyProfile:
        """Require explicit preservation when a policy defaults to removal."""

        if self.default_action == PolicyAction.REMOVE:
            unsafe = [
                category.value
                for category in _PROTECTED_CATEGORIES
                if self.rules.get(category) != PolicyAction.PRESERVE
            ]
            if unsafe:
                raise ValueError(
                    "default_action REMOVE requires explicit PRESERVE for: "
                    + ", ".join(sorted(unsafe))
                )
        return self

    def action_for(self, finding: Finding) -> PolicyAction:
        """Resolve an action for a finding category."""

        return self.rules.get(finding.category, self.default_action)

    @classmethod
    def from_yaml(cls, source: str | Path) -> PolicyProfile:
        """Load a profile from YAML text or a path."""

        try:
            path = Path(source)
            text = path.read_text(encoding="utf-8") if path.is_file() else str(source)
        except OSError:
            text = str(source)
        try:
            raw: Any = yaml.safe_load(text)
            if not isinstance(raw, dict):
                raise PolicyValidationError("Policy YAML must contain a mapping")
            return cls.model_validate(raw)
        except (yaml.YAMLError, ValidationError, ValueError) as exc:
            raise PolicyValidationError(f"Invalid policy: {exc}") from exc


class PolicyEvaluation(FrozenModel):
    """Policy decisions and derived CLI status counts."""

    decisions: tuple[PolicyDecision, ...]
    review_count: int
    violation_count: int


class PolicyEngine:
    """Evaluate findings without mutating or suppressing detector output."""

    def evaluate(self, findings: tuple[Finding, ...], policy: PolicyProfile) -> PolicyEvaluation:
        """Assign policy actions deterministically."""

        decisions: list[PolicyDecision] = []
        review_count = 0
        violation_count = 0
        for finding in findings:
            action = policy.action_for(finding)
            if action in {PolicyAction.REVIEW, PolicyAction.REMOVE}:
                review_count += 1
            elif action == PolicyAction.ERROR:
                violation_count += 1
            rationale = (
                f"Policy '{policy.policy}' maps category '{finding.category.value}' "
                f"to '{action.value}'."
            )
            decisions.append(
                PolicyDecision(finding_id=finding.id, action=action, rationale=rationale)
            )
        return PolicyEvaluation(
            decisions=tuple(decisions),
            review_count=review_count,
            violation_count=violation_count,
        )


class PolicyStore:
    """Load built-in or user-supplied policy profiles."""

    BUILTIN_NAMES = ("audit", "safe-clean", "privacy", "client-delivery", "strict")

    @classmethod
    def get(cls, name_or_path: str | Path) -> PolicyProfile:
        """Resolve a built-in name or YAML file."""

        candidate = str(name_or_path)
        if candidate in cls.BUILTIN_NAMES:
            resource = files("trueai.policies").joinpath(f"{candidate}.yaml")
            return PolicyProfile.from_yaml(resource.read_text(encoding="utf-8"))
        path = Path(name_or_path)
        if path.is_file():
            return PolicyProfile.from_yaml(path)
        raise PolicyValidationError(f"Unknown policy or missing file: {name_or_path}")

    @classmethod
    def list(cls) -> tuple[PolicyProfile, ...]:
        """Return all built-in policies."""

        return tuple(cls.get(name) for name in cls.BUILTIN_NAMES)
