from pathlib import Path

import pytest

from trueai import TrueAIEngine
from trueai.cleaners.svg import SVGCleaner
from trueai.core.errors import RemediationError
from trueai.core.models import (
    FindingCategory,
    ProvenanceClass,
    Remediation,
    RemediationSafety,
)
from trueai.core.policy import PolicyStore
from trueai.core.remediation import RemediationPlanner


def test_svg_metadata_hidden_elements_and_security_are_distinct(svg_file: Path) -> None:
    report = TrueAIEngine.default().scan(svg_file)
    categories = {item.category for item in report.findings}

    assert FindingCategory.GENERATOR_METADATA in categories
    assert FindingCategory.EXPLICIT_AI_ATTRIBUTION in categories
    assert FindingCategory.HIDDEN_ELEMENT in categories
    assert FindingCategory.SECURITY_ISSUE in categories
    assert FindingCategory.STRUCTURAL_SIGNAL in categories
    hidden = next(
        item for item in report.findings if item.category == FindingCategory.HIDDEN_ELEMENT
    )
    assert "not assumed to be watermarks" in hidden.description


def test_svg_entity_input_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "hostile.svg"
    path.write_text(
        """<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>""",
        encoding="utf-8",
    )
    report = TrueAIEngine.default().scan(path)

    assert any(item.code == "corrupt_artifact" for item in report.diagnostics)


def test_svg_dtd_without_entity_also_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "dtd.svg"
    path.write_text(
        '<!DOCTYPE svg><svg xmlns="http://www.w3.org/2000/svg"/>',
        encoding="utf-8",
    )

    report = TrueAIEngine.default().scan(path)

    assert any(item.code == "corrupt_artifact" for item in report.diagnostics)


def test_svg_provenance_metadata_is_protected_across_scan_plan_and_cleaner(
    tmp_path: Path,
) -> None:
    path = tmp_path / "credentialed.svg"
    destination = tmp_path / "cleaned.svg"
    path.write_text(
        """<svg xmlns="http://www.w3.org/2000/svg"
 xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape"
 inkscape:credential="c2pa manifest" inkscape:version="1.3">
<metadata><record>c2pa Content Credentials</record></metadata>
<rect width="10" height="10"/>
</svg>""",
        encoding="utf-8",
    )
    policy = PolicyStore.get("client-delivery")

    report = TrueAIEngine.default().scan(path, policy=policy)
    metadata_finding = next(
        finding for finding in report.findings if finding.title == "SVG metadata element"
    )
    plan = RemediationPlanner().plan(report, policy)

    assert metadata_finding.removable is False
    assert metadata_finding.provenance_class == ProvenanceClass.PROVENANCE_METADATA
    assert metadata_finding.id in plan.blocked_findings
    assert not [
        remediation
        for remediation in plan.remediations
        if remediation.remediation_id
        in {"svg.remove-metadata-element", "svg.remove-editor-attributes"}
    ]

    forged_remediation = Remediation(
        id="rem_provenance_guard",
        remediation_id="svg.remove-metadata-element",
        artifact_path=path.name,
        finding_ids=(metadata_finding.id,),
        description="Exercise the cleaner's independent provenance guard.",
        safety=RemediationSafety.PREDICTABLE_CONTENT,
    )
    with pytest.raises(RemediationError, match="provenance marker"):
        SVGCleaner().apply(path, destination, (forged_remediation,))
    assert not destination.exists()


def test_svg_provenance_in_editor_attribute_blocks_editor_cleanup(tmp_path: Path) -> None:
    path = tmp_path / "attribute-only.svg"
    path.write_text(
        """<svg xmlns="http://www.w3.org/2000/svg"
 xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape"
 inkscape:credential="c2pa manifest" inkscape:version="1.3">
<rect width="10" height="10"/></svg>""",
        encoding="utf-8",
    )
    policy = PolicyStore.get("client-delivery")

    report = TrueAIEngine.default().scan(path, policy=policy)
    editor_finding = next(
        finding for finding in report.findings if finding.title == "SVG editor-specific attributes"
    )
    plan = RemediationPlanner().plan(report, policy)

    assert editor_finding.removable is False
    assert editor_finding.provenance_class == ProvenanceClass.PROVENANCE_METADATA
    assert editor_finding.id in plan.blocked_findings
    assert not [
        remediation
        for remediation in plan.remediations
        if remediation.remediation_id == "svg.remove-editor-attributes"
    ]
