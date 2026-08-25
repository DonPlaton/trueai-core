"""One JSON bundle a desktop client can render without re-deriving anything.

A desktop client needs five views and would otherwise walk the report five times,
each walk an opportunity to describe the same finding differently. This assembles
them once, versioned so a client can tell whether it understands what it was
handed.

The bundle is a *projection*. It carries no field the report does not already
imply, because a second source of truth is a second thing to be wrong. A client
that needs anything else reads the report, which travels alongside.
"""

from __future__ import annotations

from typing import Any, Final

from trueai.adapters.views import (
    certificate_view,
    explain_findings,
    integrity_evidence,
    remediation_preview,
)
from trueai.core.certificates import AuditCertificate, CertificateVerification
from trueai.core.models import RemediationPlan, ScanReport
from trueai.core.provenance_view import facets_for_report

#: Bumped when the bundle's shape changes. A client checks it and refuses a
#: bundle it cannot read, rather than rendering half of one.
BUNDLE_VERSION: Final = "0.1"


def desktop_bundle(
    report: ScanReport,
    *,
    plan: RemediationPlan | None = None,
    certificate: AuditCertificate | None = None,
    certificate_verification: CertificateVerification | None = None,
) -> dict[str, Any]:
    """Assemble every view a desktop client renders, from one report."""

    bundle: dict[str, Any] = {
        "bundle_version": BUNDLE_VERSION,
        "scan_id": str(report.scan_id),
        "generated_at": report.generated_at.isoformat(),
        "scanner": f"trueai-core {report.package_version}",
        "report_schema_version": report.schema_version,
        "artifact": report.artifact.path,
        "summary": {
            "artifacts": report.summary.artifact_count,
            "findings": report.summary.finding_count,
            "needs_review": report.summary.review_count,
            "violations": report.summary.violation_count,
        },
        "findings": [item.to_dict() for item in explain_findings(report)],
        "provenance": [
            {
                "artifact_path": facets.artifact_path,
                "headline": facets.headline(),
                "establishes_provenance": facets.establishes_provenance,
                "facets": [
                    {
                        "key": row.key,
                        "question": row.question,
                        "answer": row.answer,
                        "detail": row.detail,
                        "unknown": row.unknown,
                    }
                    for row in facets.rows()
                ],
                "caveats": list(facets.caveats()),
            }
            for facets in facets_for_report(report)
        ],
        # Coverage sits beside the findings rather than under them: a client that
        # renders findings without diagnostics shows a clean page for a scan that
        # could not read half the repository.
        "coverage": [
            {
                "code": item.code,
                "severity": item.severity.value,
                "artifact_path": item.artifact_path,
                "message": item.message,
            }
            for item in report.diagnostics
        ],
        "integrity": integrity_evidence(report.integrity).to_dict(),
        "remediation": None,
        "certificate": None,
    }
    if plan is not None:
        bundle["remediation"] = remediation_preview(plan).to_dict()
    if certificate is not None:
        bundle["certificate"] = certificate_view(certificate, certificate_verification).to_dict()
    return bundle


__all__ = ["BUNDLE_VERSION", "desktop_bundle"]
