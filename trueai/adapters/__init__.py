"""Adapters for the surfaces built on top of the public schema.

Three interfaces need the same five views — finding explanation, remediation
preview, integrity evidence, provenance, and certificate — and if each derives
them from the schema separately they drift. :mod:`trueai.adapters.views` derives
them once; :mod:`~trueai.adapters.ci`, :mod:`~trueai.adapters.ide`, and
:mod:`~trueai.adapters.desktop` format them.

None of them adds a field the report does not already imply. A second source of
truth is a second thing to be wrong.
"""

from trueai.adapters.ci import annotation, job_summary, workflow_annotations
from trueai.adapters.desktop import BUNDLE_VERSION, desktop_bundle
from trueai.adapters.ide import diagnostic, diagnostics_by_file, hover, publish_payloads
from trueai.adapters.views import (
    CertificateView,
    FindingExplanation,
    IntegrityEvidence,
    RemediationPreview,
    RemediationStep,
    certificate_view,
    explain_finding,
    explain_findings,
    integrity_evidence,
    lsp_severity,
    remediation_preview,
)

__all__ = [
    "BUNDLE_VERSION",
    "CertificateView",
    "FindingExplanation",
    "IntegrityEvidence",
    "RemediationPreview",
    "RemediationStep",
    "annotation",
    "certificate_view",
    "desktop_bundle",
    "diagnostic",
    "diagnostics_by_file",
    "explain_finding",
    "explain_findings",
    "hover",
    "integrity_evidence",
    "job_summary",
    "lsp_severity",
    "publish_payloads",
    "remediation_preview",
    "workflow_annotations",
]
