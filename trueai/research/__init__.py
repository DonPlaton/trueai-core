"""Research-side governance: the rules a corpus must satisfy before it exists.

Kept out of the scanning path entirely. Nothing here is imported by a detector,
a cleaner, or the engine, and nothing here changes what a scan reports — it
governs data collection, which is a separate activity with separate obligations.
"""

from trueai.research.corpus import (
    AdmissionDecision,
    ConsentRecord,
    ConsentStatus,
    ContaminationControl,
    CorpusAudit,
    CorpusError,
    CorpusManifest,
    CorpusPolicy,
    CorpusSample,
    DomainBalance,
    LicenseTerms,
    LicenseUse,
    RetentionRule,
    Split,
    admit,
    admit_all,
    audit_corpus,
    withdraw_consent,
)

__all__ = [
    "AdmissionDecision",
    "ConsentRecord",
    "ConsentStatus",
    "ContaminationControl",
    "CorpusAudit",
    "CorpusError",
    "CorpusManifest",
    "CorpusPolicy",
    "CorpusSample",
    "DomainBalance",
    "LicenseTerms",
    "LicenseUse",
    "RetentionRule",
    "Split",
    "admit",
    "admit_all",
    "audit_corpus",
    "withdraw_consent",
]
