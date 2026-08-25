"""A minimal third-party TrueAI detector, written the way a real one would be.

It finds ticket references such as ``ACME-1234`` in text and reports each one as
a deterministic observation. The rule is trivial on purpose; what this package is
demonstrating is the contract around it.

Four things a detector author should copy from here:

**Import only from the public surface.** Every import below comes from a module
named in :data:`trueai.api.PUBLIC_MODULES`. Anything else may change in any
release, and a detector that reached into it would break on an upgrade with no
warning from the compatibility gate.

**Do not mutate.** ``scan`` receives an artifact and returns findings. It is
never handed a remediation API, and writing to the artifact would be caught: the
engine re-hashes every file after its detectors run, and again across the whole
corpus at the end.

**Say what kind of evidence this is.** ``ConfidenceType`` and ``EvidenceType`` are
separate on purpose: how sure you are, and what you are sure *of*. A ticket
reference is ``DETERMINISTIC`` (the string is either there or it is not) and
``TEXT`` (found by reading the document, not by parsing its structure). Neither
says anything about who wrote it, so ``ProvenanceClass.NONE`` is the honest
value — anything else would present a lexical hit as provenance.

**Build findings through ``self.finding``.** It derives the finding identifier
from the artifact path, category, detector id, evidence, and location, so the
same input produces the same id on every machine. Constructing ``Finding``
directly is possible and loses that.
"""

from __future__ import annotations

import re
from typing import Final

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
from trueai.detectors.base import BaseDetector
from trueai.plugins import PluginCapability, PluginManifest, PluginRegistration

__all__ = ["MANIFEST", "REGISTRATION", "AcmeTicketDetector"]

#: A bounded pattern. An unbounded one on hostile input is a scan that never
#: finishes, and every input here is hostile until proven otherwise.
TICKET: Final = re.compile(r"\bACME-(\d{1,6})\b")

#: Refuse absurd inputs rather than reporting ten thousand findings for one file.
MAX_FINDINGS_PER_ARTIFACT: Final = 50


class AcmeTicketDetector(BaseDetector):
    """Reports ACME ticket references found in text."""

    id = "acme.ticket.v1"
    supported_types = frozenset({ArtifactType.TEXT, ArtifactType.MARKDOWN})
    categories = frozenset({FindingCategory.TOOLING_RESIDUE})
    provider = None
    experimental = False

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        """Return one finding per distinct ticket reference, in file order."""

        # Bounded by the caller's own limit, not by whatever the file claims to
        # be. `read_text` raises rather than truncating, so a file over the limit
        # is reported as an error instead of silently half-scanned.
        text = artifact.read_text(context.options.max_file_size)

        findings: list[Finding] = []
        seen: set[str] = set()
        for match in TICKET.finditer(text):
            ticket = match.group(0)
            if ticket in seen:
                continue
            seen.add(ticket)
            if len(findings) >= MAX_FINDINGS_PER_ARTIFACT:
                break
            findings.append(
                self.finding(
                    artifact=artifact,
                    category=FindingCategory.TOOLING_RESIDUE,
                    confidence=1.0,
                    confidence_type=ConfidenceType.DETERMINISTIC,
                    severity=Severity.LOW,
                    evidence_type=EvidenceType.TEXT,
                    title="Ticket reference",
                    description=(
                        f"The text references {ticket}. This is an observation about the "
                        "document's contents and says nothing about who or what wrote it."
                    ),
                    evidence={"ticket": ticket},
                    location=FindingLocation(offset=match.start(), end_offset=match.end()),
                    provenance_class=ProvenanceClass.NONE,
                    removable=False,
                    tags=("third-party", "acme"),
                )
            )
        return findings


#: What the host is told before anything is imported.
#:
#: `READ_ARTIFACT` alone: this detector reads the file it was given and does
#: nothing else. Asking for more than is used is the same mistake as an
#: over-broad permission on a phone app — it costs the operator their ability to
#: reason about what ran.
MANIFEST = PluginManifest(
    detector_id="acme.ticket.v1",
    name="ACME ticket references",
    version="1.0",
    vendor="ACME",
    capabilities=frozenset({PluginCapability.READ_ARTIFACT}),
)

#: The entry point returns this rather than a bare detector, so the host can read
#: the manifest without instantiating anything. Import time is when hostile code
#: acts; a declaration the host can read first is the whole point.
REGISTRATION = PluginRegistration(manifest=MANIFEST, factory=AcmeTicketDetector)
