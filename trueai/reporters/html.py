"""A single-file HTML report that a hostile artifact cannot turn into a page.

Every string in a report comes from somewhere untrusted.  A file name, a metadata
value, a manifest field, an exception message — all of it originates in the
artifact under examination, and the report is then opened in a browser by the
person examining it.  That is the whole attack: put script in a document, get it
executed in the analyst's browser when they read about it.

Three things stop that here, and each is checked by a test rather than intended:

**Nothing artifact-derived is ever emitted unescaped.**  There is exactly one
function that turns a value into markup, and it escapes `&`, `<`, `>`, `"`, and
`'`.  Attributes are quoted, so an escaped quote cannot close one; text nodes are
escaped, so an escaped angle bracket cannot open a tag.

**The document contains no script and refers to nothing.**  No `<script>`, no
event-handler attributes, no external stylesheet, font, or image.  It is one file
that opens from a USB stick on a machine with no network, which is also where a
forensic report most often gets read.

**The document declares its own policy.**  A `Content-Security-Policy` meta
element sets `default-src 'none'` and `script-src 'none'`, so a browser refuses
what this file already does not contain.  Declaring a policy the content
satisfies is the point: it turns "we escaped everything" from a claim into
something the browser enforces.

The report also refuses to blur the distinctions the rest of the project keeps.
Findings are grouped by confidence type, provenance is shown as the four separate
facets of :mod:`trueai.core.provenance_view` rather than one badge, and a
question that was never answered is styled as unanswered rather than as a
negative result.
"""

from __future__ import annotations

from collections import Counter
from html import escape
from pathlib import Path
from typing import Final

from trueai.core.models import (
    ConfidenceType,
    Finding,
    ProvenanceClass,
    ScanReport,
    Severity,
)
from trueai.core.provenance_view import FacetRow, ProvenanceFacets, facets_for_report

#: The policy the document declares and satisfies. Written down as a constant so
#: a test can assert the emitted page carries it rather than trusting the string
#: in one place.
CONTENT_SECURITY_POLICY: Final = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; "
    "script-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

_SEVERITY_ORDER: Final[dict[Severity, int]] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

#: What each confidence class actually claims. Shown next to the group heading,
#: because a reader who does not know the difference is the reader most likely to
#: treat a heuristic as a fact.
_CONFIDENCE_MEANING: Final[dict[ConfidenceType, str]] = {
    ConfidenceType.DETERMINISTIC: (
        "The stated trace was observed exactly. This does not claim the artifact was AI-generated."
    ),
    ConfidenceType.VERIFIED: (
        "Checked against a cryptographic or provider mechanism that returned a result."
    ),
    ConfidenceType.PROBABILISTIC: "A calibrated estimate. It is a measurement, not provenance.",
    ConfidenceType.HEURISTIC: (
        "A rule of thumb that matched. It is a prompt for review, never evidence of authorship."
    ),
}

_STYLE: Final = """
:root { color-scheme: light dark; }
body {
  font: 15px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  margin: 0 auto; max-width: 62rem; padding: 2rem 1.25rem 4rem;
  background: Canvas; color: CanvasText;
}
h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
h2 { font-size: 1.1rem; margin: 2rem 0 .5rem; border-bottom: 1px solid; padding-bottom: .25rem; }
h3 { font-size: .95rem; margin: 1.5rem 0 .25rem; }
p.lede { margin: 0 0 1.5rem; opacity: .75; }
p.meaning { margin: 0 0 .75rem; opacity: .75; font-size: .9rem; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; font-size: .9rem; }
th, td { text-align: left; vertical-align: top; padding: .35rem .6rem; border-bottom: 1px solid; }
th { font-weight: 600; opacity: .7; font-size: .8rem; text-transform: uppercase; }
td.wrap { word-break: break-word; }
dl.summary { display: grid; grid-template-columns: auto 1fr; gap: .2rem 1rem; margin: 0 0 1rem; }
dl.summary dt { opacity: .7; }
dl.summary dd { margin: 0; font-variant-numeric: tabular-nums; }
.tag {
  display: inline-block; padding: 0 .4rem; border: 1px solid; border-radius: .2rem;
  font-size: .75rem; text-transform: uppercase; letter-spacing: .02em; white-space: nowrap;
}
.sev-critical, .sev-high { font-weight: 700; }
.unknown { font-style: italic; }
.unknown::after { content: " — not determined"; opacity: .7; font-style: normal; }
ul.notes { margin: .25rem 0 1rem; padding-left: 1.1rem; }
ul.notes li { margin: .2rem 0; }
footer { margin-top: 3rem; font-size: .8rem; opacity: .7; }
"""


def _text(value: object) -> str:
    """Escape a value for a text node or a quoted attribute.

    The single place a value becomes markup.  ``quote=True`` covers both ``"``
    and ``'``, so the same function is correct in an attribute as in text and
    there is no second one to forget.
    """

    return escape(str(value), quote=True)


def _cell(value: object, *, css: str = "") -> str:
    attribute = f' class="{_text(css)}"' if css else ""
    return f"<td{attribute}>{_text(value)}</td>"


def _row(cells: list[str]) -> str:
    return "<tr>" + "".join(cells) + "</tr>"


class HTMLReporter:
    """Render one scan report as a self-contained, script-free HTML document."""

    def render(self, report: ScanReport, *, title: str = "TrueAI scan report") -> str:
        """Return the whole document as one string."""

        sections = [
            self._summary(report),
            self._provenance(report),
            self._findings(report),
            self._diagnostics(report),
            self._integrity(report),
        ]
        body = "\n".join(section for section in sections if section)
        return (
            "<!doctype html>\n"
            '<html lang="en">\n<head>\n'
            '<meta charset="utf-8">\n'
            f'<meta http-equiv="Content-Security-Policy" content="{_text(CONTENT_SECURITY_POLICY)}">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            f"<title>{_text(title)}</title>\n"
            f"<style>{_STYLE}</style>\n"
            "</head>\n<body>\n"
            f"<h1>{_text(title)}</h1>\n"
            '<p class="lede">A deterministic finding means the stated trace was observed. '
            "It does not claim the artifact was generated by AI.</p>\n"
            f"{body}\n"
            f"{self._footer(report)}\n"
            "</body>\n</html>\n"
        )

    def write(self, report: ScanReport, path: Path, *, title: str = "TrueAI scan report") -> None:
        """Write the document as UTF-8."""

        path.write_text(self.render(report, title=title), encoding="utf-8")

    # -- sections ---------------------------------------------------------------------

    def _summary(self, report: ScanReport) -> str:
        provenance = sum(
            1 for item in report.findings if item.provenance_class is not ProvenanceClass.NONE
        )
        rows = {
            "Scanned": report.artifact.path,
            "Artifacts": report.summary.artifact_count,
            "Findings": report.summary.finding_count,
            "Provenance-related findings": provenance,
            "Needs review": report.summary.review_count,
            "Policy violations": report.summary.violation_count,
            "Scanner": f"trueai-core {report.package_version}",
            "Schema": report.schema_version,
            "Generated": report.generated_at.isoformat(),
        }
        if report.policy:
            rows["Policy"] = report.policy
        items = "".join(
            f"<dt>{_text(name)}</dt><dd>{_text(value)}</dd>" for name, value in rows.items()
        )
        return f'<h2>Summary</h2>\n<dl class="summary">{items}</dl>'

    def _provenance(self, report: ScanReport) -> str:
        faceted = facets_for_report(report)
        if not faceted:
            return ""
        header = (
            "<tr><th>Artifact</th><th>Marker</th><th>Signature</th>"
            "<th>Signer trust</th><th>Provider</th></tr>"
        )
        body = "".join(
            _row(
                [_cell(item.artifact_path, css="wrap")] + [_facet_cell(row) for row in item.rows()]
            )
            for item in faceted
        )
        notes = self._provenance_notes(faceted)
        return (
            "<h2>Provenance</h2>\n"
            '<p class="meaning">Four separate questions. A marker existing, its signature '
            "verifying, its signer being trusted, and a provider adapter confirming a watermark "
            "are different findings, and one badge would hide which of them was established.</p>\n"
            f"<table>{header}{body}</table>{notes}"
        )

    def _provenance_notes(self, faceted: tuple[ProvenanceFacets, ...]) -> str:
        notes = [
            f"<li>{_text(item.artifact_path)}: {_text(caveat)}</li>"
            for item in faceted
            for caveat in item.caveats()
        ]
        if not notes:
            return ""
        return f'<h3>What these results do not say</h3>\n<ul class="notes">{"".join(notes)}</ul>'

    def _findings(self, report: ScanReport) -> str:
        if not report.findings:
            return "<h2>Findings</h2>\n<p>No findings within the detector scope that ran.</p>"
        grouped: dict[ConfidenceType, list[Finding]] = {}
        for finding in report.findings:
            grouped.setdefault(finding.confidence_type, []).append(finding)
        blocks = ["<h2>Findings</h2>"]
        # Ordered by what the class claims, strongest first, so a reader meets a
        # deterministic observation before a heuristic one rather than after it.
        for confidence in ConfidenceType:
            findings = grouped.get(confidence)
            if not findings:
                continue
            meaning = _CONFIDENCE_MEANING.get(confidence, "")
            header = (
                "<tr><th>Severity</th><th>Category</th><th>Artifact</th>"
                "<th>Finding</th><th>Detector</th><th>Removable</th></tr>"
            )
            rows = "".join(
                _row(
                    [
                        f'<td><span class="tag sev-{_text(item.severity.value)}">'
                        f"{_text(item.severity.value)}</span></td>",
                        _cell(item.category.value),
                        _cell(item.artifact_path, css="wrap"),
                        f'<td class="wrap"><strong>{_text(item.title)}</strong><br>'
                        f"{_text(item.description)}</td>",
                        _cell(item.detector_id, css="wrap"),
                        _cell("yes" if item.removable else "no"),
                    ]
                )
                for item in sorted(
                    findings,
                    key=lambda finding: (
                        _SEVERITY_ORDER[finding.severity],
                        finding.artifact_path.casefold(),
                        finding.id,
                    ),
                )
            )
            blocks.append(
                f"<h3>{_text(confidence.value)} ({len(findings)})</h3>\n"
                f'<p class="meaning">{_text(meaning)}</p>\n'
                f"<table>{header}{rows}</table>"
            )
        return "\n".join(blocks)

    def _diagnostics(self, report: ScanReport) -> str:
        if not report.diagnostics:
            return ""
        counts = Counter(item.code for item in report.diagnostics)
        header = "<tr><th>Severity</th><th>Code</th><th>Artifact</th><th>Message</th></tr>"
        rows = "".join(
            _row(
                [
                    f'<td><span class="tag sev-{_text(item.severity.value)}">'
                    f"{_text(item.severity.value)}</span></td>",
                    _cell(item.code),
                    _cell(item.artifact_path or "—", css="wrap"),
                    _cell(item.message, css="wrap"),
                ]
            )
            for item in report.diagnostics
        )
        return (
            f"<h2>Coverage and diagnostics ({sum(counts.values())})</h2>\n"
            '<p class="meaning">A scan that could not read something did not find it clean. '
            "These entries bound what the findings above are evidence of.</p>\n"
            f"<table>{header}{rows}</table>"
        )

    def _integrity(self, report: ScanReport) -> str:
        integrity = report.integrity
        return (
            "<h2>Integrity</h2>\n"
            f'<p><span class="tag">{_text(integrity.status.value)}</span> '
            f"{_text(integrity.explanation)}</p>"
        )

    def _footer(self, report: ScanReport) -> str:
        return (
            "<footer>"
            f"Scan {_text(report.scan_id)} · trueai-core {_text(report.package_version)} · "
            f"report schema {_text(report.schema_version)}. "
            "This document contains no script and refers to no external resource."
            "</footer>"
        )


def _facet_cell(row: FacetRow) -> str:
    """Render one provenance facet, styling an unanswered question as unanswered."""

    css = "tag unknown" if row.unknown else "tag"
    return (
        f'<td><span class="{_text(css)}" title="{_text(row.detail)}">'
        f"{_text(row.answer.replace('_', ' '))}</span></td>"
    )


__all__ = ["CONTENT_SECURITY_POLICY", "HTMLReporter"]
