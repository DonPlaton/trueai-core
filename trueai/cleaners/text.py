"""Exact-span text cleanup with encoding preservation and transform verification."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from trueai.cleaners.base import CleanerOutcome
from trueai.core.errors import RemediationError
from trueai.core.integrity import verify_exact_transform
from trueai.core.models import Remediation, ScanOptions


@dataclass(frozen=True, slots=True)
class _Span:
    start: int
    end: int
    expected: str | None
    label: str


class TextCleaner:
    """Apply only detector-provided exact spans or tightly scoped HTML matches."""

    supported_remediation_ids = frozenset(
        {
            "text.remove-invisible",
            "text.remove-attribution-line",
            "text.remove-attribution-comment",
            "html.remove-generator-metadata",
            "html.remove-attribution-comment",
        }
    )

    def apply(
        self,
        source: Path,
        destination: Path,
        remediations: tuple[Remediation, ...],
        options: ScanOptions | None = None,
    ) -> CleanerOutcome:
        before = source.read_bytes()
        text, encoder = self._decode(before)
        spans: list[_Span] = []
        for remediation in remediations:
            if remediation.remediation_id not in self.supported_remediation_ids:
                raise RemediationError(
                    f"Text cleaner does not support {remediation.remediation_id}"
                )
            findings = remediation.payload.get("findings", [])
            if not isinstance(findings, (list, tuple)):
                raise RemediationError("Malformed remediation payload")
            for raw_finding in findings:
                if not isinstance(raw_finding, dict):
                    raise RemediationError("Malformed finding in remediation payload")
                finding_spans = self._spans_for(
                    remediation.remediation_id,
                    raw_finding,
                    text,
                )
                if not finding_spans:
                    raise RemediationError(
                        "A planned text finding no longer matches the current artifact"
                    )
                spans.extend(finding_spans)
        spans, labels = self._deduplicate_and_validate(spans, text)
        cleaned = text
        for span in sorted(spans, key=lambda item: item.start, reverse=True):
            cleaned = cleaned[: span.start] + cleaned[span.end :]
        expected_after = encoder(cleaned)
        destination.write_bytes(expected_after)
        after = destination.read_bytes()
        integrity = verify_exact_transform(
            before,
            after,
            expected_after,
            intentionally_removed=labels,
            explanation=(
                "Output exactly matches the planned span removals; encoding was preserved. "
                "Visible attribution removals are listed explicitly."
            ),
        )
        return CleanerOutcome(changed_fields=labels, integrity=integrity)

    def _spans_for(self, remediation_id: str, finding: dict[str, Any], text: str) -> list[_Span]:
        evidence = finding.get("evidence", {})
        location = finding.get("location") or {}
        if not isinstance(evidence, dict) or not isinstance(location, dict):
            return []
        if remediation_id == "text.remove-invisible":
            offset = location.get("offset")
            character = evidence.get("character")
            if isinstance(offset, int) and isinstance(character, str):
                return [
                    _Span(
                        offset,
                        offset + len(character),
                        character,
                        evidence.get("code_point", "character"),
                    )
                ]
        if remediation_id == "text.remove-attribution-line":
            start, end = evidence.get("line_start"), evidence.get("line_end")
            raw = evidence.get("line_raw")
            if isinstance(start, int) and isinstance(end, int) and isinstance(raw, str):
                return [
                    _Span(
                        start,
                        end,
                        raw,
                        f"attribution line: {evidence.get('rule_id', '')}",
                    )
                ]
        if remediation_id == "text.remove-attribution-comment":
            start, end = evidence.get("comment_start"), evidence.get("comment_end")
            comment = evidence.get("comment")
            if isinstance(start, int) and isinstance(end, int) and isinstance(comment, str):
                return [
                    _Span(
                        start,
                        end,
                        comment,
                        f"attribution comment: {evidence.get('rule_id', '')}",
                    )
                ]
        if remediation_id == "html.remove-attribution-comment":
            start, end = evidence.get("comment_start"), evidence.get("comment_end")
            raw = evidence.get("comment_raw")
            if isinstance(start, int) and isinstance(end, int) and isinstance(raw, str):
                return [_Span(start, end, raw, "HTML attribution comment")]
            comment = evidence.get("comment")
            if isinstance(comment, str):
                raw = f"<!--{comment}-->"
                start = text.find(raw)
                if start >= 0:
                    return [_Span(start, start + len(raw), raw, "HTML attribution comment")]
        if remediation_id == "html.remove-generator-metadata":
            start, end = evidence.get("tag_start"), evidence.get("tag_end")
            raw = evidence.get("tag_raw")
            if isinstance(start, int) and isinstance(end, int) and isinstance(raw, str):
                return [_Span(start, end, raw, "HTML generator metadata")]
            content = evidence.get("content", "")
            pattern = re.compile(
                # `[^<>]` rather than `[^>]` in all three places. A `<meta` with
                # no `>` makes each lookahead read to the end of the document,
                # and there are three of them per candidate tag.
                r"(?is)<meta\b(?=[^<>]*\bname\s*=\s*(['\"]?)generator\1)"
                r"(?=[^<>]*\bcontent\s*=\s*(['\"]?)" + re.escape(str(content)) + r"\2)[^<>]*>"
            )
            match = pattern.search(text)
            if match:
                return [
                    _Span(match.start(), match.end(), match.group(0), "HTML generator metadata")
                ]
        return []

    @staticmethod
    def _deduplicate_and_validate(
        spans: list[_Span], text: str
    ) -> tuple[list[_Span], tuple[str, ...]]:
        """Return the spans to cut, plus every label the plan actually satisfies.

        Widest-first ordering means an enclosing removal is seen before anything
        nested inside it, so the nested span is absorbed rather than treated as a
        conflict. Its label is still reported: the user asked for that removal and
        it happens, as part of the larger cut.
        """

        unique = sorted(set(spans), key=lambda item: (item.start, -item.end, item.label))
        retained: list[_Span] = []
        labels: list[str] = []
        for span in unique:
            if span.start < 0 or span.end > len(text) or span.start >= span.end:
                raise RemediationError(f"Invalid planned text span: {span.start}:{span.end}")
            if span.expected is not None and text[span.start : span.end] != span.expected:
                raise RemediationError(
                    "Artifact changed after scanning; planned span no longer matches"
                )
            labels.append(span.label)
            if retained and span.start < retained[-1].end:
                if span.end <= retained[-1].end:
                    continue
                raise RemediationError(
                    "Partially overlapping text remediations require manual review"
                )
            retained.append(span)
        return retained, tuple(labels)

    @staticmethod
    def _decode(data: bytes) -> tuple[str, Any]:
        if data.startswith(b"\xff\xfe"):
            return data[2:].decode("utf-16-le"), lambda text: b"\xff\xfe" + text.encode("utf-16-le")
        if data.startswith(b"\xfe\xff"):
            return data[2:].decode("utf-16-be"), lambda text: b"\xfe\xff" + text.encode("utf-16-be")
        return data.decode("utf-8"), lambda text: text.encode("utf-8")
