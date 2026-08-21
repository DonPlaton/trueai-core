"""Context-sensitive Unicode forensic inspection."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass

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
    UnicodeSafetyClass,
)
from trueai.detectors.base import BaseDetector, FindingBuffer

_TEXT_TYPES = frozenset(
    {
        ArtifactType.TEXT,
        ArtifactType.MARKDOWN,
        ArtifactType.SOURCE_CODE,
        ArtifactType.HTML,
        ArtifactType.CSS,
        ArtifactType.SVG,
    }
)

_NAMED_CLASSES: dict[int, UnicodeSafetyClass] = {
    0x00A0: UnicodeSafetyClass.TYPOGRAPHIC,
    0x00AD: UnicodeSafetyClass.LANGUAGE_DEPENDENT,
    0x200B: UnicodeSafetyClass.INVISIBLE,
    0x200C: UnicodeSafetyClass.LANGUAGE_DEPENDENT,
    0x200D: UnicodeSafetyClass.LANGUAGE_DEPENDENT,
    0x202F: UnicodeSafetyClass.TYPOGRAPHIC,
    0x2060: UnicodeSafetyClass.INVISIBLE,
    0xFEFF: UnicodeSafetyClass.INVISIBLE,
}
_BIDI_CONTROLS = {
    0x061C,
    0x200E,
    0x200F,
    0x202A,
    0x202B,
    0x202C,
    0x202D,
    0x202E,
    0x2066,
    0x2067,
    0x2068,
    0x2069,
}
_PREDICTABLY_REMOVABLE = {0x200B, 0x2060}


@dataclass(frozen=True, slots=True)
class UnicodeClassification:
    """Internal classification with remediation constraints."""

    safety_class: UnicodeSafetyClass
    severity: Severity
    explanation: str
    removable: bool = False


class UnicodeForensicsDetector(BaseDetector):
    """Report unusual and invisible Unicode without blanket malicious labels."""

    id = "text.unicode-forensics.v1"
    supported_types = _TEXT_TYPES
    categories = frozenset({FindingCategory.INVISIBLE_UNICODE, FindingCategory.SUSPICIOUS_UNICODE})

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        text = artifact.read_text(context.options.max_file_size)
        findings = FindingBuffer(context.options.max_findings, self.id)
        line = 1
        column = 1
        for offset, character in enumerate(text):
            classification = self._classify(character, offset)
            if classification is not None:
                code_point = ord(character)
                category = (
                    FindingCategory.INVISIBLE_UNICODE
                    if classification.safety_class
                    in {
                        UnicodeSafetyClass.INVISIBLE,
                        UnicodeSafetyClass.LANGUAGE_DEPENDENT,
                        UnicodeSafetyClass.TYPOGRAPHIC,
                    }
                    else FindingCategory.SUSPICIOUS_UNICODE
                )
                name = unicodedata.name(character, "UNNAMED CHARACTER")
                location = FindingLocation(
                    line=line,
                    column=column,
                    offset=offset,
                    end_offset=offset + 1,
                )
                findings.append(
                    self.finding(
                        artifact=artifact,
                        category=category,
                        confidence=1.0,
                        confidence_type=ConfidenceType.DETERMINISTIC,
                        severity=classification.severity,
                        evidence_type=EvidenceType.TEXT,
                        title=f"{name} (U+{code_point:04X})",
                        description=classification.explanation,
                        evidence={
                            "character": character,
                            "code_point": f"U+{code_point:04X}",
                            "unicode_name": name,
                            "safety_class": classification.safety_class.value,
                            "context": self._context(text, offset),
                        },
                        location=location,
                        removable=classification.removable,
                        remediation_id=(
                            "text.remove-invisible" if classification.removable else None
                        ),
                        provenance_class=ProvenanceClass.NONE,
                        tags=("unicode", classification.safety_class.value),
                    )
                )
            if character == "\n":
                line += 1
                column = 1
            else:
                column += 1
        findings.extend(self._whitespace_patterns(artifact, text))
        return findings

    @staticmethod
    def _classify(character: str, offset: int) -> UnicodeClassification | None:
        code_point = ord(character)
        if code_point == 0xFEFF and offset == 0:
            return UnicodeClassification(
                UnicodeSafetyClass.SAFE,
                Severity.INFO,
                "A leading byte-order mark is present. It is valid encoding metadata.",
            )
        if code_point in _BIDI_CONTROLS:
            return UnicodeClassification(
                UnicodeSafetyClass.CONTROL,
                Severity.MEDIUM,
                "A bidirectional text control changes display order. Review it in source context.",
            )
        if 0xFE00 <= code_point <= 0xFE0F or 0xE0100 <= code_point <= 0xE01EF:
            return UnicodeClassification(
                UnicodeSafetyClass.LANGUAGE_DEPENDENT,
                Severity.INFO,
                "A variation selector can intentionally select glyph or emoji presentation.",
            )
        if code_point in _NAMED_CLASSES:
            safety_class = _NAMED_CLASSES[code_point]
            explanations = {
                0x00A0: "A non-breaking space is often typographic and affects line wrapping.",
                0x00AD: "A soft hyphen can be a legitimate discretionary line-break hint.",
                0x200B: "A zero-width space is invisible and may be accidental or intentional.",
                0x200C: "A zero-width non-joiner is meaningful in several writing systems.",
                0x200D: "A zero-width joiner is meaningful in scripts and emoji sequences.",
                0x202F: "A narrow non-breaking space is legitimate in several typographic conventions.",
                0x2060: "A word joiner is invisible and prevents a line break at this position.",
                0xFEFF: "A non-leading BOM acts as an invisible zero-width no-break space.",
            }
            severity = (
                Severity.LOW
                if safety_class in {UnicodeSafetyClass.INVISIBLE, UnicodeSafetyClass.TYPOGRAPHIC}
                else Severity.INFO
            )
            return UnicodeClassification(
                safety_class,
                severity,
                explanations[code_point],
                removable=code_point in _PREDICTABLY_REMOVABLE,
            )
        category = unicodedata.category(character)
        if category == "Cc" and character not in "\t\n\r":
            return UnicodeClassification(
                UnicodeSafetyClass.CONTROL,
                Severity.MEDIUM,
                "A control character is embedded in textual content.",
            )
        if category == "Cf":
            return UnicodeClassification(
                UnicodeSafetyClass.SUSPICIOUS,
                Severity.LOW,
                "An uncommon invisible formatting character is present.",
            )
        if character.isspace() and character not in " \t\n\r":
            return UnicodeClassification(
                UnicodeSafetyClass.TYPOGRAPHIC,
                Severity.INFO,
                "An uncommon Unicode whitespace character is present.",
            )
        return None

    def _whitespace_patterns(self, artifact: Artifact, text: str) -> Iterable[Finding]:
        patterns = (
            (r"(?m)(?<=\S)[ \t]{8,}(?=\S)", "Long embedded whitespace run"),
            (r"(?:\r?\n[ \t]*){4,}", "Repeated blank-line pattern"),
        )
        for pattern, title in patterns:
            line = 1
            previous_offset = 0
            line_start = 0
            for match in re.finditer(pattern, text):
                line_breaks = text.count("\n", previous_offset, match.start())
                if line_breaks:
                    line += line_breaks
                    line_start = text.rfind("\n", previous_offset, match.start()) + 1
                previous_offset = match.start()
                column = match.start() - line_start + 1
                yield self.finding(
                    artifact=artifact,
                    category=FindingCategory.SUSPICIOUS_UNICODE,
                    confidence=0.65,
                    confidence_type=ConfidenceType.HEURISTIC,
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.STRUCTURAL,
                    title=title,
                    description=(
                        "A repeated whitespace structure was measured. It may be intentional "
                        "formatting and is not evidence of AI authorship."
                    ),
                    evidence={
                        "length": match.end() - match.start(),
                        "escaped": match.group(0).encode("unicode_escape").decode("ascii"),
                    },
                    location=FindingLocation(
                        line=line,
                        column=column,
                        offset=match.start(),
                        end_offset=match.end(),
                    ),
                    tags=("whitespace", "heuristic"),
                )

    @staticmethod
    def _context(text: str, offset: int, radius: int = 20) -> str:
        start = max(0, offset - radius)
        end = min(len(text), offset + radius + 1)
        pieces: list[str] = []
        for index, character in enumerate(text[start:end], start=start):
            if index == offset:
                pieces.append(f"⟦U+{ord(character):04X}⟧")
            elif character == "\n":
                pieces.append("\\n")
            elif character == "\r":
                pieces.append("\\r")
            elif unicodedata.category(character) in {"Cf", "Cc"}:
                pieces.append(f"\\u{ord(character):04x}")
            else:
                pieces.append(character)
        return "".join(pieces)
