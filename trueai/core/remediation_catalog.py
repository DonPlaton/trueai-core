"""Everything TrueAI can remove, declared in one place.

Until this existed, "what can this tool take out of a file" was answerable only
by reading ten cleaners, and the safety class of each operation was derived from
a **prefix match on its identifier**:

    if remediation_id.startswith(("docx.", "pptx.", "xlsx.", "pdf.", "image.", "media.")):
        return RemediationSafety.SAFE_METADATA

That works right up until somebody adds a format and does not add its prefix.
`odf.remove-metadata-field` was classified `predictable_content` for exactly that
reason — not because anybody decided ODF metadata was content, but because "odf."
was never added to a tuple. It happened to fail safe, which is why nothing
noticed, and the next such accident might not.

So safety is declared per remediation here, with a sentence saying why, and the
planner asks the catalogue. A remediation that is not catalogued cannot be
planned at all: an operation nobody wrote down is an operation nobody reviewed.

The catalogue is also the answer to a question an operator is entitled to ask
before running a cleaner over their documents, and to the question a regression
suite has to ask — every entry here must be exercised by a test, which is what
stops a new removable field shipping without a fixture.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from trueai.core.models import RemediationSafety


@dataclass(frozen=True, slots=True)
class RemediationKind:
    """One thing TrueAI knows how to remove, and what removing it costs."""

    remediation_id: str
    #: The format it applies to, as an operator would name it.
    format: str
    #: What comes out, in words. An operator should not have to read a cleaner.
    removes: str
    safety: RemediationSafety
    #: Why that safety class and not the neighbouring one. The field that would
    #: have caught the ODF misclassification, because writing it down forces the
    #: comparison.
    why: str

    @property
    def changes_visible_content(self) -> bool:
        """Whether a reader could see the difference.

        Metadata lives beside the content; a comment or an element lives in it.
        The distinction decides whether a person has to look at the result.
        """

        return self.safety is not RemediationSafety.SAFE_METADATA

    @property
    def requires_explicit_opt_in(self) -> bool:
        return self.safety is RemediationSafety.DESTRUCTIVE


#: Every remediation the codebase can emit. A test asserts this list and the
#: identifiers appearing in the cleaners and detectors are the same set, in both
#: directions, so neither an uncatalogued operation nor a stale entry survives.
CATALOGUE: Final[tuple[RemediationKind, ...]] = (
    # -- OOXML: metadata lives in a separate package part ----------------------
    RemediationKind(
        remediation_id="docx.remove-metadata-field",
        format="docx",
        removes="One field from the OOXML core or app properties part.",
        safety=RemediationSafety.SAFE_METADATA,
        why="docProps is a separate part; the document body is untouched.",
    ),
    RemediationKind(
        remediation_id="docx.remove-custom-property",
        format="docx",
        removes="One custom document property.",
        safety=RemediationSafety.SAFE_METADATA,
        why="A custom property is a separate part; nothing rendered changes.",
    ),
    RemediationKind(
        remediation_id="pptx.remove-metadata-field",
        format="pptx",
        removes="One field from the OOXML core or app properties part.",
        safety=RemediationSafety.SAFE_METADATA,
        why="Same package layout as docx.",
    ),
    RemediationKind(
        remediation_id="pptx.remove-custom-property",
        format="pptx",
        removes="One custom document property.",
        safety=RemediationSafety.SAFE_METADATA,
        why="Same package layout as docx.",
    ),
    RemediationKind(
        remediation_id="xlsx.remove-metadata-field",
        format="xlsx",
        removes="One field from the OOXML core or app properties part.",
        safety=RemediationSafety.SAFE_METADATA,
        why="Same package layout as docx.",
    ),
    RemediationKind(
        remediation_id="xlsx.remove-custom-property",
        format="xlsx",
        removes="One custom document property.",
        safety=RemediationSafety.SAFE_METADATA,
        why="Same package layout as docx.",
    ),
    # -- OpenDocument: the same shape, and it was classified differently --------
    RemediationKind(
        remediation_id="odf.remove-metadata-field",
        format="odf",
        removes="One field from the OpenDocument meta.xml part.",
        safety=RemediationSafety.SAFE_METADATA,
        why=(
            "meta.xml is a separate part, exactly like docProps: content.xml is untouched. "
            "This was predictable_content until the catalogue existed, not by decision but "
            "because 'odf.' was never added to a prefix tuple."
        ),
    ),
    # -- PDF --------------------------------------------------------------------
    RemediationKind(
        remediation_id="pdf.remove-metadata-field",
        format="pdf",
        removes="One entry from the document information dictionary.",
        safety=RemediationSafety.SAFE_METADATA,
        why="The info dictionary is not part of the page content stream.",
    ),
    RemediationKind(
        remediation_id="pdf.remove-xmp",
        format="pdf",
        removes="The XMP metadata stream.",
        safety=RemediationSafety.SAFE_METADATA,
        why="XMP sits beside the page tree and nothing renders from it.",
    ),
    # -- images and media -------------------------------------------------------
    RemediationKind(
        remediation_id="image.remove-metadata",
        format="image",
        removes="An EXIF, XMP, or textual metadata chunk.",
        safety=RemediationSafety.SAFE_METADATA,
        why="The pixel data is untouched; only the surrounding chunks change.",
    ),
    RemediationKind(
        remediation_id="media.remove-metadata-field",
        format="media",
        removes="One metadata field from an ISO-BMFF or EBML container.",
        safety=RemediationSafety.SAFE_METADATA,
        why=(
            "Replaced with same-length padding so no stored offset moves; the samples "
            "themselves are byte-identical afterwards."
        ),
    ),
    # -- text and markup: the removal is in the content -------------------------
    RemediationKind(
        remediation_id="text.remove-invisible",
        format="text",
        removes="Invisible or zero-width characters from the text.",
        safety=RemediationSafety.PREDICTABLE_CONTENT,
        why="It edits the text itself, even though nothing was visible.",
    ),
    RemediationKind(
        remediation_id="text.remove-attribution-line",
        format="text",
        removes="A whole line stating that a tool produced the document.",
        safety=RemediationSafety.PREDICTABLE_CONTENT,
        why="A line a reader can see is removed, so a reader could see the difference.",
    ),
    RemediationKind(
        remediation_id="text.remove-attribution-comment",
        format="text",
        removes="A comment stating that a tool produced the document.",
        safety=RemediationSafety.PREDICTABLE_CONTENT,
        why="It edits the document body, and a comment can carry a sentence's tail.",
    ),
    RemediationKind(
        remediation_id="html.remove-attribution-comment",
        format="html",
        removes="An HTML comment stating that a tool produced the document.",
        safety=RemediationSafety.PREDICTABLE_CONTENT,
        why="A comment sits inside the markup, and removing one can join two text nodes.",
    ),
    RemediationKind(
        remediation_id="html.remove-generator-metadata",
        format="html",
        removes="A generator meta element from the document head.",
        safety=RemediationSafety.PREDICTABLE_CONTENT,
        why="It is an element in the document tree rather than a separate part.",
    ),
    RemediationKind(
        remediation_id="svg.remove-generator-comment",
        format="svg",
        removes="An editor's generator comment.",
        safety=RemediationSafety.PREDICTABLE_CONTENT,
        why="A comment's tail is rendered text; removing one can lose visible characters.",
    ),
    RemediationKind(
        remediation_id="svg.remove-metadata-element",
        format="svg",
        removes="A metadata element from the SVG tree.",
        safety=RemediationSafety.PREDICTABLE_CONTENT,
        why="It is an element inside the rendered document, not a sidecar part.",
    ),
    RemediationKind(
        remediation_id="svg.remove-editor-attributes",
        format="svg",
        removes="Editor-specific namespaced attributes.",
        safety=RemediationSafety.PREDICTABLE_CONTENT,
        why="Attributes live on rendered elements; an editor may rely on them.",
    ),
    # -- the one that rewrites history ------------------------------------------
    RemediationKind(
        remediation_id="git.rewrite-history",
        format="git",
        removes="Attribution from commit metadata, by rewriting history.",
        safety=RemediationSafety.DESTRUCTIVE,
        why=(
            "Every commit identifier downstream changes. It is not reversible for anyone "
            "who already fetched, which is why it needs explicit consent rather than a "
            "policy default."
        ),
    ),
)

_BY_ID: Final[dict[str, RemediationKind]] = {item.remediation_id: item for item in CATALOGUE}


def kind_for(remediation_id: str) -> RemediationKind | None:
    """Return the catalogue entry for an identifier, or ``None`` if uncatalogued."""

    return _BY_ID.get(remediation_id)


def catalogued_ids() -> frozenset[str]:
    """Every identifier the catalogue declares."""

    return frozenset(_BY_ID)


def safety_for(remediation_id: str) -> RemediationSafety:
    """Return the declared safety class, refusing an uncatalogued operation.

    Refusing rather than guessing from a prefix. Guessing is what classified ODF
    metadata as a content change for as long as ODF support existed, and a guess
    that happens to fail safe is still a guess.
    """

    entry = _BY_ID.get(remediation_id)
    if entry is None:
        raise KeyError(
            f"{remediation_id!r} is not in the remediation catalogue; an operation nobody "
            "wrote down is an operation nobody reviewed"
        )
    return entry.safety


__all__ = [
    "CATALOGUE",
    "RemediationKind",
    "catalogued_ids",
    "kind_for",
    "safety_for",
]
