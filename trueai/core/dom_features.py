"""Bounded structural measurements of HTML documents and stylesheets.

Everything here is a **count**, and that is a deliberate limit on what the module
is allowed to be. A histogram of nesting depth is a fact about a document. "This
nesting depth means a machine wrote it" is not a fact about anything, and no
function here draws that conclusion — the numbers are reported, and a reader who
wants to interpret them does so with their own judgement and their own context.

That distinction is why these are measurements rather than a detector. A
structural signal presented as provenance is the specific error this project
exists to avoid, and the safest way to avoid making it is to build something that
cannot make it: no thresholds, no scores, no verdicts.

The other half of the module is budgets. Both parsers consume attacker-supplied
text, and a document can be shaped to make a parser allocate. Node counts, tree
depth, retained attribute and text bytes, and parser events are all charged as
they are consumed, so a hostile file exhausts a budget instead of the machine.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Final

DEFAULT_MAX_NODES: Final = 200_000
DEFAULT_MAX_DEPTH: Final = 256
DEFAULT_MAX_RETAINED_BYTES: Final = 8 * 1024 * 1024
DEFAULT_MAX_EVENTS: Final = 500_000
DEFAULT_MAX_RULES: Final = 100_000

#: Elements that never have a closing tag. Treating one as unclosed would report
#: every ordinary document as malformed.
VOID_ELEMENTS: Final = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
)


class FeatureLimitExceeded(ValueError):
    """Raised when a document asks for more than the budget allows."""


@dataclass(slots=True)
class FeatureBudget:
    """What one document may spend, charged as it goes."""

    max_nodes: int = DEFAULT_MAX_NODES
    max_depth: int = DEFAULT_MAX_DEPTH
    max_retained_bytes: int = DEFAULT_MAX_RETAINED_BYTES
    max_events: int = DEFAULT_MAX_EVENTS
    max_rules: int = DEFAULT_MAX_RULES

    nodes_used: int = 0
    retained_used: int = 0
    events_used: int = 0

    def charge_node(self) -> None:
        self.nodes_used += 1
        if self.nodes_used > self.max_nodes:
            raise FeatureLimitExceeded(f"More than {self.max_nodes} elements")

    def charge_event(self) -> None:
        self.events_used += 1
        if self.events_used > self.max_events:
            raise FeatureLimitExceeded(f"More than {self.max_events} parser events")

    def charge_retained(self, count: int) -> None:
        """Charge bytes the extractor keeps, not bytes it merely passes over.

        Reading a large document is bounded elsewhere. What matters here is how
        much of it ends up retained in counters and samples, because that is what
        a hostile file can grow without limit.
        """

        self.retained_used += count
        if self.retained_used > self.max_retained_bytes:
            raise FeatureLimitExceeded(
                f"Retained more than {self.max_retained_bytes} bytes of document material"
            )


# -- HTML topology -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DomTopology:
    """Shape measurements for one HTML document.

    None of these fields is a verdict. ``wrapper_only_elements`` counts elements
    whose sole child is another element, which is a real property of the tree; it
    is not evidence about who wrote it.
    """

    elements: int = 0
    max_depth: int = 0
    depth_histogram: dict[int, int] = field(default_factory=dict)
    tag_histogram: dict[str, int] = field(default_factory=dict)
    #: Elements closed by a tag that does not match the one on the stack. A
    #: document can be perfectly readable and still have these.
    mismatched_closes: int = 0
    unclosed_elements: int = 0
    void_elements: int = 0
    comments: int = 0
    #: Elements whose only child is a single element and which carry no text.
    wrapper_only_elements: int = 0
    inline_styles: int = 0
    distinct_ids: int = 0
    duplicate_ids: int = 0
    class_tokens: int = 0
    distinct_class_tokens: int = 0
    attributes: int = 0
    #: Text characters outside script and style, and markup characters. Reported
    #: separately rather than as a ratio, so a reader can compute whichever ratio
    #: they actually want.
    text_characters: int = 0
    markup_characters: int = 0
    script_elements: int = 0
    style_elements: int = 0
    external_references: int = 0
    #: Set when a budget stopped the walk. The measurements are then a lower
    #: bound, and calling them the document's shape would be wrong.
    truncated_by: str | None = None

    @property
    def complete(self) -> bool:
        return self.truncated_by is None

    def as_evidence(self) -> dict[str, object]:
        """Return the measurements in a form a finding can carry."""

        return {
            "elements": self.elements,
            "max_depth": self.max_depth,
            "distinct_tags": len(self.tag_histogram),
            "wrapper_only_elements": self.wrapper_only_elements,
            "inline_styles": self.inline_styles,
            "duplicate_ids": self.duplicate_ids,
            "class_tokens": self.class_tokens,
            "distinct_class_tokens": self.distinct_class_tokens,
            "attributes": self.attributes,
            "text_characters": self.text_characters,
            "markup_characters": self.markup_characters,
            "comments": self.comments,
            "script_elements": self.script_elements,
            "style_elements": self.style_elements,
            "external_references": self.external_references,
            "unclosed_elements": self.unclosed_elements,
            "mismatched_closes": self.mismatched_closes,
            "complete": self.complete,
        }


class _TopologyParser(HTMLParser):
    """Walk the document once, charging the budget at every step."""

    def __init__(self, budget: FeatureBudget) -> None:
        super().__init__(convert_charrefs=True)
        self.budget = budget
        self.stack: list[str] = []
        self.depth_histogram: Counter[int] = Counter()
        self.tag_histogram: Counter[str] = Counter()
        self.identifiers: Counter[str] = Counter()
        self.class_tokens: Counter[str] = Counter()
        self.elements = 0
        self.max_depth = 0
        self.attributes = 0
        self.comments = 0
        self.inline_styles = 0
        self.void_elements = 0
        self.mismatched_closes = 0
        self.text_characters = 0
        self.markup_characters = 0
        self.script_elements = 0
        self.style_elements = 0
        self.external_references = 0
        #: Element index to (child element count, whether it held text).
        self._children: list[int] = []
        self._had_text: list[bool] = []
        self.wrapper_only_elements = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.budget.charge_event()
        self.budget.charge_node()
        self.elements += 1
        self.tag_histogram[tag] += 1
        raw = self.get_starttag_text() or ""
        self.markup_characters += len(raw)
        self.budget.charge_retained(len(tag))

        if self._children:
            self._children[-1] += 1
        if tag in VOID_ELEMENTS:
            self.void_elements += 1
        else:
            self.stack.append(tag)
            self._children.append(0)
            self._had_text.append(False)
            depth = len(self.stack)
            if depth > self.budget.max_depth:
                raise FeatureLimitExceeded(f"Nesting deeper than {self.budget.max_depth}")
            self.max_depth = max(self.max_depth, depth)
            self.depth_histogram[depth] += 1
        if tag == "script":
            self.script_elements += 1
        elif tag == "style":
            self.style_elements += 1

        for key, value in attrs:
            self.attributes += 1
            lowered = key.casefold()
            text = value or ""
            if lowered == "style":
                self.inline_styles += 1
            elif lowered == "id" and text:
                self.identifiers[text] += 1
                self.budget.charge_retained(len(text))
            elif lowered == "class" and text:
                tokens = text.split()
                for token in tokens:
                    self.class_tokens[token] += 1
                self.budget.charge_retained(len(text))
            elif (
                lowered in ("src", "href", "srcset", "data")
                and text
                and not text.startswith(("#", "data:"))
            ):
                # A reference to something not in this file. Counted because a
                # reader deciding whether a document is self-contained needs it.
                self.external_references += 1

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in VOID_ELEMENTS and self.stack and self.stack[-1] == tag:
            self._close_top()

    def handle_endtag(self, tag: str) -> None:
        self.budget.charge_event()
        self.markup_characters += len(tag) + 3
        if tag in VOID_ELEMENTS:
            return
        if tag not in self.stack:
            # A close with no matching open. Real documents contain these; it is
            # a measurement, not an error.
            self.mismatched_closes += 1
            return
        while self.stack and self.stack[-1] != tag:
            self.mismatched_closes += 1
            self._close_top()
        if self.stack:
            self._close_top()

    def _close_top(self) -> None:
        self.stack.pop()
        children = self._children.pop()
        had_text = self._had_text.pop()
        if children == 1 and not had_text:
            self.wrapper_only_elements += 1

    def handle_data(self, data: str) -> None:
        self.budget.charge_event()
        if self.stack and self.stack[-1] in ("script", "style"):
            # Script and stylesheet bodies are not document text. Counting them
            # would make a page with one large bundle look text-heavy.
            self.markup_characters += len(data)
            return
        stripped = data.strip()
        self.text_characters += len(stripped)
        if stripped and self._had_text:
            self._had_text[-1] = True

    def handle_comment(self, data: str) -> None:
        self.budget.charge_event()
        self.comments += 1
        self.markup_characters += len(data) + 7


def extract_dom_topology(text: str, budget: FeatureBudget | None = None) -> DomTopology:
    """Measure a document's shape, stopping cleanly when a budget runs out.

    A budget exhaustion returns partial measurements with ``truncated_by`` set,
    rather than raising. The caller's next question is "what does this document
    look like?", and "as far as N elements, it looks like this" is a better
    answer than an exception — as long as the partiality is impossible to miss,
    which is what ``complete`` is for.
    """

    allowance = budget or FeatureBudget()
    parser = _TopologyParser(allowance)
    truncated: str | None = None
    try:
        parser.feed(text)
        parser.close()
    except FeatureLimitExceeded as exc:
        truncated = str(exc)
    except Exception as exc:
        truncated = f"the parser stopped: {type(exc).__name__}"

    unclosed = len(parser.stack)
    return DomTopology(
        elements=parser.elements,
        max_depth=parser.max_depth,
        depth_histogram=dict(sorted(parser.depth_histogram.items())),
        tag_histogram=dict(parser.tag_histogram.most_common()),
        mismatched_closes=parser.mismatched_closes,
        unclosed_elements=unclosed,
        void_elements=parser.void_elements,
        comments=parser.comments,
        wrapper_only_elements=parser.wrapper_only_elements,
        inline_styles=parser.inline_styles,
        distinct_ids=len(parser.identifiers),
        duplicate_ids=sum(1 for count in parser.identifiers.values() if count > 1),
        class_tokens=sum(parser.class_tokens.values()),
        distinct_class_tokens=len(parser.class_tokens),
        attributes=parser.attributes,
        text_characters=parser.text_characters,
        markup_characters=parser.markup_characters,
        script_elements=parser.script_elements,
        style_elements=parser.style_elements,
        external_references=parser.external_references,
        truncated_by=truncated,
    )


# -- stylesheet features -------------------------------------------------------------


_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_AT_RULE = re.compile(r"@([a-zA-Z-]+)")
_ID_SELECTOR = re.compile(r"#[\w-]+")
_CLASS_SELECTOR = re.compile(r"\.[\w-]+|\[[^\]]*\]|:[a-zA-Z-]+(?:\([^)]*\))?")
_TYPE_SELECTOR = re.compile(r"(?:^|[\s>+~])([a-zA-Z][\w-]*)")


@dataclass(frozen=True, slots=True)
class StylesheetFeatures:
    """Shape measurements for one stylesheet.

    Counts and distributions only. A stylesheet with a thousand `!important`
    declarations is a stylesheet with a thousand `!important` declarations.
    """

    rules: int = 0
    selectors: int = 0
    declarations: int = 0
    at_rules: dict[str, int] = field(default_factory=dict)
    important_declarations: int = 0
    vendor_prefixed_properties: int = 0
    custom_properties: int = 0
    #: Specificity as (ids, classes-and-attributes-and-pseudos, types), counted
    #: per selector and summarised, because the distribution says more than a mean.
    specificity_histogram: dict[str, int] = field(default_factory=dict)
    max_selector_parts: int = 0
    duplicate_selectors: int = 0
    distinct_properties: int = 0
    property_histogram: dict[str, int] = field(default_factory=dict)
    comments: int = 0
    embedded_data_uris: int = 0
    truncated_by: str | None = None

    @property
    def complete(self) -> bool:
        return self.truncated_by is None

    def as_evidence(self) -> dict[str, object]:
        return {
            "rules": self.rules,
            "selectors": self.selectors,
            "declarations": self.declarations,
            "at_rules": sum(self.at_rules.values()),
            "distinct_at_rules": len(self.at_rules),
            "important_declarations": self.important_declarations,
            "vendor_prefixed_properties": self.vendor_prefixed_properties,
            "custom_properties": self.custom_properties,
            "max_selector_parts": self.max_selector_parts,
            "duplicate_selectors": self.duplicate_selectors,
            "distinct_properties": self.distinct_properties,
            "comments": self.comments,
            "embedded_data_uris": self.embedded_data_uris,
            "complete": self.complete,
        }


def selector_specificity(selector: str) -> tuple[int, int, int]:
    """Return the (id, class, type) specificity of one selector.

    The CSS cascade's own definition, not an approximation of it: a reader
    comparing two stylesheets needs the number the browser would use.
    """

    without_ids = _ID_SELECTOR.sub(" ", selector)
    ids = len(_ID_SELECTOR.findall(selector))
    classes = len(_CLASS_SELECTOR.findall(without_ids))
    types = len(_TYPE_SELECTOR.findall(_CLASS_SELECTOR.sub(" ", without_ids)))
    return ids, classes, types


def extract_stylesheet_features(
    text: str, budget: FeatureBudget | None = None
) -> StylesheetFeatures:
    """Measure a stylesheet's shape within a budget.

    The parser is deliberately shallow — brace matching and splitting, not a full
    CSS grammar — because the measurements are counts and a full grammar would
    buy precision the counts do not need while adding surface a hostile file
    could attack.
    """

    allowance = budget or FeatureBudget()
    comments = len(_COMMENT.findall(text))
    body = _COMMENT.sub(" ", text)

    at_rules: Counter[str] = Counter(_AT_RULE.findall(body))
    properties: Counter[str] = Counter()
    specificity: Counter[str] = Counter()
    seen_selectors: Counter[str] = Counter()

    rules = selectors = declarations = 0
    important = vendor = custom = data_uris = 0
    max_parts = 0
    truncated: str | None = None

    def scan(segment: str) -> None:
        """Walk one level of rules, recursing into at-rule blocks.

        Depth-matched rather than "find the next closing brace", because
        `@media ... { .a { color: red } }` has its first `}` in the middle of the
        block. Treating that as the end made `.a { color` look like a declaration
        named `.a { color`, which is how a parser reports nonsense with total
        confidence.
        """

        nonlocal rules, selectors, declarations, important, vendor, custom, data_uris, max_parts

        cursor = 0
        length = len(segment)
        while cursor < length:
            opening = segment.find("{", cursor)
            if opening < 0:
                return
            depth = 1
            closing = opening + 1
            while closing < length and depth:
                if segment[closing] == "{":
                    depth += 1
                elif segment[closing] == "}":
                    depth -= 1
                closing += 1
            if depth:
                # An unclosed block. Stopping is right: guessing where it ended
                # would invent structure the file does not have.
                return
            closing -= 1

            allowance.charge_event()
            rules += 1
            if rules > allowance.max_rules:
                raise FeatureLimitExceeded(f"More than {allowance.max_rules} rules")

            prelude = segment[cursor:opening].strip()
            block = segment[opening + 1 : closing]
            allowance.charge_retained(len(prelude))
            cursor = closing + 1

            if prelude.startswith("@"):
                # An at-rule's prelude is not a selector list, and its block may
                # hold rules rather than declarations.
                if "{" in block:
                    scan(block)
                    continue
                prelude = ""

            for raw_selector in prelude.split(","):
                selector = " ".join(raw_selector.split())
                if not selector:
                    continue
                selectors += 1
                seen_selectors[selector] += 1
                max_parts = max(max_parts, len(selector.split()))
                score = selector_specificity(selector)
                specificity[f"{score[0]}-{score[1]}-{score[2]}"] += 1

            for raw_declaration in block.split(";"):
                if ":" not in raw_declaration or "{" in raw_declaration:
                    continue
                name, _, value = raw_declaration.partition(":")
                name = name.strip().casefold()
                if not name:
                    continue
                declarations += 1
                properties[name] += 1
                allowance.charge_retained(len(name))
                if "!important" in value.casefold():
                    important += 1
                if name.startswith(("-webkit-", "-moz-", "-ms-", "-o-")):
                    vendor += 1
                if name.startswith("--"):
                    custom += 1
                if "url(data:" in value.replace(" ", "").casefold():
                    data_uris += 1

    try:
        scan(body)
    except FeatureLimitExceeded as exc:
        truncated = str(exc)

    return StylesheetFeatures(
        rules=rules,
        selectors=selectors,
        declarations=declarations,
        at_rules=dict(at_rules.most_common()),
        important_declarations=important,
        vendor_prefixed_properties=vendor,
        custom_properties=custom,
        specificity_histogram=dict(specificity.most_common()),
        max_selector_parts=max_parts,
        duplicate_selectors=sum(1 for count in seen_selectors.values() if count > 1),
        distinct_properties=len(properties),
        property_histogram=dict(properties.most_common(50)),
        comments=comments,
        embedded_data_uris=data_uris,
        truncated_by=truncated,
    )


__all__ = [
    "DEFAULT_MAX_DEPTH",
    "DEFAULT_MAX_EVENTS",
    "DEFAULT_MAX_NODES",
    "DEFAULT_MAX_RETAINED_BYTES",
    "DEFAULT_MAX_RULES",
    "VOID_ELEMENTS",
    "DomTopology",
    "FeatureBudget",
    "FeatureLimitExceeded",
    "StylesheetFeatures",
    "extract_dom_topology",
    "extract_stylesheet_features",
    "selector_specificity",
]
