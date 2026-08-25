# HTML topology and stylesheet features

`trueai/core/dom_features.py` measures the shape of an HTML document and of a
stylesheet. Everything it produces is a **count**, and that is a deliberate limit
on what the module is allowed to be.

## Counts, not conclusions

A histogram of nesting depth is a fact about a document. "This nesting depth
means a machine wrote it" is not a fact about anything. No function here draws
that conclusion: there are no thresholds, no scores, and no verdicts.

That is not caution for its own sake. A structural signal presented as provenance
is the specific error this project exists to avoid, and the most reliable way to
avoid making it is to build something that *cannot* make it. Two tests enforce
the boundary directly: every evidence key is checked against a list of words that
would indicate a verdict crept in, and every evidence value is required to be a
number or a boolean.

The findings that carry these measurements are `STRUCTURAL_SIGNAL`, severity
`INFO`, `ProvenanceClass.NONE`, not removable, and their description says in
words that they are not evidence of authorship.

## What is measured

**HTML topology** — elements, maximum depth, a depth histogram, a tag histogram,
wrapper-only elements (an element whose sole child is one element and which holds
no text), inline styles, duplicate ids, class tokens, attributes, comments,
script and style elements, external references, unclosed elements, and mismatched
closes.

Text and markup characters are reported **separately** rather than as a ratio, so
a reader can compute whichever ratio they actually want. Script and stylesheet
bodies count as markup, not text — otherwise a page with one large bundle looks
text-heavy.

Void elements (`<br>`, `<img>`, …) are never counted as unclosed. A stray `</div>`
with no opening tag is counted as a *mismatched close*, separately from an
element that was opened and never closed: those are different shapes, and merging
them into one "error" count would lose the distinction.

**Stylesheet features** — rules, selectors, declarations, at-rules by name,
`!important` declarations, vendor-prefixed properties, custom properties, a
specificity histogram, the longest selector, duplicate selectors, a property
histogram, comments, and embedded data URIs.

Specificity uses the CSS cascade's own `(id, class, type)` definition rather than
an approximation, because a reader comparing two stylesheets needs the number the
browser would use.

The CSS parser matches braces **by depth**. The obvious implementation — find the
next `}` — breaks on `@media screen { .a { color: red } }`, where the first `}`
is in the middle of the block: `.a { color` then looks like a declaration named
`.a { color`. That is a parser reporting nonsense with total confidence, and the
tests caught it.

## Budgets

Both extractors consume attacker-supplied text, and a document can be shaped to
make a parser allocate. Every budget is charged as it is consumed.

| Budget | Default | What it stops |
|---|---|---|
| `max_nodes` | 200,000 | An element count that exists to be walked |
| `max_depth` | 256 | Nesting that would recurse the parser |
| `max_retained_bytes` | 8 MB | Bytes the extractor *keeps* — class names, ids, property names — rather than bytes it passes over |
| `max_events` | 500,000 | Parser events, wired to `ScanOptions.max_parser_events` |
| `max_rules` | 100,000 | Stylesheet rules |

A budget exhaustion returns **partial measurements** with `truncated_by` set,
rather than raising. The caller's next question is "what does this document look
like?", and "as far as ten thousand elements, it looks like this" is a better
answer than an exception — provided the partiality is impossible to miss, which
is what `complete` and the `complete` evidence key are for.
