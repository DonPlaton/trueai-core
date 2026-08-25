# The HTML report

```
trueai scan ./repository -f html -o report.html
```

One file. No script, no external stylesheet, no font, no image, no network. It
opens from a USB stick on an air-gapped machine, which is where a forensic report
most often gets read.

## The threat is the report itself

Every string in a report came from the file under examination — a name, a
metadata value, a manifest field, an exception message — and the report is then
opened in a browser by the person examining it. That is the attack in one
sentence: put script in a document, have it run in the analyst's browser when
they read about it.

Three things stop it, and each is checked rather than intended.

**One function turns a value into markup**, and it escapes `&`, `<`, `>`, `"`,
and `'`. The same function is correct in a text node and in a quoted attribute,
so there is no second one to forget and no per-context decision to get wrong.

**The document contains no script and refers to nothing.** No `<script>`, no
event-handler attribute, no `src`, `href`, or `action` anywhere in it.

**The document declares its own policy**, and satisfies it:

```
default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; script-src 'none';
base-uri 'none'; form-action 'none'; frame-ancestors 'none'
```

Declaring a policy the content already meets is the point: it turns "we escaped
everything" from a claim into something the browser enforces.

### How that is tested

`tests/unit/test_html_reporter.py` **parses** the output rather than grepping it.
Substring checks read escaped text as markup — `onmouseover=&quot;` looks like an
event handler to `in` and is inert to a parser — so the tests ask
`html.parser.HTMLParser` what elements and attributes the document actually
contains and assert that every tag is one the reporter writes and that no
attribute name starts with `on` or can fetch anything.

The suite is checked for teeth: with escaping deliberately removed, 13 of its
tests fail.

Hostile values go through the whole pipeline, including a filename containing
characters a filesystem actually permits — `<` and `>` are illegal in a Windows
filename, so a test using those would prove nothing on the platform it ran on.

## What the page shows, and what it refuses to blur

**Findings are grouped by confidence class**, strongest first, each group headed
by what that class actually claims. A reader who does not know the difference
between deterministic and heuristic is exactly the reader who will treat a
heuristic as a fact, so the page says it next to the heading rather than in a
legend somewhere else.

**Provenance is four columns, not one badge** — marker, signature, signer trust,
provider — from the same projection the terminal uses, and a question that was
never answered is styled as unanswered rather than as a negative result. See
[provenance](provenance.md).

**Caveats are printed.** "What these results do not say" lists, per artifact, the
ways a positive-looking facet is weaker than it looks: a valid signature from an
unknown signer, a scan run with no trust anchors configured, a container nothing
examined.

**Diagnostics bound the findings.** A scan that could not read something did not
find it clean, so coverage problems are a section rather than a footnote.

## Stability

The same report renders byte-identically every time, so two runs can be diffed
and a rendered report can be attached to a record. The document records the scan
id, the scanner version, and the report schema version it was produced from.
