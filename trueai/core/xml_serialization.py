"""Write XML back with the prefixes it was written with.

``ElementTree.tostring`` invents a prefix for every namespace it was not told
about. Cleaning one comment out of an SVG returned ``<ns0:svg xmlns:ns0="…">``
with every child renamed to match, and rewriting one OOXML part turned
``<cp:coreProperties>`` into ``<ns0:coreProperties>``. Both documents are
equivalent XML and every consumer of them disagrees: a diff shows the whole part
changed, and a project that advertises byte-preserving edits to MP4 and PDF
should not hand back a document with each tag renamed.

``tostring`` has a ``default_namespace`` parameter for exactly this and it cannot
be used here: it refuses a document with unqualified attribute names, and every
SVG and OOXML attribute is unqualified. What is left is the prefix table
``tostring`` consults, which is module-global. So the prefixes are read out of
the document being rewritten and installed for the length of one call, under a
lock, rather than imposed on the process permanently.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import cast
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

#: One ``xmlns`` or ``xmlns:prefix`` declaration. The value is bounded and
#: excludes its own quote characters, so an unterminated attribute stops at the
#: next one instead of reading to the end of the document once per declaration.
_DECLARATION = re.compile(rb"""xmlns(?::([A-Za-z_][\w.-]{0,64}))?\s*=\s*(["'])([^"']{0,2048})\2""")

#: More than any real document declares. A file claiming thousands is not one
#: whose prefixes are worth reproducing faithfully.
MAX_DECLARATIONS = 64

#: The table is module-global, so two documents serialized at once would
#: otherwise be able to borrow each other's prefixes.
_LOCK = threading.Lock()


def declared_prefixes(source: bytes) -> dict[str, str]:
    """Return the URI-to-prefix map ``source`` was written with.

    Read from the bytes rather than the parsed tree because ElementTree discards
    prefixes at parse time: by the time there is an ``Element``, the only
    surviving fact is the namespace URI.
    """

    mapping: dict[str, str] = {}
    for match in _DECLARATION.finditer(source):
        if len(mapping) >= MAX_DECLARATIONS:
            break
        prefix = match.group(1).decode("ascii", "replace") if match.group(1) else ""
        uri = match.group(3).decode("utf-8", "replace")
        # First declaration wins: it is the outermost in document order, and so
        # the one a reader of the file would name.
        mapping.setdefault(uri, prefix)
    return mapping


@contextmanager
def preferred_prefixes(mapping: dict[str, str]) -> Iterator[None]:
    """Install a URI-to-prefix map for one serialization, then put it back.

    ``ElementTree._namespace_map`` is private and has been present since 2.7. It
    is read by name inside ``tostring`` itself, so a version without it could not
    serialize namespaced XML at all -- which is why this reaches for it directly
    rather than guarding an absence it could not survive either.
    """

    if not mapping:
        yield
        return
    # Private, and typeshed does not declare it. Reached by name because
    # `tostring` reaches for it by the same name.
    table: dict[str, str] = ElementTree._namespace_map  # type: ignore[attr-defined]
    with _LOCK:
        saved = dict(table)
        table.update(mapping)
        try:
            yield
        finally:
            table.clear()
            table.update(saved)


def serialize_like(root: Element, source: bytes, *, xml_declaration: bool = True) -> bytes:
    """Serialize ``root`` using the prefixes ``source`` declared."""

    with preferred_prefixes(declared_prefixes(source)):
        return cast(
            bytes,
            ElementTree.tostring(root, encoding="utf-8", xml_declaration=xml_declaration),
        )


__all__ = ["MAX_DECLARATIONS", "declared_prefixes", "preferred_prefixes", "serialize_like"]
