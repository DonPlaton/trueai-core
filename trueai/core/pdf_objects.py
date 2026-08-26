"""A bounded object-graph model of a PDF, for inspection only.

The lexical scanner this replaces finds `trailer`, reads `/Info`, and follows a
textual search for `N G obj`. That works on PDFs written the way they were
written in 2003. Since PDF 1.5 a producer may put the cross-reference table in a
*stream* — no `trailer` keyword appears anywhere — and put `/Info` and the
catalog inside a compressed *object stream*. Against those files the lexical
scanner reports nothing at all, and reporting nothing looks exactly like finding
nothing.

So this walks the graph properly: `startxref` to a cross-reference table or
stream, back through `/Prev` for incremental updates, into object streams, and
out to the objects that carry metadata, signatures, and provenance.

Doing that means decompressing attacker-supplied data, which is the reason this
module is mostly limits. A PDF is a container format that can ask a parser to
allocate as much memory as the parser is willing to allocate, and the classic
attack is a few kilobytes of Flate that expand to gigabytes. Every decompression
here runs through :func:`inflate_bounded`, which decompresses *into a cap* rather
than decompressing and then checking the size — the difference between refusing a
bomb and detonating it and then complaining.

Nothing here writes, and nothing here decides. It reports what the document
contains, including the things a cleaner must refuse to touch: encryption,
signature byte ranges, and provenance streams.
"""

from __future__ import annotations

import re
import zlib
from dataclasses import dataclass, field
from typing import Final

#: Every budget is per-document and charged globally, so a file cannot spend a
#: little on each of ten thousand streams.
DEFAULT_MAX_OBJECTS: Final = 50_000
DEFAULT_MAX_INFLATED_BYTES: Final = 64 * 1024 * 1024
DEFAULT_MAX_STREAM_BYTES: Final = 16 * 1024 * 1024
DEFAULT_MAX_XREF_SECTIONS: Final = 64
DEFAULT_MAX_DEPTH: Final = 32
DEFAULT_MAX_TOKENS: Final = 2_000_000

_WHITESPACE: Final = b"\x00\t\n\x0c\r "
_DELIMITERS: Final = b"()<>[]{}/%"

_OBJECT_HEADER = re.compile(rb"(\d+)\s+(\d+)\s+obj\b")

#: Fields in one cross-reference stream entry: type, then two numbers whose
#: meaning depends on it. ISO 32000-1 7.5.8.2.
_XREF_FIELDS = 3


class PdfLimitExceeded(ValueError):
    """Raised when a document asks for more resources than the budget allows.

    Deliberately distinct from :class:`PdfStructureError`: "this file is
    malformed" and "this file is trying to exhaust the parser" are different
    things to tell an operator, and only one of them is an attack.
    """


class PdfStructureError(ValueError):
    """Raised when a document cannot be modelled as a PDF object graph."""


@dataclass(slots=True)
class Budget:
    """What one document is allowed to spend.

    Charged as it goes rather than checked at the end, because a check at the end
    happens after the memory has already been allocated.
    """

    max_objects: int = DEFAULT_MAX_OBJECTS
    max_inflated_bytes: int = DEFAULT_MAX_INFLATED_BYTES
    max_stream_bytes: int = DEFAULT_MAX_STREAM_BYTES
    max_xref_sections: int = DEFAULT_MAX_XREF_SECTIONS
    max_depth: int = DEFAULT_MAX_DEPTH
    max_tokens: int = DEFAULT_MAX_TOKENS

    objects_used: int = 0
    inflated_used: int = 0
    tokens_used: int = 0

    def charge_object(self) -> None:
        self.objects_used += 1
        if self.objects_used > self.max_objects:
            raise PdfLimitExceeded(f"More than {self.max_objects} objects were materialised")

    def charge_tokens(self, count: int = 1) -> None:
        self.tokens_used += count
        if self.tokens_used > self.max_tokens:
            raise PdfLimitExceeded(f"More than {self.max_tokens} tokens were read")

    def charge_inflated(self, count: int) -> None:
        self.inflated_used += count
        if self.inflated_used > self.max_inflated_bytes:
            raise PdfLimitExceeded(
                f"Decompressed output passed {self.max_inflated_bytes} bytes for this document"
            )


def inflate_bounded(payload: bytes, limit: int) -> bytes:
    """Decompress Flate data *into* a cap, refusing anything larger.

    ``zlib.decompress`` would produce the whole output first and let the caller
    discover the size afterwards, which is the bomb going off. The incremental
    decompressor takes a ``max_length`` and leaves the rest in
    ``unconsumed_tail``, so an over-large stream is a refusal that costs one
    buffer.
    """

    decompressor = zlib.decompressobj()
    try:
        output = decompressor.decompress(payload, limit + 1)
    except zlib.error as exc:
        raise PdfStructureError(f"Flate stream could not be decompressed: {exc}") from exc
    if len(output) > limit:
        raise PdfLimitExceeded(f"A single stream decompressed past {limit} bytes")
    return output


# -- object model --------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Reference:
    """An indirect reference, unresolved."""

    number: int
    generation: int


@dataclass(frozen=True, slots=True)
class Name:
    """A PDF name, kept distinct from a string so `/Type` cannot be forged by text."""

    value: str

    def __str__(self) -> str:
        return f"/{self.value}"


@dataclass(frozen=True, slots=True)
class Stream:
    """A stream's dictionary and the raw, still-compressed bytes it wraps."""

    dictionary: dict[str, object]
    raw: bytes
    #: Where the raw bytes start in the file, so a cleaner can locate them.
    raw_offset: int

    @property
    def filters(self) -> tuple[str, ...]:
        value = self.dictionary.get("Filter")
        if isinstance(value, Name):
            return (value.value,)
        if isinstance(value, list):
            return tuple(item.value for item in value if isinstance(item, Name))
        return ()


@dataclass(frozen=True, slots=True)
class SignatureField:
    """A signature field and the byte ranges it covers.

    Recorded so a cleaner can refuse. A signature covers explicit ranges of the
    file, so *any* edit inside them invalidates it, and an edit outside them
    still invalidates the document if the gap between ranges is where the
    signature itself lives.
    """

    object_number: int
    byte_ranges: tuple[tuple[int, int], ...]
    sub_filter: str | None = None


@dataclass(slots=True)
class PdfModel:
    """What the document contains, as far as the budget allowed."""

    version: str
    trailer: dict[str, object] = field(default_factory=dict)
    #: Object number to (offset in file) or (container object stream, index).
    locations: dict[int, tuple[str, int, int]] = field(default_factory=dict)
    info: dict[str, object] = field(default_factory=dict)
    catalog: dict[str, object] = field(default_factory=dict)
    xmp_packets: tuple[tuple[int, bytes], ...] = ()
    signatures: tuple[SignatureField, ...] = ()
    encrypted: bool = False
    #: Present when the document was only partly modelled. A caller that treats a
    #: partial model as complete would report "no metadata" for a file whose
    #: metadata simply exceeded the budget.
    incomplete: tuple[str, ...] = ()

    @property
    def modelled(self) -> bool:
        return not self.incomplete

    @property
    def has_protected_material(self) -> bool:
        """Whether the document carries anything a cleaner must not disturb."""

        return self.encrypted or bool(self.signatures) or bool(self.xmp_packets)


# -- tokenizer -----------------------------------------------------------------------


class _Lexer:
    """A minimal PDF object lexer over one slice of the file."""

    def __init__(self, data: bytes, offset: int, end: int, budget: Budget) -> None:
        self.data = data
        self.offset = offset
        self.end = end
        self.budget = budget

    def skip_space(self) -> None:
        while self.offset < self.end:
            character = self.data[self.offset]
            if character in _WHITESPACE:
                self.offset += 1
            elif character == 0x25:  # a comment runs to the end of the line
                while self.offset < self.end and self.data[self.offset] not in b"\r\n":
                    self.offset += 1
            else:
                return

    def parse(self, depth: int = 0) -> object:
        """Parse one object, refusing anything deeper or longer than the budget."""

        if depth > self.budget.max_depth:
            raise PdfLimitExceeded(f"Object nesting deeper than {self.budget.max_depth}")
        self.budget.charge_tokens()
        self.skip_space()
        if self.offset >= self.end:
            raise PdfStructureError("Unexpected end of object data")
        character = self.data[self.offset]

        if character == 0x2F:  # /
            return self._name()
        if character == 0x28:  # (
            return self._literal_string()
        if self.data.startswith(b"<<", self.offset):
            return self._dictionary(depth)
        if character == 0x3C:  # <
            return self._hex_string()
        if character == 0x5B:  # [
            return self._array(depth)
        if self.data.startswith(b"true", self.offset):
            self.offset += 4
            return True
        if self.data.startswith(b"false", self.offset):
            self.offset += 5
            return False
        if self.data.startswith(b"null", self.offset):
            self.offset += 4
            return None
        return self._number_or_reference()

    def _name(self) -> Name:
        self.offset += 1
        start = self.offset
        while self.offset < self.end:
            character = self.data[self.offset]
            if character in _WHITESPACE or character in _DELIMITERS:
                break
            self.offset += 1
        raw = self.data[start : self.offset]
        # #XX escapes are part of the name syntax; a name that decodes to
        # "Metadata" must not be distinguishable from a literal one.
        decoded = re.sub(rb"#([0-9A-Fa-f]{2})", lambda match: bytes([int(match.group(1), 16)]), raw)
        return Name(decoded.decode("latin-1"))

    def _literal_string(self) -> bytes:
        self.offset += 1
        depth = 1
        out = bytearray()
        while self.offset < self.end:
            character = self.data[self.offset]
            if character == 0x5C:  # backslash
                self.offset += 1
                if self.offset < self.end:
                    out.append(self.data[self.offset])
                    self.offset += 1
                continue
            if character == 0x28:
                depth += 1
            elif character == 0x29:
                depth -= 1
                if depth == 0:
                    self.offset += 1
                    return bytes(out)
            out.append(character)
            self.offset += 1
            if len(out) > self.budget.max_stream_bytes:
                raise PdfLimitExceeded("A literal string exceeded the stream budget")
        raise PdfStructureError("Unterminated literal string")

    def _hex_string(self) -> bytes:
        self.offset += 1
        start = self.offset
        closing = self.data.find(b">", self.offset, self.end)
        if closing < 0:
            raise PdfStructureError("Unterminated hexadecimal string")
        self.offset = closing + 1
        digits = re.sub(rb"[^0-9A-Fa-f]", b"", self.data[start:closing])
        if len(digits) % 2:
            digits += b"0"
        return bytes.fromhex(digits.decode("ascii"))

    def _array(self, depth: int) -> list[object]:
        self.offset += 1
        items: list[object] = []
        while True:
            self.skip_space()
            if self.offset >= self.end:
                raise PdfStructureError("Unterminated array")
            if self.data[self.offset] == 0x5D:  # ]
                self.offset += 1
                return items
            items.append(self.parse(depth + 1))

    def _dictionary(self, depth: int) -> dict[str, object]:
        self.offset += 2
        result: dict[str, object] = {}
        while True:
            self.skip_space()
            if self.data.startswith(b">>", self.offset):
                self.offset += 2
                return result
            if self.offset >= self.end:
                raise PdfStructureError("Unterminated dictionary")
            key = self.parse(depth + 1)
            if not isinstance(key, Name):
                raise PdfStructureError(f"A dictionary key must be a name, got {key!r}")
            result[key.value] = self.parse(depth + 1)

    def _number_or_reference(self) -> object:
        start = self.offset
        while self.offset < self.end:
            character = self.data[self.offset]
            if character in _WHITESPACE or character in _DELIMITERS:
                break
            self.offset += 1
        token = self.data[start : self.offset]
        if not token:
            raise PdfStructureError(f"Unparseable byte {self.data[start : start + 1]!r}")
        # "12 0 R" is a reference; "12 0" followed by anything else is two numbers.
        if token.isdigit():
            saved = self.offset
            self.skip_space()
            second_start = self.offset
            while self.offset < self.end and self.data[self.offset : self.offset + 1].isdigit():
                self.offset += 1
            second = self.data[second_start : self.offset]
            if second.isdigit():
                self.skip_space()
                if self.data.startswith(b"R", self.offset) and (
                    self.offset + 1 >= self.end
                    or self.data[self.offset + 1] in _WHITESPACE
                    or self.data[self.offset + 1] in _DELIMITERS
                ):
                    self.offset += 1
                    return Reference(int(token), int(second))
            self.offset = saved
            return int(token)
        try:
            return float(token)
        except ValueError as exc:
            raise PdfStructureError(f"Unparseable token {token!r}") from exc


# -- the document --------------------------------------------------------------------


class PdfDocument:
    """A lazily materialised object graph, bounded at every step."""

    def __init__(self, data: bytes, budget: Budget | None = None) -> None:
        if not data.startswith(b"%PDF-"):
            raise PdfStructureError("The PDF signature is missing")
        self.data = data
        self.budget = budget or Budget()
        self.locations: dict[int, tuple[str, int, int]] = {}
        self.trailer: dict[str, object] = {}
        self._cache: dict[int, object] = {}
        self._object_stream_cache: dict[int, dict[int, object]] = {}
        self.incomplete: list[str] = []

    # -- cross references -------------------------------------------------------------

    def load_cross_references(self) -> None:
        """Follow `startxref` and every `/Prev`, classic tables and streams alike."""

        tail = self.data[-2048:]
        marker = tail.rfind(b"startxref")
        if marker < 0:
            raise PdfStructureError("No startxref marker in the bounded tail")
        offset_text = re.match(rb"\s*(\d+)", tail[marker + 9 :])
        if offset_text is None:
            raise PdfStructureError("startxref is not followed by an offset")
        offset = int(offset_text.group(1))

        seen: set[int] = set()
        sections = 0
        while offset and offset not in seen:
            if sections >= self.budget.max_xref_sections:
                self.incomplete.append(
                    f"the cross-reference chain is longer than {self.budget.max_xref_sections}"
                )
                return
            seen.add(offset)
            sections += 1
            if offset >= len(self.data):
                self.incomplete.append(f"a cross-reference offset points past the file: {offset}")
                return
            try:
                trailer = self._read_section(offset)
            except (PdfStructureError, PdfLimitExceeded) as exc:
                self.incomplete.append(f"a cross-reference section could not be read: {exc}")
                return
            for key, value in trailer.items():
                # Earlier sections win: the newest trailer is read first, and an
                # older one must not overwrite what supersedes it.
                self.trailer.setdefault(key, value)
            following = trailer.get("Prev")
            # An /XRefStm points at a classic table shadowed by a hybrid file.
            hybrid = trailer.get("XRefStm")
            if isinstance(hybrid, int) and hybrid not in seen:
                try:
                    self._read_section(hybrid)
                    seen.add(hybrid)
                except (PdfStructureError, PdfLimitExceeded) as exc:
                    self.incomplete.append(f"a hybrid cross-reference section failed: {exc}")
            offset = following if isinstance(following, int) else 0

    def _read_section(self, offset: int) -> dict[str, object]:
        lexer = _Lexer(self.data, offset, len(self.data), self.budget)
        lexer.skip_space()
        if self.data.startswith(b"xref", lexer.offset):
            return self._read_classic_table(lexer.offset + 4)
        return self._read_xref_stream(offset)

    def _read_classic_table(self, offset: int) -> dict[str, object]:
        cursor = offset
        while True:
            header = re.match(rb"\s*(\d+)\s+(\d+)\s*", self.data[cursor : cursor + 64])
            if header is None:
                break
            first, count = int(header.group(1)), int(header.group(2))
            if count > self.budget.max_objects:
                raise PdfLimitExceeded(f"A cross-reference subsection declares {count} entries")
            cursor += header.end()
            for index in range(count):
                entry = self.data[cursor : cursor + 20]
                match = re.match(rb"\s*(\d{10})\s+(\d{5})\s+([nf])", entry)
                if match is None:
                    raise PdfStructureError("Malformed cross-reference entry")
                if match.group(3) == b"n":
                    # setdefault: the newest section was read first and wins.
                    self.locations.setdefault(
                        first + index, ("file", int(match.group(1)), int(match.group(2)))
                    )
                cursor += 20
        trailer_at = self.data.find(b"trailer", cursor)
        if trailer_at < 0:
            raise PdfStructureError("A classic cross-reference table has no trailer")
        lexer = _Lexer(self.data, trailer_at + 7, len(self.data), self.budget)
        parsed = lexer.parse()
        if not isinstance(parsed, dict):
            raise PdfStructureError("A trailer is not a dictionary")
        return parsed

    def _read_xref_stream(self, offset: int) -> dict[str, object]:
        number, generation, body_start = self._object_header_at(offset)
        del number, generation
        stream = self._parse_object_body(body_start)
        if not isinstance(stream, Stream):
            raise PdfStructureError("A cross-reference offset does not point at a stream")
        dictionary = stream.dictionary
        if dictionary.get("Type") != Name("XRef"):
            raise PdfStructureError("A cross-reference stream is not /Type /XRef")
        payload = self.decode_stream(stream)

        widths = dictionary.get("W")
        if not isinstance(widths, list) or not all(isinstance(item, int) for item in widths):
            raise PdfStructureError("A cross-reference stream has no usable /W")
        field_widths = [int(item) for item in widths if isinstance(item, int)]
        # ISO 32000-1 7.5.8.2: three fields, and the three reads below assume it.
        # Without this a file declaring two widths reaches `values[2]` and raises
        # an IndexError out of a parser whose contract is to refuse.
        if len(field_widths) < _XREF_FIELDS:
            raise PdfStructureError(
                f"A cross-reference stream declares {len(field_widths)} field widths; "
                f"an entry has {_XREF_FIELDS}"
            )
        if any(width < 0 for width in field_widths):
            raise PdfStructureError("A cross-reference stream declares a negative field width")
        size = dictionary.get("Size")
        index = dictionary.get("Index")
        if isinstance(index, list) and all(isinstance(item, int) for item in index):
            pairs = [(int(index[i]), int(index[i + 1])) for i in range(0, len(index) - 1, 2)]
        elif isinstance(size, int):
            pairs = [(0, size)]
        else:
            raise PdfStructureError("A cross-reference stream has neither /Index nor /Size")

        row = sum(field_widths[:_XREF_FIELDS])
        if row <= 0:
            raise PdfStructureError("A cross-reference stream declares zero-width fields")
        cursor = 0
        for first, count in pairs:
            if count > self.budget.max_objects:
                raise PdfLimitExceeded(f"A cross-reference stream declares {count} entries")
            for position in range(count):
                if cursor + row > len(payload):
                    raise PdfStructureError("A cross-reference stream is shorter than it declares")
                values: list[int] = []
                # Only the three the specification defines. A file may carry more
                # elements in /W; they have no meaning and a conservative reader
                # does not act on them.
                for width in field_widths[:_XREF_FIELDS]:
                    values.append(int.from_bytes(payload[cursor : cursor + width], "big"))
                    cursor += width
                kind = values[0] if field_widths[0] else 1
                if kind == 1:
                    self.locations.setdefault(first + position, ("file", values[1], values[2]))
                elif kind == 2:
                    self.locations.setdefault(first + position, ("objstm", values[1], values[2]))
        return dictionary

    # -- objects ----------------------------------------------------------------------

    def _object_header_at(self, offset: int) -> tuple[int, int, int]:
        match = _OBJECT_HEADER.match(self.data, offset)
        if match is None:
            window = self.data[offset : offset + 64]
            match = _OBJECT_HEADER.search(window)
            if match is None:
                raise PdfStructureError(f"No object header at offset {offset}")
            return int(match.group(1)), int(match.group(2)), offset + match.end()
        return int(match.group(1)), int(match.group(2)), match.end()

    def _parse_object_body(self, start: int) -> object:
        lexer = _Lexer(self.data, start, len(self.data), self.budget)
        value = lexer.parse()
        lexer.skip_space()
        if not self.data.startswith(b"stream", lexer.offset):
            return value
        if not isinstance(value, dict):
            raise PdfStructureError("A stream is not preceded by a dictionary")
        cursor = lexer.offset + 6
        if self.data.startswith(b"\r\n", cursor):
            cursor += 2
        elif self.data.startswith(b"\n", cursor) or self.data.startswith(b"\r", cursor):
            cursor += 1
        length = self.resolve(value.get("Length"))
        if isinstance(length, int) and 0 <= length <= len(self.data) - cursor:
            end = cursor + length
        else:
            end = self.data.find(b"endstream", cursor)
            if end < 0:
                raise PdfStructureError("A stream has no endstream marker")
        if end - cursor > self.budget.max_stream_bytes:
            raise PdfLimitExceeded(
                f"A stream is {end - cursor} raw bytes, past the {self.budget.max_stream_bytes} cap"
            )
        return Stream(dictionary=value, raw=self.data[cursor:end], raw_offset=cursor)

    def fetch(self, number: int) -> object:
        """Materialise one object, from the file or from an object stream."""

        if number in self._cache:
            return self._cache[number]
        location = self.locations.get(number)
        if location is None:
            return None
        self.budget.charge_object()
        kind, first, second = location
        if kind == "file":
            if first >= len(self.data):
                raise PdfStructureError(f"Object {number} points past the file")
            _, _, body = self._object_header_at(first)
            value = self._parse_object_body(body)
        else:
            value = self._object_stream(first).get(second)
        self._cache[number] = value
        return value

    def _object_stream(self, container: int) -> dict[int, object]:
        """Parse one `/ObjStm`, which is where modern PDFs keep their metadata."""

        if container in self._object_stream_cache:
            return self._object_stream_cache[container]
        self._object_stream_cache[container] = {}
        stream = self.fetch(container)
        if not isinstance(stream, Stream):
            return {}
        payload = self.decode_stream(stream)
        count = self.resolve(stream.dictionary.get("N"))
        offset_start = self.resolve(stream.dictionary.get("First"))
        if not isinstance(count, int) or not isinstance(offset_start, int):
            raise PdfStructureError("An object stream has no usable /N and /First")
        if count > self.budget.max_objects:
            raise PdfLimitExceeded(f"An object stream declares {count} objects")
        header = payload[:offset_start].split()
        parsed: dict[int, object] = {}
        for index in range(count):
            if index * 2 + 1 >= len(header):
                raise PdfStructureError("An object stream header is shorter than it declares")
            relative = int(header[index * 2 + 1])
            lexer = _Lexer(payload, offset_start + relative, len(payload), self.budget)
            parsed[index] = lexer.parse()
        self._object_stream_cache[container] = parsed
        return parsed

    def resolve(self, value: object, depth: int = 0) -> object:
        """Follow indirect references, refusing a cycle rather than chasing it."""

        seen: set[int] = set()
        while isinstance(value, Reference):
            if value.number in seen or depth > self.budget.max_depth:
                raise PdfStructureError(f"Reference cycle through object {value.number}")
            seen.add(value.number)
            depth += 1
            value = self.fetch(value.number)
        return value

    def decode_stream(self, stream: Stream) -> bytes:
        """Return a stream's bytes, decoding only filters that are safe to decode."""

        payload = stream.raw
        for name in stream.filters:
            if name in ("FlateDecode", "Fl"):
                payload = inflate_bounded(payload, self.budget.max_stream_bytes)
                self.budget.charge_inflated(len(payload))
            elif name in ("ASCIIHexDecode", "AHx"):
                digits = re.sub(rb"[^0-9A-Fa-f]", b"", payload.split(b">")[0])
                if len(digits) % 2:
                    digits += b"0"
                payload = bytes.fromhex(digits.decode("ascii"))
                self.budget.charge_inflated(len(payload))
            else:
                # Every other filter — LZW, RunLength, DCT, JBIG2, CCITT, and any
                # crypt filter — is left encoded rather than decoded by guesswork.
                # An inspector that pretends to have read a stream it could not
                # decode reports absence as evidence.
                raise PdfStructureError(f"Filter {name} is not decoded by this inspector")
        predictor = self.resolve(stream.dictionary.get("DecodeParms"))
        if isinstance(predictor, dict):
            payload = self._undo_predictor(payload, predictor)
        return payload

    def _undo_predictor(self, payload: bytes, params: dict[str, object]) -> bytes:
        """Reverse a PNG predictor, which cross-reference streams routinely use."""

        kind = self.resolve(params.get("Predictor"))
        if not isinstance(kind, int) or kind < 10:
            return payload
        columns = self.resolve(params.get("Columns"))
        colors = self.resolve(params.get("Colors")) or 1
        bits = self.resolve(params.get("BitsPerComponent")) or 8
        if not isinstance(columns, int) or not isinstance(colors, int) or not isinstance(bits, int):
            raise PdfStructureError("A predictor declares unusable parameters")
        row_length = (columns * colors * bits + 7) // 8
        if row_length <= 0 or row_length > self.budget.max_stream_bytes:
            raise PdfLimitExceeded("A predictor declares an unusable row length")
        out = bytearray()
        previous = bytearray(row_length)
        cursor = 0
        while cursor + 1 + row_length <= len(payload):
            tag = payload[cursor]
            row = bytearray(payload[cursor + 1 : cursor + 1 + row_length])
            cursor += 1 + row_length
            if tag == 2:  # Up, the only predictor xref streams use in practice
                for index in range(row_length):
                    row[index] = (row[index] + previous[index]) & 0xFF
            elif tag not in (0,):
                raise PdfStructureError(f"PNG predictor {tag} is not supported")
            out.extend(row)
            previous = row
        return bytes(out)


# -- the model -----------------------------------------------------------------------


def model_pdf(data: bytes, budget: Budget | None = None) -> PdfModel:
    """Build the bounded model, recording what it could not reach.

    A budget exhaustion is recorded in ``incomplete`` rather than raised, because
    the caller's next question is "what did you find?" and "nothing, and here is
    why" is a different answer from "nothing".
    """

    document = PdfDocument(data, budget)
    version_match = re.match(rb"%PDF-(\d+\.\d+)", data)
    version = version_match.group(1).decode("ascii") if version_match else "unknown"

    try:
        document.load_cross_references()
    except (PdfStructureError, PdfLimitExceeded) as exc:
        return PdfModel(version=version, incomplete=(str(exc),))

    info: dict[str, object] = {}
    catalog: dict[str, object] = {}
    xmp: list[tuple[int, bytes]] = []
    signatures: list[SignatureField] = []

    try:
        resolved_info = document.resolve(document.trailer.get("Info"))
        if isinstance(resolved_info, dict):
            info = resolved_info
        resolved_root = document.resolve(document.trailer.get("Root"))
        if isinstance(resolved_root, dict):
            catalog = resolved_root
            xmp.extend(_collect_xmp(document, catalog))
            signatures.extend(_collect_signatures(document, catalog))
    except (PdfStructureError, PdfLimitExceeded) as exc:
        document.incomplete.append(str(exc))

    return PdfModel(
        version=version,
        trailer=document.trailer,
        locations=dict(document.locations),
        info=info,
        catalog=catalog,
        xmp_packets=tuple(xmp),
        signatures=tuple(signatures),
        encrypted="Encrypt" in document.trailer,
        incomplete=tuple(document.incomplete),
    )


def _collect_xmp(document: PdfDocument, catalog: dict[str, object]) -> list[tuple[int, bytes]]:
    """Return the document-level XMP packet, by object number and bytes."""

    reference = catalog.get("Metadata")
    if not isinstance(reference, Reference):
        return []
    stream = document.resolve(reference)
    if not isinstance(stream, Stream):
        return []
    if stream.dictionary.get("Type") != Name("Metadata"):
        return []
    try:
        payload = document.decode_stream(stream)
    except PdfStructureError:
        # An undecodable metadata stream is still present. Saying so is more
        # useful than silently reporting no XMP at all.
        return [(reference.number, b"")]
    return [(reference.number, payload)]


def _collect_signatures(document: PdfDocument, catalog: dict[str, object]) -> list[SignatureField]:
    """Find signature fields and the byte ranges they cover."""

    form = document.resolve(catalog.get("AcroForm"))
    if not isinstance(form, dict):
        return []
    fields = document.resolve(form.get("Fields"))
    if not isinstance(fields, list):
        return []
    found: list[SignatureField] = []
    for entry in fields:
        number = entry.number if isinstance(entry, Reference) else -1
        widget = document.resolve(entry)
        if not isinstance(widget, dict) or widget.get("FT") != Name("Sig"):
            continue
        value = document.resolve(widget.get("V"))
        ranges: tuple[tuple[int, int], ...] = ()
        sub_filter: str | None = None
        if isinstance(value, dict):
            raw_ranges = document.resolve(value.get("ByteRange"))
            if isinstance(raw_ranges, list):
                numbers = [int(item) for item in raw_ranges if isinstance(item, (int, float))]
                ranges = tuple(
                    (numbers[index], numbers[index] + numbers[index + 1])
                    for index in range(0, len(numbers) - 1, 2)
                )
            filter_name = value.get("SubFilter")
            if isinstance(filter_name, Name):
                sub_filter = filter_name.value
        found.append(
            SignatureField(object_number=number, byte_ranges=ranges, sub_filter=sub_filter)
        )
    return found


__all__ = [
    "DEFAULT_MAX_DEPTH",
    "DEFAULT_MAX_INFLATED_BYTES",
    "DEFAULT_MAX_OBJECTS",
    "DEFAULT_MAX_STREAM_BYTES",
    "DEFAULT_MAX_TOKENS",
    "DEFAULT_MAX_XREF_SECTIONS",
    "Budget",
    "Name",
    "PdfDocument",
    "PdfLimitExceeded",
    "PdfModel",
    "PdfStructureError",
    "Reference",
    "SignatureField",
    "Stream",
    "inflate_bounded",
    "model_pdf",
]
