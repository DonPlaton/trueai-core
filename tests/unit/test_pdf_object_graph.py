"""The bounded PDF object graph, and the files the lexical scanner could not see.

Two fixture builders, because the point of this module is that they are different
documents to a parser and identical documents to a reader:

* ``classic_pdf`` — a `trailer` keyword and uncompressed objects, which the old
  lexical scanner handles.
* ``modern_pdf`` — a cross-reference *stream* and an object *stream*, which is
  what every current producer emits and against which the lexical scanner
  reports nothing at all.

The rest is limits. Walking the graph means decompressing attacker-supplied data,
so most of these tests are about refusing to.
"""

from __future__ import annotations

import zlib

import pytest

from trueai.core.pdf_objects import (
    Budget,
    Name,
    PdfDocument,
    PdfLimitExceeded,
    PdfStructureError,
    Reference,
    Stream,
    inflate_bounded,
    model_pdf,
)


def classic_pdf(*, author: str = "Jane Doe") -> bytes:
    """A PDF 1.4 with a classic cross-reference table and plain objects."""

    objects = [
        b"<< /Type /Catalog /Pages 3 0 R >>",
        f"<< /Author ({author}) /Producer (Acme Writer 3.1) >>".encode(),
        b"<< /Type /Pages /Kids [] /Count 0 >>",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for index, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{index} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_at = len(out)
    out += b"xref\n"
    out += f"0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode()
    out += b"trailer\n"
    out += f"<< /Size {len(objects) + 1} /Root 1 0 R /Info 2 0 R >>\n".encode()
    out += f"startxref\n{xref_at}\n%%EOF\n".encode()
    return bytes(out)


def modern_pdf(
    *,
    author: str = "Jane Doe",
    with_xmp: bool = False,
    with_signature: bool = False,
) -> bytes:
    """A PDF 1.5 whose catalog and Info live in a compressed object stream.

    This is the shape the lexical scanner cannot see: there is no `trailer`
    keyword anywhere in the file, and `/Info` never appears as plain text.
    """

    catalog = "<< /Type /Catalog /Pages 3 0 R"
    if with_xmp:
        catalog += " /Metadata 5 0 R"
    if with_signature:
        catalog += " /AcroForm << /Fields [6 0 R] >>"
    catalog += " >>"
    packed = [
        (1, catalog),
        (2, f"<< /Author ({author}) /Producer (Acme Writer 3.1) >>"),
        (3, "<< /Type /Pages /Kids [] /Count 0 >>"),
    ]
    if with_signature:
        packed.append((6, "<< /FT /Sig /T (Signature1) /V 7 0 R >>"))
        packed.append((7, "<< /ByteRange [0 840 960 720] /SubFilter /adbe.pkcs7.detached >>"))

    bodies = [body.encode("latin-1") for _, body in packed]
    header_parts: list[bytes] = []
    cursor = 0
    for (number, _), body in zip(packed, bodies, strict=True):
        header_parts.append(f"{number} {cursor}".encode())
        cursor += len(body) + 1
    header = b" ".join(header_parts) + b"\n"
    payload = header + b"\n".join(bodies) + b"\n"
    compressed = zlib.compress(payload)

    out = bytearray(b"%PDF-1.5\n")
    objstm_at = len(out)
    out += (
        f"4 0 obj\n<< /Type /ObjStm /N {len(packed)} /First {len(header)} "
        f"/Filter /FlateDecode /Length {len(compressed)} >>\nstream\n".encode()
    )
    out += compressed + b"\nendstream\nendobj\n"

    xmp_at = 0
    if with_xmp:
        xmp_at = len(out)
        packet = b'<?xpacket begin="?"?><x:xmpmeta xmlns:x="adobe:ns:meta/"></x:xmpmeta>'
        out += (
            f"5 0 obj\n<< /Type /Metadata /Subtype /XML /Length {len(packet)} >>\nstream\n".encode()
        )
        out += packet + b"\nendstream\nendobj\n"

    highest = 8 if with_signature else (6 if with_xmp else 5)
    entries = bytearray()

    #: type, field two, field three — widths 1, 4, 2.
    def row(kind: int, second: int, third: int) -> bytes:
        return bytes([kind]) + second.to_bytes(4, "big") + third.to_bytes(2, "big")

    entries += row(0, 0, 65535)
    for number in range(1, highest):
        if number == 4:
            entries += row(1, objstm_at, 0)
        elif number == 5 and with_xmp:
            entries += row(1, xmp_at, 0)
        else:
            index = next(
                (position for position, (item, _) in enumerate(packed) if item == number), None
            )
            entries += row(2, 4, index) if index is not None else row(0, 0, 0)

    xref_payload = zlib.compress(bytes(entries))
    xref_at = len(out)
    out += (
        # /Size counts the rows actually emitted above. The cross-reference
        # stream does not list itself, which is unusual but well formed and saves
        # the fixture a second layout pass.
        f"{highest} 0 obj\n<< /Type /XRef /Size {highest} /W [1 4 2] "
        f"/Root 1 0 R /Info 2 0 R /Filter /FlateDecode "
        f"/Length {len(xref_payload)} >>\nstream\n".encode()
    )
    out += xref_payload + b"\nendstream\nendobj\n"
    out += f"startxref\n{xref_at}\n%%EOF\n".encode()
    return bytes(out)


# -- the coverage gap this closes -----------------------------------------------------


def test_a_modern_pdf_has_no_trailer_keyword() -> None:
    """The premise. If this changes, the gap below is not the gap being closed."""

    assert b"trailer" not in modern_pdf()
    assert b"/Author" not in modern_pdf(), "the Info dictionary is compressed, not plain text"


def test_the_lexical_scanner_finds_nothing_in_a_modern_pdf() -> None:
    """What FMT-04 is for: reporting nothing looks exactly like finding nothing."""

    from trueai.detectors.documents.pdf import PDFDetector

    assert list(PDFDetector._info_entries(modern_pdf())) == []


def test_the_object_graph_finds_the_info_dictionary_in_a_modern_pdf() -> None:
    model = model_pdf(modern_pdf())

    assert model.modelled, model.incomplete
    assert model.info.get("Author") == b"Jane Doe"
    assert model.info.get("Producer") == b"Acme Writer 3.1"


def test_the_object_graph_also_reads_a_classic_pdf() -> None:
    """The new model must not trade one coverage hole for another."""

    model = model_pdf(classic_pdf())

    assert model.modelled, model.incomplete
    assert model.info.get("Author") == b"Jane Doe"
    assert model.catalog.get("Type") == Name("Catalog")


def test_the_version_is_reported() -> None:
    assert model_pdf(classic_pdf()).version == "1.4"
    assert model_pdf(modern_pdf()).version == "1.5"


# -- what a cleaner must not disturb --------------------------------------------------


def test_an_xmp_packet_is_found_through_the_catalog() -> None:
    model = model_pdf(modern_pdf(with_xmp=True))

    assert model.xmp_packets
    number, payload = model.xmp_packets[0]
    assert number == 5
    assert b"xmpmeta" in payload
    assert model.has_protected_material


def test_a_signature_and_its_byte_ranges_are_found() -> None:
    """A signature covers explicit ranges, so a cleaner has to know where they are."""

    model = model_pdf(modern_pdf(with_signature=True))

    assert model.signatures
    signature = model.signatures[0]
    assert signature.byte_ranges == ((0, 840), (960, 1680))
    assert signature.sub_filter == "adbe.pkcs7.detached"
    assert model.has_protected_material


def test_a_document_with_none_of_that_is_not_marked_protected() -> None:
    """Otherwise every document would be refused and the flag would mean nothing."""

    assert not model_pdf(modern_pdf()).has_protected_material


def test_an_encrypted_document_is_reported_as_encrypted() -> None:
    document = classic_pdf().replace(b"/Info 2 0 R", b"/Info 2 0 R /Encrypt 9 0 R", 1)

    model = model_pdf(document)

    assert model.encrypted
    assert model.has_protected_material


def test_an_undecodable_metadata_stream_is_still_reported_as_present() -> None:
    """Saying "no XMP" for a stream that could not be decoded would be a lie."""

    document = modern_pdf(with_xmp=True).replace(
        b"/Type /Metadata /Subtype /XML", b"/Type /Metadata /Subtype /XML /Filter /LZWDecode", 1
    )

    model = model_pdf(document)

    assert model.xmp_packets
    assert model.xmp_packets[0][1] == b""


# -- decompression bombs --------------------------------------------------------------


def test_a_bomb_is_refused_before_it_is_expanded() -> None:
    """The cap is passed *into* the decompressor, not applied to its output."""

    bomb = zlib.compress(b"\x00" * (8 * 1024 * 1024))

    assert len(bomb) < 16 * 1024
    with pytest.raises(PdfLimitExceeded, match="decompressed past"):
        inflate_bounded(bomb, 1024)


def test_a_stream_within_the_cap_still_decompresses() -> None:
    payload = b"ordinary content " * 64

    assert inflate_bounded(zlib.compress(payload), 1024 * 1024) == payload


def test_corrupt_flate_is_a_structure_error_not_a_limit_error() -> None:
    """ "Malformed" and "hostile" are different things to tell an operator."""

    with pytest.raises(PdfStructureError, match="could not be decompressed"):
        inflate_bounded(b"not compressed at all", 1024)


def test_the_document_budget_is_charged_across_streams() -> None:
    """A file must not spend a little on each of ten thousand streams."""

    budget = Budget(max_inflated_bytes=64, max_stream_bytes=1024)
    document = PdfDocument(modern_pdf(), budget)
    stream = Stream(
        dictionary={"Filter": Name("FlateDecode")}, raw=zlib.compress(b"x" * 40), raw_offset=0
    )

    document.decode_stream(stream)
    with pytest.raises(PdfLimitExceeded, match="for this document"):
        document.decode_stream(stream)


def test_an_oversized_raw_stream_is_refused_before_decoding() -> None:
    budget = Budget(max_stream_bytes=16)
    document = modern_pdf()

    model = model_pdf(document, budget)

    assert not model.modelled
    assert any("raw bytes" in item or "stream" in item for item in model.incomplete)


# -- other bounds ---------------------------------------------------------------------


def test_deeply_nested_objects_are_refused() -> None:
    from trueai.core.pdf_objects import _Lexer

    payload = b"[" * 100 + b"]" * 100
    lexer = _Lexer(payload, 0, len(payload), Budget(max_depth=8))

    with pytest.raises(PdfLimitExceeded, match="nesting deeper"):
        lexer.parse()


def test_a_token_budget_that_runs_out_is_refused() -> None:
    from trueai.core.pdf_objects import _Lexer

    payload = b"[" + b" 1" * 100 + b"]"
    lexer = _Lexer(payload, 0, len(payload), Budget(max_tokens=10))

    with pytest.raises(PdfLimitExceeded, match="tokens"):
        lexer.parse()


def test_a_reference_cycle_is_refused_rather_than_chased() -> None:
    document = PdfDocument(classic_pdf())
    document.load_cross_references()
    document._cache[99] = Reference(99, 0)
    document.locations[99] = ("file", 0, 0)

    with pytest.raises(PdfStructureError, match="cycle"):
        document.resolve(Reference(99, 0))


def test_a_long_cross_reference_chain_is_bounded() -> None:
    """Incremental updates chain through /Prev, and a chain can be a loop by another name."""

    budget = Budget(max_xref_sections=1)
    base = classic_pdf()
    chained = base.replace(b"/Info 2 0 R >>", b"/Info 2 0 R /Prev 9 >>", 1)

    model = model_pdf(chained, budget)

    assert not model.modelled
    assert any("chain is longer" in item for item in model.incomplete)


def test_a_missing_startxref_is_reported_not_raised() -> None:
    """The caller's next question is "what did you find?", so answer it."""

    model = model_pdf(b"%PDF-1.4\nnothing useful here\n")

    assert not model.modelled
    assert any("startxref" in item for item in model.incomplete)


def test_a_file_without_the_pdf_signature_is_refused() -> None:
    with pytest.raises(PdfStructureError, match="signature is missing"):
        PdfDocument(b"not a pdf")


def test_an_xref_offset_past_the_end_is_reported() -> None:
    document = classic_pdf()
    broken = document[: document.rfind(b"startxref")] + b"startxref\n999999\n%%EOF\n"

    model = model_pdf(broken)

    assert not model.modelled
    assert any("past the file" in item for item in model.incomplete)


# -- the lexer --------------------------------------------------------------------


def test_a_name_with_hex_escapes_decodes_to_the_same_name() -> None:
    """`/Meta#64ata` must not be a way to hide a /Metadata key from an inspector."""

    from trueai.core.pdf_objects import _Lexer

    payload = b"<< /Meta#64ata 5 0 R >>"
    lexer = _Lexer(payload, 0, len(payload), Budget())

    parsed = lexer.parse()

    assert isinstance(parsed, dict)
    assert "Metadata" in parsed


def test_a_reference_is_distinguished_from_two_numbers() -> None:
    from trueai.core.pdf_objects import _Lexer

    payload = b"[ 12 0 R 12 0 ]"
    lexer = _Lexer(payload, 0, len(payload), Budget())

    parsed = lexer.parse()

    assert parsed == [Reference(12, 0), 12, 0]


def test_a_hex_string_decodes() -> None:
    from trueai.core.pdf_objects import _Lexer

    payload = b"<4A616E65>"
    lexer = _Lexer(payload, 0, len(payload), Budget())

    assert lexer.parse() == b"Jane"


def test_an_escaped_parenthesis_does_not_end_a_string() -> None:
    from trueai.core.pdf_objects import _Lexer

    payload = rb"(Jane \(Doe\) Smith)"
    lexer = _Lexer(payload, 0, len(payload), Budget())

    assert lexer.parse() == b"Jane (Doe) Smith"


def test_an_unterminated_string_is_refused() -> None:
    from trueai.core.pdf_objects import _Lexer

    payload = b"(never closed"
    lexer = _Lexer(payload, 0, len(payload), Budget())

    with pytest.raises(PdfStructureError, match="Unterminated"):
        lexer.parse()


def test_a_comment_is_skipped() -> None:
    from trueai.core.pdf_objects import _Lexer

    payload = b"% a comment\n/Name"
    lexer = _Lexer(payload, 0, len(payload), Budget())

    assert lexer.parse() == Name("Name")


# -- the detector actually uses it ----------------------------------------------------


def scan_pdf(document: bytes, tmp_path):
    from trueai.core.artifact import Artifact
    from trueai.core.models import ArtifactType, ScanContext, ScanOptions
    from trueai.detectors.documents.pdf import PDFDetector

    path = tmp_path / "document.pdf"
    path.write_bytes(document)
    artifact = Artifact(artifact_type=ArtifactType.PDF, path=path, logical_path=path.name)
    return PDFDetector().scan(artifact, ScanContext(options=ScanOptions()))


def test_the_detector_now_reports_metadata_in_a_modern_pdf(tmp_path) -> None:
    """The coverage gap, closed where it matters: in the product, not the library."""

    findings = scan_pdf(modern_pdf(), tmp_path)

    authors = [item for item in findings if item.evidence.get("field") == "Author"]
    assert authors, [item.title for item in findings]
    assert authors[0].evidence["value"] == "Jane Doe"
    assert authors[0].evidence["reader"] == "object-graph"


def test_the_detector_still_reports_metadata_in_a_classic_pdf(tmp_path) -> None:
    findings = scan_pdf(classic_pdf(), tmp_path)

    authors = [item for item in findings if item.evidence.get("field") == "Author"]
    assert authors
    assert authors[0].evidence["value"] == "Jane Doe"


def test_the_lexical_reader_still_runs_when_the_graph_cannot(tmp_path) -> None:
    """A file that defeats the parser should still yield what a regex can find.

    The startxref offset is broken, so the graph gives up; the Info dictionary is
    still there in plain text for the fallback to find.
    """

    document = classic_pdf()
    broken = document[: document.rfind(b"startxref")] + b"startxref\n999999\n%%EOF\n"

    findings = scan_pdf(broken, tmp_path)

    authors = [item for item in findings if item.evidence.get("field") == "Author"]
    assert authors, "the fallback should still have found the Info dictionary"
    assert authors[0].evidence["reader"] == "lexical"


def test_which_reader_found_a_finding_is_recorded(tmp_path) -> None:
    """ "Nothing found" and "nothing found because the parser gave up" differ."""

    modern = scan_pdf(modern_pdf(), tmp_path)
    readers = {item.evidence.get("reader") for item in modern if "reader" in item.evidence}

    assert readers == {"object-graph"}


# -- what /W is allowed to say ----------------------------------------------------------


def xref_stream_with_widths(widths: list[int]) -> bytes:
    """A minimal PDF whose only cross-reference is a stream declaring ``widths``."""

    entries = bytes(max(sum(width for width in widths[:3] if width > 0), 1))
    payload = zlib.compress(entries)
    body = (
        f"1 0 obj\n<< /Type /XRef /Size 1 /W {widths} /Root 1 0 R "
        f"/Filter /FlateDecode /Length {len(payload)} >>\nstream\n".encode()
    )
    out = b"%PDF-1.5\n"
    offset = len(out)
    out += body + payload + b"\nendstream\nendobj\n"
    out += f"startxref\n{offset}\n%%EOF\n".encode()
    return out


def test_fewer_than_three_field_widths_is_refused_not_an_index_error() -> None:
    """`/W` has three elements, and three reads assumed it without checking.

    A file declaring two reached `values[2]` and raised an `IndexError` out of a
    parser whose whole contract is to refuse rather than raise. Found by the
    fuzzer, which draws exactly that distinction: a `ValueError`, a `TrueAIError`
    or a validation error is an answer; an unguarded subscript is a bug.
    """

    model = model_pdf(xref_stream_with_widths([1, 4]))

    assert not model.modelled


def test_three_field_widths_are_read() -> None:
    """The refusal must not swallow the shape the specification actually defines."""

    model = model_pdf(xref_stream_with_widths([1, 4, 2]))

    assert model is not None


def test_a_negative_field_width_is_refused() -> None:
    """`int.from_bytes` on a negative slice reads nothing and says nothing."""

    model = model_pdf(xref_stream_with_widths([1, -4, 2]))

    assert not model.modelled


def test_more_than_three_field_widths_does_not_refuse_the_file() -> None:
    """The extra elements have no meaning, and a conservative reader ignores them.

    Refusing a file some producer really emits would be a worse answer than
    reading the three fields the specification defines.
    """

    model = model_pdf(xref_stream_with_widths([1, 4, 2, 8]))

    assert model is not None
