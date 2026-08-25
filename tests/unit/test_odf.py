"""OpenDocument inspection and cleanup, and the legacy-binary refusal beside it.

`FMT-06` was an evaluation with a condition attached: proceed only with a
maintained parser, hostile-input tests, and a format-specific integrity proof.
ODF meets all three on machinery that already exists — it is a ZIP package, so
every control built for Office Open XML applies unchanged. Legacy binary Office
does not, and the tests here pin the refusal so it stays a decision rather than
an omission.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from trueai.cleaners import cleaner_for
from trueai.cleaners.odf import OpenDocumentCleaner
from trueai.core.artifact import Artifact, ArtifactDiscovery
from trueai.core.errors import RemediationError, UnsafeArtifactError
from trueai.core.models import (
    ArtifactType,
    Finding,
    IntegrityStatus,
    Remediation,
    RemediationSafety,
    ScanContext,
    ScanOptions,
)
from trueai.detectors.documents.odf import OpenDocumentDetector

CONTENT = """<?xml version="1.0" encoding="UTF-8"?>
<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
 xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0">
 <office:body><office:text><text:p>The visible document text.</text:p></office:text></office:body>
</office:document-content>
"""

META_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"
 xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0"
 xmlns:dc="http://purl.org/dc/elements/1.1/">
 <office:meta>
  <meta:generator>{generator}</meta:generator>
  <meta:initial-creator>{creator}</meta:initial-creator>
  <dc:title>{title}</dc:title>
  <meta:editing-cycles>7</meta:editing-cycles>
  <meta:user-defined meta:name="Department">Research</meta:user-defined>
 </office:meta>
</office:document-meta>
"""


def build_odf(
    path: Path,
    *,
    mimetype: str = "application/vnd.oasis.opendocument.text",
    generator: str = "LibreOffice/24.2",
    creator: str = "Jane Doe",
    title: str = "Quarterly report",
    with_macros: bool = False,
    stored_mimetype: bool = True,
) -> Path:
    """Write a valid ODF package with the mimetype entry first and uncompressed."""

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as package:
        info = zipfile.ZipInfo("mimetype")
        info.compress_type = zipfile.ZIP_STORED if stored_mimetype else zipfile.ZIP_DEFLATED
        package.writestr(info, mimetype)
        package.writestr("content.xml", CONTENT)
        package.writestr(
            "meta.xml",
            META_TEMPLATE.format(generator=generator, creator=creator, title=title),
        )
        package.writestr("styles.xml", "<styles/>")
        package.writestr("META-INF/manifest.xml", "<manifest/>")
        if with_macros:
            package.writestr("Basic/Standard/Module1.xml", "<module/>")
    return path


def classify(path: Path) -> tuple[ArtifactType, str | None]:
    """Run the real type identification over a file's opening bytes."""

    with path.open("rb") as handle:
        head = handle.read(64 * 1024)
    return ArtifactDiscovery._identify_file(path, head)


def scan(path: Path) -> list[Finding]:
    artifact = Artifact(artifact_type=ArtifactType.ODF, path=path, logical_path=path.name)
    return OpenDocumentDetector().scan(artifact, ScanContext(options=ScanOptions()))


def remediation_for(findings: list[Finding]) -> Remediation:
    return Remediation(
        id=f"rem_{findings[0].id}",
        remediation_id="odf.remove-metadata-field",
        artifact_path=findings[0].artifact_path,
        finding_ids=tuple(item.id for item in findings),
        description=f"Remove {len(findings)} OpenDocument field(s)",
        safety=RemediationSafety.SAFE_METADATA,
        payload={
            "findings": [item.model_dump(mode="json", exclude_none=True) for item in findings]
        },
    )


def selected(path: Path, fields: set[str]) -> Remediation:
    chosen = [
        finding
        for finding in scan(path)
        if finding.evidence.get("field") in fields and finding.remediation_id
    ]
    assert chosen, f"no removable finding matched {fields}"
    return remediation_for(chosen)


# -- identification -------------------------------------------------------------------


def test_an_odf_package_is_identified_by_its_declared_mimetype(tmp_path: Path) -> None:
    """The file name is attacker-controlled; the mimetype entry is the document's own."""

    path = build_odf(tmp_path / "misnamed.zip")

    artifact_type, media_type = classify(path)

    assert artifact_type == ArtifactType.ODF
    assert media_type == "application/vnd.oasis.opendocument.text"


def test_a_spreadsheet_is_identified_as_odf_too(tmp_path: Path) -> None:
    path = build_odf(
        tmp_path / "book.ods", mimetype="application/vnd.oasis.opendocument.spreadsheet"
    )

    artifact_type, media_type = classify(path)

    assert artifact_type == ArtifactType.ODF
    assert media_type.endswith("spreadsheet")


def test_an_ooxml_package_is_still_identified_as_ooxml(tmp_path: Path) -> None:
    """The ODF sniff must not capture packages that belong to the other family."""

    path = tmp_path / "report.docx"
    with zipfile.ZipFile(path, "w") as package:
        package.writestr("[Content_Types].xml", "<Types/>")
        package.writestr("word/document.xml", "<document/>")

    assert classify(path)[0] == ArtifactType.DOCX


def test_a_legacy_binary_office_file_is_identified_not_skipped(tmp_path: Path) -> None:
    """A file silently skipped looks exactly like a file that was clean."""

    path = tmp_path / "legacy.doc"
    path.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 512)

    artifact_type, media_type = classify(path)

    assert artifact_type == ArtifactType.LEGACY_OFFICE
    assert media_type == "application/x-ole-storage"


def test_legacy_binary_office_has_no_cleaner(tmp_path: Path) -> None:
    """The refusal is a decision, and it stays one until the three conditions hold."""

    with pytest.raises(ValueError, match="No cleaner supports legacy_office"):
        cleaner_for(ArtifactType.LEGACY_OFFICE)


# -- detection ------------------------------------------------------------------------


def test_metadata_fields_are_reported(tmp_path: Path) -> None:
    findings = scan(build_odf(tmp_path / "report.odt"))

    fields = {item.evidence.get("field") for item in findings}
    assert {"generator", "initial-creator", "title", "editing-cycles"} <= fields


def test_a_user_defined_field_keeps_its_declared_name(tmp_path: Path) -> None:
    findings = scan(build_odf(tmp_path / "report.odt"))

    custom = [item for item in findings if item.evidence.get("field") == "user-defined:Department"]
    assert custom
    assert custom[0].evidence["value"] == "Research"


def test_the_document_kind_comes_from_the_package(tmp_path: Path) -> None:
    path = build_odf(
        tmp_path / "deck.odp", mimetype="application/vnd.oasis.opendocument.presentation"
    )

    findings = scan(path)

    assert findings[0].evidence["document_kind"] == "presentation"


def test_a_provenance_marker_makes_a_field_unremovable(tmp_path: Path) -> None:
    path = build_odf(tmp_path / "report.odt", generator="Exported with c2pa tooling")

    generator = next(item for item in scan(path) if item.evidence.get("field") == "generator")

    assert not generator.removable
    assert generator.remediation_id is None


def test_macro_storage_is_listed_never_parsed(tmp_path: Path) -> None:
    findings = scan(build_odf(tmp_path / "macro.odt", with_macros=True))

    macros = [item for item in findings if "macro storage" in item.title]
    assert macros
    assert macros[0].evidence["entry_count"] == 1
    assert not macros[0].removable


def test_an_unrecognised_subtype_is_reported_rather_than_guessed(tmp_path: Path) -> None:
    path = build_odf(tmp_path / "odd.odt", mimetype="application/vnd.oasis.opendocument.chart")

    findings = scan(path)

    unrecognised = [item for item in findings if "Unrecognised" in item.title]
    assert unrecognised
    assert unrecognised[0].evidence["mimetype"].endswith("chart")


def test_a_package_without_content_xml_is_refused(tmp_path: Path) -> None:
    from trueai.core.errors import CorruptArtifactError

    path = tmp_path / "broken.odt"
    with zipfile.ZipFile(path, "w") as package:
        package.writestr("mimetype", "application/vnd.oasis.opendocument.text")
        package.writestr("meta.xml", META_TEMPLATE.format(generator="x", creator="y", title="z"))

    with pytest.raises(CorruptArtifactError, match=r"content\.xml"):
        scan(path)


# -- hostile input, on the shared ZIP safety layer ------------------------------------


def test_a_traversal_entry_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "hostile.odt"
    with zipfile.ZipFile(path, "w") as package:
        package.writestr("mimetype", "application/vnd.oasis.opendocument.text")
        package.writestr("content.xml", CONTENT)
        package.writestr("../escape.xml", "<x/>")

    with pytest.raises(UnsafeArtifactError, match="Unsafe archive path"):
        scan(path)


def test_a_compression_bomb_entry_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "bomb.odt"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as package:
        package.writestr("mimetype", "application/vnd.oasis.opendocument.text")
        package.writestr("content.xml", CONTENT)
        package.writestr("payload.bin", b"\x00" * (64 * 1024 * 1024))

    with pytest.raises(UnsafeArtifactError):
        scan(path)


def test_an_encrypted_entry_is_refused_rather_than_inspected(tmp_path: Path) -> None:
    """The shared layer already refuses these; ODF inherits it by construction."""

    path = build_odf(tmp_path / "report.odt")
    raw = bytearray(path.read_bytes())
    # The flag has to be set in the central directory, which is where zipfile
    # reads `flag_bits` from. Setting it on a ZipInfo before writestr does not
    # survive: zipfile rebuilds the header from the entry it was handed.
    signature = b"PK" + bytes([0x01, 0x02])
    marker = raw.find(signature)
    assert marker > 0, "no central directory header found"
    raw[marker + 8] |= 0x01
    path.write_bytes(bytes(raw))

    with pytest.raises(UnsafeArtifactError, match="Encrypted"):
        scan(path)


# -- cleanup and its integrity proof --------------------------------------------------


def test_the_selected_field_is_removed_and_content_is_untouched(tmp_path: Path) -> None:
    source = build_odf(tmp_path / "report.odt")
    destination = tmp_path / "clean.odt"
    remediation = selected(source, {"initial-creator"})

    outcome = OpenDocumentCleaner().apply(source, destination, (remediation,), ScanOptions())

    assert outcome.integrity.status == IntegrityStatus.PASS
    with zipfile.ZipFile(destination) as package:
        assert b"Jane Doe" not in package.read("meta.xml")
        assert package.read("content.xml") == CONTENT.encode("utf-8")
        assert b"LibreOffice" in package.read("meta.xml"), "unselected fields must survive"


def test_the_logical_digest_is_the_content_part(tmp_path: Path) -> None:
    """Hashing the whole package would ask "did anything change", the wrong question."""

    source = build_odf(tmp_path / "report.odt")
    destination = tmp_path / "clean.odt"

    outcome = OpenDocumentCleaner().apply(
        source, destination, (selected(source, {"title"}),), ScanOptions()
    )

    assert outcome.integrity.logical_before_sha256 == outcome.integrity.logical_after_sha256
    assert outcome.integrity.before_sha256 != outcome.integrity.after_sha256


def test_the_mimetype_entry_stays_first_and_stored(tmp_path: Path) -> None:
    """A package that loses either property stops being recognised by readers."""

    source = build_odf(tmp_path / "report.odt")
    destination = tmp_path / "clean.odt"

    OpenDocumentCleaner().apply(source, destination, (selected(source, {"title"}),), ScanOptions())

    with zipfile.ZipFile(destination) as package:
        assert package.namelist()[0] == "mimetype"
        entry = next(item for item in package.infolist() if item.filename == "mimetype")
        assert entry.compress_type == zipfile.ZIP_STORED


def test_a_user_defined_field_can_be_removed_by_its_declared_name(tmp_path: Path) -> None:
    source = build_odf(tmp_path / "report.odt")
    destination = tmp_path / "clean.odt"

    outcome = OpenDocumentCleaner().apply(
        source,
        destination,
        (selected(source, {"user-defined:Department"}),),
        ScanOptions(),
    )

    assert outcome.integrity.status == IntegrityStatus.PASS
    with zipfile.ZipFile(destination) as package:
        assert b"Research" not in package.read("meta.xml")


def test_a_field_carrying_provenance_is_refused(tmp_path: Path) -> None:
    source = build_odf(tmp_path / "report.odt")
    destination = tmp_path / "clean.odt"
    remediation = selected(source, {"title"})
    tampered = build_odf(tmp_path / "tampered.odt", title="Signed with c2pa tooling")

    with pytest.raises(RemediationError, match="provenance"):
        OpenDocumentCleaner().apply(tampered, destination, (remediation,), ScanOptions())


def test_a_stale_selection_is_refused(tmp_path: Path) -> None:
    source = build_odf(tmp_path / "report.odt")
    remediation = selected(source, {"title"})
    other = build_odf(tmp_path / "other.odt", title="A different title")
    # Removing the title works on either file, so target a field the second one
    # does not have at all.
    stale = remediation.model_copy(
        update={
            "payload": {
                "findings": [
                    {
                        **remediation.payload["findings"][0],  # type: ignore[index]
                        "evidence": {"part": "meta.xml", "field": "printed-by"},
                    }
                ]
            }
        }
    )

    with pytest.raises(RemediationError, match="missing fields"):
        OpenDocumentCleaner().apply(other, tmp_path / "out.odt", (stale,), ScanOptions())


def test_an_unsupported_operation_is_refused(tmp_path: Path) -> None:
    source = build_odf(tmp_path / "report.odt")
    remediation = selected(source, {"title"}).model_copy(
        update={"remediation_id": "docx.remove-metadata-field"}
    )

    with pytest.raises(RemediationError, match="does not support"):
        OpenDocumentCleaner().apply(source, tmp_path / "out.odt", (remediation,), ScanOptions())


def test_the_integrity_proof_fails_when_content_changes(tmp_path: Path) -> None:
    """The proof has to be able to fail, or it proves nothing."""

    source = build_odf(tmp_path / "report.odt")
    destination = tmp_path / "clean.odt"
    with zipfile.ZipFile(source) as package:
        entries = {name: package.read(name) for name in package.namelist()}
    entries["content.xml"] = CONTENT.replace("visible", "altered").encode("utf-8")
    with zipfile.ZipFile(destination, "w") as package:
        info = zipfile.ZipInfo("mimetype")
        info.compress_type = zipfile.ZIP_STORED
        package.writestr(info, entries.pop("mimetype"))
        for name, data in entries.items():
            package.writestr(name, data)

    report = OpenDocumentCleaner()._verify(source, destination, ["title"])

    assert report.status == IntegrityStatus.FAIL
    assert "content.xml changed" in report.explanation


# -- the cleaner registry -------------------------------------------------------------


def test_every_artifact_type_with_a_cleaner_resolves() -> None:
    """A cleanup that exists but is unreachable through the pipeline is not shipped.

    Video was exactly that: the ISO-BMFF and EBML branches were written and
    tested by calling the cleaner directly, while `cleaner_for` still raised
    "no cleaner supports video".
    """

    for artifact_type in (
        ArtifactType.TEXT,
        ArtifactType.DOCX,
        ArtifactType.PPTX,
        ArtifactType.XLSX,
        ArtifactType.ODF,
        ArtifactType.SVG,
        ArtifactType.PNG,
        ArtifactType.JPEG,
        ArtifactType.PDF,
        ArtifactType.AUDIO,
        ArtifactType.VIDEO,
        ArtifactType.GIT_REPOSITORY,
    ):
        assert cleaner_for(artifact_type) is not None, artifact_type


def test_video_resolves_to_the_media_cleaner() -> None:
    from trueai.cleaners.media import MediaMetadataCleaner

    assert isinstance(cleaner_for(ArtifactType.VIDEO), MediaMetadataCleaner)
