"""Synthetic, redistributable Office Open XML packages for the test suite.

These are hand-built packages rather than files produced by Office, so they can be
committed and redistributed without licensing or privacy questions. They contain
only the parts the detectors read.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

_XML_DECLARATION = '<?xml version="1.0" encoding="UTF-8"?>'

PRESENTATION_NAMESPACE = "http://schemas.openxmlformats.org/presentationml/2006/main"
DRAWING_NAMESPACE = "http://schemas.openxmlformats.org/drawingml/2006/main"
SPREADSHEET_NAMESPACE = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
THREADED_COMMENTS_NAMESPACE = (
    "http://schemas.microsoft.com/office/spreadsheetml/2018/threadedcomments"
)

CORE_PROPERTIES = f"""{_XML_DECLARATION}
<cp:coreProperties
 xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
 xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:creator>Alice</dc:creator>
  <cp:lastModifiedBy>Bob</cp:lastModifiedBy>
  <dc:title>Quarterly review</dc:title>
</cp:coreProperties>"""

CUSTOM_PROPERTIES = f"""{_XML_DECLARATION}
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"
 xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <property name="Workflow" fmtid="x" pid="2"><vt:lpwstr>Generated with Claude</vt:lpwstr></property>
</Properties>"""


def _content_types(extra_defaults: str = "") -> str:
    return f"""{_XML_DECLARATION}
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/xml"/>{extra_defaults}
</Types>"""


def _write_package(path: Path, parts: dict[str, str]) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as package:
        for name, content in parts.items():
            package.writestr(name, content)
    return path


def build_pptx(path: Path) -> Path:
    """Create a presentation with notes, comments, author identity, and metadata."""

    app_properties = f"""{_XML_DECLARATION}
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  <Application>Microsoft Office PowerPoint</Application>
  <AppVersion>16.0</AppVersion>
  <Company>Example Inc</Company>
</Properties>"""
    presentation = f"""{_XML_DECLARATION}
<p:presentation xmlns:p="{PRESENTATION_NAMESPACE}">
  <p:sldIdLst><p:sldId id="256" /></p:sldIdLst>
</p:presentation>"""
    slide = f"""{_XML_DECLARATION}
<p:sld xmlns:p="{PRESENTATION_NAMESPACE}" xmlns:a="{DRAWING_NAMESPACE}">
  <p:cSld><p:spTree><p:sp><p:txBody>
    <a:p><a:r><a:t>Visible slide headline</a:t></a:r></a:p>
  </p:txBody></p:sp></p:spTree></p:cSld>
</p:sld>"""
    notes = f"""{_XML_DECLARATION}
<p:notes xmlns:p="{PRESENTATION_NAMESPACE}" xmlns:a="{DRAWING_NAMESPACE}">
  <p:cSld><p:spTree><p:sp><p:txBody>
    <a:p><a:r><a:t>Draft note: tighten the revenue slide before the client call.</a:t></a:r></a:p>
  </p:txBody></p:sp></p:spTree></p:cSld>
</p:notes>"""
    comment_authors = f"""{_XML_DECLARATION}
<p:cmAuthorLst xmlns:p="{PRESENTATION_NAMESPACE}">
  <p:cmAuthor id="1" name="Carol" initials="C"/>
</p:cmAuthorLst>"""
    comments = f"""{_XML_DECLARATION}
<p:cmLst xmlns:p="{PRESENTATION_NAMESPACE}">
  <p:cm authorId="1" idx="1"><p:text>Generated with ChatGPT</p:text></p:cm>
</p:cmLst>"""
    return _write_package(
        path,
        {
            "[Content_Types].xml": _content_types(),
            "ppt/presentation.xml": presentation,
            "ppt/slides/slide1.xml": slide,
            "ppt/notesSlides/notesSlide1.xml": notes,
            "ppt/commentAuthors.xml": comment_authors,
            "ppt/comments/comment1.xml": comments,
            "docProps/core.xml": CORE_PROPERTIES,
            "docProps/app.xml": app_properties,
            "docProps/custom.xml": CUSTOM_PROPERTIES,
        },
    )


def build_xlsx(path: Path) -> Path:
    """Create a workbook with a hidden sheet, comments, identities, and external links."""

    app_properties = f"""{_XML_DECLARATION}
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  <Application>Microsoft Excel</Application>
  <AppVersion>16.0</AppVersion>
  <Manager>Dana</Manager>
</Properties>"""
    workbook = f"""{_XML_DECLARATION}
<workbook xmlns="{SPREADSHEET_NAMESPACE}">
  <sheets>
    <sheet name="Summary" sheetId="1" r:id="rId1"
     xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
    <sheet name="Scratch" sheetId="2" state="veryHidden" r:id="rId2"
     xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
  </sheets>
  <definedNames>
    <definedName name="_xlnm.Print_Area">Summary!$A$1:$D$20</definedName>
  </definedNames>
</workbook>"""
    worksheet = f"""{_XML_DECLARATION}
<worksheet xmlns="{SPREADSHEET_NAMESPACE}">
  <sheetData>
    <row r="1"><c r="A1" t="s"><v>0</v></c></row>
    <row r="2"><c r="B2"><f>SUM(A1:A10)</f><v>42</v></c></row>
  </sheetData>
</worksheet>"""
    shared_strings = f"""{_XML_DECLARATION}
<sst xmlns="{SPREADSHEET_NAMESPACE}" count="1" uniqueCount="1">
  <si><t>Revenue</t></si>
</sst>"""
    comments = f"""{_XML_DECLARATION}
<comments xmlns="{SPREADSHEET_NAMESPACE}">
  <authors><author>Erin</author></authors>
  <commentList>
    <comment ref="B2" authorId="0"><text><r><t>Check this total.</t></r></text></comment>
  </commentList>
</comments>"""
    threaded = f"""{_XML_DECLARATION}
<ThreadedComments xmlns="{THREADED_COMMENTS_NAMESPACE}">
  <threadedComment ref="B2" dT="2026-01-01T00:00:00" personId="{{PID}}" id="{{CID}}">
    <text>Generated with ChatGPT</text>
  </threadedComment>
</ThreadedComments>"""
    persons = f"""{_XML_DECLARATION}
<personList xmlns="{THREADED_COMMENTS_NAMESPACE}">
  <person displayName="Erin Example" id="{{PID}}" userId="erin@example.test"
   providerId="AD"/>
</personList>"""
    external_link = f"""{_XML_DECLARATION}
<externalLink xmlns="{SPREADSHEET_NAMESPACE}">
  <externalBook/>
</externalLink>"""
    return _write_package(
        path,
        {
            "[Content_Types].xml": _content_types(),
            "xl/workbook.xml": workbook,
            "xl/worksheets/sheet1.xml": worksheet,
            "xl/sharedStrings.xml": shared_strings,
            "xl/comments1.xml": comments,
            "xl/threadedComments/threadedComment1.xml": threaded,
            "xl/persons/person.xml": persons,
            "xl/externalLinks/externalLink1.xml": external_link,
            "docProps/core.xml": CORE_PROPERTIES,
            "docProps/app.xml": app_properties,
            "docProps/custom.xml": CUSTOM_PROPERTIES,
        },
    )
