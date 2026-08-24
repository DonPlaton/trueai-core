"""Cleaner registry for predictable, separately verified mutations."""

from trueai.cleaners.base import Cleaner, CleanerOutcome
from trueai.cleaners.git import GitCleaner
from trueai.cleaners.image import ImageMetadataCleaner
from trueai.cleaners.media import MediaMetadataCleaner
from trueai.cleaners.ooxml import DOCXCleaner, OfficeOpenXmlCleaner, PPTXCleaner, XLSXCleaner
from trueai.cleaners.pdf import PDFCleaner
from trueai.cleaners.svg import SVGCleaner
from trueai.cleaners.text import TextCleaner
from trueai.core.models import ArtifactType


def cleaner_for(artifact_type: ArtifactType) -> Cleaner:
    """Return the built-in cleaner for an artifact type."""

    if artifact_type in {
        ArtifactType.TEXT,
        ArtifactType.MARKDOWN,
        ArtifactType.SOURCE_CODE,
        ArtifactType.HTML,
        ArtifactType.CSS,
    }:
        return TextCleaner()
    if artifact_type == ArtifactType.DOCX:
        return DOCXCleaner()
    if artifact_type == ArtifactType.PPTX:
        return PPTXCleaner()
    if artifact_type == ArtifactType.XLSX:
        return XLSXCleaner()
    if artifact_type == ArtifactType.SVG:
        return SVGCleaner()
    if artifact_type in {ArtifactType.PNG, ArtifactType.JPEG}:
        return ImageMetadataCleaner()
    if artifact_type == ArtifactType.PDF:
        return PDFCleaner()
    if artifact_type == ArtifactType.AUDIO:
        return MediaMetadataCleaner()
    if artifact_type == ArtifactType.GIT_REPOSITORY:
        return GitCleaner()
    raise ValueError(f"No cleaner supports {artifact_type.value}")


__all__ = ["Cleaner", "CleanerOutcome", "OfficeOpenXmlCleaner", "cleaner_for"]
