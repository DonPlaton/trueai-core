"""Built-in detector registration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from trueai.plugins.host import PluginIsolation

if TYPE_CHECKING:
    from trueai.core.registry import DetectorRegistry
    from trueai.plugins.manifest import CapabilityPolicy


def create_default_registry(
    *,
    include_experimental: bool = False,
    discover_plugins: bool = True,
    plugin_isolation: PluginIsolation = PluginIsolation.SUBPROCESS,
    capability_policy: CapabilityPolicy | None = None,
    plugin_search_path: tuple[str, ...] = (),
) -> DetectorRegistry:
    """Create an isolated registry containing all built-in detectors."""

    from trueai.core.registry import DetectorRegistry
    from trueai.detectors.code.comments import CodeCommentAttributionDetector
    from trueai.detectors.design.heuristics import DesignStyleDetector
    from trueai.detectors.design.raster import RasterMetadataDetector
    from trueai.detectors.design.svg import SVGDetector
    from trueai.detectors.documents.docx import DOCXDetector
    from trueai.detectors.documents.pdf import PDFDetector
    from trueai.detectors.documents.pptx import PPTXDetector
    from trueai.detectors.documents.xlsx import XLSXDetector
    from trueai.detectors.git.commits import GitAttributionDetector
    from trueai.detectors.git.repository import GitRepositoryContextDetector
    from trueai.detectors.media.metadata import MediaMetadataDetector
    from trueai.detectors.provenance.c2pa import C2PAMarkerDetector
    from trueai.detectors.text.attribution import ExplicitAttributionDetector
    from trueai.detectors.text.stylometry import StylometryDetector
    from trueai.detectors.text.unicode import UnicodeForensicsDetector
    from trueai.detectors.web.css import CSSDetector
    from trueai.detectors.web.html import HTMLDetector

    registry = DetectorRegistry()
    builtins = (
        UnicodeForensicsDetector(),
        ExplicitAttributionDetector(),
        CodeCommentAttributionDetector(),
        GitAttributionDetector(),
        GitRepositoryContextDetector(),
        HTMLDetector(),
        CSSDetector(),
        DOCXDetector(),
        PPTXDetector(),
        XLSXDetector(),
        PDFDetector(),
        SVGDetector(),
        RasterMetadataDetector(),
        MediaMetadataDetector(),
        C2PAMarkerDetector(),
        StylometryDetector(),
        DesignStyleDetector(),
    )
    for detector in builtins:
        registry.register(detector, enabled=include_experimental or not detector.experimental)
    if discover_plugins and plugin_isolation != PluginIsolation.DISABLED:
        registry.discover(
            policy=capability_policy,
            isolation=plugin_isolation,
            search_path=plugin_search_path,
        )
    return registry


__all__ = ["create_default_registry"]
