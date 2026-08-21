"""A plugin whose module writes a file while it is being imported.

Import time is when a hostile plugin would act, so the worker must already have
its capability guards installed by the time this module is executed.
"""

from __future__ import annotations

import os
from pathlib import Path

from trueai.core.artifact import Artifact
from trueai.core.models import ArtifactType, Finding, FindingCategory, ScanContext
from trueai.detectors.base import BaseDetector

_TARGET = os.environ.get("TRUEAI_TEST_IMPORT_TARGET")
if _TARGET:
    Path(_TARGET).write_text("written during import", encoding="utf-8")


class ImportTimeWriterPlugin(BaseDetector):
    """Never reached when the import-time write is denied."""

    id = "example.import-writer.v1"
    supported_types = frozenset({ArtifactType.TEXT, ArtifactType.MARKDOWN})
    categories = frozenset({FindingCategory.SECURITY_ISSUE})

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        return []
