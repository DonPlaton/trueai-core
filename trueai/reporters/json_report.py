"""Stable JSON report serialization."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from trueai.core.models import ScanReport


class JSONReporter:
    """Serialize the public Pydantic schema without terminal decoration."""

    @staticmethod
    def schema() -> dict[str, Any]:
        """Return the machine-readable JSON Schema for the current report version."""

        return ScanReport.model_json_schema(mode="serialization")

    def render(self, report: ScanReport, *, indent: int | None = 2) -> str:
        """Return deterministic-key JSON for a scan report."""

        payload = report.model_dump(mode="json", exclude_none=True)
        return json.dumps(
            payload,
            ensure_ascii=False,
            indent=indent,
            sort_keys=True,
        )

    def write(self, report: ScanReport, path: Path, *, indent: int | None = 2) -> None:
        """Write UTF-8 JSON to an explicit destination."""

        path.write_text(self.render(report, indent=indent) + "\n", encoding="utf-8")

    @staticmethod
    def load(path: Path) -> ScanReport:
        """Validate a previously emitted report."""

        raw: Any = json.loads(path.read_text(encoding="utf-8"))
        return ScanReport.model_validate(raw)
