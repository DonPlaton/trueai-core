from pathlib import Path

from trueai import TrueAIEngine
from trueai.core.models import FindingCategory


def test_png_text_metadata(png_file: Path) -> None:
    report = TrueAIEngine.default().scan(png_file)
    fields = {item.evidence.get("field") for item in report.findings}

    assert {"Software", "Author"} <= fields
    assert FindingCategory.GENERATOR_METADATA in {item.category for item in report.findings}


def test_jpeg_exif_metadata(jpeg_file: Path) -> None:
    report = TrueAIEngine.default().scan(jpeg_file)
    fields = {item.evidence.get("field") for item in report.findings}

    assert {"Software", "Artist"} <= fields
    assert FindingCategory.PERSONAL_METADATA in {item.category for item in report.findings}


def test_malformed_png_fails_safely(tmp_path: Path) -> None:
    path = tmp_path / "broken.png"
    path.write_bytes(b"\x89PNG\r\n\x1a\nnot-a-real-png")

    report = TrueAIEngine.default().scan(path)

    assert any(item.code == "corrupt_artifact" for item in report.diagnostics)
