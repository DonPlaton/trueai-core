"""Fail when the committed public JSON Schema no longer matches the code.

The snapshot is a review trigger, not a compatibility rule: any change at all
makes this script fail so a maintainer has to regenerate the file and look at the
diff. Whether the change is allowed inside the current schema version is decided
separately by ``tests/unit/test_schema_compatibility.py``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT))

from trueai.schema import (  # noqa: E402
    SCHEMA_SNAPSHOT_PATH,
    canonical_schema_json,
    report_schema,
)


def main() -> int:
    """Compare the emitted schema against the tracked snapshot."""

    snapshot = REPOSITORY_ROOT / SCHEMA_SNAPSHOT_PATH
    if not snapshot.is_file():
        print(f"error: schema snapshot is missing: {snapshot}", file=sys.stderr)
        return 1
    emitted = json.loads(canonical_schema_json(report_schema()))
    committed = json.loads(snapshot.read_text(encoding="utf-8"))
    if emitted != committed:
        print(
            f"error: {SCHEMA_SNAPSHOT_PATH} is stale.\n"
            f"Regenerate it with: trueai schema --output {SCHEMA_SNAPSHOT_PATH}\n"
            "Then review the diff against the compatibility policy in "
            "docs/schema-compatibility.md.",
            file=sys.stderr,
        )
        return 1
    print(f"{SCHEMA_SNAPSHOT_PATH} matches the emitted schema.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
