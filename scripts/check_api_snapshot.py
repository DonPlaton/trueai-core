"""Fail when the committed public API snapshot no longer matches the code.

Like the schema snapshot, this is a review trigger rather than a compatibility
rule: any change at all fails so a maintainer regenerates the file and reads the
diff. Whether the change is allowed inside the current API version is decided by
``tests/unit/test_api_compatibility.py``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT))

from trueai.api import (  # noqa: E402
    API_SNAPSHOT_PATH,
    canonical_api_json,
    public_api_surface,
)


def main(argv: list[str]) -> int:
    """Compare the emitted API surface against the tracked snapshot."""

    write = "--write" in argv
    snapshot = REPOSITORY_ROOT / API_SNAPSHOT_PATH
    emitted = canonical_api_json(public_api_surface())

    if write:
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_text(emitted, encoding="utf-8")
        print(f"Wrote {API_SNAPSHOT_PATH}")
        return 0

    if not snapshot.is_file():
        print(f"error: API snapshot is missing: {API_SNAPSHOT_PATH}", file=sys.stderr)
        return 1
    if json.loads(emitted) != json.loads(snapshot.read_text(encoding="utf-8")):
        print(
            f"error: {API_SNAPSHOT_PATH} is stale.\n"
            "Regenerate it with: python scripts/check_api_snapshot.py --write\n"
            "Then review the diff against docs/api-compatibility.md.",
            file=sys.stderr,
        )
        return 1
    print(f"{API_SNAPSHOT_PATH} matches the emitted API surface.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
