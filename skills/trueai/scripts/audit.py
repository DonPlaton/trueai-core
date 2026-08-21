#!/usr/bin/env python3
"""Emit a validated TrueAI JSON report without terminal decoration."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[3]
if (SOURCE_ROOT / "trueai").is_dir():
    sys.path.insert(0, str(SOURCE_ROOT))

from trueai import ScanOptions, TrueAIEngine
from trueai.core.policy import PolicyStore
from trueai.reporters import JSONReporter


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--policy", default="audit")
    parser.add_argument("--experimental", action="store_true")
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if (
        args.output is not None
        and args.path.exists()
        and args.output.resolve() == args.path.resolve()
    ):
        print("Refusing to overwrite the scanned artifact with its report", file=sys.stderr)
        return 3
    policy = PolicyStore.get(args.policy)
    report = TrueAIEngine.default(include_experimental=args.experimental).scan(
        args.path,
        options=ScanOptions(include_experimental=args.experimental),
        policy=policy,
    )
    rendered = JSONReporter().render(report)
    if args.output is None:
        print(rendered)
    else:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    if any(diagnostic.severity.value in {"high", "critical"} for diagnostic in report.diagnostics):
        return 3
    if report.summary.violation_count:
        return 2
    if report.summary.review_count:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
