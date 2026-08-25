"""Benchmark a repository scan at a chosen file count and print the numbers.

    python scripts/benchmark_scale.py --files 10000
    python scripts/benchmark_scale.py --files 100000 --keep-corpus /path/to/corpus

Every number this prints is measured in the same process that did the work. The
corpus is seeded, so a run is reproducible on the same machine and comparable
across machines when the environment block is reported with it.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT))

from trueai.core.benchmark import PhaseResult, build_corpus, run_benchmark  # noqa: E402
from trueai.core.models import ScanOptions  # noqa: E402


def _megabytes(value: int | None) -> str:
    return "n/a" if value is None else f"{value / (1024 * 1024):.1f} MB"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=int, default=10_000, help="corpus size")
    parser.add_argument("--seed", type=int, default=0, help="corpus generation seed")
    parser.add_argument(
        "--keep-corpus",
        type=Path,
        default=None,
        help="build the corpus here and leave it in place",
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        default=None,
        help="benchmark an existing directory; nothing is written into it",
    )
    parser.add_argument("--json", type=Path, default=None, help="also write the result as JSON")
    parser.add_argument("--workers", type=int, default=8, help="workers for the parallel phase")
    parser.add_argument(
        "--max-findings",
        type=int,
        default=None,
        help="raise the finding budget; the default is what an ordinary scan uses",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=None,
        help="raise the discovery cap; the default is what an ordinary scan uses",
    )
    parser.add_argument(
        "--no-determinism",
        action="store_true",
        help="skip the extra scan that checks two runs agree",
    )
    arguments = parser.parse_args()

    if arguments.corpus is not None and arguments.keep_corpus is not None:
        parser.error("--corpus benchmarks a directory as it is; --keep-corpus builds one")
    workspace = Path(tempfile.mkdtemp(prefix="trueai-benchmark-"))
    corpus = arguments.corpus or arguments.keep_corpus or (workspace / "corpus")
    cache = workspace / "cache"
    try:
        if arguments.corpus is None:
            print(f"Building a {arguments.files} file corpus in {corpus} …", flush=True)
            written = build_corpus(corpus, arguments.files, seed=arguments.seed)
            print(f"Wrote {written} files.", flush=True)
        else:
            # Never write into a directory the operator named. A benchmark that
            # modified the repository it measured would be worse than useless.
            if not corpus.is_dir():
                parser.error(f"{corpus} is not a directory")
            print(f"Benchmarking {corpus} as it is; nothing is written into it.", flush=True)

        def announce(phase: PhaseResult) -> None:
            caveat = phase.caveat()
            line = (
                f"  {phase.name}: {phase.resources.seconds:.1f}s, "
                f"{phase.files_per_second:.0f} files/s, {phase.findings} findings"
            )
            print(line + (f" — INCOMPLETE: {caveat}" if caveat else ""), flush=True)

        limits: dict[str, int] = {}
        if arguments.max_findings is not None:
            limits["max_findings"] = arguments.max_findings
        if arguments.max_files is not None:
            limits["max_files"] = arguments.max_files
        result = run_benchmark(
            corpus,
            cache_directory=cache,
            options=ScanOptions(**limits) if limits else None,
            check_determinism=not arguments.no_determinism,
            workers=arguments.workers,
            on_phase=announce,
        )

        print()
        for key, value in sorted(result.environment.items()):
            print(f"{key}: {value}")
        print()
        header = f"{'phase':<12} {'files':>8} {'findings':>9} {'seconds':>9} {'files/s':>9}"
        print(f"{header} {'proc RSS':>10} {'alloc peak':>11} {'cache':>8}")
        for phase in result.phases:
            print(
                f"{phase.name:<12} {phase.artifacts:>8} {phase.findings:>9} "
                f"{phase.resources.seconds:>9.2f} {phase.files_per_second:>9.1f} "
                f"{_megabytes(phase.resources.process_peak_rss_bytes):>10} "
                f"{_megabytes(phase.resources.peak_traced_bytes):>11} "
                f"{phase.cache.hit_rate:>7.1%}"
            )
        for phase in result.phases:
            print(f"{phase.name}: {phase.cache.explain()}")
        for phase in result.phases:
            caveat = phase.caveat()
            if caveat is not None:
                print(f"INCOMPLETE {phase.name}: {caveat}")
        print(
            "\nproc RSS is a process-lifetime high-water mark: it never falls, so only the "
            "first row is that phase's own peak."
        )
        if result.determinism is not None:
            print()
            print(result.determinism.explain())
        if result.parallel_agreement is not None:
            identical = result.parallel_agreement.identical
            print(
                "Parallel and serial reports agree."
                if identical
                else f"PARALLEL DISAGREES at {result.parallel_agreement.first_difference}."
            )
        if arguments.json is not None:
            arguments.json.write_text(result.to_json(), encoding="utf-8")
            print(f"\nWrote {arguments.json}")
        failed = [
            outcome
            for outcome in (result.determinism, result.parallel_agreement)
            if outcome is not None and not outcome.identical
        ]
        return 1 if failed else 0
    finally:
        # The cache lives under the workspace in every mode, so removing the
        # workspace is enough; a corpus the operator supplied is never touched.
        if arguments.keep_corpus is None:
            shutil.rmtree(workspace, ignore_errors=True)
        else:
            shutil.rmtree(cache, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
