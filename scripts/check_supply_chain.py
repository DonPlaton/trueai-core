"""Run every supply-chain gate, and report all of them rather than the first.

Four checks that answer four different questions, and a release needs all four:

* **licenses** — is anything in the runtime closure under terms this project
  cannot ship under;
* **advisories** — has anybody looked at the advisory sources recently, and does
  the ledger still describe the build that exists;
* **SBOM completeness** — does every component carry a version, a license, and a
  package URL, or is the document one that passes a "do you have an SBOM" check
  while answering nothing;
* **packaged manifest** — does the distribution contain what it says it does.

They run together because they fail together in practice: a dependency added
without thought fails three of them at once, and seeing one failure at a time
turns one fix into three round trips.

Fetching new advisories needs the network and stays out of this. `pip-audit`
runs in hosted CI where the network is available; what runs here is everything
that can be checked from a working tree, so a maintainer can find out before
pushing rather than after.

    python scripts/check_supply_chain.py
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))


@dataclass(frozen=True, slots=True)
class Gate:
    """One check, and what a failure of it means."""

    name: str
    question: str
    run: Callable[[], int]


def _licenses() -> int:
    from scripts.check_licenses import main

    return main()


def _advisories() -> int:
    from scripts.check_advisories import main

    return main([])


def _sbom() -> int:
    from scripts.generate_sbom import main

    return main(["--check"])


def _manifest() -> int:
    from scripts.check_manifest import main

    return main()


GATES: tuple[Gate, ...] = (
    Gate("licenses", "is anything under terms this project cannot ship under?", _licenses),
    Gate("advisories", "has anybody looked recently, and does the ledger still fit?", _advisories),
    Gate("sbom", "does every component carry a version, a license, and a purl?", _sbom),
    Gate("manifest", "does the distribution contain what it says it does?", _manifest),
)


def main(argv: list[str] | None = None) -> int:
    del argv
    failures: list[str] = []
    for gate in GATES:
        print(f"\n== {gate.name}: {gate.question}")
        try:
            code = gate.run()
        except SystemExit as exc:  # a gate that exits rather than returning
            code = int(exc.code or 0)
        except Exception as exc:  # a gate that broke is a gate that did not pass
            print(f"error: {gate.name} raised {type(exc).__name__}: {exc}", file=sys.stderr)
            code = 1
        if code != 0:
            failures.append(gate.name)

    print()
    if failures:
        print(f"FAILED: {', '.join(failures)}", file=sys.stderr)
        return 1
    print(f"PASSED: {len(GATES)} supply-chain gates.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
