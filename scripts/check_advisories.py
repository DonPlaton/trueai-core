"""Fail when nobody has looked at advisories, not only when one is found.

`pip-audit` answers "does a packaged dependency have a known CVE right now". Two
questions it does not answer decide whether a scanner is safe to run on hostile
files:

**What about the parsers that are not packaged dependencies?** Most artifact
bytes reach `zipfile`, `xml.etree`, `zlib`, `html.parser`, and `json` — standard
library code that a dependency audit never mentions. A CPython advisory for any
of them applies directly and would pass a clean `pip-audit` run without comment.

**Has anybody looked recently?** "No known vulnerabilities" from a review done
eight months ago is a lie by omission, and a green check makes it a confident
one. So the gate fails on *staleness*, which means it fails when the work stops
rather than only when a specific CVE appears.

Four ways to fail, and each is a different kind of neglect:

* the ledger is older than its own `max_age_days`;
* a runtime dependency is installed that nobody reviewed;
* a reviewed component is no longer a dependency, so the ledger is describing a
  build that no longer exists;
* an accepted risk has run out its expiry, which is what stops an acceptance
  becoming permanent by inattention.

Fetching new advisories needs the network and is deliberately not done here. What
is automated is noticing that nobody fetched any.

    python scripts/check_advisories.py
    python scripts/check_advisories.py --today 2027-01-01   # test the clock
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from packaging.utils import canonicalize_name  # noqa: E402

LEDGER_PATH = REPOSITORY / "security" / "advisories.toml"

#: Kinds that are expected to be installed distributions. A `stdlib-parser` has
#: no distribution to compare against, which is exactly why it needs an entry.
DISTRIBUTION_KINDS = frozenset({"dependency", "optional-parser"})


@dataclass(frozen=True, slots=True)
class Problem:
    """One reason the gate fails, phrased as what to do about it."""

    kind: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.kind}] {self.detail}"


def load_ledger(path: Path = LEDGER_PATH) -> dict[str, object]:
    """Read the ledger, refusing a malformed one rather than assuming defaults."""

    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"No advisory ledger at {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise SystemExit(f"The advisory ledger is not valid TOML: {exc}") from exc
    if "meta" not in raw:
        raise SystemExit("The advisory ledger has no [meta] section")
    return raw


def _as_date(value: object, where: str) -> date:
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError as exc:
            raise SystemExit(f"{where} is not an ISO date: {value!r}") from exc
    raise SystemExit(f"{where} is missing or not a date")


def check(
    ledger: dict[str, object],
    *,
    installed: frozenset[str],
    today: date,
    platform: str | None = None,
) -> list[Problem]:
    """Return every reason the ledger fails to describe the current build.

    ``platform`` names the ``sys.platform`` the closure was taken on, so the
    answer for Linux can be checked from Windows. A gate that can only be
    interrogated about the machine it happens to be running on is how a
    platform-conditional entry stays wrong until a hosted runner tries it.
    """

    problems: list[Problem] = []
    meta = ledger.get("meta")
    if not isinstance(meta, dict):
        return [Problem("ledger", "the [meta] section is not a table")]

    reviewed = _as_date(meta.get("reviewed_at"), "meta.reviewed_at")
    max_age = meta.get("max_age_days")
    if not isinstance(max_age, int) or max_age <= 0:
        return [Problem("ledger", "meta.max_age_days must be a positive number of days")]

    age = (today - reviewed).days
    if age > max_age:
        # The failure that matters most: it fires when the reviewing stops,
        # rather than waiting for a specific advisory to be published.
        problems.append(
            Problem(
                "stale",
                f"the ledger was last reviewed {age} days ago and the limit is {max_age}; "
                "re-check the sources and move meta.reviewed_at",
            )
        )
    if not meta.get("sources"):
        problems.append(
            Problem("ledger", "meta.sources is empty; a handover would lose the watch list")
        )

    components = ledger.get("component")
    if not isinstance(components, list) or not components:
        return [*problems, Problem("ledger", "the ledger lists no components")]

    reviewed_names: set[str] = set()
    for entry in components:
        if not isinstance(entry, dict):
            problems.append(Problem("ledger", "a [[component]] entry is not a table"))
            continue
        name = entry.get("name")
        kind = entry.get("kind")
        if not isinstance(name, str) or not name:
            problems.append(Problem("ledger", "a component has no name"))
            continue
        if not isinstance(entry.get("why"), str) or not entry.get("why"):
            problems.append(
                Problem(
                    "unexplained",
                    f"{name} has no `why`; an entry nobody can justify is one nobody reviewed",
                )
            )
        component_reviewed = _as_date(entry.get("reviewed_at"), f"component {name}.reviewed_at")
        if (today - component_reviewed).days > max_age:
            problems.append(
                Problem(
                    "stale",
                    f"{name} was last reviewed {(today - component_reviewed).days} days ago",
                )
            )
        platforms = entry.get("platforms")
        if platforms is not None and (
            not isinstance(platforms, list)
            or not platforms
            or not all(isinstance(item, str) and item for item in platforms)
        ):
            problems.append(
                Problem(
                    "ledger",
                    f"{name}.platforms must be a non-empty list of sys.platform values; "
                    "an unreadable one would excuse a real absence",
                )
            )
        if kind in DISTRIBUTION_KINDS:
            reviewed_names.add(canonicalize_name(name))

    missing = sorted(installed - reviewed_names)
    for name in missing:
        problems.append(
            Problem(
                "unreviewed",
                f"{name} is in the runtime closure and is not in the ledger; a dependency "
                "arrived without anyone deciding what it parses",
            )
        )

    # A `dependency` entry with nothing installed behind it means the ledger
    # describes a build that no longer exists, and a reader cannot tell which
    # half is out of date.
    stale_entries = sorted(
        name
        for name in reviewed_names
        if name not in installed and not _absence_is_expected(components, name, platform)
    )
    for name in stale_entries:
        problems.append(
            Problem(
                "orphaned",
                f"{name} is reviewed but not installed; remove it, mark it optional, or "
                "declare the platforms it installs on",
            )
        )

    problems.extend(_check_accepted(ledger, today))
    return problems


def _absence_is_expected(
    components: list[object], canonical: str, platform: str | None = None
) -> bool:
    """Is this component missing for a reason the ledger already declared?

    Two reasons qualify. An `optional-parser` is installed only when somebody
    asks for the extra. A component that declares `platforms` is in the lock but
    resolves to nothing here -- `colorama` ships on Windows and on no other
    platform, and the entry still has to exist, because the question the ledger
    answers is "what does this parse", which does not stop mattering on the
    platform that installs it.

    Anything else absent is a ledger that describes a build nobody has.
    """

    current = sys.platform if platform is None else platform
    for entry in components:
        if not isinstance(entry, dict):
            continue
        if canonicalize_name(str(entry.get("name", ""))) != canonical:
            continue
        if entry.get("kind") == "optional-parser":
            return True
        platforms = entry.get("platforms")
        if isinstance(platforms, list) and platforms:
            return current not in platforms
        return False
    return False


def _check_accepted(ledger: dict[str, object], today: date) -> list[Problem]:
    """An acceptance without an expiry is a decision nobody will revisit."""

    problems: list[Problem] = []
    accepted = ledger.get("accepted")
    if accepted is None:
        return problems
    if not isinstance(accepted, list):
        return [Problem("ledger", "[[accepted]] must be a list of tables")]
    for entry in accepted:
        if not isinstance(entry, dict):
            problems.append(Problem("ledger", "an [[accepted]] entry is not a table"))
            continue
        advisory = str(entry.get("advisory", "<unnamed>"))
        for field in ("component", "reason", "accepted_by"):
            if not entry.get(field):
                problems.append(Problem("accepted", f"{advisory} has no {field}"))
        expires = entry.get("expires_at")
        if expires is None:
            problems.append(
                Problem(
                    "accepted",
                    f"{advisory} has no expiry; without one an acceptance becomes permanent "
                    "by inattention rather than by decision",
                )
            )
            continue
        when = _as_date(expires, f"accepted {advisory}.expires_at")
        if when < today:
            problems.append(
                Problem("expired", f"{advisory} was accepted until {when} and that has passed")
            )
    return problems


def installed_closure() -> frozenset[str]:
    """The runtime dependency closure, canonicalized, minus TrueAI itself."""

    from scripts.check_licenses import runtime_distribution_names

    names = runtime_distribution_names()
    return frozenset(canonicalize_name(name) for name in names) - {canonicalize_name("trueai-core")}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--today",
        type=date.fromisoformat,
        default=None,
        help="Pretend it is this date, to test the staleness clock.",
    )
    parser.add_argument(
        "--ledger", type=Path, default=LEDGER_PATH, help="A ledger other than the default."
    )
    arguments = parser.parse_args(argv)

    ledger = load_ledger(arguments.ledger)
    try:
        installed = installed_closure()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    problems = check(ledger, installed=installed, today=arguments.today or date.today())
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        print(f"\n{len(problems)} advisory-tracking problem(s).", file=sys.stderr)
        return 1

    meta = ledger["meta"]
    assert isinstance(meta, dict)
    reviewed = _as_date(meta["reviewed_at"], "meta.reviewed_at")
    horizon = reviewed + timedelta(days=int(meta["max_age_days"]))
    components = ledger.get("component")
    count = len(components) if isinstance(components, list) else 0
    print(f"{count} components reviewed on {reviewed}; the next review is due by {horizon}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
