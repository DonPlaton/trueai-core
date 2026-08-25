"""Emit a CycloneDX SBOM for the installed runtime closure, with no build tooling.

CI already runs `cyclonedx-py`. This exists because a release gate that can only
run inside one CI provider is a gate that cannot be run before pushing, and
because the interesting failure is not "the SBOM is missing" but "the SBOM is
missing something".

So the emphasis is on completeness rather than on the format. `--check` fails
when a component has no version, no license, or no purl — three fields an SBOM is
for, and three that a generator will happily leave blank when a distribution's
metadata is thin. An SBOM with blanks is worse than none: it passes a consumer's
"do you have an SBOM" check and answers none of their questions.

The declared component set lives in `security/advisories.toml`, not in a second
snapshot file. One list, checked from both ends by `check_advisories.py`.

    python scripts/generate_sbom.py --output sbom.cdx.json
    python scripts/generate_sbom.py --check
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path
from typing import Any

REPOSITORY = Path(__file__).resolve().parent.parent
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from packaging.utils import canonicalize_name  # noqa: E402

CYCLONEDX_VERSION = "1.5"

#: A license field a generator fills in when it has nothing. Treated as absent,
#: because "UNKNOWN" in an SBOM answers a consumer's question with a shrug.
_EMPTY_LICENSES = frozenset({"", "unknown", "UNKNOWN", "None", "NOASSERTION"})


@dataclass(frozen=True, slots=True)
class Component:
    """One distribution, as an SBOM consumer needs it."""

    name: str
    version: str
    license_id: str
    purl: str

    def to_dict(self) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "type": "library",
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "bom-ref": self.purl,
        }
        if self.license_id:
            entry["licenses"] = [{"license": {"name": self.license_id}}]
        return entry


def _license_of(metadata: Any) -> str:
    """Return a license name from whichever field the distribution used.

    Three places, because packaging metadata moved twice: the modern
    `License-Expression`, the older `License`, and the classifier that a great
    many distributions still rely on instead of either.
    """

    expression = metadata.get("License-Expression")
    if isinstance(expression, str) and expression.strip() not in _EMPTY_LICENSES:
        return expression.strip()
    declared = metadata.get("License")
    if isinstance(declared, str) and declared.strip() not in _EMPTY_LICENSES:
        # A few distributions paste an entire license text here. The first line
        # is the useful part; the rest belongs in the wheel, not in an SBOM.
        return declared.strip().splitlines()[0][:200]
    for classifier in metadata.get_all("Classifier") or []:
        if isinstance(classifier, str) and classifier.startswith("License ::"):
            return classifier.rsplit("::", 1)[-1].strip()
    return ""


def collect(names: tuple[str, ...]) -> list[Component]:
    """Describe every named distribution, in a stable order."""

    components: list[Component] = []
    for name in sorted(names, key=canonicalize_name):
        try:
            package = distribution(name)
        except PackageNotFoundError:
            continue
        display = package.metadata.get("Name", name)
        version = package.version or ""
        components.append(
            Component(
                name=display,
                version=version,
                license_id=_license_of(package.metadata),
                purl=f"pkg:pypi/{canonicalize_name(display)}@{version}",
            )
        )
    return components


def build_document(
    components: list[Component], *, timestamp: datetime | None = None
) -> dict[str, Any]:
    """Assemble a CycloneDX document.

    The timestamp is injectable so a reproducible build can pin it; a document
    that differs between two builds of the same source is not evidence of
    anything.
    """

    from trueai._version import PACKAGE_VERSION

    moment = timestamp or datetime.now(UTC)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": moment.isoformat(),
            "tools": [{"vendor": "TrueAI", "name": "generate_sbom.py"}],
            "component": {
                "type": "application",
                "name": "trueai-core",
                "version": PACKAGE_VERSION,
                "purl": f"pkg:pypi/trueai-core@{PACKAGE_VERSION}",
                "bom-ref": f"pkg:pypi/trueai-core@{PACKAGE_VERSION}",
            },
        },
        "components": [item.to_dict() for item in components],
    }


def incompleteness(components: list[Component]) -> list[str]:
    """Return every field an SBOM consumer would find blank.

    The failure worth catching: a document that exists, passes a "do you have an
    SBOM" check, and answers none of the questions it was requested for.
    """

    problems: list[str] = []
    if not components:
        return ["the SBOM lists no components at all"]
    for item in components:
        if not item.version:
            problems.append(f"{item.name} has no version")
        if not item.license_id:
            problems.append(f"{item.name} has no license")
        if not item.purl.startswith("pkg:pypi/") or item.purl.endswith("@"):
            problems.append(f"{item.name} has no usable package URL")
    references = [item.purl for item in components]
    if len(set(references)) != len(references):
        problems.append("two components share a bom-ref, so a consumer cannot tell them apart")
    return problems


def runtime_components() -> list[Component]:
    from scripts.check_licenses import runtime_distribution_names

    return collect(runtime_distribution_names())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=None, help="Write the SBOM here.")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail when a component is missing a version, a license, or a package URL.",
    )
    arguments = parser.parse_args(argv)

    try:
        components = runtime_components()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if arguments.check:
        problems = incompleteness(components)
        if problems:
            for problem in problems:
                print(f"error: {problem}", file=sys.stderr)
            print(f"\n{len(problems)} incomplete SBOM entr(ies).", file=sys.stderr)
            return 1
        print(f"{len(components)} components, each with a version, a license, and a package URL.")
        return 0

    document = build_document(components)
    rendered = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if arguments.output is not None:
        arguments.output.write_text(rendered, encoding="utf-8")
        print(f"Wrote {arguments.output} ({len(components)} components).")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
