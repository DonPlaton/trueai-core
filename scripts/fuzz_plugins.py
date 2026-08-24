"""Fuzz the plugin trust boundary: protocol, manifests, findings, resource limits.

Every byte crossing into the host from a plugin arrives from code the host does
not trust, and four places parse it:

* the **worker protocol** — requests and responses exchanged through files;
* the **manifest and distribution parsers** — what a plugin says it is;
* **finding validation** — what a plugin claims it observed;
* **resource limits** — the numbers a host hands the kernel.

A fuzzer that only asks "did it crash?" proves very little about any of them,
because a parser that accepts a forged finding without crashing is the failure
this boundary exists to prevent. So each target declares two things: the
exceptions it is *allowed* to raise, and the invariant that must hold when it
does not raise. Anything outside those is a finding.

Runs are seeded and replayable. A failure prints the seed and the exact input, so
a bug reported from a nightly run reproduces with one command:

    python scripts/fuzz_plugins.py --seed 12345 --iterations 200000
    python scripts/fuzz_plugins.py --seconds 3600          # a continuous run
    python scripts/fuzz_plugins.py --target findings       # one boundary
"""

from __future__ import annotations

import argparse
import json
import random
import string
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPOSITORY = Path(__file__).resolve().parents[1]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from pydantic import ValidationError  # noqa: E402

from trueai.core.errors import DetectorRegistrationError  # noqa: E402

#: What a parser at this boundary is allowed to do with hostile input: refuse it.
#: Anything else — a TypeError from an unguarded attribute access, a RecursionError
#: from an unbounded structure, a UnicodeDecodeError escaping a text read — is a
#: place where untrusted input reached code that assumed it was well formed.
EXPECTED_REFUSALS: tuple[type[BaseException], ...] = (
    ValidationError,
    ValueError,
    DetectorRegistrationError,
    json.JSONDecodeError,
)


@dataclass(frozen=True, slots=True)
class Failure:
    """One input that broke a target, with everything needed to replay it."""

    target: str
    iteration: int
    payload: str
    detail: str

    def render(self, seed: int) -> str:
        return (
            f"\n--- {self.target} failed on iteration {self.iteration} ---\n"
            f"seed:    {seed}\n"
            f"detail:  {self.detail}\n"
            f"payload: {self.payload[:2000]}\n"
        )


# -- generators ----------------------------------------------------------------------


# Printable ASCII plus the characters a naive parser mishandles: a bidi
# override, a zero-width space, a NUL, a byte-order mark, and an astral
# codepoint that is two UTF-16 units wide. Built with chr() because a literal
# NUL is not valid in Python source.
_HOSTILE_CHARACTERS = (0x202E, 0x200B, 0x00, 0xFEFF, 0x1F600)
_ALPHABET = string.printable + "".join(chr(point) for point in _HOSTILE_CHARACTERS)


def random_text(rng: random.Random, maximum: int = 40) -> str:
    """Text that includes the characters a naive parser mishandles."""

    return "".join(rng.choice(_ALPHABET) for _ in range(rng.randrange(maximum + 1)))


def random_scalar(rng: random.Random) -> Any:
    return rng.choice(
        [
            None,
            True,
            False,
            0,
            -1,
            rng.randrange(-(2**63), 2**63),
            float("inf") if rng.random() < 0.1 else rng.uniform(-1e9, 1e9),
            random_text(rng),
        ]
    )


def random_structure(rng: random.Random, depth: int = 0) -> Any:
    """A JSON-shaped value that may be deeply nested or very wide."""

    if depth > 6 or rng.random() < 0.4:
        return random_scalar(rng)
    if rng.random() < 0.5:
        return [random_structure(rng, depth + 1) for _ in range(rng.randrange(6))]
    return {random_text(rng, 12): random_structure(rng, depth + 1) for _ in range(rng.randrange(6))}


def mutate(rng: random.Random, value: Any) -> Any:
    """Change one thing about an otherwise valid structure.

    Wholly random input mostly exercises "is this JSON". Mutating something valid
    is what reaches the checks that run *after* parsing succeeds.
    """

    if isinstance(value, dict) and value:
        mutated = dict(value)
        key = rng.choice(list(mutated))
        action = rng.random()
        if action < 0.3:
            del mutated[key]
        elif action < 0.6:
            mutated[key] = random_structure(rng)
        elif action < 0.8:
            mutated[random_text(rng, 12)] = random_structure(rng)
        else:
            mutated[key] = mutate(rng, mutated[key])
        return mutated
    if isinstance(value, list) and value:
        mutated_list = list(value)
        index = rng.randrange(len(mutated_list))
        if rng.random() < 0.5:
            mutated_list[index] = random_structure(rng)
        else:
            del mutated_list[index]
        return mutated_list
    if isinstance(value, str):
        return random_text(rng) if rng.random() < 0.5 else value + random_text(rng, 4)
    return random_scalar(rng)


def as_json(value: Any) -> str:
    """Serialize a generated structure, tolerating what json refuses."""

    try:
        return json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return json.dumps(str(value))


# -- target: the worker protocol -----------------------------------------------------


def _valid_worker_response() -> dict[str, Any]:
    return {
        "protocol_version": "1",
        "detector_id": "example.v1",
        "ok": True,
        "findings": [],
        "confinement": None,
        "error_code": None,
        "error_message": None,
    }


def fuzz_protocol(rng: random.Random) -> str | None:
    """Parse hostile protocol documents; refusal is fine, misparsing is not."""

    from trueai.plugins.protocol import (
        InspectionRequest,
        InspectionResponse,
        WorkerRequest,
        WorkerResponse,
    )

    model = rng.choice([WorkerRequest, WorkerResponse, InspectionRequest, InspectionResponse])
    payload = mutate(rng, _valid_worker_response()) if rng.random() < 0.6 else random_structure(rng)
    text = as_json(payload)
    try:
        parsed = model.model_validate_json(text)
    except EXPECTED_REFUSALS:
        return None
    except Exception as exc:
        return f"{model.__name__} raised {type(exc).__name__}: {exc} for {text[:400]}"

    # Parsing succeeded, so the invariants the host relies on must hold.
    if parsed.protocol_version != "1":
        return f"{model.__name__} accepted protocol_version {parsed.protocol_version!r}"
    if isinstance(payload, dict):
        unknown = set(payload) - set(model.model_fields)
        if unknown:
            return f"{model.__name__} accepted unknown field(s) {sorted(unknown)}"
    return None


# -- target: manifests and distributions ---------------------------------------------


def _valid_manifest() -> dict[str, Any]:
    return {
        "detector_id": "acme.invoice.v1",
        "name": "ACME",
        "version": "1.0",
        "description": "",
        "vendor": "ACME",
        "capabilities": ["read_artifact"],
        "supported_types": [],
        "categories": [],
        "compatible_schema_versions": ["0.1"],
        "minimum_core_version": None,
        "declared": True,
    }


def fuzz_manifest(rng: random.Random) -> str | None:
    """A manifest is a plugin's own claim about itself, and is parsed as hostile."""

    from trueai.plugins.manifest import PluginCapability, PluginManifest

    payload = mutate(rng, _valid_manifest()) if rng.random() < 0.7 else random_structure(rng)
    try:
        manifest = PluginManifest.model_validate(payload)
    except EXPECTED_REFUSALS:
        return None
    except Exception as exc:
        return f"PluginManifest raised {type(exc).__name__}: {exc} for {as_json(payload)[:400]}"

    if not all(isinstance(item, PluginCapability) for item in manifest.capabilities):
        return f"PluginManifest accepted a non-capability: {manifest.capabilities!r}"
    if not manifest.detector_id:
        return "PluginManifest accepted an empty detector id"
    return None


def _valid_distribution() -> dict[str, Any]:
    return {
        "distribution_id": "TAIPKG1-" + "A" * 32,
        "schema_version": "0.1",
        "detector_id": "acme.invoice.v1",
        "version": "1.0",
        "entry_point": "acme:Detector",
        "manifest": _valid_manifest(),
        "publisher": "ACME",
        "publisher_id": None,
        "files": [{"path": "__init__.py", "sha256": "a" * 64, "size": 12}],
        "created_at": "2026-08-25T12:00:00+00:00",
        "expires_at": None,
        "minimum_core_version": None,
        "maximum_core_version": None,
        "compatible_schema_versions": ["0.1"],
        "signature": None,
    }


def fuzz_distribution(rng: random.Random) -> str | None:
    """A mutated distribution must never verify as authentic."""

    from trueai.plugins.distribution import (
        PluginDistribution,
        compute_distribution_id,
        verify_distribution,
    )

    payload = mutate(rng, _valid_distribution()) if rng.random() < 0.8 else random_structure(rng)
    try:
        distribution = PluginDistribution.model_validate(payload)
    except EXPECTED_REFUSALS:
        return None
    except Exception as exc:
        return f"PluginDistribution raised {type(exc).__name__}: {exc} for {as_json(payload)[:400]}"

    try:
        result = verify_distribution(distribution)
    except EXPECTED_REFUSALS:
        return None
    except Exception as exc:
        return f"verify_distribution raised {type(exc).__name__}: {exc}"

    if result.may_load():
        return f"An unsigned distribution reported may_load(): {distribution.distribution_id}"
    if result.content_id_valid != (
        compute_distribution_id(distribution) == distribution.distribution_id
    ):
        return "content_id_valid disagrees with the recomputed identifier"
    for item in distribution.files:
        if ".." in item.path.replace("\\", "/").split("/") or item.path.startswith("/"):
            return f"A distribution accepted an escaping path: {item.path!r}"
    return None


# -- target: finding validation ------------------------------------------------------


def _valid_finding(detector_id: str, artifact_path: str) -> dict[str, Any]:
    return {
        "id": "fnd_" + "0" * 20,
        "detector_id": detector_id,
        "artifact_path": artifact_path,
        "category": "structural_signal",
        "severity": "info",
        "confidence": 1.0,
        "confidence_type": "deterministic",
        "evidence_type": "structural",
        "title": "Observation",
        "description": "A third-party detector reported something.",
        "evidence": {"bytes": 1},
        "provenance_class": "none",
        "tags": [],
    }


def fuzz_findings(rng: random.Random, workspace: Path) -> str | None:
    """The host must never accept a finding it cannot re-derive.

    This is the target that matters most. A protocol parser that accepts a
    malformed document produces a diagnostic; a validator that accepts a forged
    finding puts an invented claim into a report.
    """

    import hashlib

    from trueai.core.artifact import Artifact
    from trueai.core.finding_id import finding_id_is_valid
    from trueai.core.models import ArtifactType, ScanContext, ScanOptions
    from trueai.plugins.host import IsolatedDetector, PluginExecutionError
    from trueai.plugins.manifest import CapabilityDecision, PluginManifest
    from trueai.plugins.protocol import WorkerResponse

    artifact_path = workspace / "notes.txt"
    if not artifact_path.exists():
        artifact_path.write_text("Ordinary content.\n", encoding="utf-8")
    digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()

    manifest = PluginManifest(detector_id="example.fuzz.v1", name="fuzz", version="1.0")
    detector = IsolatedDetector(
        entry_point="unused:Detector",
        manifest=manifest,
        decision=CapabilityDecision(
            detector_id=manifest.detector_id, allowed=True, reason="fuzzing"
        ),
    )
    artifact = Artifact(
        artifact_type=ArtifactType.TEXT,
        path=artifact_path,
        logical_path=artifact_path.name,
    )
    context = ScanContext(options=ScanOptions())

    count = rng.randrange(4)
    findings = [
        mutate(rng, _valid_finding(manifest.detector_id, artifact.display_path))
        if rng.random() < 0.8
        else random_structure(rng)
        for _ in range(count)
    ]
    # Built the way the host receives it: from JSON the worker wrote. A payload the
    # protocol layer refuses never reaches _validate, so a refusal here is the
    # boundary working rather than a finding.
    try:
        response = WorkerResponse.model_validate_json(
            as_json({"detector_id": manifest.detector_id, "ok": True, "findings": findings})
        )
    except EXPECTED_REFUSALS:
        return None

    try:
        accepted = detector._validate(response, artifact, digest, context)
    except PluginExecutionError:
        return None
    except EXPECTED_REFUSALS:
        return None
    except Exception as exc:
        return f"_validate raised {type(exc).__name__}: {exc} for {as_json(findings)[:400]}"

    for finding in accepted:
        if finding.detector_id != manifest.detector_id:
            return f"Accepted a finding attributed to {finding.detector_id!r}"
        if finding.artifact_path != artifact.display_path:
            return f"Accepted a finding about {finding.artifact_path!r}"
        if not finding_id_is_valid(finding):
            return f"Accepted a finding whose id does not match its evidence: {finding.id}"
    return None


# -- target: resource limits ---------------------------------------------------------


def fuzz_resource_limits(rng: random.Random) -> str | None:
    """The numbers a host hands the kernel must be bounded before they get there."""

    from trueai.plugins.resources import PluginResourceLimits

    payload: Any = {
        "max_memory_bytes": random_scalar(rng),
        "max_cpu_seconds": random_scalar(rng),
    }
    if rng.random() < 0.3:
        payload = random_structure(rng)
    try:
        limits = PluginResourceLimits.model_validate(payload)
    except EXPECTED_REFUSALS:
        return None
    except Exception as exc:
        return (
            f"PluginResourceLimits raised {type(exc).__name__}: {exc} for {as_json(payload)[:200]}"
        )

    if limits.max_memory_bytes < 64 * 1024 * 1024:
        return f"Accepted a memory limit below the floor: {limits.max_memory_bytes}"
    if not 1 <= limits.max_cpu_seconds <= 3600:
        return f"Accepted a CPU limit outside its range: {limits.max_cpu_seconds}"
    return None


# -- target: broker paths ------------------------------------------------------------


def fuzz_broker_paths(rng: random.Random, workspace: Path) -> str | None:
    """Any path a plugin supplies must resolve inside its grant or be refused."""

    from trueai.plugins.broker import (
        BrokerGrants,
        CapabilityBroker,
        CapabilityDeniedError,
        WorkspaceGrant,
    )

    root = workspace / "grant"
    root.mkdir(exist_ok=True)
    broker = CapabilityBroker(BrokerGrants(workspace=WorkspaceGrant(root=root)))

    candidate = rng.choice(
        [
            random_text(rng),
            "../" * rng.randrange(1, 6) + random_text(rng, 8),
            "/" + random_text(rng, 8),
            "sub/" + random_text(rng, 8),
            "..\\..\\" + random_text(rng, 8),
            chr(0),  # a NUL truncates the path in some APIs + random_text(rng, 8),
        ]
    )
    try:
        resolved = broker.workspace_path(candidate)
    except CapabilityDeniedError:
        return None
    except EXPECTED_REFUSALS:
        return None
    except Exception as exc:
        return f"workspace_path raised {type(exc).__name__}: {exc} for {candidate!r}"

    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        return f"workspace_path returned {resolved} for {candidate!r}, outside {root}"
    return None


# -- harness -------------------------------------------------------------------------


TARGETS: dict[str, Callable[[random.Random, Path], str | None]] = {
    "protocol": lambda rng, _: fuzz_protocol(rng),
    "manifest": lambda rng, _: fuzz_manifest(rng),
    "distribution": lambda rng, _: fuzz_distribution(rng),
    "findings": fuzz_findings,
    "limits": lambda rng, _: fuzz_resource_limits(rng),
    "broker": fuzz_broker_paths,
}


def run(
    *,
    seed: int,
    iterations: int,
    seconds: float | None = None,
    targets: tuple[str, ...] = (),
    workspace: Path | None = None,
) -> list[Failure]:
    """Run the fuzzer and return every failure it found.

    Returns rather than raises, so a caller can report all of them instead of
    stopping at the first: two failures found together are usually one bug.
    """

    import tempfile

    rng = random.Random(seed)
    chosen = targets or tuple(TARGETS)
    unknown = set(chosen) - set(TARGETS)
    if unknown:
        raise SystemExit(f"Unknown target(s): {', '.join(sorted(unknown))}")

    directory = workspace or Path(tempfile.mkdtemp(prefix="trueai-fuzz-"))
    directory.mkdir(parents=True, exist_ok=True)

    failures: list[Failure] = []
    deadline = time.monotonic() + seconds if seconds else None
    iteration = 0
    while iteration < iterations or (deadline is not None and time.monotonic() < deadline):
        iteration += 1
        name = rng.choice(chosen)
        # Each case gets its own generator seeded from the run, so a single case
        # replays without running everything before it.
        case_seed = rng.randrange(2**63)
        case_rng = random.Random(case_seed)
        try:
            detail = TARGETS[name](case_rng, directory)
        except Exception as exc:
            detail = f"the target raised {type(exc).__name__}: {exc}"
        if detail is not None:
            failures.append(
                Failure(target=name, iteration=iteration, payload=str(case_seed), detail=detail)
            )
            if len(failures) >= 25:
                break
        if deadline is not None and time.monotonic() >= deadline and iteration >= iterations:
            break
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=0, help="Replay a specific run.")
    parser.add_argument("--iterations", type=int, default=2000, help="Cases to run.")
    parser.add_argument(
        "--seconds", type=float, default=None, help="Keep going for this long (continuous mode)."
    )
    parser.add_argument(
        "--target",
        action="append",
        choices=sorted(TARGETS),
        help="Fuzz one boundary. Repeatable; the default is all of them.",
    )
    arguments = parser.parse_args(argv)

    seed = arguments.seed or random.randrange(2**32)
    print(f"seed={seed} iterations={arguments.iterations} seconds={arguments.seconds}")
    started = time.monotonic()
    failures = run(
        seed=seed,
        iterations=arguments.iterations,
        seconds=arguments.seconds,
        targets=tuple(arguments.target or ()),
    )
    elapsed = time.monotonic() - started

    if failures:
        for failure in failures:
            print(failure.render(seed))
        print(f"FAILED: {len(failures)} finding(s) in {elapsed:.1f}s")
        return 1
    print(f"PASSED: no findings in {elapsed:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
