"""Coverage-guided fuzzing of every parsing boundary TrueAI has.

A scanner's whole job is reading files somebody else made.  Ten formats reach a
parser here — ZIP/OPC packages, XML parts, PDF object graphs, ISO-BMFF and EBML
containers, Git object directories, cache entries, policy bundles, certificates,
and reports — and each one is a place where hostile bytes meet code that has to
assume nothing.

Two things make this more than a crash finder.

**Each target declares what it may do and what must hold anyway.**  A parser is
allowed to *refuse*: a `ValueError`, a `TrueAIError`, a validation error.  It is
not allowed to raise a `TypeError` from an unguarded attribute access, a
`RecursionError` from an unbounded structure, a `MemoryError` from a length field
nobody checked, or to hang.  And when it does not refuse, an invariant has to
hold — a returned model stays inside its budget, a rejected cache entry yields
nothing at all, an edited certificate never verifies.  A fuzzer that only asks
"did it crash" would pass a parser that cheerfully accepts a forged signature.

**Mutation is guided by coverage.**  `sys.monitoring` records which lines inside
`trueai/` each input reaches; an input that reaches a line no earlier input did
is kept and mutated further.  No native dependency, and the whole run reproduces
from a seed.

Guidance is not free, and the honest version of the claim is that it pays off
late.  Measured on the PDF, ISO-BMFF, and EBML targets with `--seed 11`:

    3,000 inputs    guided 601 lines   unguided 664
    12,000 inputs   guided 739 lines   unguided 709
    60,000 inputs   guided 757 lines   unguided 727

Early on, mutating a pristine seed beats mutating whatever the corpus has
accumulated; later the corpus is worth more than the seed.  `--no-coverage` is
kept for that reason rather than as a curiosity, and half of all mutations start
from a seed even in guided mode — mutating a mutation of a mutation drifts away
from anything structurally valid, which for a length-prefixed format means never
getting past the header again.

The line count counts lines inside `trueai/` only.  That is the right denominator
for "did our code get exercised" and a misleading one for a target whose parser
is a thin wrapper over pydantic or ElementTree: a low number there means the work
happens in a library, not that less was tested.  Seeds are real artifacts — a
genuinely signed bundle, an issued certificate, a rendered report — because a
seed that fails on its first field never reaches the code worth reaching.

    python scripts/fuzz_parsers.py --iterations 20000
    python scripts/fuzz_parsers.py --seed 4242 --target pdf
    python scripts/fuzz_parsers.py --seconds 600
    python scripts/fuzz_parsers.py --self-check   # prove the harness has teeth
"""

from __future__ import annotations

import argparse
import io
import json
import random
import sys
import time
import zipfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[1]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from pydantic import ValidationError  # noqa: E402

from trueai.core.errors import TrueAIError  # noqa: E402

#: What a parser is allowed to do with hostile input: refuse it, in a way the
#: caller can catch. Anything else is a place where untrusted bytes reached code
#: that assumed they were well formed.
ALLOWED_REFUSALS: tuple[type[BaseException], ...] = (
    ValueError,  # covers the format errors, which all derive from it
    TrueAIError,
    ValidationError,
    KeyError,
    zipfile.BadZipFile,
    UnicodeDecodeError,
    json.JSONDecodeError,
    OSError,
)

#: Raised by code that assumed structure. Each of these is a finding.
FORBIDDEN: tuple[type[BaseException], ...] = (
    TypeError,
    AttributeError,
    IndexError,
    RecursionError,
    MemoryError,
    OverflowError,
    ZeroDivisionError,
    NotImplementedError,
    SystemError,
)

#: Above this an input is not testing a parser, it is testing a memcpy.
MAX_INPUT_BYTES = 96 * 1024


@dataclass(frozen=True, slots=True)
class Finding:
    """One input that broke a target, with what is needed to replay it."""

    target: str
    detail: str
    payload: bytes

    def render(self, seed: int) -> str:
        preview = self.payload[:200]
        return (
            f"[{self.target}] {self.detail}\n"
            f"    replay: python scripts/fuzz_parsers.py --seed {seed} --target {self.target}\n"
            f"    input ({len(self.payload)} bytes): {preview!r}"
        )


# -- coverage ---------------------------------------------------------------------------


class Coverage:
    """Line coverage inside ``trueai/``, via `sys.monitoring`.

    `sys.settrace` would work and is roughly an order of magnitude slower, which
    matters when the point is to run hundreds of thousands of inputs. The tool
    id is the one CPython reserves for a profiler that is not a debugger.
    """

    TOOL_ID = 2

    def __init__(self, package_root: Path) -> None:
        self.package_root = str(package_root)
        self.seen: set[tuple[str, int]] = set()
        self._active = False
        self._batch: set[tuple[str, int]] = set()

    def _record(self, code: object, line: int) -> object:
        filename = getattr(code, "co_filename", "")
        if filename.startswith(self.package_root):
            self._batch.add((filename, line))
        return sys.monitoring.DISABLE if not self._active else None

    @contextmanager
    def measure(self) -> Iterator[set[tuple[str, int]]]:
        """Record the lines one input reaches, and yield the new ones."""

        monitoring = sys.monitoring
        self._batch = set()
        self._active = True
        monitoring.use_tool_id(self.TOOL_ID, "trueai-fuzz")
        try:
            monitoring.register_callback(self.TOOL_ID, monitoring.events.LINE, self._record)
            monitoring.set_events(self.TOOL_ID, monitoring.events.LINE)
            try:
                yield self._batch
            finally:
                monitoring.set_events(self.TOOL_ID, 0)
                monitoring.register_callback(self.TOOL_ID, monitoring.events.LINE, None)
        finally:
            self._active = False
            monitoring.free_tool_id(self.TOOL_ID)

    def absorb(self, batch: set[tuple[str, int]]) -> bool:
        """Return whether this batch reached anything new, and remember it."""

        fresh = batch - self.seen
        self.seen |= batch
        return bool(fresh)


# -- mutation ---------------------------------------------------------------------------

#: Byte sequences worth splicing in: format magic, boundary integers, and the
#: shapes that break a length-prefixed parser.
INTERESTING: tuple[bytes, ...] = (
    b"\x00",
    b"\xff" * 8,
    b"PK\x03\x04",
    b"PK\x01\x02",
    b"%PDF-1.7",
    b"startxref",
    b"trailer",
    b"/ObjStm",
    b"\x1a\x45\xdf\xa3",
    b"ftyp",
    b"moov",
    b"<?xml version='1.0'?>",
    b"<!DOCTYPE a [<!ENTITY e SYSTEM 'file:///etc/passwd'>]>",
    b"\x7f\xff\xff\xff",
    b"\x80\x00\x00\x00",
    (2**31).to_bytes(8, "big"),
    (2**63 - 1).to_bytes(8, "big"),
)


def mutate(rng: random.Random, data: bytes) -> bytes:
    """Return one mutation of an input, bounded in size."""

    if not data:
        return bytes(rng.randrange(256) for _ in range(rng.randrange(1, 64)))
    buffer = bytearray(data)
    for _ in range(rng.randrange(1, 5)):
        choice = rng.randrange(7)
        if choice == 0 and buffer:  # flip a bit
            index = rng.randrange(len(buffer))
            buffer[index] ^= 1 << rng.randrange(8)
        elif choice == 1 and buffer:  # overwrite a byte
            buffer[rng.randrange(len(buffer))] = rng.randrange(256)
        elif choice == 2:  # splice in something interesting
            chunk = rng.choice(INTERESTING)
            index = rng.randrange(len(buffer) + 1)
            buffer[index:index] = chunk
        elif choice == 3 and len(buffer) > 2:  # truncate
            buffer = buffer[: rng.randrange(1, len(buffer))]
        elif choice == 4 and buffer:  # duplicate a run
            start = rng.randrange(len(buffer))
            end = min(len(buffer), start + rng.randrange(1, 64))
            buffer[start:start] = buffer[start:end]
        elif choice == 5 and len(buffer) > 8:  # overwrite a length-shaped field
            index = rng.randrange(len(buffer) - 4)
            buffer[index : index + 4] = rng.choice(
                (b"\xff\xff\xff\xff", b"\x00\x00\x00\x00", b"\x7f\xff\xff\xff")
            )
        else:  # delete a run
            if len(buffer) > 2:
                start = rng.randrange(len(buffer) - 1)
                del buffer[start : start + rng.randrange(1, 32)]
    return bytes(buffer[:MAX_INPUT_BYTES])


# -- targets ----------------------------------------------------------------------------


@dataclass
class Target:
    """One parsing boundary: seeds, the call, and what must hold."""

    name: str
    seeds: tuple[bytes, ...]
    run: Callable[[bytes, Path], None]
    #: Inputs found during a run that reached somewhere new. Kept apart from the
    #: seeds so a pristine starting point is always still available to mutate.
    discovered: list[bytes] = field(default_factory=list)


def _valid_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", "<w:document xmlns:w='x'><w:body/></w:document>")
    return buffer.getvalue()


def _valid_pdfs() -> tuple[bytes, ...]:
    """Two seeds: a classic trailer PDF and a modern one built on streams.

    Both, because they exercise different halves of the object graph — the
    lexical trailer path and the cross-reference-stream path — and a fuzzer given
    only the first never reaches the second.
    """

    minimal = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
        b"trailer\n<< /Root 1 0 R /Size 3 >>\n"
        b"startxref\n0\n%%EOF\n"
    )
    try:
        from tests.unit.test_pdf_object_graph import classic_pdf, modern_pdf
    except Exception:  # pragma: no cover - tests not importable from an install
        return (minimal,)
    try:
        return (classic_pdf(), modern_pdf(), minimal)
    except Exception:  # pragma: no cover
        return (minimal,)


def _valid_iso_bmff() -> bytes:
    """A container with a track and a sample table, not just a header.

    Built by the same code the invariant fixtures use: a seed that stops at
    `ftyp` never reaches the sample-table resolution that is worth fuzzing.
    """

    try:
        from tests.unit.test_iso_bmff_invariants import build_mp4
    except Exception:  # pragma: no cover - tests not importable from an install
        ftyp = b"\x00\x00\x00\x18ftypisom\x00\x00\x02\x00isomiso2"
        free = b"\x00\x00\x00\x10free" + b"\x00" * 8
        return ftyp + free
    return build_mp4()


def _valid_ebml() -> bytes:
    """A document with a Segment, built the way the invariant tests build one.

    A header-only seed is refused before `model_ebml` reaches anything worth
    fuzzing, so the seed comes from the same builder the fixtures use.
    """

    try:
        from tests.unit.test_ebml_invariants import build_webm
    except Exception:  # pragma: no cover - tests not importable from an install
        header = b"\x1a\x45\xdf\xa3\x84\x42\x86\x81\x01"
        segment = b"\x18\x53\x80\x67\x84" + b"\xec\x82\x00\x00"
        return header + segment
    return build_webm()


def _valid_bundle() -> bytes:
    """A genuinely signed bundle, so mutations start from something that validates.

    A seed that fails on its first field never reaches the interesting code, and
    the near-miss inputs — a bundle that parses and whose signature does not
    match — are the ones worth generating.
    """

    try:
        from trueai.core.certificates import generate_ed25519_keypair
        from trueai.core.policy import PolicyStore
        from trueai.core.policy_bundle import issue_policy_bundle, policy_bundle_json
    except Exception:  # pragma: no cover - the attestation extra is absent
        return b'{"bundle_id":"TPB1-' + b"A" * 32 + b'"}'

    import tempfile

    directory = Path(tempfile.mkdtemp(prefix="trueai-fuzz-seed-"))
    private, public = directory / "k", directory / "k.pub"
    try:
        generate_ed25519_keypair(private, public)
        bundle = issue_policy_bundle(
            PolicyStore.get("client-delivery"), issuer="Seed", signing_key=private
        )
    except Exception:  # pragma: no cover - signing unavailable
        return b'{"bundle_id":"TPB1-' + b"A" * 32 + b'"}'
    return policy_bundle_json(bundle).encode("utf-8")


def _valid_certificate() -> bytes:
    """A real certificate, for the same reason."""

    try:
        from trueai.core.certificates import certificate_json, issue_certificate
        from trueai.core.models import ScanOptions
    except Exception:  # pragma: no cover
        return b'{"certificate_id":"TAI1-' + b"A" * 32 + b'"}'

    try:
        certificate = issue_certificate(_report_object(), ScanOptions())
    except Exception:  # pragma: no cover
        return b'{"certificate_id":"TAI1-' + b"A" * 32 + b'"}'
    return certificate_json(certificate).encode("utf-8")


def _report_object():
    from trueai.core.models import (
        ArtifactDescriptor,
        ArtifactType,
        IntegrityReport,
        IntegrityStatus,
        ScanReport,
        ScanSummary,
    )

    descriptor = ArtifactDescriptor(
        path="a.md", artifact_type=ArtifactType.MARKDOWN, size=3, sha256="0" * 64
    )
    return ScanReport(
        artifact=descriptor,
        artifacts=(descriptor,),
        summary=ScanSummary(artifact_count=1, finding_count=0),
        findings=(),
        integrity=IntegrityReport(status=IntegrityStatus.NOT_MODIFIED, explanation="none"),
    )


def _valid_report() -> bytes:
    from trueai.reporters import JSONReporter

    return JSONReporter().render(_report_object()).encode("utf-8")


def target_opc(data: bytes, workspace: Path) -> None:
    """A ZIP that claims to be an Office package."""

    from trueai.core.models import ScanOptions
    from trueai.detectors.documents.opc import open_validated_opc

    path = workspace / "package.docx"
    path.write_bytes(data)
    try:
        archive = open_validated_opc(path, ScanOptions())
    except ALLOWED_REFUSALS:
        return
    with archive:
        names = archive.namelist()
    # A validated package must not name a member that would escape the tree it is
    # extracted into. Nothing here extracts, which is exactly why the check has
    # to live in the validator rather than in the caller.
    for name in names:
        if name.startswith("/") or ".." in Path(name).parts or ":" in name[:3]:
            raise AssertionError(f"validated package names an escaping member {name!r}")


def target_xml(data: bytes, workspace: Path) -> None:
    """An XML part from inside a package."""

    del workspace
    from trueai.detectors.documents.opc import parse_xml

    try:
        element = parse_xml(data, "word/document.xml")
    except ALLOWED_REFUSALS:
        return
    # A DTD that resolved would have put the entity's text into the tree.
    rendered = "".join(element.itertext())
    if "root:x:" in rendered or "/etc/passwd" in rendered:
        raise AssertionError("an external entity was resolved")


def target_pdf(data: bytes, workspace: Path) -> None:
    """A PDF object graph, including cross-reference and object streams."""

    del workspace
    from trueai.core.pdf_objects import Budget, model_pdf

    budget = Budget()
    try:
        model = model_pdf(data, budget)
    except ALLOWED_REFUSALS:
        return
    if len(model.signatures) > budget.max_objects:
        raise AssertionError("more signature fields than the object budget allows")


def target_iso_bmff(data: bytes, workspace: Path) -> None:
    """An ISO base media container."""

    del workspace
    from trueai.core.iso_bmff import model_iso_bmff

    try:
        model = model_iso_bmff(data)
    except ALLOWED_REFUSALS:
        return
    for box in model.boxes:
        # A box that claims a range outside the input is one a cleaner would
        # later slice with, and a slice past the end silently returns short.
        if box.start < 0 or box.payload_start < box.start or box.end > len(data):
            raise AssertionError(f"box {box.path_name!r} runs past the end of the input")


def target_ebml(data: bytes, workspace: Path) -> None:
    """A Matroska/WebM container."""

    del workspace
    from trueai.core.ebml import model_ebml

    try:
        model = model_ebml(data)
    except ALLOWED_REFUSALS:
        return
    for element in model.elements:
        if element.start < 0 or element.payload_start < element.start or element.end > len(data):
            raise AssertionError(f"element {element.identifier:#x} runs past the end of the input")


def target_cache(data: bytes, workspace: Path) -> None:
    """A cache entry, which is untrusted local state."""

    from trueai.core.cache import ScanCache

    directory = workspace / "cache"
    cache = ScanCache(directory)
    key = "c" * 64
    entry = directory / key[:2] / f"{key}.json"
    entry.parent.mkdir(parents=True, exist_ok=True)
    entry.write_bytes(data)
    try:
        result = cache.load(key)
    except ALLOWED_REFUSALS:
        raise AssertionError("a damaged cache entry must be a miss, not an exception") from None
    if result is None:
        return
    # A hit has to be a complete, validated result. A partially decoded one would
    # silently shrink a report on the next scan.
    if any(not finding.id for finding in result.findings):
        raise AssertionError("a cache hit returned a finding with no identifier")


def target_policy_bundle(data: bytes, workspace: Path) -> None:
    """A signed enterprise policy bundle."""

    from trueai.core.policy_bundle import load_policy_bundle

    path = workspace / "bundle.json"
    path.write_bytes(data)
    try:
        bundle = load_policy_bundle(path)
    except ALLOWED_REFUSALS:
        return
    if bundle.signature is not None and not bundle.signature.value:
        raise AssertionError("a bundle loaded with an empty signature value")


def target_certificate(data: bytes, workspace: Path) -> None:
    """An audit certificate arriving from somewhere else."""

    from trueai.core.certificates import load_certificate

    path = workspace / "certificate.json"
    path.write_bytes(data)
    try:
        certificate = load_certificate(path)
    except ALLOWED_REFUSALS:
        return
    if not certificate.certificate_id.startswith("TAI1-"):
        raise AssertionError("a certificate loaded without a well-formed identifier")


def target_report(data: bytes, workspace: Path) -> None:
    """A scan report being read back, by a tool that did not produce it."""

    from trueai.reporters import JSONReporter

    path = workspace / "report.json"
    path.write_bytes(data)
    try:
        report = JSONReporter.load(path)
    except ALLOWED_REFUSALS:
        return
    if len(report.findings) != report.summary.finding_count:
        # A report whose counts disagree with its contents would make every
        # downstream number wrong without anything raising.
        raise AssertionError("a loaded report's finding count disagrees with its findings")


def target_git_scope(data: bytes, workspace: Path) -> None:
    """A Git object directory's alternates file, which names other trees."""

    from trueai.detectors.git.command import validate_repository_scope

    repository = workspace / "repo"
    objects = repository / ".git" / "objects" / "info"
    objects.mkdir(parents=True, exist_ok=True)
    (repository / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (objects / "alternates").write_bytes(data)
    try:
        validate_repository_scope(repository, 1024 * 1024)
    except ALLOWED_REFUSALS:
        return
    # Accepting the file means every path in it was judged to be inside the tree.
    for line in data.split(b"\n"):
        text = line.strip()
        if text and not text.startswith(b"#") and (b".." in text or text.startswith(b"/")):
            raise AssertionError(
                f"an alternates entry escaping the repository was accepted: {text!r}"
            )


TARGETS: dict[str, Target] = {
    "opc": Target("opc", (_valid_zip(),), target_opc),
    "xml": Target(
        "xml",
        (
            b"<a xmlns='x'><b attr='1'>text</b><!-- c --><?pi v?></a>",
            b"<?xml version='1.0'?><!DOCTYPE a [<!ENTITY e 'x'>]><a>&e;</a>",
            b"<w:document xmlns:w='u'><w:body><w:p><w:r><w:t>t</w:t></w:r></w:p></w:body>"
            b"</w:document>",
        ),
        target_xml,
    ),
    "pdf": Target("pdf", _valid_pdfs(), target_pdf),
    "iso_bmff": Target("iso_bmff", (_valid_iso_bmff(),), target_iso_bmff),
    "ebml": Target("ebml", (_valid_ebml(),), target_ebml),
    "cache": Target("cache", (b'{"key":"' + b"c" * 64 + b'","findings":[]}',), target_cache),
    "policy_bundle": Target("policy_bundle", (_valid_bundle(),), target_policy_bundle),
    "certificate": Target("certificate", (_valid_certificate(),), target_certificate),
    "report": Target("report", (_valid_report(),), target_report),
    "git_scope": Target("git_scope", (b"/tmp/objects\n", b"../../elsewhere\n"), target_git_scope),
}


# -- the run ------------------------------------------------------------------------------


def run(
    *,
    seed: int,
    iterations: int,
    seconds: float | None = None,
    targets: tuple[str, ...] = (),
    workspace: Path | None = None,
    guided: bool = True,
) -> tuple[list[Finding], int]:
    """Fuzz the chosen targets and return the findings and the coverage reached."""

    import tempfile

    chosen = targets or tuple(TARGETS)
    unknown = set(chosen) - set(TARGETS)
    if unknown:
        raise SystemExit(f"Unknown target(s): {', '.join(sorted(unknown))}")

    rng = random.Random(seed)
    directory = workspace or Path(tempfile.mkdtemp(prefix="trueai-parsefuzz-"))
    directory.mkdir(parents=True, exist_ok=True)
    coverage = Coverage(REPOSITORY / "trueai")

    for name in chosen:
        TARGETS[name].discovered = []

    findings: list[Finding] = []
    deadline = time.monotonic() + seconds if seconds else None
    iteration = 0
    while iteration < iterations or (deadline is not None and time.monotonic() < deadline):
        iteration += 1
        target = TARGETS[rng.choice(chosen)]
        # Half the time mutate a pristine seed. Mutating a mutation of a mutation
        # drifts away from anything structurally valid, and for a length-prefixed
        # format that means never getting past the header again.
        if target.discovered and rng.random() < 0.5:
            base = rng.choice(target.discovered)
        else:
            base = rng.choice(target.seeds) if target.seeds else b""
        payload = mutate(rng, base)
        case = directory / f"case{iteration % 16}"
        case.mkdir(parents=True, exist_ok=True)

        # Coverage is measured either way so the two modes are comparable; only
        # the guided one lets it decide what stays in the corpus.
        with coverage.measure() as batch:
            detail = _attempt(target, payload, case)
        reached_new = coverage.absorb(set(batch))
        # An input that reached somewhere new is worth mutating further; one that
        # did not is discarded, which is what keeps the corpus small.
        if guided and reached_new and len(target.discovered) < 256:
            target.discovered.append(payload)

        if detail is not None:
            findings.append(Finding(target=target.name, detail=detail, payload=payload))
            if len(findings) >= 25:
                break
        if deadline is not None and time.monotonic() >= deadline and iteration >= iterations:
            break
    return findings, len(coverage.seen)


def _attempt(target: Target, payload: bytes, workspace: Path) -> str | None:
    """Run one input and classify whatever came back."""

    try:
        target.run(payload, workspace)
    except AssertionError as exc:
        return f"invariant broken: {exc}"
    except FORBIDDEN as exc:
        return f"unguarded {type(exc).__name__}: {exc}"
    except ALLOWED_REFUSALS:
        return None
    except Exception as exc:  # anything a target did not declare
        return f"undeclared {type(exc).__name__}: {exc}"
    return None


def self_check() -> int:
    """Prove the harness reports a broken invariant rather than passing quietly."""

    import tempfile

    def broken(data: bytes, workspace: Path) -> None:
        del data, workspace
        raise AssertionError("deliberate")

    def unguarded(data: bytes, workspace: Path) -> None:
        del data, workspace
        raise TypeError("deliberate")

    directory = Path(tempfile.mkdtemp(prefix="trueai-selfcheck-"))
    problems = []
    if _attempt(Target("x", (b"",), broken), b"", directory) is None:
        problems.append("a broken invariant was not reported")
    if _attempt(Target("x", (b"",), unguarded), b"", directory) is None:
        problems.append("an unguarded TypeError was not reported")
    if _attempt(Target("x", (b"",), lambda data, workspace: None), b"", directory) is not None:
        problems.append("a clean target was reported as a failure")

    for problem in problems:
        print(f"SELF-CHECK FAILED: {problem}")
    if problems:
        return 1
    print("SELF-CHECK PASSED: the harness reports what it is supposed to.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=0, help="Replay a specific run.")
    parser.add_argument("--iterations", type=int, default=5000, help="Inputs to try.")
    parser.add_argument("--seconds", type=float, default=None, help="Run for this long instead.")
    parser.add_argument(
        "--target",
        action="append",
        choices=sorted(TARGETS),
        help="Fuzz one boundary. Repeatable; the default is all of them.",
    )
    parser.add_argument(
        "--no-coverage",
        action="store_true",
        help="Mutate blindly. Faster per input and much worse at getting past a length check.",
    )
    parser.add_argument(
        "--self-check", action="store_true", help="Check that the harness can fail."
    )
    parser.add_argument(
        "--write-findings",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "Write each failing input here as a file. The printed preview stops at "
            "200 bytes, so a longer one cannot be handed to a debugger or a "
            "regression test without this."
        ),
    )
    arguments = parser.parse_args(argv)

    if arguments.self_check:
        return self_check()

    seed = arguments.seed or random.randrange(2**32)
    print(f"seed={seed} iterations={arguments.iterations} seconds={arguments.seconds}")
    started = time.monotonic()
    findings, lines = run(
        seed=seed,
        iterations=arguments.iterations,
        seconds=arguments.seconds,
        targets=tuple(arguments.target or ()),
        guided=not arguments.no_coverage,
    )
    elapsed = time.monotonic() - started

    if findings:
        for index, finding in enumerate(findings):
            print(finding.render(seed))
            if arguments.write_findings is not None:
                arguments.write_findings.mkdir(parents=True, exist_ok=True)
                written = arguments.write_findings / f"{finding.target}-{seed}-{index}.bin"
                written.write_bytes(finding.payload)
                print(f"    written: {written}")
        print(f"FAILED: {len(findings)} finding(s) in {elapsed:.1f}s, {lines} lines reached")
        return 1
    print(f"PASSED: no findings in {elapsed:.1f}s, {lines} lines reached")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
