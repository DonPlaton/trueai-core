"""Local evidence adapters: what actually happened, recorded by digest.

A process attestation is only as good as what supports it, and the material that
supports it is usually private. Prompts, proprietary sources, client feedback, and
personal identifiers must not end up in a record that gets shared, so these
adapters read local artifacts and emit :class:`EvidenceReference` objects carrying
digests and narrow descriptions rather than content.

Each adapter answers "what can be recomputed later" rather than "what can be
shown now". A Git commit digest can be checked against the repository. A test
output digest can be checked against a rerun. A private note's digest can be
checked against the note if its holder chooses to disclose it. None of that
requires the record to carry the material itself.

Everything here is offline. No adapter contacts a network, and none of them reads
outside the paths the caller named.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import subprocess
from collections.abc import Iterable, Sequence
from pathlib import Path

from trueai.core.attestation import DisclosureStatus, EvidenceKind, EvidenceReference
from trueai.core.errors import AttestationError

#: A single evidence file is read within this boundary. Evidence is meant to be a
#: receipt, not a data lake, and an unbounded read here would be a denial-of-service
#: vector in an otherwise bounded tool.
MAX_EVIDENCE_BYTES = 32 * 1024 * 1024

#: Commits read in one call. The same fail-closed reasoning as the scanner's Git
#: budget: a truncated history must be visible, not silently shorter.
MAX_COMMITS = 1000

_GIT_TIMEOUT_SECONDS = 30.0


def digest_bytes(payload: bytes) -> str:
    """Return the SHA-256 of a payload."""

    return hashlib.sha256(payload).hexdigest()


def digest_file(path: str | Path) -> str:
    """Return the SHA-256 of a file, within the evidence read boundary."""

    source = Path(path)
    try:
        size = source.stat().st_size
    except OSError as exc:
        raise AttestationError(f"Evidence file is unreadable: {exc}") from exc
    if size > MAX_EVIDENCE_BYTES:
        raise AttestationError(
            f"Evidence file {source.name} is {size} bytes; limit is {MAX_EVIDENCE_BYTES}"
        )
    reader = hashlib.sha256()
    with source.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            reader.update(chunk)
    return reader.hexdigest()


def commitment(payload: bytes, salt: bytes | None = None) -> tuple[str, bytes]:
    """Return a salted commitment and the salt needed to open it later.

    A bare hash of a short, guessable statement is not a commitment: an adversary
    can confirm a guess by hashing it. The salt is returned rather than stored so
    the holder decides who ever learns it.
    """

    material = salt if salt is not None else secrets.token_bytes(32)
    return hashlib.sha256(material + payload).hexdigest(), material


def open_commitment(payload: bytes, salt: bytes, published: str) -> bool:
    """Check a disclosed payload against a previously published commitment."""

    return hashlib.sha256(salt + payload).hexdigest() == published


# -- file-backed evidence ----------------------------------------------------------


def from_file(
    identifier: str,
    path: str | Path,
    *,
    kind: EvidenceKind,
    description: str | None = None,
    disclosure: DisclosureStatus = DisclosureStatus.PRIVATE,
    issuer: str | None = None,
) -> EvidenceReference:
    """Reference a local file by digest, leaving its contents where they are."""

    source = Path(path)
    return EvidenceReference(
        id=identifier,
        kind=kind,
        description=description or f"{kind.value}: {source.name}",
        sha256=digest_file(source),
        issuer=issuer,
        collection_method=f"local file digest ({source.name})",
        disclosure=disclosure,
        locator=str(source) if disclosure == DisclosureStatus.PUBLIC else None,
    )


def research_note(
    identifier: str,
    path: str | Path,
    *,
    description: str | None = None,
) -> EvidenceReference:
    """Reference a private research note or decision record by digest.

    Notes are the most sensitive common evidence, so this adapter has no public
    variant. A caller who genuinely wants a note public can say so through
    :func:`from_file`, deliberately.
    """

    return from_file(
        identifier,
        path,
        kind=EvidenceKind.RESEARCH_NOTE,
        description=description,
        disclosure=DisclosureStatus.PRIVATE,
    )


def committed_note(
    identifier: str,
    payload: bytes,
    *,
    description: str,
    salt: bytes | None = None,
) -> tuple[EvidenceReference, bytes]:
    """Commit to private material now so it can be revealed and checked later.

    Returns the reference and the salt. The salt is the caller's to keep; without
    it nobody, including a future version of this code, can open the commitment.
    """

    published, material = commitment(payload, salt)
    reference = EvidenceReference(
        id=identifier,
        kind=EvidenceKind.RESEARCH_NOTE,
        description=description,
        disclosure=DisclosureStatus.COMMITTED,
        commitment=published,
        collection_method="salted commitment over private material",
    )
    return reference, material


def omitted(
    identifier: str, *, kind: EvidenceKind, description: str, reason: str
) -> EvidenceReference:
    """Record that evidence exists but was deliberately left out.

    A visibly omitted item is more honest than a silently missing one: a reader
    can see that something was withheld and why.
    """

    return EvidenceReference(
        id=identifier,
        kind=kind,
        description=description,
        disclosure=DisclosureStatus.OMITTED,
        omission_reason=reason,
    )


# -- Git evidence ------------------------------------------------------------------


def _run_git(repository: Path, arguments: Sequence[str]) -> str:
    """Run one bounded, read-only Git command inside a repository."""

    environment = dict(os.environ)
    # The scanner's Git rules apply here too: no interactive prompts, no lazy
    # fetches, no repository routing inherited from the caller's environment.
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY"):
        environment.pop(name, None)
    environment["GIT_TERMINAL_PROMPT"] = "0"
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), "--no-pager", *arguments],
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT_SECONDS,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AttestationError(f"Git command failed: {exc}") from exc
    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        raise AttestationError(f"Git command failed: {stderr or 'unknown error'}")
    return completed.stdout


def git_commits(
    repository: str | Path,
    *,
    identifier_prefix: str = "commit",
    revision_range: str | None = None,
    limit: int = 50,
    disclosure: DisclosureStatus = DisclosureStatus.PRIVATE,
) -> tuple[EvidenceReference, ...]:
    """Reference commits by hash, without copying messages into the record.

    A commit hash already commits to its message, tree, parents, author, and
    timestamp, so recording the hash is strictly stronger than pasting a summary
    and strictly more private.
    """

    if limit < 1 or limit > MAX_COMMITS:
        raise AttestationError(f"Commit limit must be between 1 and {MAX_COMMITS}")
    root = Path(repository)
    arguments = ["log", f"-n{limit}", "--format=%H%x00%an%x00%aI%x00%s"]
    if revision_range:
        arguments.append(revision_range)
    output = _run_git(root, arguments)

    references: list[EvidenceReference] = []
    for index, line in enumerate(output.splitlines()):
        if not line.strip():
            continue
        parts = line.split("\x00", 3)
        if len(parts) != 4:
            continue
        commit_hash, author, authored_at, summary = parts
        references.append(
            EvidenceReference(
                id=f"{identifier_prefix}-{index + 1}",
                kind=EvidenceKind.GIT_COMMIT,
                # The summary is included only when the caller asked for a public
                # record; otherwise the hash stands alone.
                description=(
                    f"Commit {commit_hash[:12]} by {author} on {authored_at}"
                    if disclosure == DisclosureStatus.PUBLIC
                    else f"Commit {commit_hash[:12]}"
                ),
                sha256=None,
                issuer=author if disclosure == DisclosureStatus.PUBLIC else None,
                collection_method=f"git log ({commit_hash})",
                disclosure=disclosure,
                locator=commit_hash if disclosure == DisclosureStatus.PUBLIC else None,
            )
        )
        del summary
    return tuple(references)


def reviewed_diff(
    identifier: str,
    repository: str | Path,
    *,
    revision_range: str,
    description: str | None = None,
    disclosure: DisclosureStatus = DisclosureStatus.PRIVATE,
) -> EvidenceReference:
    """Commit to the exact content of a reviewed change without publishing it."""

    patch = _run_git(Path(repository), ["diff", "--no-color", revision_range])
    return EvidenceReference(
        id=identifier,
        kind=EvidenceKind.REVIEWED_DIFF,
        description=description or f"Reviewed diff for {revision_range}",
        sha256=digest_bytes(patch.encode("utf-8")),
        collection_method=f"git diff {revision_range}",
        disclosure=disclosure,
    )


def repository_state(
    identifier: str,
    repository: str | Path,
    *,
    description: str | None = None,
) -> EvidenceReference:
    """Record the exact commit a piece of work was performed at."""

    head = _run_git(Path(repository), ["rev-parse", "HEAD"]).strip()
    status = _run_git(Path(repository), ["status", "--porcelain"]).strip()
    return EvidenceReference(
        id=identifier,
        kind=EvidenceKind.GIT_COMMIT,
        description=(
            description
            or f"Repository at {head[:12]}"
            + (" with uncommitted changes" if status else " with a clean tree")
        ),
        collection_method="git rev-parse HEAD",
        disclosure=DisclosureStatus.PUBLIC,
        locator=head,
    )


# -- process outputs ---------------------------------------------------------------


def command_receipt(
    identifier: str,
    command: Sequence[str],
    *,
    kind: EvidenceKind,
    working_directory: str | Path | None = None,
    description: str | None = None,
    timeout: float = 900.0,
) -> tuple[EvidenceReference, bytes]:
    """Run a command and commit to exactly what it printed.

    Returns the reference and the captured output. The output is handed back
    rather than stored, so the caller decides whether it becomes a disclosed
    artifact or stays local while only its digest travels.

    The command is run as given. This adapter deliberately does not shell out
    through a string, so a receipt cannot be turned into shell injection by an
    unquoted path.
    """

    if not command:
        raise AttestationError("A command receipt needs a command to run")
    try:
        completed = subprocess.run(
            list(command),
            cwd=str(working_directory) if working_directory else None,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AttestationError(f"Evidence command failed: {exc}") from exc
    payload = completed.stdout + completed.stderr
    if len(payload) > MAX_EVIDENCE_BYTES:
        payload = payload[:MAX_EVIDENCE_BYTES]
    reference = EvidenceReference(
        id=identifier,
        kind=kind,
        description=(description or f"{' '.join(command[:3])} exited {completed.returncode}"),
        sha256=digest_bytes(payload),
        collection_method=f"command receipt: {' '.join(command)}",
        disclosure=DisclosureStatus.PRIVATE,
    )
    return reference, payload


def test_run(
    identifier: str,
    command: Sequence[str],
    *,
    working_directory: str | Path | None = None,
) -> tuple[EvidenceReference, bytes]:
    """Run a test command and commit to its output."""

    return command_receipt(
        identifier,
        command,
        kind=EvidenceKind.TEST_RUN,
        working_directory=working_directory,
    )


def build_receipt(
    identifier: str,
    path: str | Path,
    *,
    description: str | None = None,
) -> EvidenceReference:
    """Reference a build output or provenance record by digest."""

    return from_file(
        identifier,
        path,
        kind=EvidenceKind.BUILD_RECEIPT,
        description=description,
        disclosure=DisclosureStatus.PRIVATE,
    )


# -- declarations that are not machine facts ---------------------------------------


def source_citation(
    identifier: str,
    *,
    citation: str,
    locator: str | None = None,
) -> EvidenceReference:
    """Record a source the work relied on.

    A citation is public by nature: it is a pointer to something already
    published, so withholding it would defeat its purpose.
    """

    return EvidenceReference(
        id=identifier,
        kind=EvidenceKind.SOURCE_CITATION,
        description=citation,
        collection_method="declared citation",
        disclosure=DisclosureStatus.PUBLIC,
        locator=locator,
    )


def approval(
    identifier: str,
    *,
    approver: str,
    statement: str,
    disclosure: DisclosureStatus = DisclosureStatus.PUBLIC,
) -> EvidenceReference:
    """Record a named person or body approving the result.

    This is a declaration, not a machine fact. It becomes cryptographically
    meaningful only when that actor also signs the attestation, which is why the
    adapter records who approved rather than asserting that they did.
    """

    return EvidenceReference(
        id=identifier,
        kind=EvidenceKind.APPROVAL,
        description=statement,
        issuer=approver,
        collection_method="declared approval",
        disclosure=disclosure,
    )


def external_receipt(
    identifier: str,
    path: str | Path,
    *,
    issuer: str,
    description: str | None = None,
) -> EvidenceReference:
    """Reference a receipt issued by a third party, by digest."""

    return from_file(
        identifier,
        path,
        kind=EvidenceKind.EXTERNAL_RECEIPT,
        description=description,
        issuer=issuer,
        disclosure=DisclosureStatus.PRIVATE,
    )


def tool_identity(
    identifier: str,
    *,
    name: str,
    version: str,
    description: str | None = None,
) -> EvidenceReference:
    """Record which tool or model version participated."""

    return EvidenceReference(
        id=identifier,
        kind=EvidenceKind.TOOL_IDENTITY,
        description=description or f"{name} {version}",
        issuer=name,
        collection_method="declared tool identity",
        disclosure=DisclosureStatus.PUBLIC,
    )


def scan_report(identifier: str, path: str | Path) -> EvidenceReference:
    """Reference a TrueAI scan report by digest.

    Attaching a scan tells a reader what a scanner observed. It does not populate
    any contribution claim: the caller writes claims, and the record keeps the two
    apart on purpose.
    """

    return from_file(
        identifier,
        path,
        kind=EvidenceKind.SCAN_REPORT,
        description="TrueAI scan report",
        disclosure=DisclosureStatus.PRIVATE,
    )


def audit_certificate(identifier: str, path: str | Path) -> EvidenceReference:
    """Reference a TrueAI audit certificate by digest."""

    return from_file(
        identifier,
        path,
        kind=EvidenceKind.AUDIT_CERTIFICATE,
        description="TrueAI audit certificate",
        disclosure=DisclosureStatus.PUBLIC,
    )


def unique_identifiers(references: Iterable[EvidenceReference]) -> tuple[EvidenceReference, ...]:
    """Return references with duplicate identifiers rejected rather than merged."""

    seen: set[str] = set()
    collected: list[EvidenceReference] = []
    for reference in references:
        if reference.id in seen:
            raise AttestationError(f"Duplicate evidence identifier: {reference.id}")
        seen.add(reference.id)
        collected.append(reference)
    return tuple(collected)
