"""Read-only repository context inspection."""

from __future__ import annotations

from pathlib import Path

from trueai.core.artifact import Artifact
from trueai.core.errors import CorruptArtifactError
from trueai.core.models import (
    ArtifactType,
    ConfidenceType,
    EvidenceType,
    Finding,
    FindingCategory,
    ProvenanceClass,
    ScanContext,
    Severity,
)
from trueai.detectors.base import BaseDetector, FindingBuffer
from trueai.detectors.git.command import run_git_bounded, validate_repository_scope

_TOOLING_PATHS = {
    "CLAUDE.md": "anthropic",
    ".github/copilot-instructions.md": "github-copilot",
    ".cursorrules": "cursor",
    ".windsurfrules": "windsurf",
    "AGENTS.md": "generic-agent",
}
_TOOLING_PREFIXES = {
    ".claude/": "anthropic",
    ".codex/": "openai",
    ".cursor/": "cursor",
}


class GitRepositoryContextDetector(BaseDetector):
    """Report tracked assistant configuration as neutral workflow context."""

    id = "git.repository-context.v1"
    supported_types = frozenset({ArtifactType.GIT_REPOSITORY})
    categories = frozenset({FindingCategory.TOOLING_RESIDUE, FindingCategory.STRUCTURAL_SIGNAL})

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        if artifact.path is None:
            return []
        tracked, truncated = self._tracked_files(
            artifact.path,
            context.options.max_files,
            context.options.max_git_output_bytes,
        )
        findings = FindingBuffer(context.options.max_findings, self.id)
        for path in tracked:
            provider = _TOOLING_PATHS.get(path)
            if provider is None:
                provider = next(
                    (
                        value
                        for prefix, value in _TOOLING_PREFIXES.items()
                        if path.startswith(prefix)
                    ),
                    None,
                )
            if provider is None:
                continue
            findings.append(
                self.finding(
                    artifact=artifact,
                    category=FindingCategory.TOOLING_RESIDUE,
                    confidence=1.0,
                    confidence_type=ConfidenceType.DETERMINISTIC,
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.GIT,
                    title="Tracked AI-tool configuration",
                    description=(
                        "A tracked assistant configuration file provides workflow context. "
                        "Its presence is not malicious and does not prove generated content."
                    ),
                    evidence={"tracked_path": path},
                    provider=provider,
                    provenance_class=ProvenanceClass.METADATA,
                    tags=("git", "tooling-context", provider),
                )
            )
        if truncated:
            findings.append(
                self.finding(
                    artifact=artifact,
                    category=FindingCategory.STRUCTURAL_SIGNAL,
                    confidence=1.0,
                    confidence_type=ConfidenceType.DETERMINISTIC,
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.GIT,
                    title="Tracked-file scan truncated",
                    description=(
                        f"The repository has more than {context.options.max_files} tracked files; "
                        "the tooling-context scan is incomplete."
                    ),
                    evidence={"file_limit": context.options.max_files},
                    tags=("git", "coverage", "scan-incomplete"),
                )
            )
        return findings

    @staticmethod
    def _tracked_files(
        repository: Path,
        limit: int = 100_000,
        max_output_bytes: int = 8 * 1024 * 1024,
    ) -> tuple[list[str], bool]:
        root = validate_repository_scope(repository, max_output_bytes)
        completed = run_git_bounded(
            root,
            ("ls-files", "-z"),
            max_output_bytes=max_output_bytes,
        )
        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", errors="replace").strip()
            raise CorruptArtifactError(f"git ls-files failed: {stderr or 'unknown error'}")
        tracked: list[str] = []
        offset = 0
        while len(tracked) <= limit:
            end = completed.stdout.find(b"\x00", offset)
            if end < 0:
                item = completed.stdout[offset:]
                offset = len(completed.stdout)
            else:
                item = completed.stdout[offset:end]
                offset = end + 1
            if item:
                tracked.append(item.decode("utf-8", errors="replace"))
            if end < 0:
                break
        return tracked[:limit], len(tracked) > limit
