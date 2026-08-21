"""Read-only inspection of Git commit messages and trailers."""

from __future__ import annotations

from dataclasses import dataclass
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
from trueai.providers import AttributionContext, attribution_rules


@dataclass(frozen=True, slots=True)
class GitCommit:
    """Bounded commit data needed for attribution rules."""

    commit_hash: str
    author_name: str
    author_email: str
    message: str


class GitAttributionDetector(BaseDetector):
    """Inspect Git history without checking out commits or invoking hooks."""

    id = "git.commit-attribution.v1"
    supported_types = frozenset({ArtifactType.GIT_REPOSITORY})
    categories = frozenset({FindingCategory.GIT_ATTRIBUTION, FindingCategory.STRUCTURAL_SIGNAL})

    def scan(self, artifact: Artifact, context: ScanContext) -> list[Finding]:
        if artifact.path is None:
            return []
        commits, truncated = self._read_commits(
            artifact.path,
            context.options.git_commit_limit,
            context.options.max_git_output_bytes,
        )
        findings = FindingBuffer(context.options.max_findings, self.id)
        for commit in commits:
            for rule in attribution_rules():
                if AttributionContext.GIT_COMMIT not in rule.contexts:
                    continue
                for match in rule.finditer(commit.message):
                    findings.append(
                        self.finding(
                            artifact=artifact,
                            category=FindingCategory.GIT_ATTRIBUTION,
                            confidence=rule.confidence,
                            confidence_type=ConfidenceType.DETERMINISTIC,
                            severity=Severity.MEDIUM,
                            evidence_type=EvidenceType.GIT,
                            title="AI-tool attribution in Git history",
                            description=(
                                f"{rule.explanation} History is never rewritten automatically."
                            ),
                            evidence={
                                "rule_id": rule.id,
                                "commit": commit.commit_hash,
                                "commit_short": commit.commit_hash[:12],
                                "author_name": commit.author_name,
                                "match": match.group(0),
                                "message_excerpt": self._excerpt(commit.message, match.start()),
                            },
                            provider=rule.provider,
                            removable=False,
                            remediation_id="git.rewrite-history",
                            provenance_class=ProvenanceClass.ATTRIBUTION,
                            tags=("git", "history", "destructive-remediation", rule.provider),
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
                    title="Git history scan truncated",
                    description=(
                        f"More than {context.options.git_commit_limit} commits exist across all "
                        "refs. Increase git_commit_limit for a complete audit."
                    ),
                    evidence={
                        "commit_limit": context.options.git_commit_limit,
                        "ref_scope": "all",
                    },
                    tags=("git", "coverage", "scan-incomplete"),
                )
            )
        return findings

    @staticmethod
    def _read_commits(
        repository: Path,
        limit: int,
        max_output_bytes: int = 8 * 1024 * 1024,
    ) -> tuple[list[GitCommit], bool]:
        root = validate_repository_scope(repository, max_output_bytes)
        arguments = (
            "--no-pager",
            "log",
            "--all",
            f"-n{limit + 1}",
            "--format=%H%x00%an%x00%ae%x00%B%x00%x1e",
        )
        completed = run_git_bounded(
            root,
            arguments,
            max_output_bytes=max_output_bytes,
        )
        if completed.returncode != 0:
            stderr = completed.stderr.decode("utf-8", errors="replace").strip()
            if "does not have any commits" in stderr or "your current branch" in stderr.casefold():
                return [], False
            raise CorruptArtifactError(f"Git log failed: {stderr or 'unknown error'}")
        commits: list[GitCommit] = []
        decoded = completed.stdout.decode("utf-8", errors="replace")
        offset = 0
        while len(commits) <= limit:
            end = decoded.find("\x1e", offset)
            if end < 0:
                record = decoded[offset:]
                offset = len(decoded)
            else:
                record = decoded[offset:end]
                offset = end + 1
            record = record.strip("\r\n\x00")
            if not record:
                if end < 0:
                    break
            else:
                parts = record.split("\x00", 3)
                if len(parts) == 4:
                    commits.append(
                        GitCommit(
                            commit_hash=parts[0],
                            author_name=parts[1],
                            author_email=parts[2],
                            message=parts[3],
                        )
                    )
            if end < 0:
                break
        return commits[:limit], len(commits) > limit

    @staticmethod
    def _excerpt(message: str, offset: int, radius: int = 80) -> str:
        return message[max(0, offset - radius) : offset + radius].replace("\n", " ").strip()
