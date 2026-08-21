import subprocess
from pathlib import Path

import pytest

from trueai import TrueAIEngine
from trueai.core.models import FindingCategory, ScanOptions
from trueai.core.policy import PolicyProfile
from trueai.core.remediation import RemediationPlanner
from trueai.detectors.git import command as git_command
from trueai.detectors.git.commits import GitAttributionDetector
from trueai.detectors.git.repository import GitRepositoryContextDetector


def test_git_commit_attribution_and_neutral_tooling_context(git_repository: Path) -> None:
    report = TrueAIEngine.default().scan(git_repository)

    git_findings = [
        item for item in report.findings if item.category == FindingCategory.GIT_ATTRIBUTION
    ]
    tooling = [item for item in report.findings if item.category == FindingCategory.TOOLING_RESIDUE]
    assert len(git_findings) == 1
    assert git_findings[0].provider == "anthropic"
    assert git_findings[0].removable is False
    assert git_findings[0].evidence["commit_short"]
    assert len(tooling) == 1
    assert "not malicious" in tooling[0].description


def test_git_history_removal_is_blocked(git_repository: Path) -> None:
    policy = PolicyProfile.model_validate(
        {"policy": "git-review", "rules": {"git_attribution": "remove"}}
    )
    report = TrueAIEngine.default().scan(git_repository, policy=policy)
    plan = RemediationPlanner().plan(report, policy)

    assert not [item for item in plan.remediations if item.remediation_id == "git.rewrite-history"]
    assert plan.blocked_findings


def test_git_commands_use_command_scoped_posix_safe_directory(
    git_repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands: list[list[str]] = []
    environments: list[dict[str, str]] = []
    real_popen = subprocess.Popen

    def recording_popen(command: list[str], **kwargs: object):
        commands.append(command)
        environment = kwargs.get("env")
        assert isinstance(environment, dict)
        environments.append(environment)
        return real_popen(command, **kwargs)

    monkeypatch.setattr(git_command.subprocess, "Popen", recording_popen)

    GitAttributionDetector._read_commits(git_repository, 1)
    GitRepositoryContextDetector._tracked_files(git_repository)

    expected = f"safe.directory={git_repository.resolve().as_posix()}"
    assert all(command[1:3] == ["-c", expected] for command in commands)
    assert all("--global" not in command for command in commands)
    assert all("GIT_ALTERNATE_OBJECT_DIRECTORIES" not in item for item in environments)
    assert all(item["GIT_NO_LAZY_FETCH"] == "1" for item in environments)


def test_git_scans_all_refs_and_reports_commit_limit(
    git_repository: Path,
) -> None:
    def run(*arguments: str) -> None:
        subprocess.run(
            ["git", "-C", str(git_repository), *arguments],
            check=True,
            capture_output=True,
        )

    main_branch = subprocess.run(
        ["git", "-C", str(git_repository), "branch", "--show-current"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    run("checkout", "-q", "-b", "unmerged")
    (git_repository / "branch.txt").write_text("branch\n", encoding="utf-8")
    run("add", "branch.txt")
    run("commit", "-q", "-m", "Generated with ChatGPT")
    run("checkout", "-q", main_branch)

    complete = TrueAIEngine.default().scan(git_repository)
    limited = TrueAIEngine.default().scan(
        git_repository,
        options=ScanOptions(git_commit_limit=1),
    )

    assert any(
        finding.category == FindingCategory.GIT_ATTRIBUTION and finding.provider == "openai"
        for finding in complete.findings
    )
    assert any(diagnostic.code == "detector_scan_truncated" for diagnostic in limited.diagnostics)


def test_external_gitdir_is_rejected_without_reading_sibling_history(tmp_path: Path) -> None:
    secret = tmp_path / "secret"
    secret.mkdir()

    def run(*arguments: str) -> None:
        subprocess.run(
            ["git", "-C", str(secret), *arguments],
            check=True,
            capture_output=True,
        )

    run("init", "-q")
    run("config", "user.name", "Test User")
    run("config", "user.email", "test@example.test")
    (secret / "secret.txt").write_text("secret\n", encoding="utf-8")
    run("add", "secret.txt")
    run("commit", "-q", "-m", "Generated with Claude")

    decoy = tmp_path / "decoy"
    decoy.mkdir()
    (decoy / ".git").write_text("gitdir: ../secret/.git\n", encoding="utf-8")

    report = TrueAIEngine.default().scan(decoy)

    assert not [
        finding
        for finding in report.findings
        if finding.category == FindingCategory.GIT_ATTRIBUTION
    ]
    assert any(diagnostic.code == "unsafe_artifact" for diagnostic in report.diagnostics)


def test_external_git_object_alternate_is_rejected(tmp_path: Path) -> None:
    secret = tmp_path / "secret"
    secret.mkdir()

    def run(repository: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["git", "-C", str(repository), *arguments],
            check=True,
            capture_output=True,
        )

    run(secret, "init", "-q")
    run(secret, "config", "user.name", "Test User")
    run(secret, "config", "user.email", "test@example.test")
    (secret / "secret.txt").write_text("secret\n", encoding="utf-8")
    run(secret, "add", "secret.txt")
    run(secret, "commit", "-q", "-m", "Generated with Claude")
    secret_commit = run(secret, "rev-parse", "HEAD").stdout.decode("ascii").strip()

    decoy = tmp_path / "decoy"
    decoy.mkdir()
    run(decoy, "init", "-q")
    alternates = decoy / ".git" / "objects" / "info" / "alternates"
    alternates.write_text(str((secret / ".git" / "objects").resolve()), encoding="utf-8")
    external_ref = decoy / ".git" / "refs" / "heads" / "external"
    external_ref.parent.mkdir(parents=True, exist_ok=True)
    external_ref.write_text(secret_commit + "\n", encoding="ascii")

    report = TrueAIEngine.default().scan(decoy)

    assert not [
        finding
        for finding in report.findings
        if finding.category == FindingCategory.GIT_ATTRIBUTION
    ]
    assert any(diagnostic.code == "unsafe_artifact" for diagnostic in report.diagnostics)
