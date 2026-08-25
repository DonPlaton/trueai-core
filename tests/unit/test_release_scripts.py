"""Release checks must distinguish valid metadata from real policy violations."""

import re
from pathlib import Path

import pytest
import yaml
from packaging.utils import canonicalize_name

from scripts.check_licenses import license_is_allowed, runtime_distribution_names


def test_license_gate_accepts_allowlisted_spdx_expressions() -> None:
    assert license_is_allowed("MIT OR Apache-2.0")
    assert license_is_allowed("Apache-2.0 OR BSD-3-Clause")
    assert license_is_allowed("MIT-0")
    assert license_is_allowed("PSF-2.0")


def test_license_gate_rejects_expression_with_unreviewed_atom() -> None:
    assert not license_is_allowed("MIT AND Unreviewed-Proprietary")
    assert not license_is_allowed("UNKNOWN")


def test_license_gate_targets_runtime_closure_not_release_tooling() -> None:
    names = {
        canonicalize_name(name)
        for name in runtime_distribution_names(root="pydantic", extras=frozenset())
    }

    assert {"pydantic", "pydantic-core", "typing-inspection"} <= names
    assert "pytest" not in names
    assert "pip-licenses" not in names
    assert "cyclonedx-bom" not in names


WORKFLOWS = (Path(".github/workflows/ci.yml"), Path(".github/workflows/release.yml"))


@pytest.mark.parametrize("workflow", WORKFLOWS)
def test_every_external_action_is_pinned_to_an_immutable_sha(workflow: Path) -> None:
    references = re.findall(r"uses:\s*([^\s#]+)", workflow.read_text(encoding="utf-8"))

    assert references
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", item) for item in references), references


@pytest.mark.parametrize("workflow", WORKFLOWS)
def test_github_actions_use_the_node24_generation(workflow: Path) -> None:
    """A full SHA does not make an end-of-life action runtime supportable."""

    minimum_major = {
        "actions/checkout": 6,
        "actions/setup-python": 6,
        "actions/upload-artifact": 7,
        "actions/download-artifact": 8,
        "actions/attest": 4,
    }
    content = workflow.read_text(encoding="utf-8")
    for name, minimum in minimum_major.items():
        for major in re.findall(rf"{re.escape(name)}@[0-9a-f]{{40}} # v(\d+)", content):
            assert int(major) >= minimum, f"{name} v{major} predates the Node 24 release"


def test_release_publication_cannot_bypass_the_verification_job() -> None:
    workflow = yaml.load(
        Path(".github/workflows/release.yml").read_text(encoding="utf-8"), Loader=yaml.BaseLoader
    )
    jobs = workflow["jobs"]

    assert jobs["build"]["needs"] == ["verify"]
    assert jobs["publish-testpypi"]["needs"] == ["build"]
    assert jobs["publish-pypi"]["needs"] == ["build"]
    assert "startsWith(github.ref, 'refs/tags/v') &&" in jobs["publish-pypi"]["if"]
    assert "inputs.target == 'testpypi'" in jobs["publish-testpypi"]["if"]
    verification = str(jobs["verify"])
    for required in (
        "pytest",
        "ruff check",
        "ruff format",
        # Both, because one run answers for one operating system.
        "mypy --platform win32",
        "mypy --platform linux",
        "check_schema_snapshot.py",
        "check_api_snapshot.py",
        "check_docs.py",
        "check_supply_chain.py",
    ):
        assert required in verification


def test_release_evidence_includes_runtime_sbom_and_build_inputs() -> None:
    content = Path(".github/workflows/release.yml").read_text(encoding="utf-8")

    assert "scripts/generate_sbom.py" in content
    assert "cyclonedx-py environment" not in content
    assert "dist/sbom.cdx.json" in content
    assert "dist/build-inputs.json" in content
    assert "verify: true" in content
    assert "https://test.pypi.org/legacy/" in content


@pytest.mark.parametrize("workflow", WORKFLOWS)
def test_checkout_credentials_are_not_persisted(workflow: Path) -> None:
    content = workflow.read_text(encoding="utf-8")

    assert content.count("persist-credentials: false") == content.count("actions/checkout@")


def test_reproducible_container_does_not_copy_build_tools_into_runtime() -> None:
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")

    assert "python -m build --no-isolation" in dockerfile
    assert "--only-group release" in dockerfile
    assert "COPY --from=builder /runtime/" in dockerfile
    assert "COPY --from=builder /usr/local/lib/python" not in dockerfile


# -- the scale benchmark -------------------------------------------------------------


def test_the_benchmark_writes_nothing_into_a_directory_it_was_pointed_at(
    tmp_path: Path,
) -> None:
    """A benchmark that modified the repository it measured would be worse than useless."""

    import subprocess
    import sys

    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "note.md").write_text("Generated with ChatGPT\n", encoding="utf-8")
    (repository / "code.py").write_text("VALUE = 1\n", encoding="utf-8")
    before = {
        item.relative_to(repository).as_posix(): item.read_bytes()
        for item in repository.rglob("*")
        if item.is_file()
    }

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/benchmark_scale.py",
            "--corpus",
            str(repository),
            "--workers",
            "2",
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[2],
    )

    after = {
        item.relative_to(repository).as_posix(): item.read_bytes()
        for item in repository.rglob("*")
        if item.is_file()
    }
    assert completed.returncode == 0, completed.stderr
    assert after == before
    assert "nothing is written into it" in completed.stdout


def test_the_benchmark_refuses_a_corpus_that_is_not_a_directory(tmp_path: Path) -> None:
    import subprocess
    import sys

    target = tmp_path / "single.md"
    target.write_text("x\n", encoding="utf-8")

    completed = subprocess.run(
        [sys.executable, "scripts/benchmark_scale.py", "--corpus", str(target)],
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[2],
    )

    assert completed.returncode != 0
    assert "is not a directory" in completed.stderr


def test_the_benchmark_refuses_to_both_build_and_reuse_a_corpus(tmp_path: Path) -> None:
    import subprocess
    import sys

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/benchmark_scale.py",
            "--corpus",
            str(tmp_path),
            "--keep-corpus",
            str(tmp_path / "built"),
        ],
        capture_output=True,
        text=True,
        cwd=Path(__file__).resolve().parents[2],
    )

    assert completed.returncode != 0
    assert "benchmarks a directory as it is" in completed.stderr


def test_the_runtime_prefix_is_installed_independently_of_the_builder() -> None:
    """Without --ignore-installed the image shipped almost nothing it imports.

    The builder carries the release group in its own site-packages, and hatchling
    shares pathspec, rich, packaging, pluggy and requests with the runtime set.
    pip calls those "already satisfied" and skips them for the --prefix tree, so
    `trueai --version` in the published image died on `import pathspec` while the
    build stayed byte-for-byte reproducible. A reproducible build of the wrong
    bytes is still reproducible, which is why this needs its own check.
    """

    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    install = next(
        line for line in dockerfile.splitlines() if "-r /tmp/runtime-requirements.txt" in line
    )
    stanza = dockerfile[dockerfile.index("RUN python -m build") : dockerfile.index(install)]

    assert "--ignore-installed" in stanza
    assert "--require-hashes" in stanza


@pytest.mark.parametrize("workflow", WORKFLOWS)
def test_types_are_checked_for_both_platforms(workflow: Path) -> None:
    """One mypy run answers for one operating system and is blind to the other.

    The Windows restricted-token path carried 25 type errors for as long as the
    only Linux checker was CI and the only Windows checker was a developer -- each
    correct about the branch it could see.
    """

    content = workflow.read_text(encoding="utf-8")

    assert "--platform win32" in content
    assert "--platform linux" in content
