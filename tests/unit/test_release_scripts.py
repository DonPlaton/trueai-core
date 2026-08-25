"""Release checks must distinguish valid metadata from real policy violations."""

from pathlib import Path

import pytest
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


@pytest.mark.parametrize(
    "workflow",
    [Path(".github/workflows/ci.yml"), Path(".github/workflows/release.yml")],
)
def test_workflows_use_the_current_cyclonedx_output_option(workflow: Path) -> None:
    content = workflow.read_text(encoding="utf-8")

    assert "--output-file" in content
    assert "--outfile" not in content


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
