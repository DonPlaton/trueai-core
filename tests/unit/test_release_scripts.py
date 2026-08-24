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
