"""What a reader takes away, when it is more than what was established.

Three places where the output was accurate line by line and overstated as a
whole. None of them was a wrong value; each was a headline, a total, or a count
that a reader is entitled to read one way and that meant another.

That distinction is the product. A tool whose central claim is that
`not_examined` and `absent` are different answers cannot print a green VALID over
a document nobody signed and nothing was compared to.
"""

from __future__ import annotations

import re
from pathlib import Path

from typer.testing import CliRunner

from trueai import TrueAIEngine
from trueai.cli.app import app
from trueai.detectors import create_default_registry

runner = CliRunner()


# -- the certificate verdict -----------------------------------------------------------


def issue(tmp_path: Path, *, signed: bool) -> tuple[Path, Path, Path | None]:
    """Write an artifact and a certificate over it, signed or not."""

    artifact = tmp_path / "notes.md"
    artifact.write_text("Generated with ChatGPT\n", encoding="utf-8")
    certificate = tmp_path / "certificate.json"
    arguments = ["certificates", "issue", str(artifact), "--output", str(certificate)]
    public_key: Path | None = None
    if signed:
        private_key = tmp_path / "issuer-private.pem"
        public_key = tmp_path / "issuer-public.pem"
        keygen = runner.invoke(
            app,
            [
                "certificates",
                "keygen",
                "--private-key",
                str(private_key),
                "--public-key",
                str(public_key),
            ],
        )
        assert keygen.exit_code == 0, keygen.output
        arguments += ["--signing-key", str(private_key)]
    result = runner.invoke(app, arguments)
    # The artifact carries an indicator on purpose, and `issue` reports that
    # through its exit code. What matters here is that the certificate exists.
    assert certificate.is_file(), result.output
    return artifact, certificate, public_key


def test_an_unsigned_certificate_nobody_compared_to_a_file_is_not_simply_valid(
    tmp_path: Path,
) -> None:
    """It printed VALID, in green, and exited zero.

    What had been established is that a JSON document is internally consistent
    with its own identifier. The explanations underneath said so; the headline is
    what a reader takes away, and a buyer skimming a verification report reads
    the word and not the list.
    """

    _, certificate, _ = issue(tmp_path, signed=False)

    result = runner.invoke(app, ["certificates", "verify", str(certificate)])

    assert result.exit_code == 0
    assert "VALID, NOT FULLY CHECKED" in result.stdout
    assert "not checked: the issuer signature" in result.stdout
    assert "not checked: the artifact binding" in result.stdout


def test_a_signed_certificate_bound_to_its_artifact_is_valid_without_qualification(
    tmp_path: Path,
) -> None:
    """The unqualified verdict has to stay reachable, or the qualified one is noise."""

    artifact, certificate, public_key = issue(tmp_path, signed=True)
    assert public_key is not None

    result = runner.invoke(
        app,
        [
            "certificates",
            "verify",
            str(certificate),
            "--artifact",
            str(artifact),
            "--public-key",
            str(public_key),
        ],
    )

    assert result.exit_code == 0
    assert "Verification: VALID" in result.stdout
    assert "NOT FULLY CHECKED" not in result.stdout


def test_revocation_alone_does_not_qualify_the_verdict(tmp_path: Path) -> None:
    """A caveat that fires on every verification is read on none of them.

    Revocation answers a different question -- whether an issuer has since
    withdrawn a certificate that was and remains correctly signed -- and an
    issuer who has never published a list would otherwise make the unqualified
    result unreachable. It is still printed, and `--require-revocation-check`
    is how a caller who needs it asks.
    """

    artifact, certificate, public_key = issue(tmp_path, signed=True)
    assert public_key is not None

    result = runner.invoke(
        app,
        [
            "certificates",
            "verify",
            str(certificate),
            "--artifact",
            str(artifact),
            "--public-key",
            str(public_key),
        ],
    )

    assert "not checked: revocation" in result.stdout


def test_requiring_full_verification_turns_the_caveat_into_an_exit_code(
    tmp_path: Path,
) -> None:
    """For a caller that has to prove it rather than read it."""

    _, certificate, _ = issue(tmp_path, signed=False)

    result = runner.invoke(
        app, ["certificates", "verify", str(certificate), "--require-full-verification"]
    )

    assert result.exit_code != 0


def test_the_unchecked_list_is_available_to_a_machine_consumer(tmp_path: Path) -> None:
    """The distinction cannot live only in the terminal renderer."""

    from trueai.core.certificates import load_certificate, verify_certificate

    _, certificate_path, _ = issue(tmp_path, signed=False)
    verification = verify_certificate(load_certificate(certificate_path))

    assert verification.valid is True
    assert verification.authenticated is False
    assert len(verification.unchecked()) == 3


# -- the evidence-class table ------------------------------------------------------------


def test_the_evidence_class_table_adds_up_to_the_finding_count(tmp_path: Path) -> None:
    """It is a partition, and a row counting a different axis broke it.

    `PROVENANCE` was a fifth row in a table headed "Evidence class". Every
    finding has exactly one evidence class and may separately carry a provenance
    class, so the column stopped summing to the number above it -- two findings,
    three rows, totalling three.
    """

    artifact = tmp_path / "notes.md"
    artifact.write_text("Generated with ChatGPT\nInvisible​space.\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(artifact)])

    assert result.exit_code in {0, 3}, result.output
    counts = [int(value) for value in re.findall(r"^\s+[A-Z]+\s+(\d+)\s*$", result.stdout, re.M)]
    total = int(re.search(r"(\d+) findings across", result.stdout).group(1))
    assert counts, result.stdout
    assert sum(counts) == total, result.stdout


def test_provenance_is_still_reported_as_an_attribute(tmp_path: Path) -> None:
    """Removing the row must not remove the information."""

    artifact = tmp_path / "notes.md"
    artifact.write_text("Generated with ChatGPT\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(artifact)])

    assert "provenance class" in result.stdout
    assert "attribute" in result.stdout


# -- one metadata block, one finding -------------------------------------------------------


def test_a_nested_svg_metadata_block_is_one_finding_not_two(tmp_path: Path) -> None:
    """`<metadata><rdf:RDF>` is the shape every Inkscape file has.

    Walking every element emitted a finding for the container and another for its
    child, with the same title, the same description and the same excerpt. A
    reader sees the tool counting one thing twice.
    """

    artifact = tmp_path / "logo.svg"
    artifact.write_text(
        '<?xml version="1.0"?>\n'
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10">\n'
        "  <metadata><rdf><work>Editor workflow</work></rdf></metadata>\n"
        '  <rect x="1" y="1" width="5" height="5"/>\n'
        "</svg>\n",
        encoding="utf-8",
    )

    report = TrueAIEngine(create_default_registry()).scan(artifact)
    metadata = [item for item in report.findings if item.title == "SVG metadata element"]

    assert len(metadata) == 1, [item.evidence for item in metadata]
    assert metadata[0].evidence["element"] == "metadata"
    assert metadata[0].evidence["nested_metadata_elements"] == ["rdf"]


def test_two_separate_metadata_blocks_are_still_two_findings(tmp_path: Path) -> None:
    """Deduplicating a container with its child must not merge unrelated blocks."""

    artifact = tmp_path / "logo.svg"
    artifact.write_text(
        '<?xml version="1.0"?>\n'
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10">\n'
        "  <metadata><work>first</work></metadata>\n"
        "  <g><metadata><work>second</work></metadata></g>\n"
        "</svg>\n",
        encoding="utf-8",
    )

    report = TrueAIEngine(create_default_registry()).scan(artifact)
    metadata = [item for item in report.findings if item.title == "SVG metadata element"]

    assert len(metadata) == 2


# -- the same distinction, for anything that is not the terminal ------------------------


def test_an_integration_can_see_the_qualification_the_cli_shows(tmp_path: Path) -> None:
    """Otherwise every other surface repeats the mistake the CLI just stopped making.

    A desktop or IDE integration renders `CertificateView`. If the only verdict
    it carries is `valid`, the green tick comes back somewhere else.
    """

    from trueai.adapters.views import certificate_view
    from trueai.core.certificates import load_certificate, verify_certificate

    _, certificate_path, _ = issue(tmp_path, signed=False)
    certificate = load_certificate(certificate_path)

    view = certificate_view(certificate, verify_certificate(certificate))

    assert view.valid is True
    assert view.authenticated is False
    assert view.unchecked
    assert view.to_dict()["authenticated"] is False
    assert view.to_dict()["unchecked"] == list(view.unchecked)


def test_a_signed_and_bound_certificate_reads_as_authenticated_everywhere(
    tmp_path: Path,
) -> None:
    from trueai.adapters.views import certificate_view
    from trueai.core.certificates import load_certificate, verify_certificate

    artifact, certificate_path, public_key = issue(tmp_path, signed=True)
    certificate = load_certificate(certificate_path)

    view = certificate_view(
        certificate,
        verify_certificate(certificate, public_key=public_key, artifact=artifact),
    )

    assert view.authenticated is True
