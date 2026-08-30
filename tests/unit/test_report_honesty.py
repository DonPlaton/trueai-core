"""What a reader takes away, when it is more than what was established.

Three places where the output was accurate line by line and overstated as a
whole. None of them was a wrong value; each was a headline, a total, or a count
that a reader is entitled to read one way and that meant another.

That distinction is the product. A tool whose central claim is that
`not_examined` and `absent` are different answers cannot print a green VALID over
a document nobody signed and nothing was compared to.
"""

from __future__ import annotations

import json
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
    total = int(re.search(r"(\d+) findings? across", result.stdout).group(1))
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


# -- the surface a security dashboard renders -------------------------------------------


def sarif_for(tmp_path: Path) -> dict:
    """Scan an artifact that trips one detector twice, and return the SARIF."""

    import json as json_module

    from PIL import Image, PngImagePlugin

    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("Software", "Generated with ChatGPT")
    metadata.add_text("Author", "Alice")
    artifact = tmp_path / "art.png"
    Image.new("RGB", (8, 8), (1, 2, 3)).save(artifact, pnginfo=metadata)

    result = runner.invoke(app, ["scan", str(artifact), "--format", "sarif"])
    assert result.exit_code in {0, 1, 3}, result.output
    return json_module.loads(result.stdout)


def test_a_rule_describes_the_detector_not_whichever_finding_came_first(
    tmp_path: Path,
) -> None:
    """A dashboard groups alerts by rule and prints the rule's description.

    `design.raster-metadata.v1` reports Software fields and Author fields. Its
    rule carried the title of whichever finding created the entry, so every alert
    under it read "Image metadata: Software" -- including the ones about Author.
    """

    document = sarif_for(tmp_path)
    rules = {rule["id"]: rule for rule in document["runs"][0]["tool"]["driver"]["rules"]}
    rule = rules["design.raster-metadata.v1"]

    assert "Software" not in rule["shortDescription"]["text"]
    assert "Author" not in rule["shortDescription"]["text"]
    assert "generator_metadata" in rule["shortDescription"]["text"]
    assert "personal_metadata" in rule["shortDescription"]["text"]


def test_the_rule_carries_what_a_finding_from_it_does_not_establish(
    tmp_path: Path,
) -> None:
    """`fullDescription` is the alert page's explanation, and it was empty.

    It is the place in this integration most likely to be read by somebody who
    has not read the documentation, which makes it the place the caveat belongs.
    """

    document = sarif_for(tmp_path)
    rules = {rule["id"]: rule for rule in document["runs"][0]["tool"]["driver"]["rules"]}
    text = rules["design.raster-metadata.v1"]["fullDescription"]["text"]

    assert "does not establish that the artifact was generated by AI" in text
    assert "editable by anyone who can open the file" in text


def test_the_instance_is_still_in_the_result_message(tmp_path: Path) -> None:
    """Moving the description off the rule must not lose it."""

    document = sarif_for(tmp_path)
    messages = " ".join(item["message"]["text"] for item in document["runs"][0]["results"])

    assert "Software" in messages
    assert "Author" in messages


def test_every_surface_draws_its_caveats_from_one_table(tmp_path: Path) -> None:
    """Two copies of these sentences would be the worst thing to let drift.

    The desktop and IDE surfaces read them through `explain_finding`; the SARIF
    rule reads them directly. Both have to be the same sentences, which is why
    they live beside the enums rather than inside one renderer.
    """

    from trueai.adapters.views import explain_finding
    from trueai.core.models import evidence_limits

    artifact = tmp_path / "notes.md"
    artifact.write_text("Generated with ChatGPT\n", encoding="utf-8")
    report = TrueAIEngine(create_default_registry()).scan(artifact)
    finding = report.findings[0]

    explanation = explain_finding(finding)
    expected = evidence_limits(finding.confidence_type, finding.provenance_class)

    assert explanation.does_not_claim == expected


# -- the header over a report nobody is scanning ---------------------------------------


def test_explain_does_not_say_it_is_scanning(tmp_path: Path) -> None:
    """`explain` reads a saved report. The header said "Scanning:" over it.

    The renderer is shared with `scan`, which prints it after the scan has
    already finished, so the tense was wrong there too — but only `explain` made
    it a false statement about what the tool had just done.
    """

    artifact = tmp_path / "notes.md"
    artifact.write_text("Generated with ChatGPT\n", encoding="utf-8")
    report_path = tmp_path / "report.json"
    runner.invoke(app, ["scan", str(artifact), "--format", "json", "--output", str(report_path)])
    finding_id = json.loads(report_path.read_text(encoding="utf-8"))["findings"][0]["id"]

    result = runner.invoke(app, ["explain", finding_id, "--report", str(report_path)])

    assert "Scanning:" not in result.stdout
    assert "Target:" in result.stdout


def test_the_counts_in_the_headline_agree_with_themselves(tmp_path: Path) -> None:
    """ "1 findings across 9 artifact(s)" is the first line of the first report."""

    artifact = tmp_path / "notes.md"
    artifact.write_text("Generated with ChatGPT\n", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(artifact)])

    headline = next(line for line in result.stdout.splitlines() if " across " in line)
    assert "artifact(s)" not in headline
    assert re.fullmatch(r"\d+ findings? across \d+ artifacts?", headline.strip()), headline
    count, artifacts = (int(value) for value in re.findall(r"\d+", headline))
    assert ("findings" in headline) == (count != 1)
    assert ("artifacts" in headline) == (artifacts != 1)


# -- a green residue verdict over findings it did not count ----------------------------


def test_a_clear_residue_verdict_names_what_it_did_not_cover(tmp_path: Path) -> None:
    """CLEAR is scoped, and the same rescan can be holding findings outside it.

    `safe-clean` removes the generator fields and leaves personal metadata to a
    privacy policy, so a PNG with both comes back CLEAR with an `Author` still in
    it. The status is right and its scope sentence is accurate; printing them
    with nothing else said left a reader to conclude the file was clean, which is
    the shape of overstatement this file exists to catch.
    """

    from PIL import Image, PngImagePlugin

    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("Software", "Generated with ChatGPT")
    metadata.add_text("Author", "Jane Doe")
    artifact = tmp_path / "art.png"
    Image.new("RGB", (8, 8), (1, 2, 3)).save(artifact, pnginfo=metadata)

    result = runner.invoke(app, ["clean", str(artifact), "--policy", "safe-clean"])

    assert "CLEAR" in result.stdout, result.stdout
    assert "Outside that scope" in result.stdout, result.stdout
    assert "personal_metadata" in result.stdout, result.stdout


def test_a_fully_cleaned_artifact_says_nothing_extra(tmp_path: Path) -> None:
    """Paired with the test above: the line appears because something is there."""

    artifact = tmp_path / "logo.svg"
    artifact.write_text(
        '<svg xmlns="http://www.w3.org/2000/svg" width="4" height="4">'
        '<!-- Created with Figma --><rect width="4" height="4"/></svg>',
        encoding="utf-8",
    )

    result = runner.invoke(app, ["clean", str(artifact), "--policy", "safe-clean"])

    assert "CLEAR" in result.stdout, result.stdout
    assert "Outside that scope" not in result.stdout, result.stdout
