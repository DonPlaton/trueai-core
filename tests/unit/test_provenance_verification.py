"""Authenticated C2PA verification, including the states that must stay honest."""

from __future__ import annotations

from pathlib import Path

import pytest
from PIL import Image
from typer.testing import CliRunner

from tests.fixtures_provenance import (
    SignedAsset,
    build_signed_png,
    provenance_dependencies_available,
)
from tests.support import assert_optional_dependencies
from trueai import (
    Artifact,
    PolicyStore,
    TrueAIEngine,
    attach_provenance_verifications,
    verify_provenance,
)
from trueai.cli.app import app
from trueai.core.errors import ProvenanceConfigurationError, UnsafeArtifactError
from trueai.core.models import (
    ProvenanceVerification,
    ProvenanceVerificationStatus,
    ValidationOutcome,
)
from trueai.detectors.provenance.verification import C2PAVerifier, c2pa_available

requires_c2pa = pytest.mark.skipif(
    not provenance_dependencies_available(),
    reason="Signed fixtures need both c2pa-python and cryptography",
)


def test_optional_verification_dependencies_are_present_when_required() -> None:
    """A job that claims to cover C2PA must actually have the verifier installed."""

    assert_optional_dependencies("c2pa", "cryptography")


@pytest.fixture
def signed_asset(tmp_path: Path) -> SignedAsset:
    """Generate a synthetic signed PNG and its throwaway trust anchor."""

    if not provenance_dependencies_available():
        pytest.skip("Signed fixtures need both c2pa-python and cryptography")
    return build_signed_png(tmp_path)


# -- states that must not be conflated ------------------------------------------------


@requires_c2pa
def test_a_valid_signature_without_trust_anchors_is_not_reported_as_trusted(
    signed_asset: SignedAsset,
) -> None:
    result = verify_provenance(signed_asset.path)

    assert result.status == ProvenanceVerificationStatus.VALID
    assert not result.authenticated
    assert "not authenticated provenance" in result.explanation


@requires_c2pa
def test_a_signature_chaining_to_a_configured_anchor_is_trusted(
    signed_asset: SignedAsset,
) -> None:
    result = verify_provenance(signed_asset.path, trust_anchors=signed_asset.trust_anchor_path)

    assert result.status == ProvenanceVerificationStatus.TRUSTED
    assert result.authenticated
    assert result.trust_anchors_configured


@requires_c2pa
def test_authenticated_verification_can_be_attached_to_a_scan_report(
    signed_asset: SignedAsset,
) -> None:
    report = TrueAIEngine.default(discover_plugins=False).scan(
        signed_asset.path,
        policy=PolicyStore.get("audit"),
    )

    enriched = attach_provenance_verifications(
        report,
        signed_asset.path,
        trust_anchors=signed_asset.trust_anchor_path,
    )

    assert enriched.findings == report.findings
    assert len(enriched.provenance_verifications) == 1
    assert enriched.provenance_verifications[0].status == ProvenanceVerificationStatus.TRUSTED


def test_report_verification_rejects_bytes_changed_after_scanning(tmp_path: Path) -> None:
    asset = tmp_path / "changing.png"
    Image.new("RGB", (8, 8), (1, 2, 3)).save(asset)
    report = TrueAIEngine.default(discover_plugins=False).scan(asset)

    original = asset.read_bytes()
    asset.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))

    with pytest.raises(UnsafeArtifactError, match="changed after scanning"):
        attach_provenance_verifications(report, asset)


def test_report_verification_rejects_bytes_changed_while_verifier_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asset = tmp_path / "racing.png"
    Image.new("RGB", (8, 8), (1, 2, 3)).save(asset)
    report = TrueAIEngine.default(discover_plugins=False).scan(asset)
    original_verify = C2PAVerifier.verify

    def mutate_after_verification(
        verifier: C2PAVerifier,
        artifact: Artifact,
    ) -> ProvenanceVerification:
        result = original_verify(verifier, artifact)
        path = artifact.path
        assert path is not None
        payload = path.read_bytes()
        path.write_bytes(payload[:-1] + bytes([payload[-1] ^ 1]))
        return result

    monkeypatch.setattr(C2PAVerifier, "verify", mutate_after_verification)

    with pytest.raises(UnsafeArtifactError, match="changed after scanning"):
        attach_provenance_verifications(report, asset)


@requires_c2pa
def test_trust_anchors_may_be_supplied_as_pem_text(signed_asset: SignedAsset) -> None:
    result = verify_provenance(signed_asset.path, trust_anchors=signed_asset.trust_anchor_pem)

    assert result.status == ProvenanceVerificationStatus.TRUSTED


@requires_c2pa
def test_an_unrelated_trust_anchor_does_not_make_a_signature_trusted(
    signed_asset: SignedAsset, tmp_path: Path
) -> None:
    from tests.fixtures_provenance import build_test_chain

    _, _, unrelated_root = build_test_chain()
    anchor = tmp_path / "unrelated.pem"
    anchor.write_bytes(unrelated_root)

    result = verify_provenance(signed_asset.path, trust_anchors=anchor)

    assert result.status != ProvenanceVerificationStatus.TRUSTED
    assert not result.authenticated


@requires_c2pa
def test_tampered_content_fails_verification(signed_asset: SignedAsset, tmp_path: Path) -> None:
    tampered = tmp_path / "tampered.png"
    payload = bytearray(signed_asset.path.read_bytes())
    payload[-40:-20] = b"\x00" * 20
    tampered.write_bytes(bytes(payload))

    result = verify_provenance(tampered, trust_anchors=signed_asset.trust_anchor_path)

    assert result.status == ProvenanceVerificationStatus.INVALID
    assert result.failures()
    assert all(entry.outcome == ValidationOutcome.FAILURE for entry in result.failures())


@requires_c2pa
def test_an_asset_without_a_manifest_is_not_an_error(tmp_path: Path) -> None:
    plain = tmp_path / "plain.png"
    Image.new("RGB", (8, 8), (1, 2, 3)).save(plain)

    result = verify_provenance(plain)

    assert result.status == ProvenanceVerificationStatus.NO_MANIFEST
    assert "not evidence" in result.explanation


@requires_c2pa
def test_an_unsupported_container_is_reported_as_such(tmp_path: Path) -> None:
    notes = tmp_path / "notes.txt"
    notes.write_text("ordinary text", encoding="utf-8")

    result = verify_provenance(notes)

    assert result.status == ProvenanceVerificationStatus.UNSUPPORTED_CONTAINER


# -- reported evidence ---------------------------------------------------------------


@requires_c2pa
def test_verification_reports_the_signer_and_manifest_details(
    signed_asset: SignedAsset,
) -> None:
    result = verify_provenance(signed_asset.path, trust_anchors=signed_asset.trust_anchor_path)

    assert result.signer is not None
    assert result.signer.common_name == signed_asset.signer_common_name
    assert result.signer.algorithm
    assert result.signer.certificate_serial_number
    assert result.title == signed_asset.manifest_title
    assert result.claim_generator == "trueai-test 0.1.0"
    assert result.active_manifest_label
    assert result.embedded is True
    assert any(assertion.label.startswith("c2pa.actions") for assertion in result.assertions)
    assert any(entry.outcome == ValidationOutcome.SUCCESS for entry in result.validation)


@requires_c2pa
def test_the_verifier_identifies_itself_for_audit(signed_asset: SignedAsset) -> None:
    result = verify_provenance(signed_asset.path)

    assert "c2pa-python" in result.verifier
    assert "c2pa-rs" in result.verifier


@requires_c2pa
def test_remote_manifest_fetching_is_off_unless_requested(signed_asset: SignedAsset) -> None:
    default = verify_provenance(signed_asset.path)
    explicit = verify_provenance(signed_asset.path, allow_remote_manifests=True)

    assert default.remote_manifests_allowed is False
    assert explicit.remote_manifests_allowed is True


@requires_c2pa
def test_invalid_trust_anchors_fail_closed_instead_of_being_silently_ignored(
    tmp_path: Path,
) -> None:
    plain = tmp_path / "plain.png"
    Image.new("RGB", (8, 8), (1, 2, 3)).save(plain)

    with pytest.raises(ProvenanceConfigurationError, match=r"trust|C2PA"):
        verify_provenance(plain, trust_anchors="not-a-pem")

    anchors = tmp_path / "invalid-roots.pem"
    anchors.write_text("not-a-pem", encoding="utf-8")
    result = CliRunner().invoke(
        app,
        ["verify", str(plain), "--trust-anchors", str(anchors)],
    )
    assert result.exit_code == 3, result.output


# -- behaviour without the optional dependency ---------------------------------------


def test_verification_is_unavailable_rather_than_guessed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without the verifier, no result may be inferred."""

    plain = tmp_path / "plain.png"
    Image.new("RGB", (8, 8), (1, 2, 3)).save(plain)
    monkeypatch.setattr("trueai.detectors.provenance.verification.c2pa_available", lambda: False)

    result = verify_provenance(plain)

    assert result.status == ProvenanceVerificationStatus.VERIFIER_UNAVAILABLE
    assert result.verifier == "unavailable"
    assert "trueai-core[c2pa]" in result.explanation
    assert not result.authenticated


def test_in_memory_streams_are_not_verifiable() -> None:
    from trueai import Artifact

    result = C2PAVerifier().verify(Artifact.from_text("some text"))

    assert result.status == ProvenanceVerificationStatus.UNSUPPORTED_CONTAINER


def test_supported_media_types_reflect_the_installed_verifier() -> None:
    types = C2PAVerifier().supported_media_types()

    if c2pa_available():
        assert "image/jpeg" in types
    else:
        assert types == frozenset()


# -- scanning stays separate from verification ---------------------------------------


@requires_c2pa
def test_scanning_a_signed_asset_reports_a_marker_without_claiming_verification(
    signed_asset: SignedAsset,
) -> None:
    from trueai import TrueAIEngine
    from trueai.core.models import FindingCategory

    report = TrueAIEngine.default(discover_plugins=False).scan(signed_asset.path)

    marker = next(
        finding
        for finding in report.findings
        if finding.category == FindingCategory.C2PA_PROVENANCE
    )
    assert marker.evidence["authenticated"] is False
    assert marker.evidence["verification"] == "not_attempted"
    assert marker.removable is False
    assert "trueai verify" in marker.description


# -- CLI contract --------------------------------------------------------------------


@requires_c2pa
def test_cli_verify_exit_codes_distinguish_trusted_from_valid(
    signed_asset: SignedAsset,
) -> None:
    runner = CliRunner()

    valid = runner.invoke(app, ["verify", str(signed_asset.path)])
    trusted = runner.invoke(
        app,
        ["verify", str(signed_asset.path), "--trust-anchors", str(signed_asset.trust_anchor_path)],
    )

    assert valid.exit_code == 1, valid.output
    assert trusted.exit_code == 0, trusted.output
    assert "TRUSTED" in trusted.output


@requires_c2pa
def test_cli_scan_can_emit_trusted_provenance_in_the_json_report(
    signed_asset: SignedAsset,
) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            str(signed_asset.path),
            "--verify-provenance",
            "--trust-anchors",
            str(signed_asset.trust_anchor_path),
            "--plugins",
            "disabled",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    import json

    payload = json.loads(result.stdout)
    assert payload["provenance_verifications"][0]["status"] == "trusted"
    assert payload["findings"], "Marker findings stay separate from authenticated verification"


@requires_c2pa
def test_cli_verify_emits_valid_json(signed_asset: SignedAsset) -> None:
    import json

    runner = CliRunner()

    result = runner.invoke(
        app,
        [
            "verify",
            str(signed_asset.path),
            "--format",
            "json",
            "--trust-anchors",
            str(signed_asset.trust_anchor_path),
        ],
    )

    payload = json.loads(result.output)
    assert payload["status"] == "trusted"
    assert payload["schema_version"] == "0.1"
    assert payload["signer"]["common_name"] == signed_asset.signer_common_name


@requires_c2pa
def test_cli_verify_reports_a_tampered_asset_as_a_violation(
    signed_asset: SignedAsset, tmp_path: Path
) -> None:
    tampered = tmp_path / "tampered.png"
    payload = bytearray(signed_asset.path.read_bytes())
    payload[-40:-20] = b"\x00" * 20
    tampered.write_bytes(bytes(payload))
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["verify", str(tampered), "--trust-anchors", str(signed_asset.trust_anchor_path)],
    )

    assert result.exit_code == 2, result.output
