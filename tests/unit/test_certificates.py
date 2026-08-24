"""Content binding, honest claims, and optional signatures for audit certificates."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from PIL import Image, PngImagePlugin

from trueai import PolicyStore, TrueAIEngine
from trueai.core.certificates import (
    CertificateStatus,
    RevocationReason,
    certificate_json,
    certificate_schema,
    generate_ed25519_keypair,
    issue_certificate,
    load_certificate,
    revocation_list_json,
    revocation_list_schema,
    revoke_certificate,
    verify_certificate,
    verify_revocation_list,
)
from trueai.core.errors import AttestationError
from trueai.core.models import ScanOptions


def scan(path: Path, options: ScanOptions | None = None):
    boundaries = options or ScanOptions()
    report = TrueAIEngine.default(discover_plugins=False).scan(
        path,
        options=boundaries,
        policy=PolicyStore.get("audit"),
    )
    return report, boundaries


def test_clear_certificate_is_content_bound_without_claiming_human_authorship(
    tmp_path: Path,
) -> None:
    source = tmp_path / "notes.txt"
    source.write_text("A short ordinary note.\n", encoding="utf-8")
    report, options = scan(source)

    certificate = issue_certificate(report, options)
    verification = verify_certificate(certificate, artifact=source)

    assert certificate.status == CertificateStatus.CLEAR
    assert certificate.certificate_id.startswith("TAI1-")
    assert "does not prove human authorship" in certificate.limitations[0]
    assert verification.valid
    assert verification.artifact_verified is True
    assert verification.signature_verified is None


def test_detected_attribution_prevents_a_clear_certificate(tmp_path: Path) -> None:
    source = tmp_path / "notes.txt"
    source.write_text("Generated with ChatGPT\n", encoding="utf-8")
    report, options = scan(source)

    certificate = issue_certificate(report, options)

    assert certificate.status == CertificateStatus.INDICATORS_DETECTED
    assert certificate.indicator_finding_ids


def test_invisible_unicode_prevents_a_clear_certificate(tmp_path: Path) -> None:
    source = tmp_path / "notes.txt"
    source.write_text("Hidden\u200bseparator\n", encoding="utf-8")
    report, options = scan(source)

    certificate = issue_certificate(report, options)

    assert certificate.status == CertificateStatus.INDICATORS_DETECTED


def test_safe_leading_bom_is_not_promoted_to_a_machine_indicator(tmp_path: Path) -> None:
    source = tmp_path / "notes.txt"
    source.write_text("\ufeffOrdinary text\n", encoding="utf-8")
    report, options = scan(source)

    certificate = issue_certificate(report, options)

    assert report.findings, "Unicode forensics should still disclose the BOM"
    assert certificate.status == CertificateStatus.CLEAR


def test_incomplete_scan_never_issues_clearance(tmp_path: Path) -> None:
    source = tmp_path / "large.txt"
    source.write_bytes(b"x" * 1025)
    report, options = scan(source, ScanOptions(max_file_size=1024))

    certificate = issue_certificate(report, options)

    assert certificate.status == CertificateStatus.INCOMPLETE
    assert not certificate.scan_complete
    assert "artifact_too_large" in certificate.diagnostic_codes


def test_certificate_detects_claim_and_artifact_tampering(tmp_path: Path) -> None:
    source = tmp_path / "notes.txt"
    source.write_text("Original bytes\n", encoding="utf-8")
    report, options = scan(source)
    certificate = issue_certificate(report, options)

    changed_claim = certificate.model_copy(update={"statement": "Human authored."})
    source.write_text("Changed bytes\n", encoding="utf-8")

    claim_check = verify_certificate(changed_claim)
    artifact_check = verify_certificate(certificate, artifact=source)
    assert not claim_check.valid
    assert not claim_check.certificate_id_valid
    assert not artifact_check.valid
    assert artifact_check.artifact_verified is False


def test_directory_certificate_binds_every_discovered_child(tmp_path: Path) -> None:
    root = tmp_path / "deliverable"
    root.mkdir()
    child = root / "notes.txt"
    child.write_text("Version one\n", encoding="utf-8")
    report, options = scan(root)
    certificate = issue_certificate(report, options)

    child.write_text("Version two\n", encoding="utf-8")

    assert verify_certificate(certificate, artifact=root).artifact_verified is False


def test_ed25519_signature_authenticates_the_certificate_issuer(tmp_path: Path) -> None:
    source = tmp_path / "notes.txt"
    source.write_text("A short ordinary note.\n", encoding="utf-8")
    private_key = tmp_path / "issuer-private.pem"
    public_key = tmp_path / "issuer-public.pem"
    key_id = generate_ed25519_keypair(private_key, public_key)
    report, options = scan(source)

    certificate = issue_certificate(report, options, signing_key=private_key)
    verification = verify_certificate(certificate, public_key=public_key, artifact=source)
    without_key = verify_certificate(certificate, artifact=source)

    assert certificate.signature is not None
    assert certificate.signature.key_id == key_id
    assert verification.valid
    assert verification.signature_verified is True
    assert not without_key.valid
    assert without_key.signature_verified is None


def test_signature_from_another_issuer_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "notes.txt"
    source.write_text("A short ordinary note.\n", encoding="utf-8")
    private_key = tmp_path / "issuer-private.pem"
    public_key = tmp_path / "issuer-public.pem"
    other_private = tmp_path / "other-private.pem"
    other_public = tmp_path / "other-public.pem"
    generate_ed25519_keypair(private_key, public_key)
    generate_ed25519_keypair(other_private, other_public)
    report, options = scan(source)
    certificate = issue_certificate(report, options, signing_key=private_key)

    verification = verify_certificate(certificate, public_key=other_public)

    assert not verification.valid
    assert verification.signature_verified is False


def test_provenance_marker_is_recorded_separately_not_called_machine_authorship(
    tmp_path: Path,
) -> None:
    source = tmp_path / "credential.png"
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("Note", "c2pa manifest")
    Image.new("RGB", (4, 4), (1, 2, 3)).save(source, pnginfo=metadata)
    report, options = scan(source)

    certificate = issue_certificate(report, options)

    assert certificate.status == CertificateStatus.CLEAR
    assert certificate.protected_provenance_finding_ids


def test_certificate_json_round_trip(tmp_path: Path) -> None:
    source = tmp_path / "notes.txt"
    source.write_text("A short ordinary note.\n", encoding="utf-8")
    report, options = scan(source)
    certificate = issue_certificate(report, options)
    path = tmp_path / "certificate.json"
    path.write_text(certificate_json(certificate), encoding="utf-8")

    loaded = load_certificate(path)

    assert loaded == certificate
    assert verify_certificate(loaded).certificate_id_valid


def test_certificate_schema_has_an_independent_versioned_contract() -> None:
    schema = certificate_schema()

    assert schema["$id"].endswith("/certificate/0.1/schema.json")
    assert schema["properties"]["certificate_schema_version"]["const"] == "0.1"
    assert set(schema["$defs"]["CertificateStatus"]["enum"]) == {
        "clear",
        "indicators_detected",
        "incomplete",
    }
    snapshot_path = (
        Path(__file__).resolve().parents[2] / "schema" / "trueai-certificate-0.1.schema.json"
    )
    assert json.loads(snapshot_path.read_text(encoding="utf-8")) == schema


def test_certificate_expiry_is_signed_and_enforced(tmp_path: Path) -> None:
    source = tmp_path / "notes.txt"
    source.write_text("A short ordinary note.\n", encoding="utf-8")
    issued_at = datetime(2026, 1, 1, tzinfo=UTC)
    report, options = scan(source)

    certificate = issue_certificate(
        report,
        options,
        issued_at=issued_at,
        valid_for=timedelta(days=7),
    )

    current = verify_certificate(certificate, at_time=issued_at + timedelta(days=6))
    expired = verify_certificate(certificate, at_time=issued_at + timedelta(days=7))
    assert current.valid
    assert current.temporal_valid
    assert not expired.valid
    assert not expired.temporal_valid
    assert certificate.expires_at == issued_at + timedelta(days=7)


def test_certificate_rejects_non_positive_validity(tmp_path: Path) -> None:
    source = tmp_path / "notes.txt"
    source.write_text("A short ordinary note.\n", encoding="utf-8")
    report, options = scan(source)

    with pytest.raises(AttestationError, match="validity duration must be positive"):
        issue_certificate(report, options, valid_for=timedelta(0))


def test_attestation_key_reads_are_bounded(tmp_path: Path) -> None:
    source = tmp_path / "notes.txt"
    source.write_text("A short ordinary note.\n", encoding="utf-8")
    oversized_key = tmp_path / "oversized.pem"
    oversized_key.write_bytes(b"x" * (1024 * 1024 + 1))
    report, options = scan(source)

    with pytest.raises(AttestationError, match="Key file exceeds"):
        issue_certificate(report, options, signing_key=oversized_key)


def test_signed_revocation_list_withdraws_only_the_selected_certificate(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_text("First delivery.\n", encoding="utf-8")
    second.write_text("Second delivery.\n", encoding="utf-8")
    private_key = tmp_path / "issuer-private.pem"
    public_key = tmp_path / "issuer-public.pem"
    generate_ed25519_keypair(private_key, public_key)
    issue_time = datetime(2026, 2, 1, tzinfo=UTC)
    first_report, first_options = scan(first)
    second_report, second_options = scan(second)
    first_certificate = issue_certificate(
        first_report,
        first_options,
        signing_key=private_key,
        issued_at=issue_time,
        valid_for=timedelta(days=365),
    )
    second_certificate = issue_certificate(
        second_report,
        second_options,
        signing_key=private_key,
        issued_at=issue_time,
        valid_for=timedelta(days=365),
    )

    revocations = revoke_certificate(
        first_certificate,
        signing_key=private_key,
        reason=RevocationReason.ARTIFACT_WITHDRAWN,
        explanation="Delivery was withdrawn by its owner.",
        revoked_at=issue_time + timedelta(days=1),
        valid_for=timedelta(days=30),
    )
    at_time = issue_time + timedelta(days=2)
    revoked = verify_certificate(
        first_certificate,
        public_key=public_key,
        revocation_list=revocations,
        require_revocation_check=True,
        at_time=at_time,
    )
    current = verify_certificate(
        second_certificate,
        public_key=public_key,
        revocation_list=revocations,
        require_revocation_check=True,
        at_time=at_time,
    )

    assert not revoked.valid
    assert revoked.revocation_checked
    assert revoked.revoked is True
    assert current.valid
    assert current.revocation_checked
    assert current.revoked is False


def test_revocation_list_tampering_and_expiry_fail_closed(tmp_path: Path) -> None:
    source = tmp_path / "notes.txt"
    source.write_text("A short ordinary note.\n", encoding="utf-8")
    private_key = tmp_path / "issuer-private.pem"
    public_key = tmp_path / "issuer-public.pem"
    generate_ed25519_keypair(private_key, public_key)
    issue_time = datetime(2026, 3, 1, tzinfo=UTC)
    report, options = scan(source)
    certificate = issue_certificate(
        report,
        options,
        signing_key=private_key,
        issued_at=issue_time,
        valid_for=timedelta(days=365),
    )
    revocations = revoke_certificate(
        certificate,
        signing_key=private_key,
        revoked_at=issue_time + timedelta(days=1),
        valid_for=timedelta(days=2),
    )
    tampered = revocations.model_copy(update={"sequence": revocations.sequence + 1})

    tampered_result = verify_revocation_list(
        tampered,
        public_key=public_key,
        at_time=issue_time + timedelta(days=2),
    )
    stale_result = verify_revocation_list(
        revocations,
        public_key=public_key,
        at_time=issue_time + timedelta(days=3),
    )
    assert not tampered_result.valid
    assert not tampered_result.signature_verified
    assert not stale_result.valid
    assert not stale_result.temporal_valid


def test_revocation_requires_authenticated_issuer_and_current_list(tmp_path: Path) -> None:
    source = tmp_path / "notes.txt"
    source.write_text("A short ordinary note.\n", encoding="utf-8")
    private_key = tmp_path / "issuer-private.pem"
    public_key = tmp_path / "issuer-public.pem"
    generate_ed25519_keypair(private_key, public_key)
    report, options = scan(source)
    unsigned = issue_certificate(report, options)
    signed = issue_certificate(report, options, signing_key=private_key)

    with pytest.raises(AttestationError, match="Unsigned certificates"):
        revoke_certificate(unsigned, signing_key=private_key)

    required = verify_certificate(
        signed,
        public_key=public_key,
        require_revocation_check=True,
    )
    assert not required.valid
    assert not required.revocation_checked
    assert required.revocation_list_valid is False


def test_revocation_list_json_and_schema_are_stable(tmp_path: Path) -> None:
    source = tmp_path / "notes.txt"
    source.write_text("A short ordinary note.\n", encoding="utf-8")
    private_key = tmp_path / "issuer-private.pem"
    public_key = tmp_path / "issuer-public.pem"
    generate_ed25519_keypair(private_key, public_key)
    report, options = scan(source)
    certificate = issue_certificate(report, options, signing_key=private_key)
    revocations = revoke_certificate(certificate, signing_key=private_key)

    assert json.loads(revocation_list_json(revocations))["sequence"] == 1
    schema = revocation_list_schema()
    assert schema["properties"]["revocation_schema_version"]["const"] == "0.1"
    snapshot_path = (
        Path(__file__).resolve().parents[2] / "schema" / "trueai-revocation-list-0.1.schema.json"
    )
    assert json.loads(snapshot_path.read_text(encoding="utf-8")) == schema
