"""Change one field of a signed certificate and ask the verifier again.

A signature check that passes on a modified document is worse than no signature
check, because it gets quoted. These are the edits an attacker would make, one
per test, each asking the verifier the same question it is asked in production.

The one that used to pass is `signature removed`. Stripping the signature from a
signed certificate leaves the claims and the content identifier intact, so
everything else still matched, and `signature_ok` was written as
`certificate.signature is None or signature_verified is True` — which reads the
absence of a signature as nothing to check rather than as the check failing. A
caller who supplied a public key had said they expected one.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from trueai import PolicyStore, TrueAIEngine
from trueai.core.certificates import (
    AuditCertificate,
    generate_ed25519_keypair,
    issue_certificate,
    verify_certificate,
)
from trueai.core.models import ScanOptions

pytest.importorskip("cryptography")


def signed(tmp_path: Path) -> tuple[AuditCertificate, Path, Path]:
    artifact = tmp_path / "deliverable.md"
    artifact.write_text("Generated with ChatGPT\n", encoding="utf-8")
    private_key = tmp_path / "issuer-private.pem"
    public_key = tmp_path / "issuer-public.pem"
    generate_ed25519_keypair(private_key, public_key)
    options = ScanOptions()
    report = TrueAIEngine.default(discover_plugins=False).scan(
        artifact, options=options, policy=PolicyStore.get("audit")
    )
    certificate = issue_certificate(report, options, signing_key=private_key)
    return certificate, artifact, public_key


def edited(certificate: AuditCertificate, **changes: object) -> AuditCertificate:
    """Rebuild a certificate from JSON with fields replaced or removed.

    Through JSON rather than ``model_copy`` because that is how a tampered
    certificate reaches a verifier: as a file somebody edited.
    """

    document = json.loads(certificate.model_dump_json())
    for key, value in changes.items():
        if value is None:
            document.pop(key, None)
        else:
            document[key] = value
    return AuditCertificate.model_validate(document)


def test_the_untouched_certificate_verifies(tmp_path: Path) -> None:
    """Otherwise every refusal below proves nothing."""

    certificate, artifact, public_key = signed(tmp_path)

    result = verify_certificate(certificate, public_key=public_key, artifact=artifact)

    assert result.valid
    assert result.authenticated


def test_a_stripped_signature_does_not_pass_a_check_that_was_asked_for(
    tmp_path: Path,
) -> None:
    """The claims and the content ID survive the strip. The verdict must not."""

    certificate, artifact, public_key = signed(tmp_path)

    result = verify_certificate(
        edited(certificate, signature=None), public_key=public_key, artifact=artifact
    )

    assert not result.valid
    assert result.signature_present is False
    assert any("unsigned" in item for item in result.explanations)


def test_a_stripped_signature_is_still_a_valid_unsigned_certificate_on_its_own(
    tmp_path: Path,
) -> None:
    """Without a key nobody asked about an issuer, so there is nothing to fail.

    The distinction is the whole fix: refusing here as well would make every
    unsigned certificate invalid, which is not what the format says.
    """

    certificate, artifact, _ = signed(tmp_path)

    result = verify_certificate(edited(certificate, signature=None), artifact=artifact)

    assert result.valid
    assert not result.authenticated


def test_a_signed_certificate_without_a_key_cannot_be_called_valid(
    tmp_path: Path,
) -> None:
    """A signature is a claim about the issuer, and an unchecked claim is not a pass."""

    certificate, artifact, _ = signed(tmp_path)

    result = verify_certificate(certificate, artifact=artifact)

    assert not result.valid
    assert result.signature_verified is None


def test_a_replaced_signature_value_is_refused(tmp_path: Path) -> None:
    """A well-formed signature of the right length, over nothing in particular."""

    certificate, artifact, public_key = signed(tmp_path)
    assert certificate.signature is not None
    forged = json.loads(certificate.model_dump_json())["signature"]
    forged["value"] = base64.b64encode(bytes(64)).decode("ascii")

    result = verify_certificate(
        edited(certificate, signature=forged), public_key=public_key, artifact=artifact
    )

    assert not result.valid


def test_a_swapped_key_identifier_is_refused(tmp_path: Path) -> None:
    """The key id binds the signature to a key; disagreeing with it is a forgery."""

    certificate, artifact, public_key = signed(tmp_path)
    swapped = json.loads(certificate.model_dump_json())["signature"]
    swapped["key_id"] = "sha256:" + "0" * 64

    result = verify_certificate(
        edited(certificate, signature=swapped), public_key=public_key, artifact=artifact
    )

    assert not result.valid


def test_a_rewritten_status_is_refused_before_it_reaches_a_verifier(
    tmp_path: Path,
) -> None:
    """The most valuable edit there is: turning a detection into a clean bill.

    Refused by the model rather than by the signature check, which is the
    stronger of the two answers -- a certificate claiming `clear` while listing
    indicators is internally contradictory, so it cannot be constructed at all
    and never reaches code that could be argued with.
    """

    certificate, _, _ = signed(tmp_path)

    with pytest.raises(ValidationError, match="clear certificate"):
        edited(certificate, status="clear")


def test_a_rewritten_certificate_id_is_refused(tmp_path: Path) -> None:
    certificate, artifact, public_key = signed(tmp_path)

    result = verify_certificate(
        edited(certificate, certificate_id="TAI1-" + "A" * 32),
        public_key=public_key,
        artifact=artifact,
    )

    assert not result.valid
    assert result.certificate_id_valid is False


def test_a_moved_issue_time_is_refused(tmp_path: Path) -> None:
    certificate, artifact, public_key = signed(tmp_path)

    result = verify_certificate(
        edited(certificate, issued_at="2000-01-01T00:00:00+00:00"),
        public_key=public_key,
        artifact=artifact,
    )

    assert not result.valid
