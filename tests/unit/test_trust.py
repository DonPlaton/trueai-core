"""Trust primitives: key custody, identity, timestamps, and rollback detection."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trueai.core.certificates import generate_ed25519_keypair
from trueai.core.models import NetworkPolicy
from trueai.core.trust import (
    ExternalSigningProvider,
    IdentityAssurance,
    IssuerBinding,
    LocalKeySigningProvider,
    NetworkTimestampProvider,
    OfflineTimestampProvider,
    TimestampToken,
    TransparencyLog,
    TrustError,
    TrustProfile,
    append_transparency_entry,
    public_key_id,
    resolve_identity,
    sign_transparency_log,
    verify_timestamp,
    verify_transparency_log,
)

pytest.importorskip("cryptography", reason="Trust primitives need the attestation extra")

NOW = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)


@pytest.fixture
def keys(tmp_path: Path) -> tuple[Path, Path]:
    private_key, public_key = tmp_path / "signer.key", tmp_path / "signer.pub"
    generate_ed25519_keypair(private_key, public_key)
    return private_key, public_key


# -- key custody ---------------------------------------------------------------------


def test_a_local_key_provider_signs_and_names_its_key(keys: tuple[Path, Path]) -> None:
    private_key, public_key = keys
    provider = LocalKeySigningProvider(private_key)

    signature = provider.sign(b"payload")

    assert signature.key_id == public_key_id(public_key)
    assert provider.key_id() == signature.key_id
    assert "local-key-file" in provider.describe()


def test_a_missing_signing_key_fails_at_construction(tmp_path: Path) -> None:
    with pytest.raises(TrustError, match="Signing key not found"):
        LocalKeySigningProvider(tmp_path / "absent.key")


def test_an_external_provider_never_receives_the_private_key(
    keys: tuple[Path, Path],
) -> None:
    """The HSM seam: TrueAI hands over bytes and gets a signature back."""

    private_key, public_key = keys
    seen: list[bytes] = []

    def hardware_signer(payload: bytes) -> bytes:
        seen.append(payload)
        # Stands in for a token that holds the key; here it borrows the local one.
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        key = load_pem_private_key(private_key.read_bytes(), password=None)
        return key.sign(payload)  # type: ignore[union-attr]

    provider = ExternalSigningProvider(
        name="test-hsm", public_key=public_key, signer=hardware_signer
    )
    signature = provider.sign(b"canonical bytes")

    assert seen == [b"canonical bytes"]
    assert signature.key_id == public_key_id(public_key)


def test_an_external_provider_that_returns_a_bad_signature_fails_immediately(
    keys: tuple[Path, Path],
) -> None:
    """Discovering this at verification time means a bad artifact already shipped."""

    _, public_key = keys
    provider = ExternalSigningProvider(
        name="broken-hsm", public_key=public_key, signer=lambda payload: b"\x00" * 64
    )

    with pytest.raises(TrustError, match="does not verify"):
        provider.sign(b"payload")


def test_an_external_provider_rejects_a_non_bytes_signature(keys: tuple[Path, Path]) -> None:
    _, public_key = keys
    provider = ExternalSigningProvider(
        name="confused-hsm", public_key=public_key, signer=lambda payload: "not bytes"
    )

    with pytest.raises(TrustError, match="expected raw bytes"):
        provider.sign(b"payload")


# -- organization identity -----------------------------------------------------------


def test_without_a_trust_profile_a_signature_names_only_a_key(keys: tuple[Path, Path]) -> None:
    """Possession of any key is not organizational identity."""

    _, public_key = keys

    result = resolve_identity(public_key_id(public_key))

    assert result.assurance == IdentityAssurance.KEY_ONLY
    assert not result.names_an_organization
    assert "says nothing about which organization" in result.explanation


def test_a_profile_binds_a_key_to_an_organization(keys: tuple[Path, Path]) -> None:
    _, public_key = keys
    key_id = public_key_id(public_key)
    profile = TrustProfile(
        profile_id="acme-2026",
        issued_at=NOW,
        bindings=(
            IssuerBinding(
                key_id=key_id,
                organization="ACME Research",
                organization_id="acme.example",
                subject="Release engineering",
                not_before=NOW - timedelta(days=1),
                roles=("release",),
            ),
        ),
    )

    result = resolve_identity(key_id, profile=profile, moment=NOW)

    assert result.assurance == IdentityAssurance.PROFILE_BOUND
    assert result.organization == "ACME Research"
    assert result.roles == ("release",)
    assert result.names_an_organization


def test_an_expired_binding_falls_back_to_key_only(keys: tuple[Path, Path]) -> None:
    _, public_key = keys
    key_id = public_key_id(public_key)
    profile = TrustProfile(
        profile_id="acme-2026",
        issued_at=NOW,
        bindings=(
            IssuerBinding(
                key_id=key_id,
                organization="ACME Research",
                not_before=NOW - timedelta(days=10),
                not_after=NOW - timedelta(days=1),
            ),
        ),
    )

    result = resolve_identity(key_id, profile=profile, moment=NOW)

    assert result.assurance == IdentityAssurance.KEY_ONLY
    assert "no binding in force" in result.explanation


def test_a_binding_that_expires_before_it_starts_is_refused() -> None:
    with pytest.raises(ValueError, match="not_after"):
        IssuerBinding(
            key_id="sha256:" + "a" * 64,
            organization="ACME",
            not_before=NOW,
            not_after=NOW - timedelta(days=1),
        )


def test_a_root_signed_profile_reaches_the_highest_assurance(
    keys: tuple[Path, Path], tmp_path: Path
) -> None:
    _, public_key = keys
    root_key, root_public = tmp_path / "root.key", tmp_path / "root.pub"
    generate_ed25519_keypair(root_key, root_public)
    key_id = public_key_id(public_key)
    profile = TrustProfile(
        profile_id="acme-2026",
        issued_at=NOW,
        bindings=(IssuerBinding(key_id=key_id, organization="ACME Research", not_before=NOW),),
    )
    signed = profile.model_copy(
        update={"signature": LocalKeySigningProvider(root_key).sign(profile.signed_payload())}
    )

    result = resolve_identity(key_id, profile=signed, root_public_key=root_public, moment=NOW)

    assert result.assurance == IdentityAssurance.ROOT_ATTESTED
    assert "signed by the configured root" in result.explanation


def test_a_tampered_profile_is_rejected_rather_than_downgraded(
    keys: tuple[Path, Path], tmp_path: Path
) -> None:
    _, public_key = keys
    root_key, root_public = tmp_path / "root.key", tmp_path / "root.pub"
    generate_ed25519_keypair(root_key, root_public)
    key_id = public_key_id(public_key)
    profile = TrustProfile(
        profile_id="acme-2026",
        issued_at=NOW,
        bindings=(IssuerBinding(key_id=key_id, organization="ACME", not_before=NOW),),
    )
    signed = profile.model_copy(
        update={"signature": LocalKeySigningProvider(root_key).sign(profile.signed_payload())}
    )
    tampered = signed.model_copy(
        update={
            "bindings": (IssuerBinding(key_id=key_id, organization="Someone Else", not_before=NOW),)
        }
    )

    with pytest.raises(TrustError, match="root signature does not verify"):
        resolve_identity(key_id, profile=tampered, root_public_key=root_public, moment=NOW)


# -- timestamps ----------------------------------------------------------------------


def test_an_offline_authority_attests_a_digest(tmp_path: Path) -> None:
    authority_key, authority_public = tmp_path / "tsa.key", tmp_path / "tsa.pub"
    generate_ed25519_keypair(authority_key, authority_public)
    provider = OfflineTimestampProvider(
        LocalKeySigningProvider(authority_key), authority="ACME timestamping"
    )
    digest = "b" * 64

    token = provider.timestamp(digest)
    valid, explanation = verify_timestamp(
        token, digest_sha256=digest, authority_public_key=authority_public
    )

    assert valid
    assert "ACME timestamping" in explanation
    assert token.format == "trueai-tsa"


def test_a_timestamp_over_a_different_digest_is_rejected(tmp_path: Path) -> None:
    authority_key, authority_public = tmp_path / "tsa.key", tmp_path / "tsa.pub"
    generate_ed25519_keypair(authority_key, authority_public)
    token = OfflineTimestampProvider(
        LocalKeySigningProvider(authority_key), authority="ACME"
    ).timestamp("b" * 64)

    valid, explanation = verify_timestamp(
        token, digest_sha256="c" * 64, authority_public_key=authority_public
    )

    assert not valid
    assert "different digest" in explanation


def test_a_timestamp_without_an_authority_key_is_unverified_not_valid(
    tmp_path: Path,
) -> None:
    authority_key, _ = tmp_path / "tsa.key", tmp_path / "tsa.pub"
    generate_ed25519_keypair(authority_key, tmp_path / "tsa.pub")
    token = OfflineTimestampProvider(
        LocalKeySigningProvider(authority_key), authority="ACME"
    ).timestamp("b" * 64)

    valid, explanation = verify_timestamp(token, digest_sha256="b" * 64)

    assert not valid
    assert "unverified" in explanation


def test_an_unparsed_rfc3161_token_is_not_treated_as_evidence() -> None:
    """An opaque blob is not evidence just because it is present."""

    token = TimestampToken(
        format="rfc3161",
        authority="https://tsa.example.test",
        digest_sha256="d" * 64,
        timestamped_at=NOW,
        token="AAAA",
    )

    valid, explanation = verify_timestamp(token, digest_sha256="d" * 64)

    assert not valid
    assert "not parsed by TrueAI" in explanation


def test_a_network_authority_requires_an_explicit_network_policy() -> None:
    with pytest.raises(TrustError, match="EXPLICIT_ONLY"):
        NetworkTimestampProvider(
            endpoint="https://tsa.example.test",
            network_policy=NetworkPolicy.OFFLINE,
            allowed_endpoints=frozenset({"https://tsa.example.test"}),
            transport=lambda endpoint, digest: b"token",
        )


def test_a_network_authority_requires_an_allowlisted_endpoint() -> None:
    with pytest.raises(TrustError, match="allowlist"):
        NetworkTimestampProvider(
            endpoint="https://attacker.example.test",
            network_policy=NetworkPolicy.EXPLICIT_ONLY,
            allowed_endpoints=frozenset({"https://tsa.example.test"}),
            transport=lambda endpoint, digest: b"token",
        )


def test_an_allowlisted_authority_records_the_token_it_returned() -> None:
    calls: list[tuple[str, str]] = []

    provider = NetworkTimestampProvider(
        endpoint="https://tsa.example.test",
        network_policy=NetworkPolicy.EXPLICIT_ONLY,
        allowed_endpoints=frozenset({"https://tsa.example.test"}),
        transport=lambda endpoint, digest: calls.append((endpoint, digest)) or b"raw-token",
        authority="Example TSA",
    )
    token = provider.timestamp("e" * 64)

    assert calls == [("https://tsa.example.test", "e" * 64)]
    assert token.format == "rfc3161"
    assert token.token is not None


# -- transparency and rollback -------------------------------------------------------


def build_log() -> TransparencyLog:
    log = TransparencyLog(log_id="revocations")
    for index in range(3):
        log = append_transparency_entry(
            log,
            kind="revocation",
            subject_id=f"TAI1-CERT{index}",
            payload=f"payload {index}".encode(),
            recorded_at=NOW + timedelta(minutes=index),
        )
    return log


def test_an_intact_log_verifies() -> None:
    log = build_log()

    result = verify_transparency_log(log)

    assert result.usable
    assert result.chain_intact
    assert result.sequence_contiguous
    assert result.sequence == 3
    assert not result.problems


def test_an_edited_entry_breaks_the_chain() -> None:
    log = build_log()
    entries = list(log.entries)
    entries[1] = entries[1].model_copy(update={"subject_id": "TAI1-SOMETHING-ELSE"})
    tampered = log.model_copy(update={"entries": tuple(entries)})

    result = verify_transparency_log(tampered)

    assert not result.chain_intact
    assert not result.usable
    assert any("modified after it was recorded" in problem for problem in result.problems)


def test_a_removed_entry_is_detected() -> None:
    log = build_log()
    truncated = log.model_copy(update={"entries": (log.entries[0], log.entries[2])})

    result = verify_transparency_log(truncated)

    assert not result.usable
    assert not result.sequence_contiguous


def test_replacing_a_log_with_an_older_copy_is_a_rollback() -> None:
    """A revocation list that can be replaced by an older copy revokes nothing."""

    log = build_log()
    older = log.model_copy(update={"entries": log.entries[:2]})

    result = verify_transparency_log(older, known_head=log.head, known_sequence=log.sequence)

    assert result.rolled_back
    assert not result.usable
    assert any("older copy" in problem for problem in result.problems)


def test_a_rewritten_history_is_detected_even_at_the_same_length() -> None:
    log = build_log()
    rewritten = append_transparency_entry(
        log.model_copy(update={"entries": log.entries[:2]}),
        kind="revocation",
        subject_id="TAI1-DIFFERENT",
        payload=b"different",
        recorded_at=NOW + timedelta(minutes=2),
    )

    result = verify_transparency_log(rewritten, known_head=log.head, known_sequence=log.sequence)

    assert result.rolled_back
    assert any("history was rewritten" in problem for problem in result.problems)


def test_appending_invalidates_a_previous_maintainer_signature(
    keys: tuple[Path, Path],
) -> None:
    """A maintainer signs a state, not a prefix of one."""

    private_key, _ = keys
    provider = LocalKeySigningProvider(private_key)
    signed = sign_transparency_log(build_log(), provider)
    assert signed.signature is not None

    extended = append_transparency_entry(
        signed, kind="revocation", subject_id="TAI1-NEW", payload=b"new"
    )

    assert extended.signature is None


def test_a_signed_log_reports_its_signature_status(keys: tuple[Path, Path]) -> None:
    private_key, public_key = keys
    signed = sign_transparency_log(build_log(), LocalKeySigningProvider(private_key))

    verified = verify_transparency_log(signed, maintainer_public_key=public_key)
    unverified = verify_transparency_log(signed)

    assert verified.signature_status == "valid"
    assert unverified.signature_status == "unverified"


def test_a_tampered_signed_log_reports_an_invalid_signature(
    keys: tuple[Path, Path],
) -> None:
    private_key, public_key = keys
    signed = sign_transparency_log(build_log(), LocalKeySigningProvider(private_key))
    tampered = signed.model_copy(update={"log_id": "someone-elses-log"})

    result = verify_transparency_log(tampered, maintainer_public_key=public_key)

    assert result.signature_status == "invalid"


# -- attestations reuse these primitives ---------------------------------------------


def build_record(digest: str):
    """A minimal attestation to sign in the tests below."""

    from trueai.core.attestation import (
        Actor,
        ActorKind,
        ClaimType,
        ContributionClaim,
        ContributionDimension,
        ContributionLevel,
        EvidenceStatus,
        issue_attestation,
    )

    return issue_attestation(
        subject_sha256=digest,
        subject_name="deliverable.md",
        actors=(Actor(id="alice", kind=ActorKind.PERSON, display_name="Alice"),),
        claims=(
            ContributionClaim(
                dimension=ContributionDimension.ORIGINATION,
                actor_id="alice",
                claim_type=ClaimType.DECLARATION,
                level=ContributionLevel.PRIMARY,
                evidence_status=EvidenceStatus.SELF_DECLARED,
                explanation="Alice proposed the approach.",
            ),
        ),
    )


def test_an_attestation_can_be_signed_through_an_external_provider(
    keys: tuple[Path, Path],
) -> None:
    """The same HSM seam serves certificates and attestations."""

    from trueai.core.attestation import SignatureRole, sign_attestation, verify_attestation

    private_key, public_key = keys
    record = sign_attestation(
        build_record("f" * 64),
        role=SignatureRole.CLAIMANT,
        actor_id="alice",
        provider=LocalKeySigningProvider(private_key),
    )

    result = verify_attestation(record, public_keys={"alice": public_key})

    assert result.claimant_signature == "valid"
    assert result.authenticated_declaration


def test_signing_requires_exactly_one_key_source(keys: tuple[Path, Path]) -> None:
    from trueai.core.attestation import SignatureRole, sign_attestation
    from trueai.core.errors import AttestationError

    private_key, _ = keys

    with pytest.raises(AttestationError, match="exactly one"):
        sign_attestation(
            build_record("f" * 64),
            role=SignatureRole.CLAIMANT,
            actor_id="alice",
            signing_key=private_key,
            provider=LocalKeySigningProvider(private_key),
        )


def test_a_signature_alone_does_not_attribute_a_record_to_an_organization(
    keys: tuple[Path, Path],
) -> None:
    """ "Someone signed this" must not read as "a company vouched for this"."""

    from trueai.core.attestation import SignatureRole, sign_attestation, verify_attestation

    private_key, public_key = keys
    record = sign_attestation(
        build_record("f" * 64),
        role=SignatureRole.CLAIMANT,
        actor_id="alice",
        signing_key=private_key,
    )

    result = verify_attestation(record, public_keys={"alice": public_key})

    assert result.authenticated_declaration
    assert not result.organizationally_attributed
    assert result.claimant_identity is not None
    assert result.claimant_identity.assurance == IdentityAssurance.KEY_ONLY


def test_a_trust_profile_attributes_a_record_to_its_organization(
    keys: tuple[Path, Path],
) -> None:
    from trueai.core.attestation import SignatureRole, sign_attestation, verify_attestation

    private_key, public_key = keys
    record = sign_attestation(
        build_record("f" * 64),
        role=SignatureRole.CLAIMANT,
        actor_id="alice",
        signing_key=private_key,
    )
    profile = TrustProfile(
        profile_id="acme-2026",
        issued_at=NOW,
        bindings=(
            IssuerBinding(
                key_id=public_key_id(public_key),
                organization="ACME Research",
                not_before=NOW - timedelta(days=1),
            ),
        ),
    )

    result = verify_attestation(
        record, public_keys={"alice": public_key}, trust_profile=profile, now=NOW
    )

    assert result.organizationally_attributed
    assert result.claimant_identity is not None
    assert result.claimant_identity.organization == "ACME Research"


def test_a_trusted_timestamp_is_reported_separately_from_the_signers_own_time(
    keys: tuple[Path, Path], tmp_path: Path
) -> None:
    from trueai.core.attestation import SignatureRole, sign_attestation, verify_attestation

    private_key, public_key = keys
    authority_key, authority_public = tmp_path / "tsa.key", tmp_path / "tsa.pub"
    generate_ed25519_keypair(authority_key, authority_public)
    record = sign_attestation(
        build_record("f" * 64),
        role=SignatureRole.CLAIMANT,
        actor_id="alice",
        signing_key=private_key,
        timestamp_provider=OfflineTimestampProvider(
            LocalKeySigningProvider(authority_key), authority="ACME timestamping"
        ),
    )

    result = verify_attestation(
        record,
        public_keys={"alice": public_key},
        timestamp_authority_key=authority_public,
    )

    assert result.trusted_timestamp is True
    assert result.timestamp_explanation is not None
    assert "ACME timestamping" in result.timestamp_explanation


def test_a_record_without_a_timestamp_says_so_rather_than_implying_one(
    keys: tuple[Path, Path],
) -> None:
    from trueai.core.attestation import SignatureRole, sign_attestation, verify_attestation

    private_key, public_key = keys
    record = sign_attestation(
        build_record("f" * 64),
        role=SignatureRole.CLAIMANT,
        actor_id="alice",
        signing_key=private_key,
    )

    result = verify_attestation(record, public_keys={"alice": public_key})

    assert result.trusted_timestamp is None
    assert result.timestamp_explanation is None
