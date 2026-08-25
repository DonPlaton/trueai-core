"""A managed trust store: distribution, rotation, and offline updates.

Three separate failures are checked here because they are three separate
problems. A store that can be rolled back lets an attacker reinstate a revoked
key. A rotation with a gap makes signatures fail months later for a reason
nobody connects to a key change. An update that can skip a sequence silently
skips whatever that sequence revoked.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from trueai.core import trust_store as trust_store_module
from trueai.core.certificates import generate_ed25519_keypair
from trueai.core.trust import public_key_id
from trueai.core.trust_store import (
    AnchorKind,
    AnchorRevocation,
    TrustAnchor,
    TrustStore,
    TrustStoreError,
    TrustStoreUpdate,
    apply_update,
    build_trust_store,
    compute_store_id,
    install_trust_store,
    load_trust_store,
    load_trust_store_update,
    sign_trust_store,
    trust_store_json,
    trust_store_update_json,
    verify_trust_store,
)

pytest.importorskip("cryptography", reason="Signing needs the attestation extra")

NOW = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
YEAR = timedelta(days=365)

KEY_A = "sha256:" + "a" * 64
KEY_B = "sha256:" + "b" * 64

PEM = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----"


@pytest.fixture
def keys(tmp_path: Path) -> tuple[Path, Path]:
    private, public = tmp_path / "org.key", tmp_path / "org.pub"
    generate_ed25519_keypair(private, public)
    return private, public


@pytest.fixture
def other_keys(tmp_path: Path) -> tuple[Path, Path]:
    private, public = tmp_path / "other.key", tmp_path / "other.pub"
    generate_ed25519_keypair(private, public)
    return private, public


def issuer_anchor(anchor_id: str = "issuer-2026", **extra: object) -> TrustAnchor:
    fields: dict[str, object] = {
        "anchor_id": anchor_id,
        "kind": AnchorKind.ISSUER_KEY,
        "subject": "Example Forensics",
        "material": KEY_A,
        "not_before": NOW - YEAR,
        "not_after": NOW + YEAR,
        "organization_id": "example.test",
        "roles": ("audit",),
    }
    fields.update(extra)
    return TrustAnchor.model_validate(fields)


def store(keys: tuple[Path, Path], *, sequence: int = 1, **extra: object) -> TrustStore:
    fields: dict[str, object] = {
        "organization": "Example Forensics",
        "issuer_key_id": public_key_id(keys[1]),
        "sequence": sequence,
        "issued_at": NOW - timedelta(days=1),
        "expires_at": NOW + timedelta(days=90),
        "anchors": (issuer_anchor(),),
    }
    fields.update(extra)
    return sign_trust_store(build_trust_store(**fields), signing_key=keys[0])  # type: ignore[arg-type]


# -- identity ------------------------------------------------------------------------


def test_the_identifier_is_derived_from_everything_the_store_claims(
    keys: tuple[Path, Path],
) -> None:
    original = store(keys)

    renamed = original.model_copy(update={"organization": "Someone Else"})

    assert compute_store_id(renamed) != renamed.store_id


def test_signing_does_not_move_the_identifier(keys: tuple[Path, Path]) -> None:
    """The signature covers the store; the identifier covers what it says."""

    unsigned = build_trust_store(
        organization="Example Forensics",
        issuer_key_id=public_key_id(keys[1]),
        sequence=1,
        issued_at=NOW,
        expires_at=NOW + YEAR,
    )

    signed = sign_trust_store(unsigned, signing_key=keys[0])

    assert signed.store_id == unsigned.store_id


def test_a_store_whose_contents_were_edited_is_not_signed(keys: tuple[Path, Path]) -> None:
    draft = build_trust_store(
        organization="Example Forensics",
        issuer_key_id=public_key_id(keys[1]),
        sequence=1,
        issued_at=NOW,
        expires_at=NOW + YEAR,
    )
    tampered = draft.model_copy(update={"organization": "Someone Else"})

    with pytest.raises(TrustStoreError, match="does not match its contents"):
        sign_trust_store(tampered, signing_key=keys[0])


def test_signing_takes_a_key_or_a_provider_and_not_both(keys: tuple[Path, Path]) -> None:
    draft = build_trust_store(
        organization="Example Forensics",
        issuer_key_id=public_key_id(keys[1]),
        sequence=1,
        issued_at=NOW,
        expires_at=NOW + YEAR,
    )

    with pytest.raises(TrustStoreError, match="exactly one"):
        sign_trust_store(draft)


# -- verification --------------------------------------------------------------------


def test_a_clean_store_verifies(keys: tuple[Path, Path]) -> None:
    valid, problems = verify_trust_store(store(keys), public_key=keys[1], now=NOW)

    assert valid
    assert problems == ()


def test_an_edited_anchor_breaks_the_signature(keys: tuple[Path, Path]) -> None:
    original = store(keys)

    widened = original.model_copy(update={"anchors": (issuer_anchor(material=KEY_B),)})
    valid, problems = verify_trust_store(widened, public_key=keys[1], now=NOW)

    assert not valid
    assert "the signature does not verify" in problems


def test_an_unsigned_store_is_refused(keys: tuple[Path, Path]) -> None:
    unsigned = build_trust_store(
        organization="Example Forensics",
        issuer_key_id=public_key_id(keys[1]),
        sequence=1,
        issued_at=NOW,
        expires_at=NOW + YEAR,
    )

    valid, problems = verify_trust_store(unsigned, public_key=keys[1], now=NOW)

    assert not valid
    assert "the store is unsigned" in problems


def test_a_store_signed_by_the_wrong_key_is_refused(
    keys: tuple[Path, Path], other_keys: tuple[Path, Path]
) -> None:
    signed_by_other = sign_trust_store(
        build_trust_store(
            organization="Example Forensics",
            issuer_key_id=public_key_id(keys[1]),
            sequence=1,
            issued_at=NOW,
            expires_at=NOW + YEAR,
        ),
        signing_key=other_keys[0],
    )

    valid, problems = verify_trust_store(signed_by_other, public_key=keys[1], now=NOW)

    assert not valid
    assert any("the wrong key for this store, not a bad signature" in p for p in problems)


def test_a_valid_signature_from_an_unnamed_issuer_is_still_refused(
    keys: tuple[Path, Path], other_keys: tuple[Path, Path]
) -> None:
    """A signature verifying is not the same as the named issuer having made it."""

    signed = sign_trust_store(
        build_trust_store(
            organization="Example Forensics",
            issuer_key_id=public_key_id(keys[1]),
            sequence=1,
            issued_at=NOW,
            expires_at=NOW + YEAR,
        ),
        signing_key=other_keys[0],
    )

    valid, problems = verify_trust_store(signed, public_key=other_keys[1], now=NOW)

    assert not valid
    assert any("but was signed by" in problem for problem in problems)


def test_an_unreadable_public_key_is_reported_not_raised(
    keys: tuple[Path, Path], tmp_path: Path
) -> None:
    junk = tmp_path / "not-a-key.pub"
    junk.write_text("nonsense", encoding="utf-8")

    valid, problems = verify_trust_store(store(keys), public_key=junk, now=NOW)

    assert not valid
    assert any("the public key could not be read" in problem for problem in problems)
    assert not any("does not verify" in problem for problem in problems)


def test_an_expired_store_is_refused(keys: tuple[Path, Path]) -> None:
    valid, problems = verify_trust_store(
        store(keys), public_key=keys[1], now=NOW + timedelta(days=200)
    )

    assert not valid
    assert "the store has expired" in problems


def test_a_store_from_the_future_is_refused(keys: tuple[Path, Path]) -> None:
    valid, problems = verify_trust_store(
        store(keys), public_key=keys[1], now=NOW - timedelta(days=30)
    )

    assert not valid
    assert "the store is not yet in force" in problems


def test_every_problem_is_reported_not_only_the_first(keys: tuple[Path, Path]) -> None:
    """An operator fixing one problem should see the others in the same run."""

    unsigned = build_trust_store(
        organization="Example Forensics",
        issuer_key_id=public_key_id(keys[1]),
        sequence=1,
        issued_at=NOW,
        expires_at=NOW + timedelta(days=1),
    )

    _, problems = verify_trust_store(
        unsigned, public_key=keys[1], known_sequence=5, now=NOW + timedelta(days=2)
    )

    assert len(problems) == 3


# -- rollback ------------------------------------------------------------------------


def test_an_older_sequence_than_the_installed_one_is_a_rollback(keys: tuple[Path, Path]) -> None:
    valid, problems = verify_trust_store(
        store(keys, sequence=3), public_key=keys[1], known_sequence=7, now=NOW
    )

    assert not valid
    assert any("rollback" in problem for problem in problems)


def test_the_same_sequence_is_not_a_rollback(keys: tuple[Path, Path]) -> None:
    """Reinstalling the store already held is a no-op, not an attack."""

    valid, _ = verify_trust_store(
        store(keys, sequence=4), public_key=keys[1], known_sequence=4, now=NOW
    )

    assert valid


def test_a_verifier_with_no_memory_cannot_detect_a_rollback(keys: tuple[Path, Path]) -> None:
    """Stated rather than hidden: without ``known_sequence`` there is no check."""

    valid, _ = verify_trust_store(store(keys, sequence=1), public_key=keys[1], now=NOW)

    assert valid


# -- anchors in force ----------------------------------------------------------------


def test_an_anchor_outside_its_window_is_not_in_force() -> None:
    anchor = issuer_anchor()

    assert anchor.in_force(NOW)
    assert not anchor.in_force(NOW - 2 * YEAR)
    assert not anchor.in_force(NOW + 2 * YEAR)


def test_an_anchor_without_an_expiry_stays_in_force() -> None:
    anchor = issuer_anchor(not_after=None)

    assert anchor.in_force(NOW + 100 * YEAR)


def test_a_revocation_removes_an_anchor_from_the_moment_it_takes_effect(
    keys: tuple[Path, Path],
) -> None:
    revoked_at = NOW + timedelta(days=10)
    subject = store(
        keys,
        anchors=(issuer_anchor(),),
        revocations=(
            AnchorRevocation(
                anchor_id="issuer-2026",
                revoked_at=revoked_at,
                reason="the key was exposed in a backup",
            ),
        ),
    )

    assert subject.active_anchors(NOW)
    assert subject.active_anchors(revoked_at) == ()
    assert subject.active_anchors(revoked_at + timedelta(days=1)) == ()


def test_an_expired_store_yields_no_anchors(keys: tuple[Path, Path]) -> None:
    """Otherwise the store's own lifetime would be decorative."""

    subject = store(keys, anchors=(issuer_anchor(not_after=None),))

    assert subject.active_anchors(NOW)
    assert subject.active_anchors(NOW + timedelta(days=200)) == ()


def test_anchors_can_be_selected_by_what_they_are_trusted_for(keys: tuple[Path, Path]) -> None:
    subject = store(
        keys,
        anchors=(
            issuer_anchor(),
            TrustAnchor(
                anchor_id="c2pa-root",
                kind=AnchorKind.C2PA_ROOT,
                subject="Example Root CA",
                material=PEM,
                not_before=NOW - YEAR,
            ),
        ),
    )

    issuers = subject.active_anchors(NOW, AnchorKind.ISSUER_KEY)
    roots = subject.active_anchors(NOW, AnchorKind.C2PA_ROOT)

    assert [anchor.anchor_id for anchor in issuers] == ["issuer-2026"]
    assert [anchor.anchor_id for anchor in roots] == ["c2pa-root"]


def test_an_anchor_reports_a_stable_fingerprint_of_its_material() -> None:
    assert issuer_anchor().fingerprint == issuer_anchor(anchor_id="other").fingerprint
    assert issuer_anchor().fingerprint != issuer_anchor(material=KEY_B).fingerprint


# -- rotation ------------------------------------------------------------------------


def rotated(gap: timedelta, keys: tuple[Path, Path]) -> TrustStore:
    old_end = NOW + timedelta(days=30)
    return store(
        keys,
        anchors=(
            issuer_anchor("issuer-2025", not_before=NOW - YEAR, not_after=old_end),
            issuer_anchor(
                "issuer-2026",
                material=KEY_B,
                not_before=old_end + gap,
                not_after=NOW + 2 * YEAR,
                replaces="issuer-2025",
            ),
        ),
    )


def test_a_rotation_that_leaves_a_gap_is_reported(keys: tuple[Path, Path]) -> None:
    """The failure is delayed: a signature made in the gap fails months later."""

    problems = rotated(timedelta(days=7), keys).rotation_problems()

    assert len(problems) == 1
    assert "issuer-2026" in problems[0]
    assert "nothing signed in that window will verify" in problems[0]


def test_an_overlapping_rotation_is_clean(keys: tuple[Path, Path]) -> None:
    assert rotated(timedelta(days=-7), keys).rotation_problems() == ()


def test_a_rotation_that_starts_exactly_when_the_old_one_ends_is_clean(
    keys: tuple[Path, Path],
) -> None:
    assert rotated(timedelta(0), keys).rotation_problems() == ()


def test_a_predecessor_that_never_expires_cannot_leave_a_gap(keys: tuple[Path, Path]) -> None:
    subject = store(
        keys,
        anchors=(
            issuer_anchor("issuer-2025", not_before=NOW - YEAR, not_after=None),
            issuer_anchor(
                "issuer-2026",
                material=KEY_B,
                not_before=NOW + 10 * YEAR,
                not_after=NOW + 11 * YEAR,
                replaces="issuer-2025",
            ),
        ),
    )

    assert subject.rotation_problems() == ()


def test_a_rotation_chain_reads_newest_first(keys: tuple[Path, Path]) -> None:
    subject = store(
        keys,
        anchors=(
            issuer_anchor("issuer-2024", not_before=NOW - 3 * YEAR, not_after=NOW - 2 * YEAR),
            issuer_anchor(
                "issuer-2025",
                material=KEY_B,
                not_before=NOW - 2 * YEAR,
                not_after=NOW - YEAR,
                replaces="issuer-2024",
            ),
            issuer_anchor("issuer-2026", replaces="issuer-2025"),
        ),
    )

    chain = subject.rotation_chain("issuer-2026")

    assert [anchor.anchor_id for anchor in chain] == ["issuer-2026", "issuer-2025", "issuer-2024"]


def test_a_rotation_naming_an_anchor_the_store_does_not_hold_is_refused(
    keys: tuple[Path, Path],
) -> None:
    """A gap that cannot be checked is refused, not accepted with the check skipped."""

    with pytest.raises(ValueError, match="which is not in"):
        build_trust_store(
            organization="Example Forensics",
            issuer_key_id=public_key_id(keys[1]),
            sequence=1,
            issued_at=NOW,
            expires_at=NOW + YEAR,
            anchors=(issuer_anchor("issuer-2026", replaces="issuer-from-another-store"),),
        )


def test_installing_reports_rotation_gaps_as_warnings_not_refusals(
    keys: tuple[Path, Path],
) -> None:
    """The gap may be deliberate; the operator decides, but not unknowingly."""

    result = install_trust_store(rotated(timedelta(days=7), keys), public_key=keys[1], now=NOW)

    assert result.installed
    assert len(result.rotation_warnings) == 1
    assert "1 rotation warning" in result.explain()


def test_a_refused_store_is_not_searched_for_rotation_gaps(keys: tuple[Path, Path]) -> None:
    result = install_trust_store(
        rotated(timedelta(days=7), keys), public_key=keys[1], now=NOW + timedelta(days=200)
    )

    assert not result.installed
    assert result.rotation_warnings == ()
    assert "Refused" in result.explain()


# -- offline updates -----------------------------------------------------------------


def update(keys: tuple[Path, Path], *, from_sequence: int, **extra: object) -> TrustStoreUpdate:
    return TrustStoreUpdate(
        from_sequence=from_sequence,
        store=store(keys, sequence=from_sequence + 1, **extra),
        summary="rotate the issuer key",
    )


def test_an_update_must_advance_exactly_one_sequence(keys: tuple[Path, Path]) -> None:
    with pytest.raises(ValueError, match="advance exactly one sequence"):
        TrustStoreUpdate(from_sequence=4, store=store(keys, sequence=6), summary="skip ahead")


def test_applying_the_next_update_replaces_the_installed_store(keys: tuple[Path, Path]) -> None:
    installed = store(keys, sequence=1)

    current, result = apply_update(
        installed, update(keys, from_sequence=1), public_key=keys[1], now=NOW
    )

    assert result.installed
    assert current.sequence == 2


def test_an_update_that_skips_a_sequence_is_refused(keys: tuple[Path, Path]) -> None:
    """The skipped sequence is where a revocation lives."""

    installed = store(keys, sequence=1)

    current, result = apply_update(
        installed, update(keys, from_sequence=2), public_key=keys[1], now=NOW
    )

    assert not result.installed
    assert current is installed
    assert any("no revocation is skipped" in problem for problem in result.problems)


def test_replaying_an_old_update_is_refused(keys: tuple[Path, Path]) -> None:
    installed = store(keys, sequence=5)

    _, result = apply_update(installed, update(keys, from_sequence=1), public_key=keys[1], now=NOW)

    assert not result.installed


def test_the_first_update_applies_to_a_machine_with_no_store(keys: tuple[Path, Path]) -> None:
    current, result = apply_update(None, update(keys, from_sequence=0), public_key=keys[1], now=NOW)

    assert result.installed
    assert current.sequence == 1


def test_an_update_for_another_organization_is_refused(keys: tuple[Path, Path]) -> None:
    installed = store(keys, sequence=1)
    foreign = TrustStoreUpdate(
        from_sequence=1,
        store=store(keys, sequence=2, organization="Someone Else"),
        summary="quietly change hands",
    )

    current, result = apply_update(installed, foreign, public_key=keys[1], now=NOW)

    assert not result.installed
    assert current is installed
    assert any("Someone Else" in problem for problem in result.problems)


def test_a_failed_update_leaves_the_installed_store_in_place(keys: tuple[Path, Path]) -> None:
    installed = store(keys, sequence=1)

    current, result = apply_update(
        installed,
        update(keys, from_sequence=1),
        public_key=keys[1],
        now=NOW + timedelta(days=200),
    )

    assert not result.installed
    assert current is installed


def test_an_update_carries_the_whole_successor_so_the_result_needs_no_computation(
    keys: tuple[Path, Path],
) -> None:
    step = update(keys, from_sequence=1)

    assert step.store.anchors == (issuer_anchor(),)


# -- projection ----------------------------------------------------------------------


def test_the_profile_projection_carries_only_issuer_anchors(keys: tuple[Path, Path]) -> None:
    subject = store(
        keys,
        anchors=(
            issuer_anchor(),
            TrustAnchor(
                anchor_id="c2pa-root",
                kind=AnchorKind.C2PA_ROOT,
                subject="Example Root CA",
                material=PEM,
                not_before=NOW - YEAR,
            ),
        ),
    )

    profile = subject.to_trust_profile(NOW)

    assert [binding.key_id for binding in profile.bindings] == [KEY_A]
    assert profile.bindings[0].organization == "Example Forensics"
    assert profile.bindings[0].organization_id == "example.test"
    assert profile.bindings[0].roles == ("audit",)


def test_the_profile_identifier_names_the_store_and_its_sequence(keys: tuple[Path, Path]) -> None:
    subject = store(keys, sequence=3)

    assert subject.to_trust_profile(NOW).profile_id == f"{subject.store_id}#3"


def test_a_revoked_anchor_does_not_reach_the_profile(keys: tuple[Path, Path]) -> None:
    subject = store(
        keys,
        revocations=(
            AnchorRevocation(
                anchor_id="issuer-2026",
                revoked_at=NOW - timedelta(days=1),
                reason="superseded",
                replacement_anchor_id="issuer-2027",
            ),
        ),
    )

    assert subject.to_trust_profile(NOW).bindings == ()


def test_the_c2pa_bundle_holds_only_active_roots(keys: tuple[Path, Path]) -> None:
    other = "-----BEGIN CERTIFICATE-----\nWFla\n-----END CERTIFICATE-----"
    subject = store(
        keys,
        anchors=(
            TrustAnchor(
                anchor_id="root-current",
                kind=AnchorKind.C2PA_ROOT,
                subject="Example Root CA",
                material=PEM,
                not_before=NOW - YEAR,
            ),
            TrustAnchor(
                anchor_id="root-retired",
                kind=AnchorKind.C2PA_ROOT,
                subject="Old Root CA",
                material=other,
                not_before=NOW - 3 * YEAR,
                not_after=NOW - 2 * YEAR,
            ),
        ),
    )

    bundle = subject.c2pa_anchor_pems(NOW)

    assert PEM in bundle
    assert other not in bundle


def test_the_c2pa_bundle_is_empty_when_nothing_is_trusted(keys: tuple[Path, Path]) -> None:
    assert store(keys).c2pa_anchor_pems(NOW) == ""


def test_lookups_return_nothing_for_an_unknown_anchor(keys: tuple[Path, Path]) -> None:
    subject = store(keys)

    assert subject.anchor("absent") is None
    assert subject.revocation_for("absent") is None
    assert subject.rotation_chain("absent") == ()


# -- what a store refuses to be ------------------------------------------------------


def test_an_anchor_that_expires_before_it_starts_is_refused() -> None:
    with pytest.raises(ValueError, match="can never be valid"):
        issuer_anchor(not_before=NOW, not_after=NOW - YEAR)


def test_an_anchor_window_without_an_offset_is_refused() -> None:
    with pytest.raises(ValueError, match="must include a UTC offset"):
        issuer_anchor(not_before=datetime(2026, 1, 1))


def test_an_anchor_cannot_replace_itself() -> None:
    with pytest.raises(ValueError, match="cannot replace itself"):
        issuer_anchor("issuer-2026", replaces="issuer-2026")


def test_an_issuer_anchor_holding_a_certificate_is_refused() -> None:
    """Caught here, not in ``to_trust_profile`` on a machine that cannot fix it."""

    with pytest.raises(ValueError, match="must be a sha256"):
        issuer_anchor(material=PEM)


def test_a_c2pa_root_holding_a_key_id_is_refused() -> None:
    with pytest.raises(ValueError, match="must be a PEM certificate"):
        TrustAnchor(
            anchor_id="root",
            kind=AnchorKind.C2PA_ROOT,
            subject="Example Root CA",
            material=KEY_A,
            not_before=NOW,
        )


def test_a_revocation_without_an_offset_is_refused() -> None:
    with pytest.raises(ValueError, match="must include a UTC offset"):
        AnchorRevocation(anchor_id="issuer-2026", revoked_at=datetime(2026, 1, 1), reason="exposed")


def test_a_revocation_cannot_point_at_itself_as_the_replacement() -> None:
    with pytest.raises(ValueError, match="must differ from the revoked one"):
        AnchorRevocation(
            anchor_id="issuer-2026",
            revoked_at=NOW,
            reason="exposed",
            replacement_anchor_id="issuer-2026",
        )


def test_a_store_that_expires_before_it_is_issued_is_refused(keys: tuple[Path, Path]) -> None:
    with pytest.raises(ValueError, match="must expire after it is issued"):
        build_trust_store(
            organization="Example Forensics",
            issuer_key_id=public_key_id(keys[1]),
            sequence=1,
            issued_at=NOW,
            expires_at=NOW - YEAR,
        )


def test_duplicate_anchor_identifiers_are_refused(keys: tuple[Path, Path]) -> None:
    with pytest.raises(ValueError, match="must be unique"):
        build_trust_store(
            organization="Example Forensics",
            issuer_key_id=public_key_id(keys[1]),
            sequence=1,
            issued_at=NOW,
            expires_at=NOW + YEAR,
            anchors=(issuer_anchor(), issuer_anchor(material=KEY_B)),
        )


def test_an_anchor_may_be_revoked_only_once(keys: tuple[Path, Path]) -> None:
    revocation = AnchorRevocation(anchor_id="issuer-2026", revoked_at=NOW, reason="exposed")

    with pytest.raises(ValueError, match="only once in the revocations"):
        build_trust_store(
            organization="Example Forensics",
            issuer_key_id=public_key_id(keys[1]),
            sequence=1,
            issued_at=NOW,
            expires_at=NOW + YEAR,
            anchors=(issuer_anchor(),),
            revocations=(revocation, revocation),
        )


def test_a_store_time_without_an_offset_is_refused(keys: tuple[Path, Path]) -> None:
    with pytest.raises(ValueError, match="must include a UTC offset"):
        TrustStore(
            store_id="TAITS1-" + "A" * 32,
            organization="Example Forensics",
            issuer_key_id=public_key_id(keys[1]),
            sequence=1,
            issued_at=datetime(2026, 1, 1),
            expires_at=NOW + YEAR,
        )


def test_a_sequence_starts_at_one(keys: tuple[Path, Path]) -> None:
    with pytest.raises(ValueError):
        build_trust_store(
            organization="Example Forensics",
            issuer_key_id=public_key_id(keys[1]),
            sequence=0,
            issued_at=NOW,
            expires_at=NOW + YEAR,
        )


# -- reading a document off a disk it does not control -------------------------------


def test_a_round_trip_through_json_preserves_the_store(
    keys: tuple[Path, Path], tmp_path: Path
) -> None:
    original = store(keys)
    path = tmp_path / "store.json"
    path.write_text(trust_store_json(original), encoding="utf-8")

    assert load_trust_store(path) == original


def test_a_round_trip_through_json_preserves_an_update(
    keys: tuple[Path, Path], tmp_path: Path
) -> None:
    original = update(keys, from_sequence=1)
    path = tmp_path / "update.json"
    path.write_text(trust_store_update_json(original), encoding="utf-8")

    assert load_trust_store_update(path) == original


def test_an_oversized_document_is_refused_before_it_is_parsed(
    keys: tuple[Path, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "store.json"
    path.write_text(trust_store_json(store(keys)), encoding="utf-8")
    monkeypatch.setattr(trust_store_module, "MAX_TRUST_STORE_BYTES", 32)

    with pytest.raises(TrustStoreError, match="the limit is 32"):
        load_trust_store(path)


def test_a_document_that_is_not_json_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "store.json"
    path.write_text("{not json", encoding="utf-8")

    with pytest.raises(TrustStoreError, match="Unable to read"):
        load_trust_store(path)


def test_a_missing_document_is_refused_as_an_error_not_a_traceback(tmp_path: Path) -> None:
    with pytest.raises((TrustStoreError, OSError)):
        load_trust_store(tmp_path / "absent.json")


def test_a_document_of_the_wrong_shape_is_refused(keys: tuple[Path, Path], tmp_path: Path) -> None:
    path = tmp_path / "update.json"
    path.write_text(trust_store_json(store(keys)), encoding="utf-8")

    with pytest.raises(TrustStoreError, match="Invalid TrustStoreUpdate"):
        load_trust_store_update(path)


def test_more_anchors_than_the_cap_are_refused(keys: tuple[Path, Path], tmp_path: Path) -> None:
    payload = json.loads(trust_store_json(store(keys)))
    payload["anchors"] = [payload["anchors"][0]] * (trust_store_module.MAX_ANCHORS + 1)
    path = tmp_path / "store.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(TrustStoreError, match="Invalid TrustStore"):
        load_trust_store(path)
