"""Signed plugin distributions: integrity, identity, currency, compatibility.

The property that matters most is an ordering one. Reading a plugin's manifest
used to mean importing the plugin, and import time is when hostile code acts. A
signed distribution moves the manifest out of the module, so the host decides
before anything runs — and the module's bytes are covered by the same signature,
so a declared capability set cannot be contradicted by what module-level code
actually does.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from importlib.metadata import EntryPoint
from pathlib import Path

import pytest
from typer.testing import CliRunner

import trueai.plugins.host as host_module
from trueai.cli.app import app
from trueai.core.certificates import generate_ed25519_keypair
from trueai.core.registry import DetectorRegistry
from trueai.core.trust import IssuerBinding, TrustProfile, public_key_id
from trueai.plugins import (
    DistributionPolicy,
    PluginAllowlist,
    PluginCapability,
    PluginIsolation,
    PluginManifest,
    build_distribution,
    sign_distribution,
    verify_distribution,
)
from trueai.plugins.distribution import (
    DISTRIBUTION_FILENAME,
    DistributionError,
    DistributionRevocation,
    RevocationReason,
    compute_distribution_id,
    distribution_json,
    load_distribution,
    sign_allowlist,
    verify_allowlist,
)

pytest.importorskip("cryptography", reason="Signing needs the attestation extra")

runner = CliRunner()

NOW = datetime(2026, 8, 25, 12, 0, tzinfo=UTC)
REPOSITORY_ROOT = str(Path(__file__).resolve().parents[2])
EXAMPLES = "tests.plugin_examples"

MANIFEST = PluginManifest(
    detector_id="acme.invoice.v1",
    name="ACME invoice forensics",
    version="1.0",
    vendor="ACME",
    capabilities=frozenset({PluginCapability.READ_ARTIFACT}),
)


@pytest.fixture
def plugin_root(tmp_path: Path) -> Path:
    root = tmp_path / "acme_plugin"
    (root / "internal").mkdir(parents=True)
    (root / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "internal" / "helper.py").write_text("def help(): return 2\n", encoding="utf-8")
    return root


@pytest.fixture
def keys(tmp_path: Path) -> tuple[Path, Path]:
    private, public = tmp_path / "publisher.key", tmp_path / "publisher.pub"
    generate_ed25519_keypair(private, public)
    return private, public


def published(plugin_root: Path, keys: tuple[Path, Path], **extra: object):
    distribution = build_distribution(
        detector_id="acme.invoice.v1",
        version="1.0",
        entry_point=f"{EXAMPLES}:DECLARED_REGISTRATION",
        manifest=MANIFEST,
        publisher="ACME",
        root=plugin_root,
        created_at=extra.pop("created_at", NOW),  # type: ignore[arg-type]
        **extra,  # type: ignore[arg-type]
    )
    return sign_distribution(distribution, signing_key=keys[0])


# -- integrity -----------------------------------------------------------------------


def test_a_distribution_covers_every_file_not_only_the_interesting_ones(
    plugin_root: Path, keys: tuple[Path, Path]
) -> None:
    """A publisher who signs some files has signed nothing useful."""

    distribution = published(plugin_root, keys)

    paths = {item.path for item in distribution.files}
    assert paths == {"__init__.py", "internal/helper.py"}


def test_a_clean_installation_verifies(plugin_root: Path, keys: tuple[Path, Path]) -> None:
    distribution = published(plugin_root, keys)

    result = verify_distribution(distribution, root=plugin_root, public_key=keys[1], now=NOW)

    assert result.content_id_valid
    assert result.files_match is True
    assert result.signature == "valid"
    assert result.authenticated_publisher
    assert result.may_load()


def test_one_changed_byte_in_any_file_breaks_the_distribution(
    plugin_root: Path, keys: tuple[Path, Path]
) -> None:
    distribution = published(plugin_root, keys)
    (plugin_root / "internal" / "helper.py").write_text("def help(): return 3\n", encoding="utf-8")

    result = verify_distribution(distribution, root=plugin_root, public_key=keys[1], now=NOW)

    assert result.files_match is False
    assert not result.may_load()
    assert any("does not match the digest" in problem for problem in result.problems)


def test_an_extra_file_is_a_different_plugin(plugin_root: Path, keys: tuple[Path, Path]) -> None:
    """A plugin that ships an extra module is not the plugin that was signed."""

    distribution = published(plugin_root, keys)
    (plugin_root / "payload.py").write_text("import socket\n", encoding="utf-8")

    result = verify_distribution(distribution, root=plugin_root, public_key=keys[1], now=NOW)

    assert result.unlisted_files == ("payload.py",)
    assert not result.may_load()


def test_a_removed_file_is_reported_separately_from_a_changed_one(
    plugin_root: Path, keys: tuple[Path, Path]
) -> None:
    distribution = published(plugin_root, keys)
    (plugin_root / "internal" / "helper.py").unlink()

    result = verify_distribution(distribution, root=plugin_root, public_key=keys[1], now=NOW)

    assert result.missing_files == ("internal/helper.py",)
    assert result.files_match is True, "no file that is present disagrees with its digest"
    assert not result.may_load()


def test_the_distribution_document_is_not_listed_inside_itself(
    plugin_root: Path, keys: tuple[Path, Path]
) -> None:
    """The identifier is derived from the file list, so the document cannot list itself."""

    distribution = published(plugin_root, keys)
    (plugin_root / DISTRIBUTION_FILENAME).write_text(
        distribution_json(distribution) + "\n", encoding="utf-8"
    )

    result = verify_distribution(distribution, root=plugin_root, public_key=keys[1], now=NOW)

    assert DISTRIBUTION_FILENAME not in {item.path for item in distribution.files}
    assert result.unlisted_files == ()
    assert result.may_load()


def test_compiled_bytecode_is_not_treated_as_publisher_content(
    plugin_root: Path, keys: tuple[Path, Path]
) -> None:
    """Listing __pycache__ would make every distribution fail the first time it ran."""

    distribution = published(plugin_root, keys)
    cache = plugin_root / "__pycache__"
    cache.mkdir()
    (cache / "module.cpython-312.pyc").write_bytes(b"\x00\x01")

    result = verify_distribution(distribution, root=plugin_root, public_key=keys[1], now=NOW)

    assert result.unlisted_files == ()
    assert result.may_load()


def test_without_a_root_the_files_are_reported_as_unchecked(
    plugin_root: Path, keys: tuple[Path, Path]
) -> None:
    """ "Not checked" and "checked and matching" are different answers."""

    result = verify_distribution(published(plugin_root, keys), public_key=keys[1], now=NOW)

    assert result.files_match is None
    assert not result.may_load()


def test_editing_the_signed_manifest_breaks_the_identifier(
    plugin_root: Path, keys: tuple[Path, Path]
) -> None:
    """Swapping the capabilities after signing must not survive verification."""

    distribution = published(plugin_root, keys)
    widened = distribution.model_copy(
        update={
            "manifest": MANIFEST.model_copy(
                update={
                    "capabilities": frozenset(
                        {PluginCapability.READ_ARTIFACT, PluginCapability.NETWORK}
                    )
                }
            )
        }
    )

    result = verify_distribution(widened, root=plugin_root, public_key=keys[1], now=NOW)

    assert result.content_id_valid is False
    assert result.signature == "invalid"


def test_a_distribution_path_cannot_escape_its_root() -> None:
    from trueai.plugins.distribution import DistributionFile

    for path in ("../outside.py", "/etc/passwd", "C:\\Windows\\win.ini"):
        with pytest.raises(ValueError):
            DistributionFile(path=path, sha256="a" * 64, size=1)


# -- identity ------------------------------------------------------------------------


def test_an_unknown_key_verifies_the_signature_and_nothing_else(
    plugin_root: Path, keys: tuple[Path, Path]
) -> None:
    """Possession of a key is possession of a key."""

    result = verify_distribution(
        published(plugin_root, keys), root=plugin_root, public_key=keys[1], now=NOW
    )

    assert result.authenticated_publisher
    assert result.organizationally_attributed is False
    assert result.publisher_identity is not None
    assert result.publisher_identity.organization is None


def test_a_trust_profile_is_what_names_the_publisher(
    plugin_root: Path, keys: tuple[Path, Path]
) -> None:
    profile = TrustProfile(
        profile_id="acme-2026",
        issued_at=NOW - timedelta(days=1),
        bindings=(
            IssuerBinding(
                key_id=public_key_id(keys[1]),
                organization="ACME Research",
                not_before=NOW - timedelta(days=1),
                not_after=NOW + timedelta(days=365),
            ),
        ),
    )

    result = verify_distribution(
        published(plugin_root, keys),
        root=plugin_root,
        public_key=keys[1],
        trust_profile=profile,
        now=NOW,
    )

    assert result.organizationally_attributed
    assert result.publisher_identity is not None
    assert result.publisher_identity.organization == "ACME Research"


def test_a_signature_from_the_wrong_key_does_not_verify(
    plugin_root: Path, keys: tuple[Path, Path], tmp_path: Path
) -> None:
    other_private, other_public = tmp_path / "other.key", tmp_path / "other.pub"
    generate_ed25519_keypair(other_private, other_public)

    result = verify_distribution(
        published(plugin_root, keys), root=plugin_root, public_key=other_public, now=NOW
    )

    assert result.signature == "invalid"
    assert not result.authenticated_publisher


def test_no_key_means_unverified_not_invalid(plugin_root: Path, keys: tuple[Path, Path]) -> None:
    """A missing key is the verifier's gap, not a defect in the distribution."""

    result = verify_distribution(published(plugin_root, keys), root=plugin_root, now=NOW)

    assert result.signature == "unverified"
    assert not result.may_load()


def test_an_unsigned_distribution_says_so(plugin_root: Path) -> None:
    distribution = build_distribution(
        detector_id="acme.invoice.v1",
        version="1.0",
        entry_point="acme:Detector",
        manifest=MANIFEST,
        publisher="ACME",
        root=plugin_root,
        created_at=NOW,
    )

    result = verify_distribution(distribution, root=plugin_root, now=NOW)

    assert result.signature == "absent"
    assert any("unsigned" in problem for problem in result.problems)


def test_signing_a_stale_document_is_refused(plugin_root: Path, keys: tuple[Path, Path]) -> None:
    """A signature over a document whose identifier no longer matches is a trap."""

    distribution = build_distribution(
        detector_id="acme.invoice.v1",
        version="1.0",
        entry_point="acme:Detector",
        manifest=MANIFEST,
        publisher="ACME",
        root=plugin_root,
        created_at=NOW,
    )
    stale = distribution.model_copy(update={"version": "2.0"})

    with pytest.raises(DistributionError, match="rebuild it before signing"):
        sign_distribution(stale, signing_key=keys[0])


# -- currency ------------------------------------------------------------------------


def test_a_withdrawn_distribution_is_reported_with_its_reason(
    plugin_root: Path, keys: tuple[Path, Path]
) -> None:
    distribution = published(plugin_root, keys)
    allowlist = PluginAllowlist(
        organization="ACME",
        issuer_key_id=public_key_id(keys[1]),
        sequence=3,
        issued_at=NOW - timedelta(days=1),
        expires_at=NOW + timedelta(days=30),
        allowed_distribution_ids=frozenset({distribution.distribution_id}),
        revocations=(
            DistributionRevocation(
                distribution_id=distribution.distribution_id,
                revoked_at=NOW - timedelta(hours=1),
                reason=RevocationReason(
                    code="vulnerable", statement="Version 1.0 mishandles nested archives."
                ),
            ),
        ),
    )

    result = verify_distribution(
        distribution, root=plugin_root, public_key=keys[1], allowlist=allowlist, now=NOW
    )

    assert result.revoked
    assert result.revocation_reason is not None
    assert "nested archives" in result.revocation_reason.statement
    assert not result.may_load()


def test_a_future_dated_revocation_does_not_apply_yet(
    plugin_root: Path, keys: tuple[Path, Path]
) -> None:
    distribution = published(plugin_root, keys)
    allowlist = PluginAllowlist(
        organization="ACME",
        issuer_key_id=public_key_id(keys[1]),
        sequence=1,
        issued_at=NOW - timedelta(days=1),
        expires_at=NOW + timedelta(days=30),
        allowed_distribution_ids=frozenset({distribution.distribution_id}),
        revocations=(
            DistributionRevocation(
                distribution_id=distribution.distribution_id,
                revoked_at=NOW + timedelta(days=1),
                reason=RevocationReason(code="planned", statement="Scheduled withdrawal."),
            ),
        ),
    )

    result = verify_distribution(
        distribution, root=plugin_root, public_key=keys[1], allowlist=allowlist, now=NOW
    )

    assert not result.revoked
    assert result.may_load()


def test_a_distribution_not_on_the_allowlist_is_refused(
    plugin_root: Path, keys: tuple[Path, Path]
) -> None:
    distribution = published(plugin_root, keys)
    allowlist = PluginAllowlist(
        organization="ACME",
        issuer_key_id=public_key_id(keys[1]),
        sequence=1,
        issued_at=NOW - timedelta(days=1),
        expires_at=NOW + timedelta(days=30),
    )

    result = verify_distribution(
        distribution, root=plugin_root, public_key=keys[1], allowlist=allowlist, now=NOW
    )

    assert result.allowlisted is False
    assert not result.may_load()


def test_trusting_a_publisher_key_admits_its_distributions(
    plugin_root: Path, keys: tuple[Path, Path]
) -> None:
    """An operator may trust a vendor rather than an individual build."""

    distribution = published(plugin_root, keys)
    allowlist = PluginAllowlist(
        organization="ACME",
        issuer_key_id=public_key_id(keys[1]),
        sequence=1,
        issued_at=NOW - timedelta(days=1),
        expires_at=NOW + timedelta(days=30),
        allowed_publisher_key_ids=frozenset({public_key_id(keys[1])}),
    )

    result = verify_distribution(
        distribution, root=plugin_root, public_key=keys[1], allowlist=allowlist, now=NOW
    )

    assert result.allowlisted is True
    assert result.may_load()


def test_an_older_allowlist_is_detected_as_a_rollback(keys: tuple[Path, Path]) -> None:
    """An allowlist replaceable by an older copy allows whatever the older copy allowed."""

    allowlist = sign_allowlist(
        PluginAllowlist(
            organization="ACME",
            issuer_key_id=public_key_id(keys[1]),
            sequence=4,
            issued_at=NOW - timedelta(days=1),
            expires_at=NOW + timedelta(days=30),
        ),
        signing_key=keys[0],
    )

    fresh, problems = verify_allowlist(allowlist, public_key=keys[1], known_sequence=4, now=NOW)
    stale, stale_problems = verify_allowlist(
        allowlist, public_key=keys[1], known_sequence=9, now=NOW
    )

    assert fresh and not problems
    assert not stale
    assert any("rollback" in item for item in stale_problems)


def test_an_expired_allowlist_is_refused(keys: tuple[Path, Path]) -> None:
    allowlist = sign_allowlist(
        PluginAllowlist(
            organization="ACME",
            issuer_key_id=public_key_id(keys[1]),
            sequence=1,
            issued_at=NOW - timedelta(days=60),
            expires_at=NOW - timedelta(days=1),
        ),
        signing_key=keys[0],
    )

    valid, problems = verify_allowlist(allowlist, public_key=keys[1], now=NOW)

    assert not valid
    assert any("expired" in item for item in problems)


def test_an_expired_distribution_cannot_load(plugin_root: Path, keys: tuple[Path, Path]) -> None:
    distribution = published(
        plugin_root,
        keys,
        created_at=NOW - timedelta(days=30),
        expires_at=NOW - timedelta(days=1),
    )

    result = verify_distribution(distribution, root=plugin_root, public_key=keys[1], now=NOW)

    assert result.expired
    assert not result.may_load()


# -- compatibility -------------------------------------------------------------------


def test_a_core_version_outside_the_declared_range_is_refused(
    plugin_root: Path, keys: tuple[Path, Path]
) -> None:
    distribution = published(plugin_root, keys, minimum_core_version="9.0")

    result = verify_distribution(
        distribution, root=plugin_root, public_key=keys[1], now=NOW, core_version="0.1.0-dev"
    )

    assert result.core_compatible is False
    assert not result.may_load()


def test_versions_compare_numerically_not_as_text(
    plugin_root: Path, keys: tuple[Path, Path]
) -> None:
    """0.10 is newer than 0.9, and a string comparison says otherwise."""

    distribution = published(plugin_root, keys, minimum_core_version="0.9")

    result = verify_distribution(
        distribution, root=plugin_root, public_key=keys[1], now=NOW, core_version="0.10"
    )

    assert result.core_compatible is True


def test_an_unsupported_report_schema_is_refused(
    plugin_root: Path, keys: tuple[Path, Path]
) -> None:
    distribution = published(plugin_root, keys, compatible_schema_versions=frozenset({"9.9"}))

    result = verify_distribution(distribution, root=plugin_root, public_key=keys[1], now=NOW)

    assert result.schema_compatible is False
    assert not result.may_load()


# -- the host decides before importing -----------------------------------------------


def test_a_signed_manifest_removes_the_need_to_import_the_plugin(
    plugin_root: Path, keys: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The manifest comes from the signature, so the module never has to run."""

    distribution = published(plugin_root, keys)
    policy = DistributionPolicy(
        require_signed=True,
        distributions=(distribution,),
        publisher_keys={public_key_id(keys[1]): str(keys[1])},
        install_roots={"acme.invoice.v1": str(plugin_root)},
    )

    decision = policy.evaluate(f"{EXAMPLES}:DECLARED_REGISTRATION", now=NOW)

    assert decision.allowed
    assert decision.manifest is not None
    assert decision.manifest.capabilities == frozenset({PluginCapability.READ_ARTIFACT})


def test_requiring_a_signature_refuses_a_plugin_that_has_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = DistributionPolicy(require_signed=True)

    decision = policy.evaluate("some.module:Detector", now=NOW)

    assert not decision.allowed
    assert "requires a signed distribution" in decision.reason


def test_without_the_requirement_an_unsigned_plugin_still_loads() -> None:
    """Useful during a rollout, and not a control. The docstring says which."""

    decision = DistributionPolicy().evaluate("some.module:Detector", now=NOW)

    assert decision.allowed
    assert decision.manifest is None


def test_the_host_refuses_a_tampered_plugin_without_importing_it(
    plugin_root: Path, keys: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    distribution = published(plugin_root, keys)
    (plugin_root / "payload.py").write_text("raise SystemExit(1)\n", encoding="utf-8")
    point = EntryPoint(
        name="acme",
        value=f"{EXAMPLES}:DECLARED_REGISTRATION",
        group=host_module.ENTRY_POINT_GROUP,
    )
    monkeypatch.setattr(host_module, "entry_points", lambda *, group: [point])

    registry = DetectorRegistry()
    registry.discover(
        isolation=PluginIsolation.SUBPROCESS,
        timeout=60.0,
        search_path=(REPOSITORY_ROOT,),
        distribution_policy=DistributionPolicy(
            require_signed=True,
            distributions=(distribution,),
            publisher_keys={public_key_id(keys[1]): str(keys[1])},
            install_roots={"acme.invoice.v1": str(plugin_root)},
        ),
    )

    rejections = registry.plugin_discovery.rejections
    assert rejections, "a tampered distribution must be refused"
    assert "does not list" in rejections[0].reason


def test_a_verified_distribution_lets_the_plugin_run(
    plugin_root: Path, keys: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The refusal path must not be the only path that works."""

    distribution = published(plugin_root, keys)
    point = EntryPoint(
        name="acme",
        value=f"{EXAMPLES}:DECLARED_REGISTRATION",
        group=host_module.ENTRY_POINT_GROUP,
    )
    monkeypatch.setattr(host_module, "entry_points", lambda *, group: [point])

    registry = DetectorRegistry()
    registry.discover(
        isolation=PluginIsolation.SUBPROCESS,
        timeout=60.0,
        search_path=(REPOSITORY_ROOT,),
        distribution_policy=DistributionPolicy(
            require_signed=True,
            distributions=(distribution,),
            publisher_keys={public_key_id(keys[1]): str(keys[1])},
            install_roots={"acme.invoice.v1": str(plugin_root)},
        ),
    )

    assert registry.plugin_discovery.rejections == ()
    assert "acme.invoice.v1" in [getattr(detector, "id", "") for detector in registry.detectors()]


# -- the CLI -------------------------------------------------------------------------


def test_the_cli_signs_and_verifies_a_distribution(
    plugin_root: Path, keys: tuple[Path, Path]
) -> None:
    signed = runner.invoke(
        app,
        [
            "plugins",
            "sign",
            str(plugin_root),
            "--detector-id",
            "acme.invoice.v1",
            "--version",
            "1.0",
            "--entry-point",
            "acme_plugin:Detector",
            "--publisher",
            "ACME",
            "--signing-key",
            str(keys[0]),
            "--capability",
            "read_artifact",
        ],
    )
    assert signed.exit_code == 0, signed.output

    verified = runner.invoke(
        app,
        [
            "plugins",
            "verify",
            str(plugin_root / DISTRIBUTION_FILENAME),
            "--root",
            str(plugin_root),
            "--public-key",
            str(keys[1]),
        ],
    )

    assert verified.exit_code == 0, verified.output
    assert "may be loaded" in verified.output


def test_the_cli_reports_a_tampered_installation(
    plugin_root: Path, keys: tuple[Path, Path]
) -> None:
    runner.invoke(
        app,
        [
            "plugins",
            "sign",
            str(plugin_root),
            "--detector-id",
            "acme.invoice.v1",
            "--version",
            "1.0",
            "--entry-point",
            "acme_plugin:Detector",
            "--publisher",
            "ACME",
            "--signing-key",
            str(keys[0]),
        ],
    )
    (plugin_root / "__init__.py").write_text("VALUE = 2\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "plugins",
            "verify",
            str(plugin_root / DISTRIBUTION_FILENAME),
            "--root",
            str(plugin_root),
            "--public-key",
            str(keys[1]),
        ],
    )

    assert result.exit_code == 1
    assert "will not be loaded" in result.output


def test_the_cli_emits_machine_readable_verification(
    plugin_root: Path, keys: tuple[Path, Path]
) -> None:
    distribution = published(plugin_root, keys)
    path = plugin_root.parent / "dist.json"
    path.write_text(distribution_json(distribution) + "\n", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "plugins",
            "verify",
            str(path),
            "--root",
            str(plugin_root),
            "--public-key",
            str(keys[1]),
            "--format",
            "json",
        ],
    )

    payload = json.loads(result.stdout)
    assert payload["signature"] == "valid"
    assert payload["files_match"] is True
    assert "may_load" not in payload, (
        "the derived convenience is presentation, not a field consumers should key on"
    )


def test_the_cli_publishes_a_signed_allowlist(tmp_path: Path, keys: tuple[Path, Path]) -> None:
    destination = tmp_path / "allowlist.json"

    result = runner.invoke(
        app,
        [
            "plugins",
            "allowlist",
            str(destination),
            "--organization",
            "ACME",
            "--signing-key",
            str(keys[0]),
            "--sequence",
            "7",
            "--allow-publisher-key",
            public_key_id(keys[1]),
        ],
    )

    assert result.exit_code == 0, result.output
    from trueai.plugins.distribution import load_allowlist

    allowlist = load_allowlist(destination)
    assert allowlist.sequence == 7
    assert verify_allowlist(allowlist, public_key=keys[1])[0]


def test_a_distribution_document_round_trips(
    plugin_root: Path, keys: tuple[Path, Path], tmp_path: Path
) -> None:
    distribution = published(plugin_root, keys)
    path = tmp_path / "dist.json"
    path.write_text(distribution_json(distribution) + "\n", encoding="utf-8")

    reloaded = load_distribution(path)

    assert reloaded == distribution
    assert compute_distribution_id(reloaded) == reloaded.distribution_id
