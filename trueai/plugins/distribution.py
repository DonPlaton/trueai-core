"""Signed plugin distributions: who published this, and is it still what they signed.

Everything before this module decides what a plugin may *do*. This decides
whether it should be loaded at all, and the difference matters because of one
ordering problem: reading a plugin's manifest currently means importing the
plugin, and import time is when hostile code acts. A capability decision made
after the module ran is a decision made too late.

A signed distribution moves the manifest out of the module. The capabilities, the
detector id, and the digest of every file are in a document the publisher signed,
so the host can decide before anything is imported — and a publisher cannot
declare `read_artifact` in a signed manifest and open a socket from module level,
because the module's bytes are covered by the same signature.

Four questions, kept apart because collapsing them is how "signed" comes to mean
"safe":

* **Integrity** — do the files on disk still hash to what was signed?
* **Identity** — whose key signed it, and does a trust profile say who owns that
  key? Possession of a key is possession of a key.
* **Currency** — has the publisher withdrawn this version, and is the withdrawal
  list the current one rather than a convenient older copy?
* **Compatibility** — was it built for this core and this report schema?

Each is reported separately. A distribution can be perfectly signed by an unknown
key, or correctly signed by a known publisher and revoked an hour ago, and an
operator needs to be able to tell those apart.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, model_validator

from trueai._version import PACKAGE_VERSION, SCHEMA_VERSION
from trueai.core.certificates import (
    CertificateSignature,
    canonical_json_bytes,
    verify_detached_payload,
)
from trueai.core.errors import DetectorRegistrationError
from trueai.core.models import FrozenModel
from trueai.core.trust import (
    IdentityAssurance,
    IdentityResult,
    SigningProvider,
    TrustProfile,
    resolve_identity,
)
from trueai.plugins.manifest import PluginManifest

DISTRIBUTION_SCHEMA_VERSION: Literal["0.1"] = "0.1"

#: Distributions get their own prefix. An audit certificate, a process
#: attestation, and a plugin distribution are three different statements, and a
#: shared prefix would invite one to be presented as another.
DISTRIBUTION_ID_PREFIX = "TAIPKG1-"

#: Where a distribution document conventionally sits, beside the code it covers.
#: It is excluded from its own file list for the obvious reason: the list is part
#: of what the identifier is derived from, so a document cannot contain its own
#: digest. Leaving it in would make every distribution report an unlisted file.
DISTRIBUTION_FILENAME = "trueai-distribution.json"

#: A distribution document larger than this is refused before it is parsed.
MAX_DISTRIBUTION_BYTES = 4 * 1024 * 1024

#: No realistic plugin ships more files than this, and an unbounded list is a
#: cheap way to make a verifier hash for a very long time.
MAX_DISTRIBUTION_FILES = 4096


class DistributionError(DetectorRegistrationError):
    """Raised when a distribution document cannot be read or built."""


class RevocationReason(FrozenModel):
    """Why a publisher withdrew a version, in machine and human form."""

    code: str = Field(min_length=1, max_length=60)
    statement: str = Field(min_length=1, max_length=500)


class DistributionFile(FrozenModel):
    """One file the publisher signed, by relative path and digest."""

    path: str = Field(min_length=1, max_length=1000)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size: int = Field(ge=0)

    @model_validator(mode="after")
    def reject_paths_that_escape(self) -> Self:
        """A distribution describes files inside itself and nowhere else."""

        if self.path.startswith(("/", "\\")) or ":" in self.path:
            raise ValueError(f"Distribution paths must be relative: {self.path!r}")
        parts = self.path.replace("\\", "/").split("/")
        if ".." in parts:
            raise ValueError(f"Distribution paths must not traverse upwards: {self.path!r}")
        return self


class PluginDistribution(FrozenModel):
    """A publisher's signed statement about one version of one plugin."""

    distribution_id: str = Field(pattern=r"^TAIPKG1-[A-Z2-7]{32}$")
    schema_version: Literal["0.1"] = DISTRIBUTION_SCHEMA_VERSION
    detector_id: str = Field(min_length=3, max_length=120)
    version: str = Field(min_length=1, max_length=40)
    entry_point: str = Field(min_length=3, max_length=300)

    #: The capabilities the publisher signed. This is the copy the host decides
    #: on; the one inside the module is never consulted when a distribution is in
    #: force, because reading it would mean importing the module.
    manifest: PluginManifest

    publisher: str = Field(min_length=1, max_length=200)
    publisher_id: str | None = Field(default=None, max_length=300)

    files: tuple[DistributionFile, ...] = Field(default=(), max_length=MAX_DISTRIBUTION_FILES)

    created_at: datetime
    expires_at: datetime | None = None
    minimum_core_version: str | None = Field(default=None, max_length=40)
    maximum_core_version: str | None = Field(default=None, max_length=40)
    compatible_schema_versions: frozenset[str] = frozenset({SCHEMA_VERSION})

    signature: CertificateSignature | None = None

    @model_validator(mode="after")
    def validate_document(self) -> Self:
        for label, value in (("creation", self.created_at), ("expiry", self.expires_at)):
            if value is not None and (value.tzinfo is None or value.utcoffset() is None):
                raise ValueError(f"Distribution {label} time must include a UTC offset")
        if self.expires_at is not None and self.expires_at <= self.created_at:
            raise ValueError("Distribution expiry must be later than its creation time")
        if self.manifest.detector_id != self.detector_id:
            raise ValueError(
                f"The signed manifest declares {self.manifest.detector_id!r} but the "
                f"distribution is for {self.detector_id!r}"
            )
        paths = tuple(item.path for item in self.files)
        if paths != tuple(sorted(paths)):
            raise ValueError("Distribution files must be sorted by path")
        if len(set(paths)) != len(paths):
            raise ValueError("A file may appear only once in a distribution")
        return self

    def is_expired(self, now: datetime | None = None) -> bool:
        """Return whether the distribution has passed its stated validity window."""

        if self.expires_at is None:
            return False
        return (now or datetime.now(UTC)) > self.expires_at


class DistributionRevocation(FrozenModel):
    """One withdrawn distribution, named by its content identifier."""

    distribution_id: str = Field(pattern=r"^TAIPKG1-[A-Z2-7]{32}$")
    revoked_at: datetime
    reason: RevocationReason
    replacement_distribution_id: str | None = Field(default=None, pattern=r"^TAIPKG1-[A-Z2-7]{32}$")

    @model_validator(mode="after")
    def validate_entry(self) -> Self:
        if self.revoked_at.tzinfo is None or self.revoked_at.utcoffset() is None:
            raise ValueError("Revocation time must include a UTC offset")
        if self.replacement_distribution_id == self.distribution_id:
            raise ValueError("A replacement distribution must have a different identifier")
        return self


class PluginAllowlist(FrozenModel):
    """What an organization has decided about third-party plugins.

    Sequenced and finite-lifetime for the same reason a revocation list is: an
    allowlist that can be replaced with an older copy allows whatever the older
    copy allowed. Comparing ``sequence`` against the last one a verifier saw is
    what turns "this is signed" into "this is current".
    """

    schema_version: Literal["0.1"] = DISTRIBUTION_SCHEMA_VERSION
    organization: str = Field(min_length=1, max_length=200)
    issuer_key_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    sequence: int = Field(ge=1)
    issued_at: datetime
    expires_at: datetime

    #: Distribution identifiers this organization permits. Empty means the
    #: allowlist permits nothing, which is a deliberate state and not an oversight.
    allowed_distribution_ids: frozenset[str] = frozenset()
    #: Publisher key identifiers whose distributions are permitted without being
    #: named individually. An operator who trusts a vendor rather than a build.
    allowed_publisher_key_ids: frozenset[str] = frozenset()
    revocations: tuple[DistributionRevocation, ...] = Field(default=(), max_length=4096)

    signature: CertificateSignature | None = None

    @model_validator(mode="after")
    def validate_list(self) -> Self:
        for label, value in (("issue", self.issued_at), ("expiry", self.expires_at)):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"Allowlist {label} time must include a UTC offset")
        if self.expires_at <= self.issued_at:
            raise ValueError("Allowlist expiry must be later than its issue time")
        identifiers = tuple(item.distribution_id for item in self.revocations)
        if identifiers != tuple(sorted(identifiers)):
            raise ValueError("Revocations must be sorted by distribution identifier")
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("A distribution may appear only once in the revocations")
        return self

    def revocation_for(self, distribution_id: str) -> DistributionRevocation | None:
        """Return the withdrawal record for a distribution, if there is one."""

        return next(
            (item for item in self.revocations if item.distribution_id == distribution_id),
            None,
        )

    def signed_payload(self) -> bytes:
        """Return the canonical bytes the allowlist signature covers."""

        return canonical_json_bytes(self.model_dump(mode="json", exclude={"signature"}))


class DistributionVerification(FrozenModel):
    """Every independent property, reported separately.

    There is no ``valid`` field on purpose. "Signed by an unknown key" and
    "signed by a known publisher and revoked yesterday" are different situations,
    and a single boolean would make them look the same.
    """

    distribution_id: str
    content_id_valid: bool
    #: ``None`` when no files were checked because no root was supplied.
    files_match: bool | None = None
    #: Files present in the plugin directory that the distribution does not list.
    #: A plugin that ships an extra module is a different plugin.
    unlisted_files: tuple[str, ...] = ()
    #: Files the distribution lists that are not on disk.
    missing_files: tuple[str, ...] = ()
    signature: Literal["valid", "invalid", "unverified", "absent", "error"] = "absent"
    publisher_identity: IdentityResult | None = None
    expired: bool = False
    revoked: bool = False
    revocation_reason: RevocationReason | None = None
    allowlisted: bool | None = None
    core_compatible: bool = True
    schema_compatible: bool = True
    problems: tuple[str, ...] = ()

    @property
    def authenticated_publisher(self) -> bool:
        """Whether an identified publisher signed these exact bytes and files.

        Deliberately not called "trusted". It says a signature verified over
        content that still matches, and nothing about whether the publisher
        should be believed.
        """

        return (
            self.content_id_valid
            and self.signature == "valid"
            and self.files_match is not False
            and not self.expired
            and not self.revoked
        )

    @property
    def organizationally_attributed(self) -> bool:
        """Whether a configured trust profile names the publisher's organization."""

        return (
            self.authenticated_publisher
            and self.publisher_identity is not None
            and self.publisher_identity.assurance != IdentityAssurance.KEY_ONLY
        )

    def may_load(self) -> bool:
        """Whether every check a host requires before import came back clean.

        A convenience for the host, not a summary for a human: the properties
        above are what a report shows.
        """

        return (
            self.authenticated_publisher
            and self.files_match is True
            and not self.unlisted_files
            and not self.missing_files
            and self.core_compatible
            and self.schema_compatible
            and self.allowlisted is not False
        )


# -- building ------------------------------------------------------------------------


def describe_files(root: Path, *, ignore: tuple[str, ...] = ()) -> tuple[DistributionFile, ...]:
    """Hash every file under ``root`` for inclusion in a distribution.

    Everything is listed. A publisher who signs only the interesting files has
    signed nothing useful, because the uninteresting ones are where an attacker
    would put the payload.
    """

    resolved = root.resolve()
    described: list[DistributionFile] = []
    for path in sorted(resolved.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(resolved).as_posix()
        if _excluded(relative, ignore):
            continue
        payload = path.read_bytes()
        described.append(
            DistributionFile(
                path=relative,
                sha256=hashlib.sha256(payload).hexdigest(),
                size=len(payload),
            )
        )
    if len(described) > MAX_DISTRIBUTION_FILES:
        raise DistributionError(
            f"{root} contains {len(described)} files; the limit is {MAX_DISTRIBUTION_FILES}"
        )
    return tuple(described)


def _excluded(relative: str, ignore: tuple[str, ...] = ()) -> bool:
    """Return whether a path is outside what a publisher signs.

    Compiled bytecode is produced by the interpreter, not shipped, and the
    distribution document cannot list itself.
    """

    if relative == DISTRIBUTION_FILENAME:
        return True
    if relative.startswith("__pycache__") or "/__pycache__/" in relative:
        return True
    return any(relative.startswith(prefix) for prefix in ignore)


def compute_distribution_id(distribution: PluginDistribution) -> str:
    """Derive the identifier from everything the distribution claims."""

    payload = distribution.model_dump(mode="json", exclude={"distribution_id", "signature"})
    digest = hashlib.sha256(canonical_json_bytes(payload)).digest()
    return DISTRIBUTION_ID_PREFIX + base64.b32encode(digest)[:32].decode("ascii")


def build_distribution(
    *,
    detector_id: str,
    version: str,
    entry_point: str,
    manifest: PluginManifest,
    publisher: str,
    root: Path,
    publisher_id: str | None = None,
    ignore: tuple[str, ...] = ("__pycache__",),
    created_at: datetime | None = None,
    expires_at: datetime | None = None,
    minimum_core_version: str | None = None,
    maximum_core_version: str | None = None,
    compatible_schema_versions: frozenset[str] | None = None,
) -> PluginDistribution:
    """Build an unsigned, content-addressed distribution over a plugin directory."""

    draft = PluginDistribution(
        distribution_id=DISTRIBUTION_ID_PREFIX + "A" * 32,
        detector_id=detector_id,
        version=version,
        entry_point=entry_point,
        manifest=manifest,
        publisher=publisher,
        publisher_id=publisher_id,
        files=describe_files(root, ignore=ignore),
        created_at=created_at or datetime.now(UTC),
        expires_at=expires_at,
        minimum_core_version=minimum_core_version,
        maximum_core_version=maximum_core_version,
        compatible_schema_versions=compatible_schema_versions or frozenset({SCHEMA_VERSION}),
    )
    return draft.model_copy(update={"distribution_id": compute_distribution_id(draft)})


def distribution_payload(distribution: PluginDistribution) -> bytes:
    """Return the canonical bytes the publisher's signature covers."""

    return canonical_json_bytes(distribution.model_dump(mode="json", exclude={"signature"}))


def sign_distribution(
    distribution: PluginDistribution,
    *,
    signing_key: str | Path | None = None,
    provider: SigningProvider | None = None,
) -> PluginDistribution:
    """Sign a distribution with a local key or through a signing provider."""

    if (signing_key is None) == (provider is None):
        raise DistributionError("Pass exactly one of signing_key or provider")
    if compute_distribution_id(distribution) != distribution.distribution_id:
        raise DistributionError(
            "The distribution identifier does not match its contents; rebuild it before signing"
        )
    payload = distribution_payload(distribution)
    if provider is not None:
        signature = provider.sign(payload)
    else:
        from trueai.core.certificates import sign_detached_payload

        assert signing_key is not None
        signature = sign_detached_payload(payload, signing_key)
    return distribution.model_copy(update={"signature": signature})


def sign_allowlist(
    allowlist: PluginAllowlist,
    *,
    signing_key: str | Path | None = None,
    provider: SigningProvider | None = None,
) -> PluginAllowlist:
    """Sign an organization's allowlist."""

    if (signing_key is None) == (provider is None):
        raise DistributionError("Pass exactly one of signing_key or provider")
    payload = allowlist.signed_payload()
    if provider is not None:
        signature = provider.sign(payload)
    else:
        from trueai.core.certificates import sign_detached_payload

        assert signing_key is not None
        signature = sign_detached_payload(payload, signing_key)
    return allowlist.model_copy(update={"signature": signature})


# -- verification --------------------------------------------------------------------


def verify_distribution(
    distribution: PluginDistribution,
    *,
    root: Path | None = None,
    public_key: str | Path | None = None,
    trust_profile: TrustProfile | None = None,
    trust_root_public_key: str | Path | None = None,
    allowlist: PluginAllowlist | None = None,
    now: datetime | None = None,
    core_version: str = PACKAGE_VERSION,
    schema_version: str = SCHEMA_VERSION,
) -> DistributionVerification:
    """Check every independent property of a distribution and report them apart.

    ``root`` is the directory the plugin was installed into. Without it the file
    digests are not checked and ``files_match`` stays ``None``, because "not
    checked" and "checked and matching" are different answers.
    """

    problems: list[str] = []
    moment = now or datetime.now(UTC)

    content_id_valid = compute_distribution_id(distribution) == distribution.distribution_id
    if not content_id_valid:
        problems.append("The distribution identifier does not match its own contents")

    signature_status: Literal["valid", "invalid", "unverified", "absent", "error"] = "absent"
    if distribution.signature is None:
        problems.append("The distribution is unsigned")
    elif public_key is None:
        signature_status = "unverified"
    else:
        try:
            valid = verify_detached_payload(
                distribution.signature, distribution_payload(distribution), public_key
            )
        except Exception as exc:  # the key is caller-supplied and may be anything
            signature_status = "error"
            problems.append(f"The publisher signature could not be checked: {exc}")
        else:
            signature_status = "valid" if valid else "invalid"
            if not valid:
                problems.append("The publisher signature does not verify")

    files_match: bool | None = None
    unlisted: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()
    if root is not None:
        files_match, unlisted, missing = _check_files(distribution, root)
        if not files_match:
            problems.append("A file on disk does not match the digest the publisher signed")
        if unlisted:
            problems.append(
                f"{len(unlisted)} file(s) are present that the distribution does not list"
            )
        if missing:
            problems.append(f"{len(missing)} signed file(s) are missing from the installation")

    expired = distribution.is_expired(moment)
    if expired:
        problems.append("The distribution has passed its stated validity window")

    identity: IdentityResult | None = None
    if signature_status == "valid" and distribution.signature is not None:
        identity = resolve_identity(
            distribution.signature.key_id,
            profile=trust_profile,
            root_public_key=trust_root_public_key,
            moment=moment,
        )

    revoked = False
    reason: RevocationReason | None = None
    allowlisted: bool | None = None
    if allowlist is not None:
        record = allowlist.revocation_for(distribution.distribution_id)
        if record is not None and record.revoked_at <= moment:
            revoked = True
            reason = record.reason
            problems.append(f"The publisher withdrew this distribution: {record.reason.statement}")
        key_id = distribution.signature.key_id if distribution.signature else ""
        allowlisted = distribution.distribution_id in allowlist.allowed_distribution_ids or (
            bool(key_id) and key_id in allowlist.allowed_publisher_key_ids
        )
        if not allowlisted:
            problems.append(
                f"Neither this distribution nor its publisher key is on {allowlist.organization}'s "
                "allowlist"
            )

    core_compatible = _version_in_range(
        core_version, distribution.minimum_core_version, distribution.maximum_core_version
    )
    if not core_compatible:
        problems.append(
            f"The distribution declares core {distribution.minimum_core_version or '*'}.."
            f"{distribution.maximum_core_version or '*'}, and this core is {core_version}"
        )
    schema_compatible = schema_version in distribution.compatible_schema_versions
    if not schema_compatible:
        declared = ", ".join(sorted(distribution.compatible_schema_versions)) or "none"
        problems.append(
            f"The distribution declares schema compatibility with {declared}, but this host "
            f"emits schema {schema_version}"
        )

    return DistributionVerification(
        distribution_id=distribution.distribution_id,
        content_id_valid=content_id_valid,
        files_match=files_match,
        unlisted_files=unlisted,
        missing_files=missing,
        signature=signature_status,
        publisher_identity=identity,
        expired=expired,
        revoked=revoked,
        revocation_reason=reason,
        allowlisted=allowlisted,
        core_compatible=core_compatible,
        schema_compatible=schema_compatible,
        problems=tuple(problems),
    )


def _check_files(
    distribution: PluginDistribution, root: Path
) -> tuple[bool, tuple[str, ...], tuple[str, ...]]:
    """Compare the installation against what the publisher signed."""

    resolved = root.resolve()
    signed = {item.path: item for item in distribution.files}
    present: set[str] = set()
    matched = True
    for path in sorted(resolved.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(resolved).as_posix()
        if _excluded(relative):
            continue
        present.add(relative)
        record = signed.get(relative)
        if record is None:
            continue
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != record.sha256:
            matched = False
    unlisted = tuple(sorted(present - set(signed)))
    missing = tuple(sorted(set(signed) - present))
    return matched, unlisted, missing


def verify_allowlist(
    allowlist: PluginAllowlist,
    *,
    public_key: str | Path,
    known_sequence: int | None = None,
    now: datetime | None = None,
) -> tuple[bool, tuple[str, ...]]:
    """Check an allowlist's signature, lifetime, and sequence.

    ``known_sequence`` is the highest sequence this verifier has seen before. An
    allowlist that can be replaced with an older copy allows whatever the older
    copy allowed, and a verifier with no memory cannot notice, so the API asks
    for the memory rather than pretending it is unnecessary.
    """

    problems: list[str] = []
    moment = now or datetime.now(UTC)

    if allowlist.signature is None:
        return False, ("The allowlist is unsigned",)
    try:
        verified = verify_detached_payload(
            allowlist.signature, allowlist.signed_payload(), public_key
        )
    except Exception as exc:
        return False, (f"The allowlist signature could not be checked: {exc}",)
    if not verified:
        problems.append("The allowlist signature does not verify")
    if moment > allowlist.expires_at:
        problems.append("The allowlist has expired")
    if moment < allowlist.issued_at:
        problems.append("The allowlist is not yet in force")
    if known_sequence is not None and allowlist.sequence < known_sequence:
        problems.append(
            f"This allowlist is sequence {allowlist.sequence}; a verifier already saw "
            f"{known_sequence}. An older copy is a rollback."
        )
    return not problems, tuple(problems)


# -- host policy ---------------------------------------------------------------------


class DistributionDecision(FrozenModel):
    """Whether a plugin may be loaded, and the verification that decided it."""

    entry_point: str
    allowed: bool
    reason: str
    #: The manifest to use. Present only when a signed distribution supplied one,
    #: which is the case where the host never has to import the module to find out.
    manifest: PluginManifest | None = None
    verification: DistributionVerification | None = None


class DistributionPolicy(FrozenModel):
    """An operator's decision about which published plugins may be installed.

    ``require_signed`` is the posture that makes the rest matter. Without it a
    signed distribution is checked when present and absent otherwise, which is
    useful during a rollout and is not a control. With it, an unsigned plugin does
    not run — and, more importantly, is never imported, so the decision happens
    before the module gets to execute anything.
    """

    model_config = FrozenModel.model_config | {"arbitrary_types_allowed": True}

    require_signed: bool = False
    distributions: tuple[PluginDistribution, ...] = ()
    #: ``key_id`` to public-key path. Keyed by identifier rather than by publisher
    #: name so a renamed publisher cannot inherit another's key.
    publisher_keys: dict[str, str] = Field(default_factory=dict)
    #: ``detector_id`` to the directory the plugin was installed into, so the
    #: file digests can be checked against what is actually on disk.
    install_roots: dict[str, str] = Field(default_factory=dict)
    allowlist: PluginAllowlist | None = None
    trust_profile: TrustProfile | None = None
    trust_root_public_key: str | None = None
    #: The highest allowlist sequence this host has seen. Without it a rollback to
    #: an older allowlist is undetectable, and the API asks rather than pretending.
    known_allowlist_sequence: int | None = None

    def distribution_for(self, entry_point: str) -> PluginDistribution | None:
        """Return the distribution published for an entry point, if any."""

        return next((item for item in self.distributions if item.entry_point == entry_point), None)

    def evaluate(
        self,
        entry_point: str,
        *,
        now: datetime | None = None,
        core_version: str = PACKAGE_VERSION,
        schema_version: str = SCHEMA_VERSION,
    ) -> DistributionDecision:
        """Decide whether an entry point may be loaded, without importing it."""

        published = self.distribution_for(entry_point)
        if published is None:
            if self.require_signed:
                return DistributionDecision(
                    entry_point=entry_point,
                    allowed=False,
                    reason=(
                        "The host requires a signed distribution and none was supplied for "
                        "this entry point."
                    ),
                )
            return DistributionDecision(
                entry_point=entry_point,
                allowed=True,
                reason="No signed distribution was supplied, and the host does not require one.",
            )

        key_id = published.signature.key_id if published.signature else None
        public_key = self.publisher_keys.get(key_id or "")
        root = self.install_roots.get(published.detector_id)
        verification = verify_distribution(
            published,
            root=Path(root) if root else None,
            public_key=public_key,
            trust_profile=self.trust_profile,
            trust_root_public_key=self.trust_root_public_key,
            allowlist=self.allowlist,
            now=now,
            core_version=core_version,
            schema_version=schema_version,
        )
        if not verification.may_load():
            return DistributionDecision(
                entry_point=entry_point,
                allowed=False,
                reason="; ".join(verification.problems) or "The distribution did not verify.",
                verification=verification,
            )
        return DistributionDecision(
            entry_point=entry_point,
            allowed=True,
            reason="The publisher signature verifies over files that still match.",
            # The signed manifest is the one the host acts on. Reading the copy
            # inside the module would mean importing the module, which is the
            # thing a signed distribution exists to avoid.
            manifest=published.manifest,
            verification=verification,
        )


# -- serialization -------------------------------------------------------------------


def distribution_json(distribution: PluginDistribution) -> str:
    """Return the canonical JSON text of a distribution."""

    return canonical_json_bytes(distribution.model_dump(mode="json")).decode("utf-8")


def allowlist_json(allowlist: PluginAllowlist) -> str:
    """Return the canonical JSON text of an allowlist."""

    return canonical_json_bytes(allowlist.model_dump(mode="json")).decode("utf-8")


def load_distribution(path: str | Path) -> PluginDistribution:
    """Read and validate a distribution document within a bounded read."""

    return _load(path, PluginDistribution)


def load_allowlist(path: str | Path) -> PluginAllowlist:
    """Read and validate an allowlist document within a bounded read."""

    return _load(path, PluginAllowlist)


def _load[Document: (PluginDistribution, PluginAllowlist)](
    path: str | Path, model: type[Document]
) -> Document:
    import json

    source = Path(path)
    size = source.stat().st_size
    if size > MAX_DISTRIBUTION_BYTES:
        raise DistributionError(f"{source} is {size} bytes; the limit is {MAX_DISTRIBUTION_BYTES}")
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DistributionError(f"Unable to read {source}: {exc}") from exc
    try:
        return model.model_validate(raw)
    except Exception as exc:
        raise DistributionError(f"Invalid {model.__name__}: {exc}") from exc


def _version_in_range(version: str, minimum: str | None, maximum: str | None) -> bool:
    """Compare dotted versions numerically where possible, textually otherwise.

    A plugin declaring ``0.10`` against a core of ``0.9`` must not be refused by
    string comparison, and a non-numeric suffix must not make the comparison
    throw.
    """

    def key(value: str) -> tuple[int | str, ...]:
        parts: list[int | str] = []
        for part in value.replace("-", ".").split("."):
            parts.append(int(part) if part.isdigit() else part)
        return tuple(parts)

    def compare(left: str, right: str) -> int:
        for a, b in zip(key(left), key(right), strict=False):
            if a == b:
                continue
            if isinstance(a, int) and isinstance(b, int):
                return -1 if a < b else 1
            return -1 if str(a) < str(b) else 1
        return (len(key(left)) > len(key(right))) - (len(key(left)) < len(key(right)))

    if minimum is not None and compare(version, minimum) < 0:
        return False
    return not (maximum is not None and compare(version, maximum) > 0)


__all__ = [
    "DISTRIBUTION_FILENAME",
    "DISTRIBUTION_ID_PREFIX",
    "DISTRIBUTION_SCHEMA_VERSION",
    "MAX_DISTRIBUTION_BYTES",
    "MAX_DISTRIBUTION_FILES",
    "DistributionDecision",
    "DistributionError",
    "DistributionFile",
    "DistributionPolicy",
    "DistributionRevocation",
    "DistributionVerification",
    "PluginAllowlist",
    "PluginDistribution",
    "RevocationReason",
    "allowlist_json",
    "build_distribution",
    "compute_distribution_id",
    "describe_files",
    "distribution_json",
    "distribution_payload",
    "load_allowlist",
    "load_distribution",
    "sign_allowlist",
    "sign_distribution",
    "verify_allowlist",
    "verify_distribution",
]
