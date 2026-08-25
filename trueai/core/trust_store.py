"""A managed trust store: what an organization trusts, and when it stopped.

`TrustProfile` answers "whose key is this" for one signature.  A trust store is
the thing an organization actually deploys: the C2PA roots, the issuer keys, and
the plugin publisher keys a fleet of machines should honour, distributed as one
signed document with a lifetime and a sequence number.

Three problems this exists to handle, and they are not the same problem:

**Distribution.**  A store is signed, versioned, and finite-lifetime.  It is
installed against a remembered sequence, so a store that arrives claiming to be
older than the one already installed is a rollback and is refused.  An expired
store stops being authoritative rather than silently continuing.

**Rotation.**  A replacement anchor names the one it replaces.  The interesting
failure is not the replacement itself but the *gap*: if the successor's validity
starts after the predecessor's ends, there is a window in which nothing verifies,
and every signature made in it fails for a reason nobody will connect to a key
rotation months earlier.  :meth:`TrustStore.rotation_problems` looks for exactly
that.

**Offline updates.**  A machine that never touches the network still needs new
roots.  A :class:`TrustStoreUpdate` carries one step and is applied from a file.
Updates apply **strictly one sequence at a time**, because jumping from 4 to 6
would skip whatever 5 revoked — and a revocation you skipped is a key you are
still trusting.

Nothing here fetches anything.  A store or an update arrives as bytes, from a
file, a share, or a USB stick; if it arrives over a network it does so through
:mod:`trueai.core.network` like everything else.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, Literal, Self

from pydantic import Field, model_validator

from trueai.core.certificates import (
    CertificateSignature,
    canonical_json_bytes,
    sign_detached_payload,
    verify_detached_payload,
)
from trueai.core.errors import TrueAIError
from trueai.core.models import FrozenModel
from trueai.core.trust import (
    IssuerBinding,
    SigningProvider,
    TrustProfile,
    public_key_id,
)

TRUST_STORE_SCHEMA_VERSION: Final[Literal["0.1"]] = "0.1"

#: Trust stores get their own identifier prefix.  A store, a certificate, an
#: attestation, and a plugin distribution are four different statements.
TRUST_STORE_ID_PREFIX: Final = "TAITS1-"

MAX_TRUST_STORE_BYTES: Final = 8 * 1024 * 1024
MAX_ANCHORS: Final = 4096

_KEY_ID: Final = re.compile(r"^sha256:[0-9a-f]{64}$")


class TrustStoreError(TrueAIError):
    """Raised when a store or an update cannot be read, verified, or applied."""


class AnchorKind(StrEnum):
    """What an anchor is trusted *for*.

    Kept apart because trusting a key to sign C2PA manifests is not trusting it
    to publish plugins, and a store that conflated them would silently widen
    every anchor it holds.
    """

    C2PA_ROOT = "c2pa_root"
    ISSUER_KEY = "issuer_key"
    PLUGIN_PUBLISHER = "plugin_publisher"
    TIMESTAMP_AUTHORITY = "timestamp_authority"


class TrustAnchor(FrozenModel):
    """One thing an organization has decided to trust, for a stated period."""

    anchor_id: str = Field(min_length=1, max_length=120)
    kind: AnchorKind
    subject: str = Field(min_length=1, max_length=300)
    #: A PEM certificate for a root, or a ``sha256:…`` key id for a key.
    material: str = Field(min_length=1, max_length=64_000)
    not_before: datetime
    not_after: datetime | None = None
    #: The anchor this one replaces, when it is a rotation rather than an
    #: addition.  Recorded so a gap between them can be found.
    replaces: str | None = Field(default=None, max_length=120)
    organization_id: str | None = Field(default=None, max_length=300)
    roles: tuple[str, ...] = ()

    @model_validator(mode="after")
    def check_window(self) -> Self:
        for label, value in (("not_before", self.not_before), ("not_after", self.not_after)):
            if value is not None and (value.tzinfo is None or value.utcoffset() is None):
                raise ValueError(f"Anchor {label} must include a UTC offset")
        if self.not_after is not None and self.not_after <= self.not_before:
            raise ValueError("An anchor that expires before it starts can never be valid")
        if self.replaces == self.anchor_id:
            raise ValueError("An anchor cannot replace itself")
        # Checked here rather than where the material is consumed, because the
        # consumer is `to_trust_profile` or `c2pa_anchor_pems` — running long
        # after the store was authored, on a machine that cannot fix it.
        if self.kind is AnchorKind.ISSUER_KEY and not _KEY_ID.fullmatch(self.material):
            raise ValueError(
                "An issuer_key anchor's material must be a sha256:… key id, not a "
                "certificate: the key id is what a signature carries and what identity "
                "resolution compares"
            )
        if self.kind is AnchorKind.C2PA_ROOT and "-----BEGIN " not in self.material:
            raise ValueError("A c2pa_root anchor's material must be a PEM certificate")
        return self

    def in_force(self, moment: datetime) -> bool:
        """Return whether this anchor is valid at a moment."""

        if moment < self.not_before:
            return False
        return not (self.not_after is not None and moment > self.not_after)

    @property
    def fingerprint(self) -> str:
        """A stable digest of the trusted material, for logs and comparisons."""

        return "sha256:" + hashlib.sha256(self.material.encode("utf-8")).hexdigest()


class AnchorRevocation(FrozenModel):
    """One anchor withdrawn before its stated expiry."""

    anchor_id: str = Field(min_length=1, max_length=120)
    revoked_at: datetime
    reason: str = Field(min_length=1, max_length=500)
    #: The anchor operators should move to, when there is one.
    replacement_anchor_id: str | None = Field(default=None, max_length=120)

    @model_validator(mode="after")
    def check_time(self) -> Self:
        if self.revoked_at.tzinfo is None or self.revoked_at.utcoffset() is None:
            raise ValueError("Revocation time must include a UTC offset")
        if self.replacement_anchor_id == self.anchor_id:
            raise ValueError("A replacement anchor must differ from the revoked one")
        return self


class TrustStore(FrozenModel):
    """One organization's signed, sequenced set of trust anchors."""

    store_id: str = Field(pattern=r"^TAITS1-[A-Z2-7]{32}$")
    schema_version: Literal["0.1"] = TRUST_STORE_SCHEMA_VERSION
    organization: str = Field(min_length=1, max_length=300)
    issuer_key_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    #: Monotonic.  A store arriving with a lower sequence than the installed one
    #: is a rollback, not an update.
    sequence: int = Field(ge=1)
    issued_at: datetime
    expires_at: datetime
    anchors: tuple[TrustAnchor, ...] = Field(default=(), max_length=MAX_ANCHORS)
    revocations: tuple[AnchorRevocation, ...] = Field(default=(), max_length=MAX_ANCHORS)
    signature: CertificateSignature | None = None

    @model_validator(mode="after")
    def validate_store(self) -> Self:
        for label, value in (("issue", self.issued_at), ("expiry", self.expires_at)):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"Trust store {label} time must include a UTC offset")
        if self.expires_at <= self.issued_at:
            raise ValueError("A trust store must expire after it is issued")
        identifiers = [anchor.anchor_id for anchor in self.anchors]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("Anchor identifiers must be unique within a store")
        known = set(identifiers)
        for anchor in self.anchors:
            if anchor.replaces is not None and anchor.replaces not in known:
                # A rotation pointing at an anchor the store does not contain
                # cannot be checked for a gap, so it is refused rather than
                # accepted with the check quietly skipped.
                raise ValueError(
                    f"Anchor {anchor.anchor_id} replaces {anchor.replaces}, which is not in "
                    "this store"
                )
        revoked = [item.anchor_id for item in self.revocations]
        if len(set(revoked)) != len(revoked):
            raise ValueError("An anchor may appear only once in the revocations")
        return self

    # -- reading -------------------------------------------------------------------

    def anchor(self, anchor_id: str) -> TrustAnchor | None:
        return next((item for item in self.anchors if item.anchor_id == anchor_id), None)

    def revocation_for(self, anchor_id: str) -> AnchorRevocation | None:
        return next((item for item in self.revocations if item.anchor_id == anchor_id), None)

    def is_expired(self, moment: datetime | None = None) -> bool:
        return (moment or datetime.now(UTC)) > self.expires_at

    def active_anchors(
        self, moment: datetime | None = None, kind: AnchorKind | None = None
    ) -> tuple[TrustAnchor, ...]:
        """Return the anchors in force at a moment, revocations applied.

        An expired *store* yields nothing.  Continuing to honour anchors from a
        store whose own lifetime ran out would make the lifetime decorative.
        """

        now = moment or datetime.now(UTC)
        if self.is_expired(now):
            return ()
        selected: list[TrustAnchor] = []
        for anchor in self.anchors:
            if kind is not None and anchor.kind != kind:
                continue
            if not anchor.in_force(now):
                continue
            revocation = self.revocation_for(anchor.anchor_id)
            if revocation is not None and revocation.revoked_at <= now:
                continue
            selected.append(anchor)
        return tuple(selected)

    def rotation_chain(self, anchor_id: str) -> tuple[TrustAnchor, ...]:
        """Return an anchor and everything it replaces, newest first."""

        chain: list[TrustAnchor] = []
        seen: set[str] = set()
        current = self.anchor(anchor_id)
        while current is not None and current.anchor_id not in seen:
            seen.add(current.anchor_id)
            chain.append(current)
            current = self.anchor(current.replaces) if current.replaces else None
        return tuple(chain)

    def rotation_problems(self) -> tuple[str, ...]:
        """Return every rotation that leaves a window with no valid anchor.

        The failure this catches is quiet and delayed: a signature made during
        the gap fails months later, and nobody connects it to a key rotation.
        """

        problems: list[str] = []
        for anchor in self.anchors:
            if anchor.replaces is None:
                continue
            predecessor = self.anchor(anchor.replaces)
            if predecessor is None:
                continue
            if predecessor.not_after is None:
                # The predecessor never expires, so no gap is possible.
                continue
            if anchor.not_before > predecessor.not_after:
                problems.append(
                    f"{anchor.anchor_id} starts at {anchor.not_before.isoformat()}, after "
                    f"{predecessor.anchor_id} ends at {predecessor.not_after.isoformat()}: "
                    "nothing signed in that window will verify"
                )
        return tuple(problems)

    # -- consuming ------------------------------------------------------------------

    def to_trust_profile(self, moment: datetime | None = None) -> TrustProfile:
        """Project the issuer anchors into the profile `resolve_identity` uses.

        A projection rather than a second source of truth: the store is what the
        organization deploys, and the profile is the shape one verification call
        wants.
        """

        bindings = tuple(
            IssuerBinding(
                key_id=anchor.material,
                organization=anchor.subject,
                organization_id=anchor.organization_id,
                not_before=anchor.not_before,
                not_after=anchor.not_after,
                roles=anchor.roles,
            )
            for anchor in self.active_anchors(moment, AnchorKind.ISSUER_KEY)
        )
        return TrustProfile(
            profile_id=f"{self.store_id}#{self.sequence}",
            issued_at=self.issued_at,
            bindings=bindings,
        )

    def c2pa_anchor_pems(self, moment: datetime | None = None) -> str:
        """Return the active C2PA roots as one PEM bundle, or an empty string."""

        return "\n".join(
            anchor.material.strip() for anchor in self.active_anchors(moment, AnchorKind.C2PA_ROOT)
        )

    def signed_payload(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json", exclude={"signature"}))


class TrustStoreUpdate(FrozenModel):
    """One offline step from one store sequence to the next.

    Carries the whole successor rather than a diff.  A diff would be smaller and
    would make "what will I be trusting afterwards" a question requiring
    computation; the store is small enough that clarity wins.
    """

    schema_version: Literal["0.1"] = TRUST_STORE_SCHEMA_VERSION
    from_sequence: int = Field(ge=0)
    store: TrustStore
    #: What changed, in words, for an operator applying this by hand.
    summary: str = Field(min_length=1, max_length=2000)

    @model_validator(mode="after")
    def check_step(self) -> Self:
        if self.store.sequence != self.from_sequence + 1:
            raise ValueError(
                f"An update must advance exactly one sequence: {self.from_sequence} to "
                f"{self.from_sequence + 1}, not {self.store.sequence}"
            )
        return self


class InstallResult(FrozenModel):
    """Whether a store was installed, and everything that decided it."""

    installed: bool
    store_id: str
    sequence: int
    #: Reasons it was refused.  Plural because an operator fixing one should see
    #: the others rather than discovering them one run at a time.
    problems: tuple[str, ...] = ()
    #: Rotation gaps found in an otherwise acceptable store.  A warning, not a
    #: refusal: the gap may be deliberate.
    rotation_warnings: tuple[str, ...] = ()

    def explain(self) -> str:
        if self.installed:
            note = (
                f" {len(self.rotation_warnings)} rotation warning(s)."
                if self.rotation_warnings
                else ""
            )
            return f"Installed {self.store_id} at sequence {self.sequence}.{note}"
        return f"Refused {self.store_id}: " + "; ".join(self.problems)


# -- building and signing ------------------------------------------------------------


def compute_store_id(store: TrustStore) -> str:
    """Derive the identifier from everything the store claims."""

    payload = store.model_dump(mode="json", exclude={"store_id", "signature"})
    digest = hashlib.sha256(canonical_json_bytes(payload)).digest()
    return TRUST_STORE_ID_PREFIX + base64.b32encode(digest)[:32].decode("ascii")


def build_trust_store(
    *,
    organization: str,
    issuer_key_id: str,
    sequence: int,
    issued_at: datetime,
    expires_at: datetime,
    anchors: tuple[TrustAnchor, ...] = (),
    revocations: tuple[AnchorRevocation, ...] = (),
) -> TrustStore:
    """Build an unsigned, content-addressed trust store."""

    draft = TrustStore(
        store_id=TRUST_STORE_ID_PREFIX + "A" * 32,
        organization=organization,
        issuer_key_id=issuer_key_id,
        sequence=sequence,
        issued_at=issued_at,
        expires_at=expires_at,
        anchors=anchors,
        revocations=revocations,
    )
    return draft.model_copy(update={"store_id": compute_store_id(draft)})


def sign_trust_store(
    store: TrustStore,
    *,
    signing_key: str | Path | None = None,
    provider: SigningProvider | None = None,
) -> TrustStore:
    """Sign a store with a local key or through a signing provider."""

    if (signing_key is None) == (provider is None):
        raise TrustStoreError("Pass exactly one of signing_key or provider")
    if compute_store_id(store) != store.store_id:
        raise TrustStoreError(
            "The store identifier does not match its contents; rebuild it before signing"
        )
    payload = store.signed_payload()
    signature = (
        provider.sign(payload)
        if provider is not None
        else sign_detached_payload(payload, signing_key)  # type: ignore[arg-type]
    )
    return store.model_copy(update={"signature": signature})


# -- verifying and installing ---------------------------------------------------------


def verify_trust_store(
    store: TrustStore,
    *,
    public_key: str | Path,
    known_sequence: int | None = None,
    now: datetime | None = None,
) -> tuple[bool, tuple[str, ...]]:
    """Check a store's identity, signature, lifetime, and sequence.

    ``known_sequence`` is the highest sequence this machine has installed.  A
    verifier with no memory cannot detect a rollback, so the API asks for the
    memory rather than pretending it is unnecessary.
    """

    problems: list[str] = []
    moment = now or datetime.now(UTC)

    if compute_store_id(store) != store.store_id:
        problems.append("the store identifier does not match its own contents")
    if store.signature is None:
        problems.append("the store is unsigned")
    else:
        # Three different failures that a single "the signature does not verify"
        # would collapse into one: an unreadable key file, the wrong key for this
        # store, and an actually broken signature.  An operator who typed the
        # wrong path should not go looking for a tampered store.
        try:
            presented = public_key_id(public_key)
        except Exception as exc:  # the key is caller-supplied and may be anything
            problems.append(f"the public key could not be read: {exc}")
            presented = None
        if presented is not None and presented != store.signature.key_id:
            problems.append(
                f"the store was signed by {store.signature.key_id} and the public key "
                f"supplied is {presented}: this is the wrong key for this store, not a "
                "bad signature"
            )
        elif presented is not None and not verify_detached_payload(
            store.signature, store.signed_payload(), public_key
        ):
            problems.append("the signature does not verify")
        if store.signature.key_id != store.issuer_key_id:
            problems.append(
                f"the store names issuer {store.issuer_key_id} but was signed by "
                f"{store.signature.key_id}"
            )
    if moment < store.issued_at:
        problems.append("the store is not yet in force")
    if store.is_expired(moment):
        problems.append("the store has expired")
    if known_sequence is not None and store.sequence < known_sequence:
        problems.append(
            f"this store is sequence {store.sequence}; sequence {known_sequence} is already "
            "installed, so this is a rollback"
        )
    return not problems, tuple(problems)


def install_trust_store(
    store: TrustStore,
    *,
    public_key: str | Path,
    known_sequence: int | None = None,
    now: datetime | None = None,
) -> InstallResult:
    """Verify a store and report whether it may replace the installed one."""

    valid, problems = verify_trust_store(
        store, public_key=public_key, known_sequence=known_sequence, now=now
    )
    return InstallResult(
        installed=valid,
        store_id=store.store_id,
        sequence=store.sequence,
        problems=problems,
        rotation_warnings=store.rotation_problems() if valid else (),
    )


def apply_update(
    installed: TrustStore | None,
    update: TrustStoreUpdate,
    *,
    public_key: str | Path,
    now: datetime | None = None,
) -> tuple[TrustStore, InstallResult]:
    """Apply one offline update step, or refuse it and say why.

    Strictly one sequence at a time.  Jumping from 4 to 6 would skip whatever 5
    revoked, and a revocation you skipped is a key you are still trusting.
    """

    current = installed.sequence if installed is not None else 0
    if update.from_sequence != current:
        result = InstallResult(
            installed=False,
            store_id=update.store.store_id,
            sequence=update.store.sequence,
            problems=(
                f"this update starts from sequence {update.from_sequence}, but sequence "
                f"{current} is installed; apply the intervening updates first so no "
                "revocation is skipped",
            ),
        )
        return (installed or update.store), result

    if installed is not None and installed.organization != update.store.organization:
        result = InstallResult(
            installed=False,
            store_id=update.store.store_id,
            sequence=update.store.sequence,
            problems=(
                f"the installed store belongs to {installed.organization!r} and the update to "
                f"{update.store.organization!r}",
            ),
        )
        return installed, result

    result = install_trust_store(
        update.store, public_key=public_key, known_sequence=current, now=now
    )
    return (update.store if result.installed else (installed or update.store)), result


# -- serialization --------------------------------------------------------------------


def trust_store_json(store: TrustStore) -> str:
    return canonical_json_bytes(store.model_dump(mode="json")).decode("utf-8")


def trust_store_update_json(update: TrustStoreUpdate) -> str:
    return canonical_json_bytes(update.model_dump(mode="json")).decode("utf-8")


def load_trust_store(path: str | Path) -> TrustStore:
    return _load(path, TrustStore)


def load_trust_store_update(path: str | Path) -> TrustStoreUpdate:
    return _load(path, TrustStoreUpdate)


def _load[Document: (TrustStore, TrustStoreUpdate)](
    path: str | Path, model: type[Document]
) -> Document:
    source = Path(path)
    size = source.stat().st_size
    if size > MAX_TRUST_STORE_BYTES:
        raise TrustStoreError(f"{source} is {size} bytes; the limit is {MAX_TRUST_STORE_BYTES}")
    try:
        raw: Any = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TrustStoreError(f"Unable to read {source}: {exc}") from exc
    try:
        return model.model_validate(raw)
    except Exception as exc:
        raise TrustStoreError(f"Invalid {model.__name__}: {exc}") from exc


__all__ = [
    "MAX_ANCHORS",
    "MAX_TRUST_STORE_BYTES",
    "TRUST_STORE_ID_PREFIX",
    "TRUST_STORE_SCHEMA_VERSION",
    "AnchorKind",
    "AnchorRevocation",
    "InstallResult",
    "TrustAnchor",
    "TrustStore",
    "TrustStoreError",
    "TrustStoreUpdate",
    "apply_update",
    "build_trust_store",
    "compute_store_id",
    "install_trust_store",
    "load_trust_store",
    "load_trust_store_update",
    "sign_trust_store",
    "trust_store_json",
    "trust_store_update_json",
    "verify_trust_store",
]
