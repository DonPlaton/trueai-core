"""Shared trust primitives: key custody, identity, timestamps, and transparency.

Certificates, policy bundles, and process attestations all need the same four
things, and all four are places where a system quietly overstates what it knows:

**Key custody.** Possession of a private key file is what TrueAI currently proves.
:class:`SigningProvider` narrows that to one interface so an HSM or KMS can hold
the key instead, without the signing code learning where keys live. Nothing here
ever moves a private key into a TrueAI process; a provider either has the key or
asks something else to sign.

**Organization identity.** Possession of *any* Ed25519 key is not organizational
identity. A key becomes an organization's key because a trust profile the operator
configured says so, within a stated validity window. Without a profile, a
signature authenticates a key and nothing more, and the result says exactly that.

**Time.** A `signed_at` field is a claim by the signer about when they signed.
A timestamp token is a claim by a separate authority. Only the second survives a
signer who backdates, so they are different fields with different verification
results, and the honest default is that no timestamp authority was consulted.

**Ordering.** A revocation list or policy bundle that can be replaced by an older
copy is not a revocation mechanism. Sequence numbers plus a hash chain make a
rollback detectable, and the transparency log makes an omission detectable too.

Every primitive is offline by default. Contacting a timestamp authority requires
an explicit network policy and an endpoint the operator allowlisted.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, model_validator

from trueai.core.certificates import (
    CertificateSignature,
    canonical_json_bytes,
    sign_detached_payload,
    verify_detached_payload,
)
from trueai.core.errors import AttestationError, TrueAIError
from trueai.core.models import FrozenModel, NetworkPolicy
from trueai.core.network import NetworkGate

TRUST_SCHEMA_VERSION: Literal["0.1"] = "0.1"

#: Bounded reads for every trust document, for the same reason the scanner bounds
#: artifact reads: a control-plane file is attacker-reachable in a fleet.
MAX_TRUST_DOCUMENT_BYTES = 4 * 1024 * 1024


class TrustError(TrueAIError):
    """Raised when a trust decision cannot be made safely."""

    code = "trust_error"


# -- key custody -------------------------------------------------------------------


class SigningProvider(ABC):
    """Where a signature comes from, without the caller knowing where the key is.

    An implementation may hold a key file, call an HSM, or ask a KMS. The contract
    is only that it can produce an Ed25519 signature and name the public key it
    corresponds to, so a verifier can check the result independently.
    """

    #: Human-readable provider name, recorded so an auditor knows what signed.
    name: str = "unknown"

    @abstractmethod
    def key_id(self) -> str:
        """Return the stable `sha256:…` identifier of the public key."""

    @abstractmethod
    def sign(self, payload: bytes) -> CertificateSignature:
        """Sign canonical bytes and return a verifiable signature."""

    def describe(self) -> str:
        """Return a short description for audit output."""

        return f"{self.name} ({self.key_id()})"


class LocalKeySigningProvider(SigningProvider):
    """Sign with a private key file on this machine.

    This is the weakest custody model TrueAI supports and it is named accordingly:
    anyone who can read the file can sign as its owner. It exists because it works
    offline with no infrastructure, not because it is the recommendation for an
    organization that signs on behalf of other people.
    """

    name = "local-key-file"

    def __init__(self, private_key: str | Path) -> None:
        self.private_key = Path(private_key)
        if not self.private_key.is_file():
            raise TrustError(f"Signing key not found: {self.private_key}")

    def key_id(self) -> str:
        """Return the identifier by signing an empty probe payload."""

        return self.sign(b"").key_id

    def sign(self, payload: bytes) -> CertificateSignature:
        """Sign with the local key."""

        return sign_detached_payload(payload, self.private_key)


class ExternalSigningProvider(SigningProvider):
    """Delegate signing to something outside this process.

    ``signer`` receives the canonical bytes and returns a raw Ed25519 signature.
    This is the seam an HSM, a KMS, or a hardware token plugs into: TrueAI never
    sees key material, and the provider decides what authorisation signing needs.

    The public key must be supplied, because a verifier has to be able to check
    the result without asking the same service that produced it.
    """

    def __init__(
        self,
        *,
        name: str,
        public_key: str | Path,
        signer: Any,
    ) -> None:
        self.name = name
        self.public_key = Path(public_key)
        if not self.public_key.is_file():
            raise TrustError(f"Public key not found: {self.public_key}")
        if not callable(signer):
            raise TrustError("An external signing provider needs a callable signer")
        self._signer = signer
        self._key_id: str | None = None

    def key_id(self) -> str:
        """Return the identifier derived from the supplied public key."""

        if self._key_id is None:
            self._key_id = public_key_id(self.public_key)
        return self._key_id

    def sign(self, payload: bytes) -> CertificateSignature:
        """Ask the external signer for a signature over exact bytes."""

        import base64

        raw = self._signer(payload)
        if not isinstance(raw, (bytes, bytearray)):
            raise TrustError(f"{self.name} returned {type(raw).__name__}, expected raw bytes")
        signature = CertificateSignature(
            key_id=self.key_id(),
            value=base64.b64encode(bytes(raw)).decode("ascii"),
        )
        # A provider that returns a signature the public key does not verify is a
        # misconfiguration, and finding out at verification time would mean an
        # unusable artifact was already published.
        if not verify_detached_payload(signature, payload, self.public_key):
            raise TrustError(
                f"{self.name} produced a signature that its own public key does not verify"
            )
        return signature


def public_key_id(public_key: str | Path) -> str:
    """Return the stable identifier of a PEM public key."""

    path = Path(public_key)
    try:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
            load_pem_public_key,
        )
    except ImportError as exc:
        raise AttestationError(
            "Key identity needs the optional attestation extra: install trueai-core[attestation]"
        ) from exc
    try:
        key = load_pem_public_key(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise TrustError(f"Unusable public key {path}: {exc}") from exc
    encoded = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


# -- organization identity ---------------------------------------------------------


class IdentityAssurance(StrEnum):
    """How strongly a signing key is tied to a named organization."""

    #: The key verified; nothing says whose it is.
    KEY_ONLY = "key_only"
    #: A configured trust profile names this key, within its validity window.
    PROFILE_BOUND = "profile_bound"
    #: The trust profile itself is signed by a root the operator configured.
    ROOT_ATTESTED = "root_attested"


class IssuerBinding(FrozenModel):
    """One key bound to one named issuer for a stated period."""

    key_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    organization: str = Field(min_length=1, max_length=300)
    #: A stable organizational identifier: a domain, a DUNS number, an LEI.
    organization_id: str | None = Field(default=None, max_length=300)
    subject: str | None = Field(default=None, max_length=300)
    not_before: datetime
    not_after: datetime | None = None
    roles: tuple[str, ...] = ()

    @model_validator(mode="after")
    def check_window(self) -> IssuerBinding:
        """A binding that expires before it starts can never be valid."""

        if self.not_after is not None and self.not_after <= self.not_before:
            raise ValueError("not_after must be later than not_before")
        return self

    def covers(self, moment: datetime) -> bool:
        """Return whether the binding is in force at a moment."""

        if moment < self.not_before:
            return False
        return self.not_after is None or moment < self.not_after


class TrustProfile(FrozenModel):
    """The operator's answer to "whose keys count, and for what".

    TrueAI ships no default profile. Deciding which organizations to trust is a
    policy decision that belongs to whoever runs the scan, not to the scanner.
    """

    schema_version: Literal["0.1"] = TRUST_SCHEMA_VERSION
    profile_id: str = Field(min_length=1, max_length=120)
    issued_at: datetime
    bindings: tuple[IssuerBinding, ...] = ()
    #: When present, the profile itself is signed by a configured root.
    signature: CertificateSignature | None = None

    def binding_for(self, key_id: str, moment: datetime | None = None) -> IssuerBinding | None:
        """Return the in-force binding for a key, if the profile has one."""

        now = moment or datetime.now(UTC)
        for binding in self.bindings:
            if binding.key_id == key_id and binding.covers(now):
                return binding
        return None

    def signed_payload(self) -> bytes:
        """Return the canonical bytes a root signature covers."""

        return canonical_json_bytes(self.model_dump(mode="json", exclude={"signature"}))


class IdentityResult(FrozenModel):
    """What a verifier learned about who signed something."""

    key_id: str
    assurance: IdentityAssurance
    organization: str | None = None
    organization_id: str | None = None
    subject: str | None = None
    roles: tuple[str, ...] = ()
    explanation: str

    @property
    def names_an_organization(self) -> bool:
        """Whether this result actually identifies an organization."""

        return self.assurance != IdentityAssurance.KEY_ONLY and self.organization is not None


def resolve_identity(
    key_id: str,
    *,
    profile: TrustProfile | None = None,
    root_public_key: str | Path | None = None,
    moment: datetime | None = None,
) -> IdentityResult:
    """Say what a verified key actually tells you about its owner.

    Without a profile the answer is ``key_only``, and the explanation says so
    plainly. Treating possession of any key as organizational identity is the
    mistake this function exists to prevent.
    """

    if profile is None:
        return IdentityResult(
            key_id=key_id,
            assurance=IdentityAssurance.KEY_ONLY,
            explanation=(
                "No trust profile was supplied, so this signature authenticates a key and "
                "says nothing about which organization holds it."
            ),
        )

    root_attested = False
    if root_public_key is not None:
        if profile.signature is None:
            raise TrustError("A root public key was supplied but the profile is unsigned")
        root_attested = verify_detached_payload(
            profile.signature, profile.signed_payload(), root_public_key
        )
        if not root_attested:
            raise TrustError("The trust profile's root signature does not verify")

    binding = profile.binding_for(key_id, moment)
    if binding is None:
        return IdentityResult(
            key_id=key_id,
            assurance=IdentityAssurance.KEY_ONLY,
            explanation=(
                f"Trust profile {profile.profile_id!r} has no binding in force for this key, "
                "so it authenticates a key and nothing more."
            ),
        )
    return IdentityResult(
        key_id=key_id,
        assurance=(
            IdentityAssurance.ROOT_ATTESTED if root_attested else IdentityAssurance.PROFILE_BOUND
        ),
        organization=binding.organization,
        organization_id=binding.organization_id,
        subject=binding.subject,
        roles=binding.roles,
        explanation=(
            f"Trust profile {profile.profile_id!r} binds this key to "
            f"{binding.organization!r}"
            + (
                ", and the profile is signed by the configured root."
                if root_attested
                else ". The profile itself was not checked against a root key."
            )
        ),
    )


# -- trusted timestamps ------------------------------------------------------------


class TimestampToken(FrozenModel):
    """An authority's statement that a digest existed at a time.

    This is deliberately not the signer's own `signed_at`. A signer can write any
    time they like; only a separate authority's signature over the digest makes
    the time evidence rather than a claim.
    """

    schema_version: Literal["0.1"] = TRUST_SCHEMA_VERSION
    #: `rfc3161` for a real TSA token, `trueai-tsa` for the offline equivalent.
    format: str = Field(min_length=1, max_length=40)
    authority: str = Field(min_length=1, max_length=300)
    digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    timestamped_at: datetime
    signature: CertificateSignature | None = None
    #: Raw token bytes, base64, for formats TrueAI does not parse itself.
    token: str | None = None

    def signed_payload(self) -> bytes:
        """Return the canonical bytes the authority's signature covers."""

        return canonical_json_bytes(self.model_dump(mode="json", exclude={"signature", "token"}))


class TimestampProvider(ABC):
    """Where a trusted time comes from."""

    name: str = "unknown"

    @abstractmethod
    def timestamp(self, digest_sha256: str) -> TimestampToken:
        """Return an authority's token over a digest."""


class OfflineTimestampProvider(TimestampProvider):
    """Sign a time with a designated local timestamping key.

    This is the "or equivalent" in "RFC 3161 or equivalent". It gives a separate
    key, held by a separate role, attesting when it saw a digest — which is the
    property that matters — without requiring the scanner to reach a network.

    It is weaker than a real TSA in one specific way, and the token says so: the
    authority's clock is the machine's clock. It defends against a signer
    backdating their own record; it does not defend against the timestamping role
    itself lying.
    """

    name = "trueai-offline-tsa"

    def __init__(self, provider: SigningProvider, *, authority: str) -> None:
        self.provider = provider
        self.authority = authority

    def timestamp(self, digest_sha256: str) -> TimestampToken:
        """Sign the digest together with the current time."""

        draft = TimestampToken(
            format="trueai-tsa",
            authority=self.authority,
            digest_sha256=digest_sha256,
            timestamped_at=datetime.now(UTC),
        )
        return draft.model_copy(update={"signature": self.provider.sign(draft.signed_payload())})


class NetworkTimestampProvider(TimestampProvider):
    """An RFC 3161 authority, reachable only through the shared network gate.

    Normal scanning stays offline; asking for a trusted timestamp is a separate,
    deliberate act. The conditions for that act are not stated here — they live
    in :class:`trueai.core.network.NetworkGate`, so "did this tool contact
    anything" has one answer, one set of rules, and one audit trail rather than a
    copy per caller.

    The transport is supplied by the caller. TrueAI does not embed an HTTP client,
    because a forensic tool that can reach the network by default is a different
    product with a different threat model.

    A caller that already has a configured gate passes it. A caller that does not
    may pass the endpoint, policy, allowlist, and transport instead, and a gate is
    built from them — with a consent record naming the constructor arguments as
    the source, because a synthesised consent must not be mistaken for a person's.
    """

    name = "rfc3161"
    purpose = "rfc3161 timestamp"

    def __init__(
        self,
        *,
        endpoint: str,
        network_policy: NetworkPolicy | None = None,
        allowed_endpoints: frozenset[str] | None = None,
        transport: Any = None,
        authority: str | None = None,
        gate: NetworkGate | None = None,
    ) -> None:
        from trueai.core.network import NetworkConsent

        if gate is None:
            if network_policy is None or allowed_endpoints is None:
                raise TrustError(
                    "Pass a configured NetworkGate, or the policy and allowlist to build one"
                )
            if not callable(transport):
                raise TrustError("A network timestamp provider needs a callable transport")

            def adapted(
                endpoint_url: str,
                *,
                payload: bytes,
                headers: Mapping[str, str],
                timeout: float,
            ) -> bytes:
                """Bridge the timestamp transport's own shape to the gate's.

                A timestamp transport was always ``(endpoint, digest) -> bytes``.
                Changing that to the gate's signature would break every caller
                who wrote one, so the shape is adapted rather than replaced. A
                caller who passes a ``gate`` uses the gate's protocol directly.
                """

                del headers, timeout
                raw = transport(endpoint_url, payload.decode("ascii"))
                if not isinstance(raw, (bytes, bytearray)):
                    raise TrustError("A timestamp transport must return raw token bytes")
                return bytes(raw)

            gate = NetworkGate(
                policy=network_policy,
                allowed_endpoints=allowed_endpoints,
                consent=NetworkConsent(
                    granted_by="constructor arguments",
                    purpose=self.purpose,
                    endpoints=allowed_endpoints,
                ),
                transport=adapted,
            )
        refusal = gate.check(endpoint, self.purpose)
        if refusal is not None:
            if gate.policy != NetworkPolicy.EXPLICIT_ONLY:
                # Named explicitly because the policy is the condition a caller is
                # most likely to have got wrong, and the enum member is what they
                # need to pass.
                raise TrustError(
                    "Contacting a timestamp authority requires NetworkPolicy.EXPLICIT_ONLY; "
                    f"got {gate.policy.value}"
                )
            raise TrustError(f"This timestamp authority will not be contacted: {refusal}")
        self.endpoint = endpoint
        self.authority = authority or endpoint
        self.gate = gate

    def timestamp(self, digest_sha256: str) -> TimestampToken:
        """Request a token from the allowlisted authority."""

        import base64

        try:
            # Through the gate, so the request is bounded, credential-isolated,
            # and recorded like every other remote call this tool makes.
            raw = self.gate.request(
                self.endpoint, purpose=self.purpose, payload=digest_sha256.encode("ascii")
            )
        except Exception as exc:
            raise TrustError(f"Timestamp authority {self.endpoint} failed: {exc}") from exc
        return TimestampToken(
            format="rfc3161",
            authority=self.authority,
            digest_sha256=digest_sha256,
            timestamped_at=datetime.now(UTC),
            token=base64.b64encode(bytes(raw)).decode("ascii"),
        )


def verify_timestamp(
    token: TimestampToken,
    *,
    digest_sha256: str,
    authority_public_key: str | Path | None = None,
) -> tuple[bool, str]:
    """Check a token against the digest it should cover.

    Returns whether the token is usable evidence and why. An RFC 3161 token that
    TrueAI cannot parse is reported as unverified rather than assumed good: an
    opaque blob is not evidence just because it is present.
    """

    if token.digest_sha256 != digest_sha256:
        return False, "The token covers a different digest than the record."
    if token.format == "rfc3161":
        return False, (
            "RFC 3161 tokens are recorded but not parsed by TrueAI. Verify the token with a "
            "TSA-aware verifier; its presence alone is not evidence."
        )
    if token.signature is None:
        return False, "The token carries no authority signature."
    if authority_public_key is None:
        return False, (
            "No authority public key was supplied, so the timestamp is recorded but unverified."
        )
    if not verify_detached_payload(token.signature, token.signed_payload(), authority_public_key):
        return False, "The authority signature does not verify."
    return True, (
        f"Authority {token.authority!r} attested this digest at {token.timestamped_at.isoformat()}."
    )


# -- transparency and rollback protection ------------------------------------------


class TransparencyEntry(FrozenModel):
    """One append-only record in a hash-chained log."""

    sequence: int = Field(ge=1)
    recorded_at: datetime
    kind: str = Field(min_length=1, max_length=80)
    subject_id: str = Field(min_length=1, max_length=200)
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    #: The chained digest, covering this entry and every entry before it.
    entry_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    previous_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class TransparencyLog(FrozenModel):
    """An append-only log that makes omission and rollback detectable.

    Sequence numbers alone catch a replaced-with-older-copy attack. The hash chain
    catches an edited middle entry. Neither is worth anything without someone
    keeping the previous head, so :func:`verify_transparency_log` takes the head a
    verifier saw last and reports a rollback rather than silently accepting a
    shorter log.
    """

    schema_version: Literal["0.1"] = TRUST_SCHEMA_VERSION
    log_id: str = Field(min_length=1, max_length=120)
    entries: tuple[TransparencyEntry, ...] = ()
    signature: CertificateSignature | None = None

    @property
    def head(self) -> str | None:
        """Return the digest a verifier should remember."""

        return self.entries[-1].entry_hash if self.entries else None

    @property
    def sequence(self) -> int:
        """Return the highest sequence number in the log."""

        return self.entries[-1].sequence if self.entries else 0

    def signed_payload(self) -> bytes:
        """Return the canonical bytes a maintainer signature covers."""

        return canonical_json_bytes(self.model_dump(mode="json", exclude={"signature"}))


def append_transparency_entry(
    log: TransparencyLog,
    *,
    kind: str,
    subject_id: str,
    payload: bytes,
    recorded_at: datetime | None = None,
) -> TransparencyLog:
    """Return a new log with one entry appended and the chain extended."""

    previous = log.entries[-1].entry_hash if log.entries else None
    payload_digest = hashlib.sha256(payload).hexdigest()
    moment = recorded_at or datetime.now(UTC)
    sequence = log.sequence + 1
    entry_hash = _chain_digest(
        sequence=sequence,
        recorded_at=moment,
        kind=kind,
        subject_id=subject_id,
        payload_sha256=payload_digest,
        previous_hash=previous,
    )
    entry = TransparencyEntry(
        sequence=sequence,
        recorded_at=moment,
        kind=kind,
        subject_id=subject_id,
        payload_sha256=payload_digest,
        entry_hash=entry_hash,
        previous_hash=previous,
    )
    # Appending invalidates any existing signature, which is correct: the
    # maintainer signs a state, not a prefix of one.
    return log.model_copy(update={"entries": (*log.entries, entry), "signature": None})


class TransparencyVerification(FrozenModel):
    """What a verifier learned about a log's integrity and freshness."""

    log_id: str
    chain_intact: bool
    sequence_contiguous: bool
    rolled_back: bool
    signature_status: str = "absent"
    head: str | None = None
    sequence: int = 0
    problems: tuple[str, ...] = ()

    @property
    def usable(self) -> bool:
        """Whether the log can be relied on for a trust decision."""

        return self.chain_intact and self.sequence_contiguous and not self.rolled_back


def verify_transparency_log(
    log: TransparencyLog,
    *,
    known_head: str | None = None,
    known_sequence: int = 0,
    maintainer_public_key: str | Path | None = None,
) -> TransparencyVerification:
    """Recompute the chain and compare against what a verifier saw before."""

    problems: list[str] = []
    chain_intact = True
    sequence_contiguous = True
    previous: str | None = None
    for index, entry in enumerate(log.entries, start=1):
        if entry.sequence != index:
            sequence_contiguous = False
            problems.append(
                f"Entry {index} declares sequence {entry.sequence}; entries are missing or "
                "reordered"
            )
        if entry.previous_hash != previous:
            chain_intact = False
            problems.append(f"Entry {entry.sequence} does not chain to the entry before it")
        expected = _chain_digest(
            sequence=entry.sequence,
            recorded_at=entry.recorded_at,
            kind=entry.kind,
            subject_id=entry.subject_id,
            payload_sha256=entry.payload_sha256,
            previous_hash=entry.previous_hash,
        )
        if expected != entry.entry_hash:
            chain_intact = False
            problems.append(f"Entry {entry.sequence} has been modified after it was recorded")
        previous = entry.entry_hash

    rolled_back = False
    if known_sequence and log.sequence < known_sequence:
        rolled_back = True
        problems.append(
            f"The log claims sequence {log.sequence} but {known_sequence} was already seen; "
            "this is an older copy"
        )
    if known_head and known_head not in {entry.entry_hash for entry in log.entries}:
        rolled_back = True
        problems.append(
            "The previously seen head is absent from this log, so history was rewritten"
        )

    signature_status = "absent"
    if log.signature is not None:
        if maintainer_public_key is None:
            signature_status = "unverified"
        elif verify_detached_payload(log.signature, log.signed_payload(), maintainer_public_key):
            signature_status = "valid"
        else:
            signature_status = "invalid"
            problems.append("The maintainer signature does not verify")

    return TransparencyVerification(
        log_id=log.log_id,
        chain_intact=chain_intact,
        sequence_contiguous=sequence_contiguous,
        rolled_back=rolled_back,
        signature_status=signature_status,
        head=log.head,
        sequence=log.sequence,
        problems=tuple(problems),
    )


def sign_transparency_log(log: TransparencyLog, provider: SigningProvider) -> TransparencyLog:
    """Attach a maintainer signature over the log's current state."""

    return log.model_copy(update={"signature": provider.sign(log.signed_payload())})


def _chain_digest(
    *,
    sequence: int,
    recorded_at: datetime,
    kind: str,
    subject_id: str,
    payload_sha256: str,
    previous_hash: str | None,
) -> str:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "sequence": sequence,
                "recorded_at": recorded_at.isoformat(),
                "kind": kind,
                "subject_id": subject_id,
                "payload_sha256": payload_sha256,
                "previous_hash": previous_hash,
            }
        )
    ).hexdigest()
