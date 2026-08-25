"""The one place TrueAI is allowed to reach the network, and what it costs to.

A forensic tool that can reach the network by default is a different product with
a different threat model. Everything in this project runs offline, and the few
operations that could benefit from a remote service — a timestamp authority, a
provider's verification API — go through this gate or do not happen.

Six conditions, all of them, before a single byte leaves the machine:

* **Policy.** `NetworkPolicy.EXPLICIT_ONLY`. The default is `OFFLINE`, and a
  caller that did not think about the network does not get it.
* **Consent.** A recorded decision naming who allowed it and for what. A policy
  flag says the software may; consent says a person did.
* **Allowlist.** An exact endpoint the operator wrote down. Not a host pattern,
  not a scheme — the URL that will be contacted.
* **Limits.** A timeout and a response-size cap, so a hostile or broken endpoint
  cannot hold the scan open or fill memory.
* **Credential isolation.** Credentials are fetched per request through a
  caller-supplied callable, never stored on the gate, never logged, and never
  attached to a request for an endpoint other than the one they were scoped to.
* **Auditable metadata.** Every attempt — allowed or refused — produces a record
  of what was contacted, how long it took, how much came back, and whether it
  succeeded. Never the request body, never the response body, never the
  credential.

TrueAI embeds no HTTP client. The transport is supplied by the caller, which
keeps the dependency surface out of a scanner and makes the boundary a thing an
auditor can see rather than a thing they have to trust.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Final, Protocol

from trueai.core.models import FrozenModel, NetworkPolicy

#: Longer than this and a scan is waiting on someone else's outage.
DEFAULT_TIMEOUT_SECONDS: Final = 15.0
#: A verification response is a signature or a small document. Anything larger
#: is either a mistake or an attempt to fill memory.
DEFAULT_MAX_RESPONSE_BYTES: Final = 4 * 1024 * 1024


class NetworkRefused(RuntimeError):
    """Raised when a request did not meet every condition for leaving the machine."""


class Transport(Protocol):
    """What a caller must supply to make a request possible at all.

    Deliberately minimal. TrueAI hands over an endpoint, headers, and a body, and
    receives bytes. It does not configure proxies, retries, or TLS, because those
    are the operator's decisions about their own network.
    """

    def __call__(
        self,
        __endpoint: str,
        *,
        payload: bytes,
        headers: Mapping[str, str],
        timeout: float,
    ) -> bytes: ...


@dataclass(frozen=True, slots=True)
class NetworkConsent:
    """A recorded decision that a person allowed this class of request.

    Separate from the policy on purpose. `NetworkPolicy.EXPLICIT_ONLY` says the
    software is permitted to; consent says somebody decided it should. Collapsing
    them would let a configuration default stand in for a human.
    """

    granted_by: str
    purpose: str
    #: Endpoints this consent covers. A consent for one service is not a consent
    #: for another that happens to be allowlisted.
    endpoints: frozenset[str]

    def covers(self, endpoint: str) -> bool:
        return endpoint in self.endpoints


class RequestRecord(FrozenModel):
    """What happened, in a form that can be published without leaking anything.

    Carries no request body, no response body, and no credential — only the
    facts an auditor needs to answer "what did this tool contact, and when".
    """

    endpoint: str
    purpose: str
    granted_by: str
    allowed: bool
    #: Present when the request was refused, naming which condition failed.
    refusal: str | None = None
    duration_seconds: float | None = None
    response_bytes: int | None = None
    #: Header names that were sent. Names only: a value could be a credential.
    header_names: tuple[str, ...] = ()

    def summary(self) -> str:
        if not self.allowed:
            return f"refused {self.endpoint}: {self.refusal}"
        return (
            f"contacted {self.endpoint} for {self.purpose} "
            f"({self.response_bytes} bytes in {self.duration_seconds:.2f}s)"
        )


@dataclass(slots=True)
class NetworkGate:
    """The gate every remote request passes through.

    Holds no credentials. ``credentials`` is a callable invoked per request with
    the endpoint being contacted, so a credential is produced for one destination
    and cannot be replayed to another by a later call.
    """

    policy: NetworkPolicy
    allowed_endpoints: frozenset[str]
    consent: NetworkConsent | None = None
    transport: Transport | None = None
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    credentials: Callable[[str], Mapping[str, str]] | None = None
    #: Every attempt, in order. Refusals are recorded too: "we did not contact
    #: anything" is a fact worth being able to prove.
    audit: list[RequestRecord] = field(default_factory=list)

    def check(self, endpoint: str, purpose: str) -> str | None:
        """Return the reason this request would be refused, or None.

        Separated from :meth:`request` so a caller can ask before committing to
        a workflow, and so the refusal reasons are testable without a transport.
        """

        if self.policy != NetworkPolicy.EXPLICIT_ONLY:
            return (
                f"the network policy is {self.policy.value}; a remote request needs explicit_only"
            )
        if endpoint not in self.allowed_endpoints:
            return f"{endpoint} is not in the operator's endpoint allowlist"
        if self.consent is None:
            return "no consent was recorded for a remote request"
        if not self.consent.covers(endpoint):
            return f"the recorded consent covers {sorted(self.consent.endpoints)}, not {endpoint}"
        if self.consent.purpose != purpose:
            return f"the recorded consent is for {self.consent.purpose!r}, not {purpose!r}"
        if self.transport is None:
            return "no transport was supplied; TrueAI embeds no HTTP client"
        if self.timeout_seconds <= 0:
            return "a request needs a positive timeout"
        return None

    def request(
        self,
        endpoint: str,
        *,
        purpose: str,
        payload: bytes = b"",
        headers: Mapping[str, str] | None = None,
    ) -> bytes:
        """Make one request, or refuse it and say which condition failed."""

        refusal = self.check(endpoint, purpose)
        if refusal is not None:
            self.audit.append(
                RequestRecord(
                    endpoint=endpoint,
                    purpose=purpose,
                    granted_by=self.consent.granted_by if self.consent else "nobody",
                    allowed=False,
                    refusal=refusal,
                )
            )
            raise NetworkRefused(refusal)

        assert self.consent is not None
        assert self.transport is not None

        # Credentials are produced for this endpoint and discarded with the
        # request. Holding them on the gate would make one leak into the next
        # destination the moment an allowlist grew.
        supplied = dict(headers or {})
        if self.credentials is not None:
            supplied.update(self.credentials(endpoint))

        started = time.monotonic()
        try:
            response = self.transport(
                endpoint,
                payload=payload,
                headers=supplied,
                timeout=self.timeout_seconds,
            )
        except Exception as exc:
            self.audit.append(
                RequestRecord(
                    endpoint=endpoint,
                    purpose=purpose,
                    granted_by=self.consent.granted_by,
                    allowed=True,
                    refusal=f"the transport failed: {type(exc).__name__}",
                    duration_seconds=time.monotonic() - started,
                    header_names=tuple(sorted(supplied)),
                )
            )
            raise
        duration = time.monotonic() - started

        if not isinstance(response, (bytes, bytearray)):
            self.audit.append(
                RequestRecord(
                    endpoint=endpoint,
                    purpose=purpose,
                    granted_by=self.consent.granted_by,
                    allowed=True,
                    refusal="the transport returned something other than bytes",
                    duration_seconds=duration,
                    header_names=tuple(sorted(supplied)),
                )
            )
            raise NetworkRefused("A transport must return bytes")
        if len(response) > self.max_response_bytes:
            self.audit.append(
                RequestRecord(
                    endpoint=endpoint,
                    purpose=purpose,
                    granted_by=self.consent.granted_by,
                    allowed=True,
                    refusal=(
                        f"the response was {len(response)} bytes, past the "
                        f"{self.max_response_bytes} cap"
                    ),
                    duration_seconds=duration,
                    response_bytes=len(response),
                    header_names=tuple(sorted(supplied)),
                )
            )
            raise NetworkRefused(
                f"A response of {len(response)} bytes exceeds the {self.max_response_bytes} cap"
            )

        self.audit.append(
            RequestRecord(
                endpoint=endpoint,
                purpose=purpose,
                granted_by=self.consent.granted_by,
                allowed=True,
                duration_seconds=duration,
                response_bytes=len(response),
                header_names=tuple(sorted(supplied)),
            )
        )
        return bytes(response)

    def offline_audit(self) -> tuple[RequestRecord, ...]:
        """Return the record of every attempt, refusals included."""

        return tuple(self.audit)


def offline_gate() -> NetworkGate:
    """Return a gate that refuses everything, which is the default posture."""

    return NetworkGate(policy=NetworkPolicy.OFFLINE, allowed_endpoints=frozenset())


__all__ = [
    "DEFAULT_MAX_RESPONSE_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "NetworkConsent",
    "NetworkGate",
    "NetworkRefused",
    "RequestRecord",
    "Transport",
    "offline_gate",
]
