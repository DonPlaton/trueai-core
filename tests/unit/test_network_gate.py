"""The network gate, and the admission standard for provider adapters.

Two things a forensic tool has to be able to prove. First, that it did not
contact anything — which needs the refusals recorded, not just the successes.
Second, that a provider reported as unverifiable is unverifiable for a stated
reason rather than because nobody got round to it.
"""

from __future__ import annotations

from collections.abc import Mapping

import pytest

from trueai.core.artifact import Artifact
from trueai.core.models import (
    ArtifactType,
    NetworkPolicy,
    WatermarkSupportStatus,
)
from trueai.core.network import (
    DEFAULT_MAX_RESPONSE_BYTES,
    NetworkConsent,
    NetworkGate,
    NetworkRefused,
    offline_gate,
)
from trueai.detectors.provenance.provider import (
    PROVIDER_ASSESSMENTS,
    AdmissionCriteria,
    ProviderWatermarkDetector,
    UnavailableProviderWatermarkAdapter,
    assessment_for,
)

ENDPOINT = "https://verify.example.test/v1/check"
PURPOSE = "provider watermark verification"

CONSENT = NetworkConsent(
    granted_by="operator@example.test", purpose=PURPOSE, endpoints=frozenset({ENDPOINT})
)


def echo_transport(response: bytes = b"ok"):
    """A transport that records what it was handed and returns a fixed body."""

    seen: list[tuple[str, bytes, Mapping[str, str], float]] = []

    def transport(
        endpoint: str, *, payload: bytes, headers: Mapping[str, str], timeout: float
    ) -> bytes:
        seen.append((endpoint, payload, dict(headers), timeout))
        return response

    transport.seen = seen  # type: ignore[attr-defined]
    return transport


def open_gate(**overrides) -> NetworkGate:
    settings = {
        "policy": NetworkPolicy.EXPLICIT_ONLY,
        "allowed_endpoints": frozenset({ENDPOINT}),
        "consent": CONSENT,
        "transport": echo_transport(),
    }
    settings.update(overrides)
    return NetworkGate(**settings)  # type: ignore[arg-type]


# -- the six conditions ----------------------------------------------------------------


def test_the_default_posture_refuses_everything() -> None:
    """A caller that did not think about the network does not get it."""

    gate = offline_gate()

    assert gate.policy == NetworkPolicy.OFFLINE
    with pytest.raises(NetworkRefused, match="explicit_only"):
        gate.request(ENDPOINT, purpose=PURPOSE)


def test_an_offline_policy_refuses_even_an_allowlisted_endpoint() -> None:
    gate = open_gate(policy=NetworkPolicy.OFFLINE)

    assert gate.check(ENDPOINT, PURPOSE) is not None
    with pytest.raises(NetworkRefused):
        gate.request(ENDPOINT, purpose=PURPOSE)


def test_an_endpoint_outside_the_allowlist_is_refused() -> None:
    gate = open_gate()

    with pytest.raises(NetworkRefused, match="allowlist"):
        gate.request("https://elsewhere.example.test/", purpose=PURPOSE)


def test_policy_without_consent_is_refused() -> None:
    """A policy flag says the software may; consent says a person decided."""

    gate = open_gate(consent=None)

    with pytest.raises(NetworkRefused, match="no consent"):
        gate.request(ENDPOINT, purpose=PURPOSE)


def test_consent_for_one_endpoint_does_not_cover_another() -> None:
    other = "https://second.example.test/"
    gate = open_gate(allowed_endpoints=frozenset({ENDPOINT, other}))

    gate.request(ENDPOINT, purpose=PURPOSE)
    with pytest.raises(NetworkRefused, match="consent covers"):
        gate.request(other, purpose=PURPOSE)


def test_consent_for_one_purpose_does_not_cover_another() -> None:
    """Consent to check a watermark is not consent to upload a document."""

    gate = open_gate()

    with pytest.raises(NetworkRefused, match="consent is for"):
        gate.request(ENDPOINT, purpose="telemetry")


def test_no_transport_means_no_request() -> None:
    """TrueAI embeds no HTTP client, and says so rather than importing one."""

    gate = open_gate(transport=None)

    with pytest.raises(NetworkRefused, match="embeds no HTTP client"):
        gate.request(ENDPOINT, purpose=PURPOSE)


def test_a_non_positive_timeout_is_refused() -> None:
    gate = open_gate(timeout_seconds=0)

    with pytest.raises(NetworkRefused, match="positive timeout"):
        gate.request(ENDPOINT, purpose=PURPOSE)


def test_a_fully_configured_gate_makes_the_request() -> None:
    """The refusal path must not be the only path that works."""

    transport = echo_transport(b"verified")
    gate = open_gate(transport=transport)

    assert gate.request(ENDPOINT, purpose=PURPOSE, payload=b"digest") == b"verified"
    assert transport.seen[0][0] == ENDPOINT
    assert transport.seen[0][1] == b"digest"


# -- limits ----------------------------------------------------------------------------


def test_the_timeout_reaches_the_transport() -> None:
    transport = echo_transport()
    gate = open_gate(transport=transport, timeout_seconds=3.5)

    gate.request(ENDPOINT, purpose=PURPOSE)

    assert transport.seen[0][3] == 3.5


def test_an_oversized_response_is_refused() -> None:
    """A hostile endpoint must not be able to fill memory through the gate."""

    gate = open_gate(transport=echo_transport(b"x" * 200), max_response_bytes=100)

    with pytest.raises(NetworkRefused, match="exceeds"):
        gate.request(ENDPOINT, purpose=PURPOSE)


def test_the_default_response_cap_is_modest() -> None:
    """A verification response is a signature or a small document."""

    assert DEFAULT_MAX_RESPONSE_BYTES <= 8 * 1024 * 1024


def test_a_transport_returning_something_other_than_bytes_is_refused() -> None:
    def wrong(endpoint: str, *, payload: bytes, headers, timeout: float):
        return "a string, not bytes"

    gate = open_gate(transport=wrong)

    with pytest.raises(NetworkRefused, match="must return bytes"):
        gate.request(ENDPOINT, purpose=PURPOSE)


# -- credential isolation --------------------------------------------------------------


def test_credentials_are_produced_per_endpoint() -> None:
    """A credential scoped to one destination cannot be replayed to another."""

    asked: list[str] = []

    def credentials(endpoint: str) -> Mapping[str, str]:
        asked.append(endpoint)
        return {"Authorization": f"Bearer token-for-{endpoint}"}

    transport = echo_transport()
    gate = open_gate(transport=transport, credentials=credentials)

    gate.request(ENDPOINT, purpose=PURPOSE)

    assert asked == [ENDPOINT]
    assert transport.seen[0][2]["Authorization"].endswith(ENDPOINT)


def test_the_gate_holds_no_credential_of_its_own() -> None:
    """Holding one would leak it into the next destination an allowlist grew to."""

    gate = open_gate(credentials=lambda endpoint: {"Authorization": "Bearer secret"})

    # The gate uses __slots__, so its attributes are read by name rather than
    # from a __dict__. That is the point being checked: nothing but the callable
    # holds the credential.
    stored = [getattr(gate, name) for name in NetworkGate.__slots__]
    assert not any("secret" in str(value) for value in stored if not callable(value))


def test_the_audit_records_header_names_but_never_values() -> None:
    gate = open_gate(credentials=lambda endpoint: {"Authorization": "Bearer secret"})

    gate.request(ENDPOINT, purpose=PURPOSE)
    record = gate.offline_audit()[0]

    assert record.header_names == ("Authorization",)
    assert "secret" not in record.model_dump_json()


# -- auditability ----------------------------------------------------------------------


def test_a_successful_request_is_recorded_with_its_shape() -> None:
    gate = open_gate(transport=echo_transport(b"1234"))

    gate.request(ENDPOINT, purpose=PURPOSE)
    record = gate.offline_audit()[0]

    assert record.allowed
    assert record.endpoint == ENDPOINT
    assert record.granted_by == "operator@example.test"
    assert record.response_bytes == 4
    assert record.duration_seconds is not None
    assert "contacted" in record.summary()


def test_a_refusal_is_recorded_too() -> None:
    """ "We did not contact anything" is a fact worth being able to prove."""

    gate = offline_gate()

    with pytest.raises(NetworkRefused):
        gate.request(ENDPOINT, purpose=PURPOSE)
    record = gate.offline_audit()[0]

    assert not record.allowed
    assert record.refusal
    assert record.summary().startswith("refused")


def test_the_audit_carries_no_request_or_response_body() -> None:
    gate = open_gate(transport=echo_transport(b"SECRET-RESPONSE"))

    gate.request(ENDPOINT, purpose=PURPOSE, payload=b"SECRET-REQUEST")
    serialised = gate.offline_audit()[0].model_dump_json()

    assert "SECRET-REQUEST" not in serialised
    assert "SECRET-RESPONSE" not in serialised


def test_a_transport_failure_is_recorded_and_re_raised() -> None:
    def failing(endpoint: str, *, payload: bytes, headers, timeout: float) -> bytes:
        raise TimeoutError("the endpoint did not answer")

    gate = open_gate(transport=failing)

    with pytest.raises(TimeoutError):
        gate.request(ENDPOINT, purpose=PURPOSE)
    record = gate.offline_audit()[0]

    assert record.allowed
    assert record.refusal is not None
    assert "TimeoutError" in record.refusal


# -- the admission standard ------------------------------------------------------------


def test_admission_needs_all_four_criteria() -> None:
    """Three out of four is a watermark someone reverse-engineered."""

    almost = AdmissionCriteria(
        published_mechanism=True,
        independently_runnable=True,
        specified_semantics=True,
        stable_contract=False,
    )

    assert not almost.admitted
    assert almost.unmet() == ("no stable, versioned contract",)


def test_c2pa_is_the_only_admitted_provider() -> None:
    """Not a permanent fact, but the current one, and it should change deliberately."""

    admitted = {item.provider for item in PROVIDER_ASSESSMENTS if item.admitted}

    assert admitted == {"c2pa"}


def test_every_assessment_explains_itself() -> None:
    for assessment in PROVIDER_ASSESSMENTS:
        assert assessment.note, assessment.provider
        if not assessment.admitted:
            assert assessment.criteria.unmet(), assessment.provider


def test_an_unadmitted_provider_reports_unavailable_with_reasons(tmp_path) -> None:
    """ "Unavailable" should be a position with reasons, not a shrug."""

    class GoogleAdapter(UnavailableProviderWatermarkAdapter):
        id = "provenance.google.v1"
        provider = "google"
        supported_types = frozenset({ArtifactType.PNG})

    path = tmp_path / "image.png"
    path.write_bytes(b"\x89PNG\r\n\x1a\n")
    artifact = Artifact(artifact_type=ArtifactType.PNG, path=path, logical_path=path.name)

    result = GoogleAdapter().verify(artifact)

    assert result.status == WatermarkSupportStatus.VERIFICATION_UNAVAILABLE
    assert not result.verified
    assert "no published verifier" in result.explanation
    assert "No watermark algorithm, secret key, or removal method is inferred" in (
        result.explanation
    )


def test_an_assessment_can_be_looked_up_by_name() -> None:
    assert assessment_for("C2PA") is not None
    assert assessment_for("nobody") is None


# -- an adapter cannot reach the network on its own ------------------------------------


class _Adapter(ProviderWatermarkDetector):
    id = "test.adapter.v1"
    provider = "test"
    supported_types = frozenset({ArtifactType.PNG})

    def verify(self, artifact):  # pragma: no cover - not the subject of these tests
        raise NotImplementedError


def test_an_adapter_is_offline_unless_handed_a_gate() -> None:
    """A default that reached the network would make the boundary opt-out."""

    adapter = _Adapter()

    assert adapter.gate.policy == NetworkPolicy.OFFLINE
    assert adapter.network_refusal(ENDPOINT, PURPOSE) is not None


def test_an_adapter_that_does_not_declare_network_required_cannot_fetch() -> None:
    adapter = _Adapter(open_gate())

    with pytest.raises(NetworkRefused, match="does not declare network_required"):
        adapter.fetch(ENDPOINT, purpose=PURPOSE)


def test_a_declaring_adapter_reaches_the_network_only_through_the_gate() -> None:
    class Networked(_Adapter):
        network_required = True

    transport = echo_transport(b"answer")
    adapter = Networked(open_gate(transport=transport))

    assert adapter.fetch(ENDPOINT, purpose=PURPOSE) == b"answer"
    assert len(adapter.gate.offline_audit()) == 1


def test_a_declaring_adapter_with_a_closed_gate_still_cannot_reach_it() -> None:
    class Networked(_Adapter):
        network_required = True

    adapter = Networked()

    with pytest.raises(NetworkRefused):
        adapter.fetch(ENDPOINT, purpose=PURPOSE)
