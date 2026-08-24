"""Interoperable exports: W3C PROV, in-toto/DSSE, and C2PA assertions.

The exports exist so a TrueAI record is readable by tools that were not written
for TrueAI. The risk in every one of them is the same: a standard vocabulary
makes a claim look established, so each test checks both what was carried and
what was refused.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from trueai.cli.app import app
from trueai.core.attestation import (
    Activity,
    Actor,
    ActorKind,
    AiAutonomy,
    ArtifactBinding,
    BindingRole,
    ClaimType,
    ContributionClaim,
    ContributionDimension,
    ContributionLevel,
    EvidenceStatus,
    ProcessAttestation,
    ReviewDecision,
    attestation_json,
    issue_attestation,
)
from trueai.core.certificates import generate_ed25519_keypair, verify_detached_payload
from trueai.core.interop import (
    DSSE_PAYLOAD_TYPE,
    DSSE_PREDICATE_TYPE,
    IN_TOTO_STATEMENT_TYPE,
    PROV_NAMESPACE,
    dsse_pae,
    in_toto_statement_from_envelope,
    interop_summary,
    to_c2pa_assertions,
    to_dsse_envelope,
    to_in_toto_statement,
    to_prov,
    unmapped_concepts,
)
from trueai.core.trust import LocalKeySigningProvider

pytest.importorskip("cryptography", reason="Signing needs the attestation extra")

runner = CliRunner()

NOW = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
DIGEST = hashlib.sha256(b"deliverable").hexdigest()

ALICE = Actor(id="alice", kind=ActorKind.PERSON, display_name="Alice", identifier="alice@acme")
ASSISTANT = Actor(id="assistant", kind=ActorKind.AI_SYSTEM, display_name="Assistant", version="2")
NOBODY = Actor(id="nobody", kind=ActorKind.PERSON, pseudonymous=True)

SOURCE = ArtifactBinding(
    id="source",
    role=BindingRole.INPUT,
    name="notes.md",
    sha256="a" * 64,
    media_type="text/markdown",
    size=120,
)
OUTPUT = ArtifactBinding(
    id="output",
    role=BindingRole.OUTPUT,
    name="deliverable.md",
    sha256=DIGEST,
    media_type="text/markdown",
)


def claim(
    dimension: ContributionDimension,
    actor: str,
    level: ContributionLevel = ContributionLevel.PRIMARY,
    *,
    autonomy: AiAutonomy = AiAutonomy.NONE,
) -> ContributionClaim:
    return ContributionClaim(
        dimension=dimension,
        actor_id=actor,
        claim_type=ClaimType.DECLARATION,
        level=level,
        evidence_status=EvidenceStatus.SELF_DECLARED,
        ai_autonomy=autonomy,
        explanation=f"{actor} contributed to {dimension.value}.",
    )


def record(**extra: object) -> ProcessAttestation:
    """A record with a real derivation graph: inputs, an activity, an output."""

    return issue_attestation(
        subject_sha256=DIGEST,
        subject_name="deliverable.md",
        actors=(ALICE, ASSISTANT, NOBODY),
        artifact_bindings=(SOURCE, OUTPUT),
        activities=(
            Activity(
                id="draft",
                action="Generated the draft from the notes",
                actor_ids=("assistant",),
                started_at=NOW,
                ended_at=NOW,
                input_binding_ids=("source",),
                output_binding_ids=("output",),
                ai_autonomy=AiAutonomy.DELEGATED_EXECUTION,
                review_decision=ReviewDecision.ACCEPTED_WITH_CHANGES,
                reviewer_actor_id="alice",
            ),
            Activity(
                id="abandoned",
                action="A first attempt that was thrown away",
                actor_ids=("assistant",),
                ai_autonomy=AiAutonomy.DELEGATED_EXECUTION,
                superseded=True,
            ),
        ),
        claims=(
            claim(ContributionDimension.ORIGINATION, "alice"),
            claim(
                ContributionDimension.EXECUTION,
                "assistant",
                autonomy=AiAutonomy.DELEGATED_EXECUTION,
            ),
        ),
        created_at=NOW,
        **extra,  # type: ignore[arg-type]
    )


# -- W3C PROV ------------------------------------------------------------------------


def test_the_prov_graph_carries_agents_activities_and_entities() -> None:
    document = to_prov(record())

    assert set(document["agent"]) == {
        f"{PROV_NAMESPACE}:alice",
        f"{PROV_NAMESPACE}:assistant",
        f"{PROV_NAMESPACE}:nobody",
    }
    assert set(document["activity"]) == {
        f"{PROV_NAMESPACE}:draft",
        f"{PROV_NAMESPACE}:abandoned",
    }
    assert f"{PROV_NAMESPACE}:output" in document["entity"]
    assert document["used"][f"{PROV_NAMESPACE}:draft-used-source"] == {
        "prov:activity": f"{PROV_NAMESPACE}:draft",
        "prov:entity": f"{PROV_NAMESPACE}:source",
    }
    assert document["wasGeneratedBy"][f"{PROV_NAMESPACE}:draft-gen-output"] == {
        "prov:entity": f"{PROV_NAMESPACE}:output",
        "prov:activity": f"{PROV_NAMESPACE}:draft",
    }


def test_an_ai_actor_maps_to_a_software_agent() -> None:
    """A PROV consumer must be able to tell a person from a model."""

    document = to_prov(record())

    assert document["agent"][f"{PROV_NAMESPACE}:alice"]["prov:type"] == "prov:Person"
    assert document["agent"][f"{PROV_NAMESPACE}:assistant"]["prov:type"] == "prov:SoftwareAgent"


def test_a_superseded_attempt_stays_in_the_prov_graph() -> None:
    """A record that hides rejected attempts describes a process that did not happen."""

    document = to_prov(record())

    abandoned = document["activity"][f"{PROV_NAMESPACE}:abandoned"]
    assert abandoned[f"{PROV_NAMESPACE}:superseded"] is True


def test_contribution_strength_never_uses_a_prov_prefix() -> None:
    """Inventing a prov: term for a TrueAI concept would look like a standard one."""

    document = to_prov(record())

    attribution = next(iter(document["wasAttributedTo"].values()))
    trueai_keys = {key for key in attribution if key.startswith(f"{PROV_NAMESPACE}:")}
    prov_keys = {key for key in attribution if key.startswith("prov:")}

    assert prov_keys == {"prov:entity", "prov:agent"}
    assert f"{PROV_NAMESPACE}:level" in trueai_keys
    assert f"{PROV_NAMESPACE}:evidenceStatus" in trueai_keys
    assert f"{PROV_NAMESPACE}:claimType" in trueai_keys


def test_the_prov_export_carries_its_own_limitations_and_gaps() -> None:
    document = to_prov(record())

    assert len(document[f"{PROV_NAMESPACE}:limitations"]) >= 4
    concepts = {item["concept"] for item in document[f"{PROV_NAMESPACE}:unmapped"]}
    assert "contribution level per dimension" in concepts
    assert "evidence status" in concepts


def test_the_prov_document_declares_both_prefixes() -> None:
    document = to_prov(record())

    assert document["prefix"]["prov"] == "http://www.w3.org/ns/prov#"
    assert document["prefix"][PROV_NAMESPACE].startswith("https://")


def test_a_record_with_no_activities_omits_the_empty_relations() -> None:
    """An empty PROV relation map is noise a consumer has to special-case."""

    minimal = issue_attestation(
        subject_sha256=DIGEST,
        subject_name="deliverable.md",
        actors=(ALICE,),
        claims=(claim(ContributionDimension.ORIGINATION, "alice"),),
    )

    document = to_prov(minimal)

    assert "activity" not in document
    assert "used" not in document
    assert "wasAttributedTo" in document


# -- in-toto / DSSE ------------------------------------------------------------------


def test_the_statement_binds_the_subject_by_digest() -> None:
    statement = to_in_toto_statement(record())

    assert statement["_type"] == IN_TOTO_STATEMENT_TYPE
    assert statement["predicateType"] == DSSE_PREDICATE_TYPE
    assert statement["subject"] == [{"name": "deliverable.md", "digest": {"sha256": DIGEST}}]


def test_the_predicate_excludes_the_records_own_signatures(tmp_path: Path) -> None:
    """Envelope signatures and record signatures cover different bytes."""

    from trueai.core.attestation import SignatureRole, sign_attestation

    private, _ = tmp_path / "alice.key", tmp_path / "alice.pub"
    generate_ed25519_keypair(private, tmp_path / "alice.pub")
    signed = sign_attestation(
        record(), role=SignatureRole.CLAIMANT, actor_id="alice", signing_key=private
    )

    statement = to_in_toto_statement(signed)

    assert signed.signatures
    assert "signatures" not in statement["predicate"]


def test_the_envelope_round_trips_to_its_statement() -> None:
    envelope = to_dsse_envelope(record())

    assert envelope.payloadType == DSSE_PAYLOAD_TYPE
    assert in_toto_statement_from_envelope(envelope) == to_in_toto_statement(record())


def test_an_unsigned_envelope_is_produced_without_pretending_otherwise() -> None:
    envelope = to_dsse_envelope(record())

    assert envelope.signatures == ()


def test_an_envelope_signature_verifies_over_the_pae(tmp_path: Path) -> None:
    """Signing the payload directly would let a signature be replayed."""

    private, public = tmp_path / "alice.key", tmp_path / "alice.pub"
    generate_ed25519_keypair(private, public)

    envelope = to_dsse_envelope(record(), providers=(LocalKeySigningProvider(private),))

    payload = base64.b64decode(envelope.payload)
    signature = envelope.signatures[0]
    assert verify_detached_payload(
        _certificate_signature(signature, public), dsse_pae(DSSE_PAYLOAD_TYPE, payload), public
    )
    # The same signature must not verify over the bare payload.
    assert not verify_detached_payload(_certificate_signature(signature, public), payload, public)


def _certificate_signature(signature: object, public_key: Path) -> object:
    """Rebuild a CertificateSignature from a DSSE signature for verification."""

    from trueai.core.certificates import CertificateSignature
    from trueai.core.trust import public_key_id

    assert hasattr(signature, "sig")
    return CertificateSignature(
        algorithm="ed25519",
        key_id=public_key_id(public_key),
        value=signature.sig,  # type: ignore[attr-defined]
    )


def test_the_pae_encodes_the_payload_type_and_length() -> None:
    encoded = dsse_pae("application/example", b"payload")

    assert encoded == b"DSSEv1 19 application/example 7 payload"


def test_a_corrupt_envelope_payload_is_refused() -> None:
    from trueai.core.errors import AttestationError
    from trueai.core.interop import DsseEnvelope

    with pytest.raises(AttestationError):
        in_toto_statement_from_envelope(DsseEnvelope(payload="not base64 !!"))


def test_the_dsse_gaps_name_the_role_semantics_that_are_lost() -> None:
    concepts = {item.concept for item in unmapped_concepts("dsse")}

    assert "per-role signature semantics" in concepts
    assert "the record's own signatures" in concepts


# -- C2PA ----------------------------------------------------------------------------


def test_delegated_execution_maps_to_the_trained_algorithmic_source_type() -> None:
    assertions = to_c2pa_assertions(record())

    actions = next(item for item in assertions if item["label"] == "c2pa.actions")
    action = actions["data"]["actions"][0]
    assert action["digitalSourceType"].endswith("trainedAlgorithmicMedia")
    assert action["softwareAgent"] == "Assistant"


def test_assistive_autonomy_does_not_claim_the_asset_was_machine_produced() -> None:
    """A human acting on suggestions is not a machine-produced asset."""

    assisted = issue_attestation(
        subject_sha256=DIGEST,
        subject_name="deliverable.md",
        actors=(ALICE, ASSISTANT),
        artifact_bindings=(OUTPUT,),
        activities=(
            Activity(
                id="write",
                action="Alice wrote it with completion suggestions",
                actor_ids=("alice", "assistant"),
                output_binding_ids=("output",),
                ai_autonomy=AiAutonomy.ASSISTIVE,
            ),
        ),
        claims=(claim(ContributionDimension.EXECUTION, "alice"),),
    )

    assertions = to_c2pa_assertions(assisted)
    action = next(item for item in assertions if item["label"] == "c2pa.actions")["data"][
        "actions"
    ][0]

    assert action["digitalSourceType"].endswith("compositeWithTrainedAlgorithmicMedia")


def test_purely_human_work_gets_no_digital_source_type() -> None:
    """Absence of a code is the honest output. A wrong code is worse than none."""

    human = issue_attestation(
        subject_sha256=DIGEST,
        subject_name="deliverable.md",
        actors=(ALICE,),
        artifact_bindings=(OUTPUT,),
        activities=(
            Activity(
                id="write",
                action="Alice wrote it",
                actor_ids=("alice",),
                output_binding_ids=("output",),
            ),
        ),
        claims=(claim(ContributionDimension.EXECUTION, "alice"),),
    )

    assertions = to_c2pa_assertions(human)
    action = next(item for item in assertions if item["label"] == "c2pa.actions")["data"][
        "actions"
    ][0]

    assert "digitalSourceType" not in action
    assert "softwareAgent" not in action


def test_a_superseded_attempt_is_not_asserted_against_the_delivered_asset() -> None:
    """C2PA assertions describe the bytes. A discarded attempt is not in them."""

    assertions = to_c2pa_assertions(record())

    actions = next(item for item in assertions if item["label"] == "c2pa.actions")
    descriptions = [action["description"] for action in actions["data"]["actions"]]
    assert "A first attempt that was thrown away" not in descriptions
    assert len(descriptions) == 1


def test_a_pseudonymous_actor_is_not_named_in_a_public_assertion() -> None:
    assertions = to_c2pa_assertions(record())

    creative = next(item for item in assertions if item["label"] == "stds.schema-org.CreativeWork")
    names = {person["name"] for person in creative["data"]["creator"]}
    assert names == {"Alice"}
    assert "nobody" not in json.dumps(creative)


def test_the_c2pa_assertions_describe_creators_not_authors() -> None:
    """C2PA's vocabulary is where overstating participation is easiest.

    The standing limitations do say "authorship", because denying it is their
    whole purpose. What must not appear is an assertion field claiming it.
    """

    assertions = to_c2pa_assertions(record())
    creative = next(item for item in assertions if item["label"] == "stds.schema-org.CreativeWork")
    limitations = next(
        item for item in assertions if item["label"] == "trueai.process-attestation"
    )["data"].pop("limitations")

    assert "creator" in creative["data"]
    assert "author" not in json.dumps(assertions).lower()
    assert any("exclusive human authorship" in item["statement"] for item in limitations)


def test_the_c2pa_export_carries_the_limitations_and_the_gaps() -> None:
    assertions = to_c2pa_assertions(record())

    trueai = next(item for item in assertions if item["label"] == "trueai.process-attestation")
    assert len(trueai["data"]["limitations"]) >= 4
    concepts = {item["concept"] for item in trueai["data"]["unmapped"]}
    assert "assurance level" in concepts


# -- summary and CLI -----------------------------------------------------------------


def test_the_interop_summary_names_what_is_kept_trueai_specific() -> None:
    summary = interop_summary(record())

    assert "W3C PROV" in summary
    assert "in-toto / DSSE" in summary
    assert "C2PA" in summary
    assert "contribution level per dimension" in summary


def test_an_unknown_export_target_names_the_ones_that_exist() -> None:
    with pytest.raises(KeyError, match="prov"):
        unmapped_concepts("rdf")  # type: ignore[arg-type]


def written(attestation: ProcessAttestation, tmp_path: Path) -> Path:
    destination = tmp_path / "record.process.json"
    destination.write_text(attestation_json(attestation) + "\n", encoding="utf-8")
    return destination


def test_the_cli_exports_prov(tmp_path: Path) -> None:
    path = written(record(), tmp_path)

    result = runner.invoke(app, ["attestations", "export", str(path), "--to", "prov"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["prefix"]["prov"]


def test_the_cli_exports_a_signed_dsse_envelope(tmp_path: Path) -> None:
    path = written(record(), tmp_path)
    private, public = tmp_path / "alice.key", tmp_path / "alice.pub"
    generate_ed25519_keypair(private, public)
    destination = tmp_path / "envelope.json"

    result = runner.invoke(
        app,
        [
            "attestations",
            "export",
            str(path),
            "--to",
            "dsse",
            "--signing-key",
            str(private),
            "--output",
            str(destination),
        ],
    )

    assert result.exit_code == 0, result.output
    envelope = json.loads(destination.read_text(encoding="utf-8"))
    assert envelope["payloadType"] == DSSE_PAYLOAD_TYPE
    assert len(envelope["signatures"]) == 1


def test_the_cli_refuses_a_signing_key_for_a_target_that_cannot_use_it(
    tmp_path: Path,
) -> None:
    path = written(record(), tmp_path)
    private, public = tmp_path / "alice.key", tmp_path / "alice.pub"
    generate_ed25519_keypair(private, public)

    result = runner.invoke(
        app,
        ["attestations", "export", str(path), "--to", "prov", "--signing-key", str(private)],
    )

    assert result.exit_code == 3
    assert "only to --to dsse" in result.output


def test_the_cli_reports_what_each_export_leaves_behind(tmp_path: Path) -> None:
    path = written(record(), tmp_path)

    result = runner.invoke(app, ["attestations", "interop", str(path)])

    assert result.exit_code == 0, result.output
    assert "Not expressible" in result.output
    assert "contribution level per dimension" in result.output
