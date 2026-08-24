"""Map contribution records onto interoperable provenance vocabularies.

Three standards already describe parts of what a Human Contribution Record says,
and re-inventing them would leave TrueAI records readable only by TrueAI:

- **W3C PROV** describes who did what to which artifact, as a graph.
- **in-toto / DSSE** describes a signed statement about a subject's digest.
- **C2PA** describes assertions embedded in a media asset.

None of them expresses contribution *strength*, evidence status, or the
difference between a declaration and a machine fact. Those are the parts TrueAI
exists to keep separate, so they are not forced into a standard's vocabulary
where they would arrive looking like something they are not.

Every exporter here returns what it mapped **and** what it could not, through
:func:`unmapped_concepts`. An export that quietly drops the evidence status is
how "alice declared she originated this" becomes "alice originated this".
"""

from __future__ import annotations

import base64
import json
from typing import Any, Literal

from pydantic import Field

from trueai.core.attestation import (
    ActorKind,
    AiAutonomy,
    ArtifactBinding,
    BindingRole,
    ProcessAttestation,
    SignatureRole,
)
from trueai.core.certificates import canonical_json_bytes
from trueai.core.errors import AttestationError
from trueai.core.models import FrozenModel
from trueai.core.trust import SigningProvider

INTEROP_SCHEMA_VERSION = "0.1"

#: The predicate a TrueAI process attestation is carried under in an in-toto
#: statement. Versioned separately from the record schema so a consumer can pin it.
DSSE_PREDICATE_TYPE = "https://trueai.dev/attestation/process/v0.1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

#: The TrueAI namespace for PROV extension properties. Anything under this prefix
#: is a TrueAI concept the PROV vocabulary does not define, and is labelled as such.
PROV_NAMESPACE = "trueai"
PROV_NAMESPACE_URI = "https://trueai.dev/prov#"

#: IPTC digital source type codes. C2PA uses these to say how an asset was
#: produced. Only the two that a record can honestly establish are used.
_IPTC_TRAINED_ALGORITHMIC = "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
_IPTC_COMPOSITE_WITH_TRAINED = (
    "http://cv.iptc.org/newscodes/digitalsourcetype/compositeWithTrainedAlgorithmicMedia"
)

#: How much machine involvement each autonomy level licenses saying in C2PA terms.
#: ``assistive`` and ``proposal`` describe a human acting on machine suggestions,
#: which is not the same as the asset being machine-produced, so they map to the
#: composite code rather than the trained-algorithmic one.
_C2PA_SOURCE_TYPE: dict[AiAutonomy, str | None] = {
    AiAutonomy.NONE: None,
    AiAutonomy.ASSISTIVE: _IPTC_COMPOSITE_WITH_TRAINED,
    AiAutonomy.PROPOSAL: _IPTC_COMPOSITE_WITH_TRAINED,
    AiAutonomy.DELEGATED_EXECUTION: _IPTC_TRAINED_ALGORITHMIC,
    AiAutonomy.AUTONOMOUS_WITH_REVIEW: _IPTC_TRAINED_ALGORITHMIC,
}

_PROV_AGENT_TYPE = {
    ActorKind.PERSON: "prov:Person",
    ActorKind.ORGANIZATION: "prov:Organization",
    ActorKind.AI_SYSTEM: "prov:SoftwareAgent",
    ActorKind.AUTOMATION: "prov:SoftwareAgent",
}


class UnmappedConcept(FrozenModel):
    """One thing a target vocabulary cannot express, and why it matters."""

    concept: str
    reason: str


#: What every exporter leaves behind. Stated once, here, so no exporter can
#: quietly disagree with another about what it dropped.
_UNMAPPED: dict[str, tuple[UnmappedConcept, ...]] = {
    "prov": (
        UnmappedConcept(
            concept="contribution level per dimension",
            reason=(
                "PROV records that an agent was associated with an activity. It has no "
                "vocabulary for how much of it they carried, and inventing one under a "
                "prov: prefix would look like a standard term."
            ),
        ),
        UnmappedConcept(
            concept="evidence status",
            reason=(
                "PROV has no notion of how well a statement is corroborated, so a "
                "self-declared claim and an artifact-correlated one would export "
                "identically."
            ),
        ),
        UnmappedConcept(
            concept="claim type",
            reason=(
                "The difference between a machine fact, a declaration, and a subjective "
                "assessment has no PROV equivalent, and losing it is how a signed "
                "declaration reads as an established fact."
            ),
        ),
        UnmappedConcept(
            concept="standing limitations",
            reason=(
                "PROV has no field for what a record does not establish. A PROV export "
                "consumed on its own is missing them entirely."
            ),
        ),
    ),
    "dsse": (
        UnmappedConcept(
            concept="the record's own signatures",
            reason=(
                "DSSE signs a pre-authentication encoding of its payload. TrueAI "
                "signatures cover the record's canonical bytes, which are different "
                "bytes, so they cannot be copied into an envelope. Sign the envelope "
                "separately."
            ),
        ),
        UnmappedConcept(
            concept="per-role signature semantics",
            reason=(
                "A DSSE envelope carries a flat list of signatures. Claimant, reviewer, "
                "and assessor mean different things, and the envelope cannot say which "
                "is which."
            ),
        ),
    ),
    "c2pa": (
        UnmappedConcept(
            concept="contribution level per dimension",
            reason=(
                "C2PA actions describe what was done to an asset, not how much of it a "
                "given participant carried."
            ),
        ),
        UnmappedConcept(
            concept="evidence status and claim type",
            reason=(
                "A C2PA assertion is asserted by the manifest signer. It has no place "
                "to record how well the underlying statement is corroborated."
            ),
        ),
        UnmappedConcept(
            concept="dimensions other than execution",
            reason=(
                "Framing, decision control, validation, integration, and accountability "
                "have no C2PA action equivalents, so an assertion set describes only "
                "what was done to the bytes."
            ),
        ),
        UnmappedConcept(
            concept="assurance level",
            reason=(
                "C2PA has no equivalent of PAL, and the manifest's own signature says "
                "nothing about how well the process was evidenced."
            ),
        ),
    ),
}


def unmapped_concepts(target: Literal["prov", "dsse", "c2pa"]) -> tuple[UnmappedConcept, ...]:
    """Return what an export to ``target`` cannot carry.

    Callers that publish an export should publish this alongside it. A consumer
    who only sees the mapped half will read the record as stronger than it is.
    """

    try:
        return _UNMAPPED[target]
    except KeyError as exc:
        available = ", ".join(sorted(_UNMAPPED))
        raise KeyError(f"Unknown export target {target!r}; available: {available}") from exc


# -- W3C PROV ----------------------------------------------------------------------


def _prov_entity(binding: ArtifactBinding) -> dict[str, Any]:
    entity: dict[str, Any] = {
        "prov:label": binding.name,
        f"{PROV_NAMESPACE}:sha256": binding.sha256,
        f"{PROV_NAMESPACE}:role": binding.role.value,
    }
    if binding.media_type:
        entity["prov:type"] = binding.media_type
    if binding.size is not None:
        entity[f"{PROV_NAMESPACE}:size"] = binding.size
    if binding.relationship:
        entity[f"{PROV_NAMESPACE}:relationship"] = binding.relationship
    return entity


def to_prov(attestation: ProcessAttestation) -> dict[str, Any]:
    """Export the derivation graph as a PROV-JSON document.

    Activities, agents, and artifacts map cleanly, because that is exactly what
    PROV was designed for. Everything TrueAI adds on top sits under the
    ``trueai:`` prefix, so a PROV consumer can see at a glance which terms it is
    expected to understand and which are ours.
    """

    entities: dict[str, Any] = {}
    for binding in attestation.artifact_bindings:
        entities[f"{PROV_NAMESPACE}:{binding.id}"] = _prov_entity(binding)

    subject_key = f"{PROV_NAMESPACE}:subject"
    entities[subject_key] = {
        "prov:label": attestation.subject_name,
        f"{PROV_NAMESPACE}:sha256": attestation.subject_sha256,
        f"{PROV_NAMESPACE}:isInventory": attestation.subject_is_inventory,
    }

    agents: dict[str, Any] = {}
    for actor in attestation.actors:
        agent: dict[str, Any] = {
            "prov:type": _PROV_AGENT_TYPE[actor.kind],
            f"{PROV_NAMESPACE}:actorKind": actor.kind.value,
            f"{PROV_NAMESPACE}:pseudonymous": actor.pseudonymous,
        }
        if actor.display_name:
            agent["prov:label"] = actor.display_name
        if actor.identifier:
            agent[f"{PROV_NAMESPACE}:identifier"] = actor.identifier
        if actor.version:
            agent[f"{PROV_NAMESPACE}:version"] = actor.version
        agents[f"{PROV_NAMESPACE}:{actor.id}"] = agent

    activities: dict[str, Any] = {}
    associations: dict[str, Any] = {}
    used: dict[str, Any] = {}
    generated: dict[str, Any] = {}
    for activity in attestation.activities:
        key = f"{PROV_NAMESPACE}:{activity.id}"
        entry: dict[str, Any] = {
            "prov:label": activity.action,
            f"{PROV_NAMESPACE}:aiAutonomy": activity.ai_autonomy.value,
            f"{PROV_NAMESPACE}:reviewDecision": activity.review_decision.value,
            # A rejected attempt is part of the process. PROV has no term for it,
            # so it is labelled rather than dropped.
            f"{PROV_NAMESPACE}:superseded": activity.superseded,
        }
        if activity.started_at:
            entry["prov:startTime"] = activity.started_at.isoformat()
        if activity.ended_at:
            entry["prov:endTime"] = activity.ended_at.isoformat()
        activities[key] = entry

        for actor_id in activity.actor_ids:
            associations[f"{PROV_NAMESPACE}:{activity.id}-{actor_id}"] = {
                "prov:activity": key,
                "prov:agent": f"{PROV_NAMESPACE}:{actor_id}",
            }
        for binding_id in activity.input_binding_ids:
            used[f"{PROV_NAMESPACE}:{activity.id}-used-{binding_id}"] = {
                "prov:activity": key,
                "prov:entity": f"{PROV_NAMESPACE}:{binding_id}",
            }
        for binding_id in activity.output_binding_ids:
            generated[f"{PROV_NAMESPACE}:{activity.id}-gen-{binding_id}"] = {
                "prov:entity": f"{PROV_NAMESPACE}:{binding_id}",
                "prov:activity": key,
            }

    attributions: dict[str, Any] = {}
    for claim in attestation.claims:
        # wasAttributedTo is the closest PROV relation, and it deliberately carries
        # no strength. The dimension and level ride along as trueai: properties so
        # nothing reads them as standard PROV terms.
        attributions[f"{PROV_NAMESPACE}:{claim.dimension.value}-{claim.actor_id}"] = {
            "prov:entity": subject_key,
            "prov:agent": f"{PROV_NAMESPACE}:{claim.actor_id}",
            f"{PROV_NAMESPACE}:dimension": claim.dimension.value,
            f"{PROV_NAMESPACE}:level": claim.level.value,
            f"{PROV_NAMESPACE}:evidenceStatus": claim.evidence_status.value,
            f"{PROV_NAMESPACE}:claimType": claim.claim_type.value,
            f"{PROV_NAMESPACE}:aiAutonomy": claim.ai_autonomy.value,
        }

    document: dict[str, Any] = {
        "prefix": {
            PROV_NAMESPACE: PROV_NAMESPACE_URI,
            "prov": "http://www.w3.org/ns/prov#",
        },
        "entity": entities,
        "agent": agents,
        f"{PROV_NAMESPACE}:attestationId": attestation.attestation_id,
        f"{PROV_NAMESPACE}:limitations": [
            {"code": limitation.code, "statement": limitation.statement}
            for limitation in attestation.limitations
        ],
        f"{PROV_NAMESPACE}:unmapped": [
            {"concept": item.concept, "reason": item.reason} for item in unmapped_concepts("prov")
        ],
    }
    if activities:
        document["activity"] = activities
    if associations:
        document["wasAssociatedWith"] = associations
    if used:
        document["used"] = used
    if generated:
        document["wasGeneratedBy"] = generated
    if attributions:
        document["wasAttributedTo"] = attributions
    return document


# -- in-toto / DSSE ----------------------------------------------------------------


def to_in_toto_statement(attestation: ProcessAttestation) -> dict[str, Any]:
    """Wrap the record as an in-toto Statement about its subject's digest.

    The predicate is the record itself minus its signatures, because an envelope
    signature covers different bytes than a record signature and carrying both
    would suggest the two are interchangeable.
    """

    return {
        "_type": IN_TOTO_STATEMENT_TYPE,
        "subject": [
            {
                "name": attestation.subject_name,
                "digest": {"sha256": attestation.subject_sha256},
            }
        ],
        "predicateType": DSSE_PREDICATE_TYPE,
        "predicate": attestation.model_dump(mode="json", exclude={"signatures"}),
    }


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """Return the DSSE pre-authentication encoding.

    ``DSSEv1 <len(type)> <type> <len(payload)> <payload>``. Signing the payload
    directly would let a signature be replayed under a different payload type.
    """

    header = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(header), header, len(payload), payload)


class DsseSignature(FrozenModel):
    """One signature over a DSSE envelope's pre-authentication encoding."""

    keyid: str
    sig: str


class DsseEnvelope(FrozenModel):
    """A DSSE envelope carrying an in-toto statement.

    Deliberately not a drop-in replacement for a signed record: the envelope's
    signatures are new, made over the PAE, and carry no role. Verify a record as
    a record; use the envelope to hand it to an in-toto-shaped consumer.
    """

    payload: str
    payloadType: str = DSSE_PAYLOAD_TYPE
    signatures: tuple[DsseSignature, ...] = Field(default=(), max_length=50)


def to_dsse_envelope(
    attestation: ProcessAttestation,
    *,
    providers: tuple[SigningProvider, ...] = (),
) -> DsseEnvelope:
    """Return a DSSE envelope, signed by each provider over the PAE.

    ``providers`` is empty by default and the result is then an unsigned
    envelope, which is a legitimate thing to produce and a useless thing to
    trust. The record's own signatures are never copied in: they cover the
    record's canonical bytes, not the PAE, and a signature that does not verify
    over what it appears to cover is worse than no signature.
    """

    payload = canonical_json_bytes(to_in_toto_statement(attestation))
    encoded = base64.b64encode(payload).decode("ascii")
    to_sign = dsse_pae(DSSE_PAYLOAD_TYPE, payload)
    signatures = tuple(
        DsseSignature(keyid=provider.key_id(), sig=provider.sign(to_sign).value)
        for provider in providers
    )
    return DsseEnvelope(payload=encoded, signatures=signatures)


def in_toto_statement_from_envelope(envelope: DsseEnvelope) -> dict[str, Any]:
    """Decode an envelope's payload back to its statement.

    Used to check that an export round-trips rather than assuming it does.
    """

    try:
        decoded = base64.b64decode(envelope.payload, validate=True)
    except (ValueError, TypeError) as exc:
        raise AttestationError(f"Envelope payload is not valid base64: {exc}") from exc
    try:
        statement: Any = json.loads(decoded)
    except json.JSONDecodeError as exc:
        raise AttestationError(f"Envelope payload is not valid JSON: {exc}") from exc
    if not isinstance(statement, dict):
        raise AttestationError("Envelope payload is not a JSON object")
    return statement


# -- C2PA --------------------------------------------------------------------------


def to_c2pa_assertions(attestation: ProcessAttestation) -> list[dict[str, Any]]:
    """Return C2PA-shaped assertions a manifest-signing tool can embed.

    TrueAI does not sign, embed, or produce C2PA manifests. It produces the
    assertion data, conservatively: an action is emitted only where the record
    documents one, and a digital source type only where the autonomy level
    actually licenses saying it.
    """

    actions: list[dict[str, Any]] = []
    actors = {actor.id: actor for actor in attestation.actors}
    for activity in attestation.activities:
        if activity.superseded:
            # A superseded attempt did not produce the delivered asset. Asserting
            # it as an action on that asset would describe work the bytes do not
            # carry.
            continue
        produced_output = bool(activity.output_binding_ids)
        action: dict[str, Any] = {
            "action": "c2pa.created" if produced_output else "c2pa.edited",
            "description": activity.action,
        }
        source_type = _C2PA_SOURCE_TYPE[activity.ai_autonomy]
        if source_type is not None:
            action["digitalSourceType"] = source_type
        software = [
            actors[actor_id].display_name or actor_id
            for actor_id in activity.actor_ids
            if actor_id in actors and actors[actor_id].kind == ActorKind.AI_SYSTEM
        ]
        if software:
            action["softwareAgent"] = ", ".join(software)
        if activity.ended_at:
            action["when"] = activity.ended_at.isoformat()
        actions.append(action)

    assertions: list[dict[str, Any]] = []
    if actions:
        assertions.append({"label": "c2pa.actions", "data": {"actions": actions}})

    people = [
        {"@type": "Person", "name": actor.display_name or actor.id}
        for actor in attestation.actors
        if actor.kind == ActorKind.PERSON and not actor.pseudonymous
    ]
    if people:
        # schema.org creator, not "author". A record establishes participation,
        # and C2PA's own vocabulary is the one place this is easiest to overstate.
        assertions.append(
            {
                "label": "stds.schema-org.CreativeWork",
                "data": {
                    "@context": "https://schema.org",
                    "@type": "CreativeWork",
                    "creator": people,
                },
            }
        )

    assertions.append(
        {
            "label": "trueai.process-attestation",
            "data": {
                "attestationId": attestation.attestation_id,
                "schemaVersion": attestation.schema_version,
                "subjectSha256": attestation.subject_sha256,
                "limitations": [
                    {"code": limitation.code, "statement": limitation.statement}
                    for limitation in attestation.limitations
                ],
                "unmapped": [
                    {"concept": item.concept, "reason": item.reason}
                    for item in unmapped_concepts("c2pa")
                ],
            },
        }
    )
    return assertions


# -- summary -----------------------------------------------------------------------


def interop_summary(attestation: ProcessAttestation) -> str:
    """Describe what each export carries and what it leaves behind."""

    lines = [f"Interoperable exports for {attestation.attestation_id}", ""]
    counts = {
        "W3C PROV": (
            f"{len(attestation.activities)} activities, {len(attestation.actors)} agents, "
            f"{len(attestation.artifact_bindings) + 1} entities, "
            f"{len(attestation.claims)} attributions"
        ),
        "in-toto / DSSE": (
            f"1 statement over {attestation.subject_name}, predicate {DSSE_PREDICATE_TYPE}"
        ),
        "C2PA": f"{len(to_c2pa_assertions(attestation))} assertions",
    }
    for target, mapped in counts.items():
        lines.append(f"{target}: {mapped}")
    lines.append("")
    lines.append("Not expressible in these vocabularies, and kept TrueAI-specific:")
    seen: set[str] = set()
    targets: tuple[Literal["prov", "dsse", "c2pa"], ...] = ("prov", "dsse", "c2pa")
    for key in targets:
        for item in unmapped_concepts(key):
            if item.concept in seen:
                continue
            seen.add(item.concept)
            lines.append(f"  - {item.concept}")
    return "\n".join(lines)


__all__ = [
    "DSSE_PAYLOAD_TYPE",
    "DSSE_PREDICATE_TYPE",
    "INTEROP_SCHEMA_VERSION",
    "IN_TOTO_STATEMENT_TYPE",
    "PROV_NAMESPACE",
    "PROV_NAMESPACE_URI",
    "DsseEnvelope",
    "DsseSignature",
    "UnmappedConcept",
    "dsse_pae",
    "in_toto_statement_from_envelope",
    "interop_summary",
    "to_c2pa_assertions",
    "to_dsse_envelope",
    "to_in_toto_statement",
    "to_prov",
    "unmapped_concepts",
]


# ``BindingRole`` and ``SignatureRole`` are imported for the type-checked mapping
# above; re-export them so a consumer of this module does not have to reach into
# the attestation module for the vocabulary the exports reference.
_ROLE_VOCABULARY = (BindingRole, SignatureRole)
