"""Declarative manifests, summaries, and redaction for process attestations.

Writing a record by hand in Python is fine for a tool; the people who actually
need to declare their contribution are writing a YAML file and running one
command. This module turns that file into a validated record, renders a record
into prose that repeats its own limitations, and produces a public variant that
provably carries no private material.

Redaction is deterministic and verifiable: a redacted record is produced by a
stated rule, and a test can assert that nothing withheld survives. "We removed
the private bits" is not a security property unless someone can check it.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

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
    Decision,
    DisclosureStatus,
    Evaluation,
    EvidenceKind,
    EvidenceReference,
    EvidenceStatus,
    Limitation,
    ProcessAttestation,
    ReviewDecision,
    ValidationRecord,
    issue_attestation,
)
from trueai.core.errors import AttestationError

MAX_MANIFEST_BYTES = 4 * 1024 * 1024

#: A starter manifest that is valid, honest, and obviously incomplete. It claims
#: nothing it cannot support, so a user who runs `issue` without editing it gets a
#: record that says almost nothing rather than a record that overclaims.
TEMPLATE_MANIFEST = """\
# TrueAI process attestation manifest.
#
# This describes who did what. Nothing here is inferred from a scan: a scanner
# can tell you what is in the bytes, never who decided what.
#
# Fill in only what you can support. A dimension you leave out stays
# `not_claimed`, which is a valid and honest answer.

project:
  title: Example deliverable
  purpose: What this work was for.

subject:
  # The file the record is about. Its digest is computed at issue time.
  name: deliverable.md

actors:
  - id: author
    kind: person
    display_name: Your Name
  - id: assistant
    kind: ai_system
    display_name: Name of the AI tool you used
    version: "1.0"

# Evidence is referenced by digest. Files are never copied into the record.
evidence:
  - id: notes
    kind: research_note
    description: Working notes for the central idea
    disclosure: private
    # path: notes.md          # uncomment to bind this note by digest

activities:
  - id: draft
    action: Produced the first draft
    actors: [assistant]
    ai_autonomy: delegated_execution
    review_decision: accepted_with_changes
    reviewer: author

claims:
  - dimension: origination
    actor: author
    claim_type: declaration
    level: originating_or_controlling
    evidence_status: self_declared
    explanation: >-
      Describe, specifically, what you introduced. "I had the idea" is weaker
      than naming the idea.

  - dimension: execution
    actor: assistant
    claim_type: declaration
    level: primary
    ai_autonomy: delegated_execution
    evidence_status: self_declared
    explanation: The assistant produced the concrete text from the stated direction.

  - dimension: accountability
    actor: author
    claim_type: declaration
    level: originating_or_controlling
    evidence_status: self_declared
    explanation: Name who stands behind the delivered result.
"""


def template_manifest() -> str:
    """Return a starter manifest that overclaims nothing."""

    return TEMPLATE_MANIFEST


def load_manifest(path: str | Path) -> dict[str, Any]:
    """Read and parse a manifest within a bounded read."""

    source = Path(path)
    try:
        size = source.stat().st_size
    except OSError as exc:
        raise AttestationError(f"Manifest is unreadable: {exc}") from exc
    if size > MAX_MANIFEST_BYTES:
        raise AttestationError(f"Manifest is {size} bytes; limit is {MAX_MANIFEST_BYTES}")
    try:
        raw = yaml.safe_load(source.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise AttestationError(f"Invalid manifest: {exc}") from exc
    if not isinstance(raw, dict):
        raise AttestationError("A manifest must contain a mapping")
    return raw


def build_attestation(
    manifest: dict[str, Any],
    *,
    artifact: str | Path | None = None,
    base_directory: str | Path | None = None,
    valid_for_days: int | None = None,
    created_at: datetime | None = None,
) -> ProcessAttestation:
    """Turn a validated manifest into an unsigned record bound to exact bytes."""

    base = Path(base_directory) if base_directory else Path.cwd()
    subject = manifest.get("subject") or {}
    if not isinstance(subject, dict):
        raise AttestationError("`subject` must be a mapping")

    if artifact is not None:
        artifact_path = Path(artifact)
        subject_name = str(subject.get("name") or artifact_path.name)
        subject_sha256 = _digest_file(artifact_path)
        subject_is_inventory = False
    else:
        declared = subject.get("sha256")
        if not isinstance(declared, str):
            raise AttestationError(
                "Provide the subject artifact, or declare subject.sha256 in the manifest"
            )
        subject_name = str(subject.get("name") or "subject")
        subject_sha256 = declared
        subject_is_inventory = bool(subject.get("is_inventory", False))

    actors = _actors(manifest)
    evidence = _evidence(manifest, base)
    bindings = _bindings(manifest, base)
    activities = _activities(manifest)
    decisions = _decisions(manifest)
    validations = _validations(manifest)
    claims = _claims(manifest)
    evaluation = _evaluation(manifest)
    extra = tuple(
        Limitation(code=str(item["code"]), statement=str(item["statement"]))
        for item in _sequence(manifest, "limitations")
        if isinstance(item, dict) and "code" in item and "statement" in item
    )

    project = manifest.get("project") or {}
    if not isinstance(project, dict):
        raise AttestationError("`project` must be a mapping")

    issued_at = created_at or datetime.now(UTC)
    return issue_attestation(
        subject_sha256=subject_sha256,
        subject_name=subject_name,
        subject_is_inventory=subject_is_inventory,
        actors=actors,
        claims=claims,
        artifact_bindings=bindings,
        activities=activities,
        decisions=decisions,
        validations=validations,
        evidence=evidence,
        evaluation=evaluation,
        extra_limitations=extra,
        project_title=_optional_str(project.get("title")),
        project_purpose=_optional_str(project.get("purpose")),
        policy_context=_optional_str(project.get("policy_context")),
        parent_attestation_id=_optional_str(project.get("parent")),
        created_at=issued_at,
        expires_at=(issued_at + timedelta(days=valid_for_days) if valid_for_days else None),
    )


# -- redaction ---------------------------------------------------------------------


def redact_for_public(attestation: ProcessAttestation) -> ProcessAttestation:
    """Return a public variant that carries no withheld material.

    The rule is stated rather than improvised: private and committed evidence
    keeps its identifier, kind, disclosure status, and commitment, and loses its
    digest, issuer, collection method, and description. Omitted evidence keeps its
    stated reason, because a visible refusal is the point of that status.

    Claims, activities, decisions, and validations are kept in full. They are what
    the record is *for*, and a public record that hides its own claims attests to
    nothing. What the redaction removes is the material that could identify or
    reveal private sources.

    The identifier changes, because the redacted record is a different document
    making a narrower set of statements. Reusing the original identifier would let
    a reader believe they had verified the full record.
    """

    redacted_evidence = tuple(_redact_evidence(reference) for reference in attestation.evidence)
    redacted_decisions = tuple(
        decision.model_copy(update={"rationale": None})
        if decision.rationale and decision.rationale_commitment
        else decision
        for decision in attestation.decisions
    )
    rebuilt = attestation.model_copy(
        update={
            "evidence": redacted_evidence,
            "decisions": redacted_decisions,
            # A signature covers the unredacted bytes and cannot cover these.
            "signatures": (),
            "attestation_id": attestation.attestation_id,
        }
    )
    from trueai.core.attestation import compute_attestation_id

    return rebuilt.model_copy(update={"attestation_id": compute_attestation_id(rebuilt)})


def _redact_evidence(reference: EvidenceReference) -> EvidenceReference:
    if reference.disclosure == DisclosureStatus.PUBLIC:
        return reference
    if reference.disclosure == DisclosureStatus.OMITTED:
        return reference
    return reference.model_copy(
        update={
            "description": f"Withheld {reference.kind.value} evidence",
            "sha256": None,
            "issuer": None,
            "collection_method": None,
            "locator": None,
        }
    )


def private_material(attestation: ProcessAttestation) -> tuple[str, ...]:
    """Return every string a public variant must not contain.

    Used by the redaction tests to assert leakage rather than assume it away.
    """

    leaking: list[str] = []
    for reference in attestation.evidence:
        if reference.disclosure in {DisclosureStatus.PUBLIC, DisclosureStatus.OMITTED}:
            continue
        leaking.append(reference.description)
        if reference.sha256:
            leaking.append(reference.sha256)
        if reference.issuer:
            leaking.append(reference.issuer)
        if reference.collection_method:
            leaking.append(reference.collection_method)
        if reference.locator:
            leaking.append(reference.locator)
    for decision in attestation.decisions:
        if decision.rationale and decision.rationale_commitment:
            leaking.append(decision.rationale)
    return tuple(item for item in leaking if item)


# -- summary -----------------------------------------------------------------------


def summarize(attestation: ProcessAttestation) -> str:
    """Render a human-readable summary that repeats its own limitations.

    Every summary ends with the limitations because a summary is exactly where a
    reader stops reading. A stage table without them invites the inference the
    whole model exists to prevent.
    """

    actors = {actor.id: actor for actor in attestation.actors}
    lines: list[str] = []
    lines.append(f"Process attestation {attestation.attestation_id}")
    if attestation.project_title:
        lines.append(f"Project: {attestation.project_title}")
    lines.append(f"Subject: {attestation.subject_name} ({attestation.subject_sha256[:16]}…)")
    lines.append(f"Issued: {attestation.created_at.isoformat()}")
    if attestation.expires_at:
        lines.append(f"Expires: {attestation.expires_at.isoformat()}")
    lines.append("")

    if attestation.claims:
        lines.append("Contribution by stage:")
        for dimension in ContributionDimension:
            claims = attestation.claims_for(dimension)
            if not claims:
                lines.append(f"  {dimension.value:<18} not_claimed")
                continue
            for claim in claims:
                actor = actors.get(claim.actor_id)
                who = actor.display_name or claim.actor_id if actor else claim.actor_id
                lines.append(
                    f"  {dimension.value:<18} {claim.level.value:<28} {who}"
                    f"  [{claim.claim_type.value}, {claim.evidence_status.value}"
                    f", ai={claim.ai_autonomy.value}]"
                )
        lines.append("")
    else:
        lines.append("No contribution claims are made in this record.")
        lines.append("")

    if attestation.evaluation:
        evaluation = attestation.evaluation
        lines.append(
            f"Evaluation: profile {evaluation.profile} rubric {evaluation.rubric_version} "
            f"by {evaluation.assessor_actor_id}"
        )
        for result in evaluation.results:
            note = f" (dissent: {result.dissent})" if result.dissent else ""
            lines.append(
                f"  {result.dimension.value:<18} {result.level.value:<28} "
                f"confidence {result.confidence}{note}"
            )
        lines.append("")

    counts: dict[str, int] = {}
    for reference in attestation.evidence:
        counts[reference.disclosure.value] = counts.get(reference.disclosure.value, 0) + 1
    if counts:
        summary = ", ".join(f"{count} {status}" for status, count in sorted(counts.items()))
        lines.append(f"Evidence: {summary}")
        lines.append("")

    lines.append("Limitations:")
    for limitation in attestation.limitations:
        lines.append(f"  - {limitation.statement}")
    return "\n".join(lines)


# -- manifest parsing --------------------------------------------------------------


def _sequence(manifest: dict[str, Any], key: str) -> list[Any]:
    value = manifest.get(key) or []
    if not isinstance(value, list):
        raise AttestationError(f"`{key}` must be a list")
    return value


def _require(item: dict[str, Any], key: str, where: str) -> Any:
    if key not in item:
        raise AttestationError(f"{where} is missing required field `{key}`")
    return item[key]


def _optional_str(value: Any) -> str | None:
    return str(value) if value is not None else None


def _enum(enum_type: Any, value: Any, where: str, default: Any = None) -> Any:
    if value is None:
        if default is not None:
            return default
        raise AttestationError(f"{where} is missing a value")
    try:
        return enum_type(str(value))
    except ValueError as exc:
        allowed = ", ".join(sorted(member.value for member in enum_type))
        raise AttestationError(f"{where}: {value!r} is not one of {allowed}") from exc


def _actors(manifest: dict[str, Any]) -> tuple[Actor, ...]:
    actors = []
    for item in _sequence(manifest, "actors"):
        if not isinstance(item, dict):
            raise AttestationError("Each actor must be a mapping")
        where = f"Actor {item.get('id', '?')}"
        actors.append(
            Actor(
                id=str(_require(item, "id", where)),
                kind=_enum(ActorKind, _require(item, "kind", where), where),
                display_name=_optional_str(item.get("display_name")),
                identifier=_optional_str(item.get("identifier")),
                version=_optional_str(item.get("version")),
                public_key=_optional_str(item.get("public_key")),
                pseudonymous=bool(item.get("pseudonymous", False)),
            )
        )
    if not actors:
        raise AttestationError("A record must name at least one actor")
    return tuple(actors)


def _evidence(manifest: dict[str, Any], base: Path) -> tuple[EvidenceReference, ...]:
    from trueai.core.evidence import digest_file

    references = []
    for item in _sequence(manifest, "evidence"):
        if not isinstance(item, dict):
            raise AttestationError("Each evidence entry must be a mapping")
        where = f"Evidence {item.get('id', '?')}"
        disclosure = _enum(
            DisclosureStatus, item.get("disclosure"), where, DisclosureStatus.PRIVATE
        )
        digest = _optional_str(item.get("sha256"))
        path = item.get("path")
        if path:
            candidate = Path(str(path))
            digest = digest_file(candidate if candidate.is_absolute() else base / candidate)
        references.append(
            EvidenceReference(
                id=str(_require(item, "id", where)),
                kind=_enum(EvidenceKind, _require(item, "kind", where), where),
                description=str(_require(item, "description", where)),
                sha256=digest,
                issuer=_optional_str(item.get("issuer")),
                collection_method=_optional_str(item.get("collection_method")),
                disclosure=disclosure,
                locator=_optional_str(item.get("locator")),
                commitment=_optional_str(item.get("commitment")),
                omission_reason=_optional_str(item.get("omission_reason")),
            )
        )
    return tuple(references)


def _bindings(manifest: dict[str, Any], base: Path) -> tuple[ArtifactBinding, ...]:
    from trueai.core.evidence import digest_file

    bindings = []
    for item in _sequence(manifest, "artifacts"):
        if not isinstance(item, dict):
            raise AttestationError("Each artifact binding must be a mapping")
        where = f"Artifact {item.get('id', '?')}"
        digest = _optional_str(item.get("sha256"))
        path = item.get("path")
        if path:
            candidate = Path(str(path))
            digest = digest_file(candidate if candidate.is_absolute() else base / candidate)
        if digest is None:
            raise AttestationError(f"{where} needs either `path` or `sha256`")
        bindings.append(
            ArtifactBinding(
                id=str(_require(item, "id", where)),
                role=_enum(BindingRole, item.get("role"), where, BindingRole.INPUT),
                name=str(item.get("name") or item.get("path") or item["id"]),
                sha256=digest,
                media_type=_optional_str(item.get("media_type")),
                relationship=_optional_str(item.get("relationship")),
            )
        )
    return tuple(bindings)


def _activities(manifest: dict[str, Any]) -> tuple[Activity, ...]:
    activities = []
    for item in _sequence(manifest, "activities"):
        if not isinstance(item, dict):
            raise AttestationError("Each activity must be a mapping")
        where = f"Activity {item.get('id', '?')}"
        activities.append(
            Activity(
                id=str(_require(item, "id", where)),
                action=str(_require(item, "action", where)),
                actor_ids=tuple(str(actor) for actor in item.get("actors") or []),
                input_binding_ids=tuple(str(x) for x in item.get("inputs") or []),
                output_binding_ids=tuple(str(x) for x in item.get("outputs") or []),
                ai_autonomy=_enum(AiAutonomy, item.get("ai_autonomy"), where, AiAutonomy.NONE),
                evidence_ids=tuple(str(x) for x in item.get("evidence") or []),
                review_decision=_enum(
                    ReviewDecision,
                    item.get("review_decision"),
                    where,
                    ReviewDecision.NOT_REVIEWED,
                ),
                reviewer_actor_id=_optional_str(item.get("reviewer")),
                description=_optional_str(item.get("description")),
                superseded=bool(item.get("superseded", False)),
            )
        )
    return tuple(activities)


def _decisions(manifest: dict[str, Any]) -> tuple[Decision, ...]:
    decisions = []
    for item in _sequence(manifest, "decisions"):
        if not isinstance(item, dict):
            raise AttestationError("Each decision must be a mapping")
        where = f"Decision {item.get('id', '?')}"
        decisions.append(
            Decision(
                id=str(_require(item, "id", where)),
                question=str(_require(item, "question", where)),
                alternatives=tuple(str(x) for x in item.get("alternatives") or []),
                selected=str(_require(item, "selected", where)),
                rationale=_optional_str(item.get("rationale")),
                rationale_commitment=_optional_str(item.get("rationale_commitment")),
                approving_actor_id=_optional_str(item.get("approved_by")),
                evidence_ids=tuple(str(x) for x in item.get("evidence") or []),
            )
        )
    return tuple(decisions)


def _validations(manifest: dict[str, Any]) -> tuple[ValidationRecord, ...]:
    validations = []
    for item in _sequence(manifest, "validations"):
        if not isinstance(item, dict):
            raise AttestationError("Each validation must be a mapping")
        where = f"Validation {item.get('id', '?')}"
        validations.append(
            ValidationRecord(
                id=str(_require(item, "id", where)),
                kind=str(_require(item, "kind", where)),
                description=str(_require(item, "description", where)),
                outcome=str(_require(item, "outcome", where)),
                outcome_sha256=_optional_str(item.get("outcome_sha256")),
                performed_by_actor_id=_optional_str(item.get("performed_by")),
                evidence_ids=tuple(str(x) for x in item.get("evidence") or []),
            )
        )
    return tuple(validations)


def _claims(manifest: dict[str, Any]) -> tuple[ContributionClaim, ...]:
    claims = []
    for item in _sequence(manifest, "claims"):
        if not isinstance(item, dict):
            raise AttestationError("Each claim must be a mapping")
        where = f"Claim {item.get('dimension', '?')}"
        claims.append(
            ContributionClaim(
                dimension=_enum(ContributionDimension, _require(item, "dimension", where), where),
                actor_id=str(_require(item, "actor", where)),
                claim_type=_enum(ClaimType, _require(item, "claim_type", where), where),
                level=_enum(ContributionLevel, _require(item, "level", where), where),
                evidence_status=_enum(
                    EvidenceStatus, _require(item, "evidence_status", where), where
                ),
                ai_autonomy=_enum(AiAutonomy, item.get("ai_autonomy"), where, AiAutonomy.NONE),
                scope=_optional_str(item.get("scope")),
                explanation=str(_require(item, "explanation", where)),
                evidence_ids=tuple(str(x) for x in item.get("evidence") or []),
                limitations=tuple(str(x) for x in item.get("limitations") or []),
            )
        )
    return tuple(claims)


def _evaluation(manifest: dict[str, Any]) -> Evaluation | None:
    from trueai.core.attestation import DimensionAssessment

    raw = manifest.get("evaluation")
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise AttestationError("`evaluation` must be a mapping")
    where = "Evaluation"
    results = []
    for item in raw.get("results") or []:
        if not isinstance(item, dict):
            raise AttestationError("Each evaluation result must be a mapping")
        results.append(
            DimensionAssessment(
                dimension=_enum(ContributionDimension, _require(item, "dimension", where), where),
                level=_enum(ContributionLevel, _require(item, "level", where), where),
                confidence=str(_require(item, "confidence", where)),
                rationale=_optional_str(item.get("rationale")),
                dissent=_optional_str(item.get("dissent")),
            )
        )
    assessed = raw.get("assessed_at")
    return Evaluation(
        profile=str(_require(raw, "profile", where)),
        rubric_version=str(_require(raw, "rubric_version", where)),
        assessor_actor_id=str(_require(raw, "assessor", where)),
        assessed_at=(datetime.fromisoformat(str(assessed)) if assessed else datetime.now(UTC)),
        results=tuple(results),
        evidence_confidence=_optional_str(raw.get("evidence_confidence")),
        dissent=_optional_str(raw.get("dissent")),
    )


def _digest_file(path: Path) -> str:
    reader = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                reader.update(chunk)
    except OSError as exc:
        raise AttestationError(f"Subject artifact is unreadable: {exc}") from exc
    return reader.hexdigest()
