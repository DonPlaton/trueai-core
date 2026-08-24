"""Authenticated C2PA verification through the official c2pa-rs implementation.

Marker discovery and verification answer different questions. A detector finding
says the literal bytes "c2pa" appear in a file, which anyone can write. This
module answers whether a cryptographically signed manifest validates, whose
certificate signed it, and whether that certificate chains to an anchor the
operator decided to trust.

TrueAI does not implement C2PA validation itself. It adapts the reference
implementation and reports exactly what that implementation returned, including
the states people find inconvenient:

* ``TRUSTED`` is the only result that establishes provenance. The signature and
  content hashes validated and the signer chains to a configured trust anchor.
* ``VALID`` means the cryptography checks out but the signer is unknown to the
  trust store in use. Presenting that as verified provenance would be a
  misrepresentation, so it is a separate state.
* ``INVALID`` means a check failed. Every failing check is reported with the
  verifier's own code and explanation.
* ``VERIFIER_UNAVAILABLE`` means the optional dependency is not installed. No
  result is inferred, guessed, or approximated in its absence.

Verification is a separate, explicit operation rather than part of a scan. A scan
stays offline and non-authenticating; verification is what the operator asks for
when a signature actually matters.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
from pathlib import Path
from typing import Any

from trueai.core.artifact import Artifact, ArtifactDiscovery
from trueai.core.errors import (
    OptionalDependencyError,
    ProvenanceConfigurationError,
    TrueAIError,
    UnsafeArtifactError,
)
from trueai.core.models import (
    ArtifactDescriptor,
    ArtifactType,
    FindingCategory,
    ProvenanceAssertion,
    ProvenanceSigner,
    ProvenanceValidationEntry,
    ProvenanceVerification,
    ProvenanceVerificationStatus,
    ScanReport,
    ValidationOutcome,
)

C2PA_DISTRIBUTION = "c2pa-python"
INSTALL_HINT = "install trueai-core[c2pa] to enable authenticated verification"

# The reference implementation reports these three states. Anything else is
# treated as unknown rather than silently mapped onto a friendlier one.
_STATE_MAP = {
    "trusted": ProvenanceVerificationStatus.TRUSTED,
    "valid": ProvenanceVerificationStatus.VALID,
    "invalid": ProvenanceVerificationStatus.INVALID,
}
_OUTCOME_KEYS = {
    "success": ValidationOutcome.SUCCESS,
    "informational": ValidationOutcome.INFORMATIONAL,
    "failure": ValidationOutcome.FAILURE,
}
_MAX_ASSERTIONS = 200
_MAX_VALIDATION_ENTRIES = 500
_SUMMARY_LIMIT = 300


def c2pa_available() -> bool:
    """Return whether the optional verification dependency is importable."""

    return importlib.util.find_spec("c2pa") is not None


class C2PAVerifier:
    """Adapter over the C2PA reference implementation.

    Trust is an operator decision, not a library default. Passing no anchors means
    a correctly signed asset comes back ``VALID`` rather than ``TRUSTED``, because
    without a trust store there is nothing to chain to.
    """

    id = "provenance.c2pa-verification.v1"

    def __init__(
        self,
        *,
        trust_anchors: str | None = None,
        allow_remote_manifests: bool = False,
    ) -> None:
        self.trust_anchors = trust_anchors
        self.allow_remote_manifests = allow_remote_manifests

    @classmethod
    def from_trust_store(
        cls,
        path: str | Path | None,
        *,
        allow_remote_manifests: bool = False,
    ) -> C2PAVerifier:
        """Build a verifier from a PEM bundle of trust anchors."""

        anchors = None
        if path is not None:
            anchors = Path(path).read_text(encoding="utf-8")
        return cls(trust_anchors=anchors, allow_remote_manifests=allow_remote_manifests)

    def verifier_name(self) -> str:
        """Return an auditable identifier for whatever performed the verification."""

        if not c2pa_available():
            return "unavailable"
        module = importlib.import_module("c2pa")
        binding = getattr(module, "__version__", "unknown")
        try:
            native = str(module.sdk_version())
        except Exception:  # pragma: no cover - defensive around a foreign library
            native = "unknown"
        return f"{C2PA_DISTRIBUTION} {binding} (c2pa-rs {native})"

    def supported_media_types(self) -> frozenset[str]:
        """Return the containers the installed verifier can read."""

        if not c2pa_available():
            return frozenset()
        module = importlib.import_module("c2pa")
        try:
            return frozenset(str(item) for item in module.Reader.get_supported_mime_types())
        except Exception:  # pragma: no cover - defensive around a foreign library
            return frozenset()

    def verify(self, artifact: Artifact) -> ProvenanceVerification:
        """Verify one artifact and report exactly what the implementation returned."""

        path = artifact.path
        if path is None:
            return self._unavailable(
                artifact,
                ProvenanceVerificationStatus.UNSUPPORTED_CONTAINER,
                "Verification requires a file on disk; in-memory streams are not verifiable.",
            )
        if not c2pa_available():
            return self._unavailable(
                artifact,
                ProvenanceVerificationStatus.VERIFIER_UNAVAILABLE,
                f"No C2PA verifier is installed, so no verification was attempted. {INSTALL_HINT}.",
            )

        module = importlib.import_module("c2pa")
        errors = module.C2paError
        try:
            context = self._build_context(module)
            reader_arguments: dict[str, Any] = {}
            if context is not None:
                reader_arguments["context"] = context
            with module.Reader(str(path), **reader_arguments) as reader:
                return self._describe(artifact, reader)
        except errors.ManifestNotFound:
            return self._unavailable(
                artifact,
                ProvenanceVerificationStatus.NO_MANIFEST,
                "The artifact carries no C2PA manifest. Absence of a manifest is not "
                "evidence about how the artifact was produced.",
            )
        except errors.NotSupported:
            return self._unavailable(
                artifact,
                ProvenanceVerificationStatus.UNSUPPORTED_CONTAINER,
                "The installed verifier does not support this container format.",
            )
        except errors.FileNotFound as exc:
            raise OptionalDependencyError(f"Verifier could not read {path}: {exc}") from exc
        except ProvenanceConfigurationError:
            raise
        except Exception as exc:  # foreign library boundary
            return self._unavailable(
                artifact,
                ProvenanceVerificationStatus.INVALID,
                f"The verifier failed to process the manifest: {type(exc).__name__}: {exc}",
            )

    # -- internals -------------------------------------------------------------------

    def _build_context(self, module: Any) -> Any | None:
        """Configure trust and the network boundary for a single Reader.

        Settings are applied per context rather than through the deprecated global
        loader, so verifying one artifact never changes how the host application
        verifies another.
        """

        verify_settings: dict[str, Any] = {
            # The scanner is local-first. A manifest stored on a remote server is
            # reported by URL and never fetched unless the caller opts in.
            "remote_manifest_fetch": self.allow_remote_manifests,
            "verify_trust": self.trust_anchors is not None,
        }
        settings: dict[str, Any] = {"verify": verify_settings}
        if self.trust_anchors is not None:
            settings["trust"] = {"trust_anchors": self.trust_anchors}
        try:
            configuration = module.Settings.from_dict(settings)
            return module.ContextBuilder().with_settings(configuration).build()
        except Exception as exc:  # foreign library boundary
            requested = " with a caller-supplied trust store" if self.trust_anchors else ""
            raise ProvenanceConfigurationError(
                f"C2PA verification settings{requested} could not be enforced: "
                f"{type(exc).__name__}: {exc}"
            ) from exc

    def _describe(self, artifact: Artifact, reader: Any) -> ProvenanceVerification:
        state = reader.get_validation_state()
        status = _STATE_MAP.get(str(state).casefold(), ProvenanceVerificationStatus.INVALID)
        store = self._manifest_store(reader)
        label = store.get("active_manifest") if isinstance(store, dict) else None
        manifests = store.get("manifests", {}) if isinstance(store, dict) else {}
        active = manifests.get(label, {}) if isinstance(manifests, dict) else {}
        if not isinstance(active, dict):
            active = {}
        validation = self._validation_entries(reader)
        return ProvenanceVerification(
            artifact_path=artifact.display_path,
            status=status,
            verifier=self.verifier_name(),
            explanation=self._explain(status, validation),
            trust_anchors_configured=self.trust_anchors is not None,
            remote_manifests_allowed=self.allow_remote_manifests,
            active_manifest_label=str(label) if label else None,
            claim_generator=self._claim_generator(active),
            title=self._optional_string(active.get("title")),
            embedded=self._optional_bool(reader, "is_embedded"),
            remote_manifest_url=self._remote_url(reader),
            signer=self._signer(active),
            assertions=self._assertions(active),
            ingredients=self._ingredients(active),
            validation=validation,
        )

    @staticmethod
    def _manifest_store(reader: Any) -> dict[str, Any]:
        try:
            raw: Any = json.loads(reader.json())
        except Exception:  # pragma: no cover - defensive around a foreign library
            return {}
        return raw if isinstance(raw, dict) else {}

    @staticmethod
    def _validation_entries(reader: Any) -> tuple[ProvenanceValidationEntry, ...]:
        try:
            results = reader.get_validation_results()
        except Exception:  # pragma: no cover - defensive around a foreign library
            return ()
        if not isinstance(results, dict):
            return ()
        entries: list[ProvenanceValidationEntry] = []
        for scope in sorted(results):
            bucket = results[scope]
            if not isinstance(bucket, dict):
                continue
            for key, outcome in _OUTCOME_KEYS.items():
                items = bucket.get(key)
                if not isinstance(items, list):
                    continue
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    entries.append(
                        ProvenanceValidationEntry(
                            code=str(item.get("code", "unknown")),
                            outcome=outcome,
                            explanation=str(item.get("explanation", ""))[:_SUMMARY_LIMIT],
                            target=(str(item["url"])[:_SUMMARY_LIMIT] if item.get("url") else None),
                        )
                    )
                    if len(entries) >= _MAX_VALIDATION_ENTRIES:
                        return tuple(entries)
        return tuple(entries)

    @staticmethod
    def _signer(active: dict[str, Any]) -> ProvenanceSigner | None:
        info = active.get("signature_info")
        if not isinstance(info, dict):
            return None
        return ProvenanceSigner(
            common_name=C2PAVerifier._optional_string(info.get("common_name")),
            issuer=C2PAVerifier._optional_string(info.get("issuer")),
            algorithm=C2PAVerifier._optional_string(info.get("alg")),
            certificate_serial_number=C2PAVerifier._optional_string(info.get("cert_serial_number")),
            signed_at=C2PAVerifier._optional_string(info.get("time")),
        )

    @staticmethod
    def _assertions(active: dict[str, Any]) -> tuple[ProvenanceAssertion, ...]:
        raw = active.get("assertions")
        if not isinstance(raw, list):
            return ()
        assertions: list[ProvenanceAssertion] = []
        for item in raw[:_MAX_ASSERTIONS]:
            if not isinstance(item, dict):
                continue
            label = str(item.get("label", "unlabelled"))
            data = item.get("data")
            summary = json.dumps(data, ensure_ascii=False, sort_keys=True)[:_SUMMARY_LIMIT]
            assertions.append(ProvenanceAssertion(label=label, summary=summary))
        return tuple(assertions)

    @staticmethod
    def _ingredients(active: dict[str, Any]) -> tuple[str, ...]:
        raw = active.get("ingredients")
        if not isinstance(raw, list):
            return ()
        names: list[str] = []
        for item in raw:
            if isinstance(item, dict):
                names.append(str(item.get("title") or item.get("instance_id") or "unnamed"))
        return tuple(names)

    @staticmethod
    def _claim_generator(active: dict[str, Any]) -> str | None:
        info = active.get("claim_generator_info")
        if isinstance(info, list) and info and isinstance(info[0], dict):
            name = info[0].get("name")
            version = info[0].get("version")
            if name and version:
                return f"{name} {version}"
            if name:
                return str(name)
        return C2PAVerifier._optional_string(active.get("claim_generator"))

    @staticmethod
    def _remote_url(reader: Any) -> str | None:
        try:
            url = reader.get_remote_url()
        except Exception:  # pragma: no cover - defensive around a foreign library
            return None
        return str(url) if url else None

    @staticmethod
    def _optional_bool(reader: Any, attribute: str) -> bool | None:
        try:
            return bool(getattr(reader, attribute)())
        except Exception:  # pragma: no cover - defensive around a foreign library
            return None

    @staticmethod
    def _optional_string(value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @staticmethod
    def _explain(
        status: ProvenanceVerificationStatus,
        validation: tuple[ProvenanceValidationEntry, ...],
    ) -> str:
        failures = [entry for entry in validation if entry.outcome == ValidationOutcome.FAILURE]
        if status == ProvenanceVerificationStatus.TRUSTED:
            return (
                "The manifest signature and content hashes validated, and the signing "
                "certificate chains to a configured trust anchor."
            )
        if status == ProvenanceVerificationStatus.VALID:
            reason = (
                "no trust anchors were configured"
                if not failures
                else "; ".join(entry.code for entry in failures[:3])
            )
            return (
                "The manifest signature and content hashes validated, but the signer is not "
                f"established as trusted ({reason}). This is not authenticated provenance."
            )
        if failures:
            return "Verification failed: " + "; ".join(
                f"{entry.code}: {entry.explanation}" for entry in failures[:3]
            )
        return "Verification failed."

    def _unavailable(
        self,
        artifact: Artifact,
        status: ProvenanceVerificationStatus,
        explanation: str,
    ) -> ProvenanceVerification:
        return ProvenanceVerification(
            artifact_path=artifact.display_path,
            status=status,
            verifier=self.verifier_name(),
            explanation=explanation,
            trust_anchors_configured=self.trust_anchors is not None,
            remote_manifests_allowed=self.allow_remote_manifests,
        )


def verify_provenance(
    target: str | Path | Artifact,
    *,
    trust_anchors: str | Path | None = None,
    allow_remote_manifests: bool = False,
) -> ProvenanceVerification:
    """Verify authenticated provenance for one artifact.

    ``trust_anchors`` accepts a path to a PEM bundle or the PEM text itself.
    Without it, a correctly signed asset is reported as ``VALID`` rather than
    ``TRUSTED``: verification proves the signature, the trust store decides whose
    signature counts.
    """

    artifact = (
        target if isinstance(target, Artifact) else ArtifactDiscovery().identify(Path(target))
    )
    anchors = _resolve_trust_anchors(trust_anchors)
    verifier = C2PAVerifier(
        trust_anchors=anchors,
        allow_remote_manifests=allow_remote_manifests,
    )
    return verifier.verify(artifact)


def attach_provenance_verifications(
    report: ScanReport,
    target: str | Path,
    *,
    trust_anchors: str | Path | None = None,
    allow_remote_manifests: bool = False,
) -> ScanReport:
    """Explicitly verify eligible report artifacts and attach typed results."""

    try:
        root = Path(target).resolve(strict=True)
    except OSError as exc:
        raise UnsafeArtifactError(
            f"Provenance verification target changed or became inaccessible: {target}"
        ) from exc
    verifier = C2PAVerifier(
        trust_anchors=_resolve_trust_anchors(trust_anchors),
        allow_remote_manifests=allow_remote_manifests,
    )
    if root.is_file():
        artifact = Artifact(
            artifact_type=report.artifact.artifact_type,
            path=root,
            logical_path=report.artifact.path,
            size=report.artifact.size,
            media_type=report.artifact.media_type,
        )
        single_result = (_verify_scanned_artifact(verifier, artifact, report.artifact),)
        return report.model_copy(update={"provenance_verifications": single_result})

    if not c2pa_available():
        unavailable = verifier.verify(
            Artifact(
                artifact_type=ArtifactType.DIRECTORY,
                path=root,
                logical_path=report.artifact.path,
            )
        )
        return report.model_copy(update={"provenance_verifications": (unavailable,)})

    supported_media_types = verifier.supported_media_types()
    marker_paths = {
        finding.artifact_path
        for finding in report.findings
        if finding.category == FindingCategory.C2PA_PROVENANCE
    }
    results: list[ProvenanceVerification] = []
    for descriptor in report.artifacts:
        if descriptor.sha256 is None or descriptor.artifact_type in {
            ArtifactType.DIRECTORY,
            ArtifactType.GIT_REPOSITORY,
        }:
            continue
        if (
            descriptor.media_type not in supported_media_types
            and descriptor.path not in marker_paths
        ):
            continue
        try:
            candidate = (root / descriptor.path).resolve(strict=True)
            candidate.relative_to(root)
        except (OSError, ValueError) as exc:
            raise UnsafeArtifactError(
                "Provenance verification candidate escaped the scanned root, changed, "
                "or became inaccessible"
            ) from exc
        artifact = Artifact(
            artifact_type=descriptor.artifact_type,
            path=candidate,
            logical_path=descriptor.path,
            size=descriptor.size,
            media_type=descriptor.media_type,
        )
        results.append(_verify_scanned_artifact(verifier, artifact, descriptor))
    return report.model_copy(update={"provenance_verifications": tuple(results)})


def _verify_scanned_artifact(
    verifier: C2PAVerifier,
    artifact: Artifact,
    descriptor: ArtifactDescriptor,
) -> ProvenanceVerification:
    """Verify only while the artifact remains identical to its scan descriptor."""

    _assert_matches_scanned_descriptor(artifact, descriptor)
    result = verifier.verify(artifact)
    _assert_matches_scanned_descriptor(artifact, descriptor)
    return result


def _assert_matches_scanned_descriptor(
    artifact: Artifact,
    descriptor: ArtifactDescriptor,
) -> None:
    """Fail closed when verification would inspect bytes absent from the scan."""

    if descriptor.sha256 is None or descriptor.size is None:
        raise UnsafeArtifactError(
            f"Cannot bind provenance verification to the scan for {descriptor.path}: "
            "the report has no complete content fingerprint"
        )
    if artifact.path is None or not artifact.path.is_file():
        raise UnsafeArtifactError(
            f"Provenance verification target is no longer a file: {descriptor.path}"
        )
    try:
        current_size = artifact.path.stat().st_size
    except OSError as exc:
        raise UnsafeArtifactError(
            f"Unable to bind provenance verification to {descriptor.path}: {exc}"
        ) from exc
    if current_size != descriptor.size:
        raise UnsafeArtifactError(
            f"Artifact changed after scanning: {descriptor.path} has size {current_size}, "
            f"expected {descriptor.size}"
        )
    try:
        current_sha256 = artifact.sha256(max(descriptor.size, 1))
    except (OSError, TrueAIError) as exc:
        raise UnsafeArtifactError(
            f"Unable to bind provenance verification to {descriptor.path}: {exc}"
        ) from exc
    if current_sha256 != descriptor.sha256:
        raise UnsafeArtifactError(
            f"Artifact changed after scanning: SHA-256 mismatch for {descriptor.path}"
        )


def _resolve_trust_anchors(trust_anchors: str | Path | None) -> str | None:
    if trust_anchors is None:
        return None
    if isinstance(trust_anchors, Path):
        return trust_anchors.read_text(encoding="utf-8")
    candidate = Path(trust_anchors)
    try:
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    except OSError:
        pass
    return trust_anchors
