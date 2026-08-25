"""Deterministic scan orchestration independent of CLI and UI."""

from __future__ import annotations

from collections import Counter, deque
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from trueai.core.artifact import Artifact, ArtifactDiscovery, DiscoveryOptions
from trueai.core.cache import CachedArtifactResult, ScanCache, options_fingerprint
from trueai.core.errors import ArtifactTooLargeError, TrueAIError
from trueai.core.models import (
    ArtifactDescriptor,
    ArtifactType,
    Finding,
    IntegrityReport,
    IntegrityStatus,
    PolicyDecision,
    ScanContext,
    ScanDiagnostic,
    ScanOptions,
    ScanReport,
    ScanSummary,
    Severity,
)
from trueai.core.policy import PolicyEngine, PolicyProfile
from trueai.core.registry import DetectorRegistry
from trueai.detectors.base import Detector
from trueai.plugins.confinement import ConfinementLevel
from trueai.plugins.host import PluginIsolation
from trueai.plugins.manifest import CapabilityPolicy

_CONTAINER_TYPES = frozenset({ArtifactType.DIRECTORY, ArtifactType.GIT_REPOSITORY})


class _FindingBudget:
    """Global finding allowance, consumed strictly in artifact order.

    The budget is global rather than per artifact so that a directory scan cannot
    quietly grow past its declared limit. It is charged from a single thread while
    merging results in order, never from the workers, because a budget consumed in
    completion order would make a truncated report depend on thread scheduling.
    Exhausting it marks the report incomplete; it never silently returns a partial
    result as a clean one.
    """

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._used = 0
        self._exhausted = False

    def take(self, requested: int) -> tuple[int, bool]:
        """Reserve up to ``requested`` findings and report whether the limit was hit."""

        remaining = max(self._limit - self._used, 0)
        granted = min(requested, remaining)
        self._used += granted
        hit_limit = requested > granted
        if hit_limit:
            self._exhausted = True
        return granted, hit_limit

    @property
    def exhausted(self) -> bool:
        """Return whether the limit has already been reached."""

        return self._exhausted


@dataclass(slots=True)
class _ArtifactOutcome:
    """Everything one artifact contributed, kept separable so merges stay ordered."""

    findings: list[Finding] = field(default_factory=list)
    diagnostics: list[ScanDiagnostic] = field(default_factory=list)
    detectors_run: set[str] = field(default_factory=set)
    mutated: bool = False
    cacheable: bool = True
    cache_key: str | None = None


class TrueAIEngine:
    """Public scanner API with no UI or network dependency."""

    def __init__(self, registry: DetectorRegistry) -> None:
        self.registry = registry

    @classmethod
    def default(
        cls,
        *,
        include_experimental: bool = False,
        discover_plugins: bool = True,
        plugin_isolation: PluginIsolation = PluginIsolation.SUBPROCESS,
        capability_policy: CapabilityPolicy | None = None,
        plugin_search_path: tuple[str, ...] = (),
        plugin_confinement: ConfinementLevel = ConfinementLevel.BEST_EFFORT,
    ) -> TrueAIEngine:
        """Construct an engine with all stable built-in detectors."""

        from trueai.detectors import create_default_registry

        return cls(
            create_default_registry(
                include_experimental=include_experimental,
                discover_plugins=discover_plugins,
                plugin_isolation=plugin_isolation,
                capability_policy=capability_policy,
                plugin_search_path=plugin_search_path,
                plugin_confinement=plugin_confinement,
            )
        )

    def scan(
        self,
        target: str | Path | Artifact,
        *,
        options: ScanOptions | None = None,
        policy: PolicyProfile | None = None,
        cache: ScanCache | None = None,
    ) -> ScanReport:
        """Scan a target recursively and return a versioned report.

        ``cache`` overrides the instance the engine would build from
        ``options.cache_directory``. A caller supplies one when it needs to read
        the cache back afterwards — hit and rejection counts, for instance,
        which are otherwise invisible because the instance would be created and
        discarded inside this call.
        """

        scan_options = options or ScanOptions()
        discovery = ArtifactDiscovery(
            DiscoveryOptions(
                max_file_size=scan_options.max_file_size,
                max_files=scan_options.max_files,
                follow_symlinks=scan_options.follow_symlinks,
            )
        )
        artifacts = discovery.discover(target)
        descriptors = tuple(
            self._describe(artifact, scan_options.max_file_size) for artifact in artifacts
        )
        root_path = artifacts[0].path if artifacts else None
        if root_path is not None and root_path.is_file():
            root_path = root_path.parent
        context = ScanContext(options=scan_options, root=root_path)
        diagnostics: list[ScanDiagnostic] = []

        if discovery.truncated:
            diagnostics.append(
                ScanDiagnostic(
                    code="discovery_truncated",
                    message=(
                        f"Recursive discovery exceeded the {scan_options.max_files} file limit; "
                        "the report is incomplete."
                    ),
                    artifact_path=artifacts[0].display_path,
                    severity=Severity.HIGH,
                )
            )
        diagnostics.extend(
            ScanDiagnostic(
                code="discovery_error",
                message=issue.message,
                artifact_path=issue.path,
                severity=Severity.HIGH,
            )
            for issue in discovery.issues
        )
        # A refused plugin means the scan ran with less coverage than the
        # installed set implies. That belongs in the report, not in a log line.
        diagnostics.extend(
            ScanDiagnostic(
                code="plugin_rejected",
                message=(
                    f"Third-party detector {rejection.detector_id} "
                    f"({rejection.entry_point}) did not run: {rejection.reason}"
                ),
                severity=Severity.MEDIUM,
            )
            for rejection in self.registry.plugin_discovery.rejections
        )

        budget = _FindingBudget(scan_options.max_findings)
        if cache is None and scan_options.cache_directory is not None:
            cache = ScanCache(scan_options.cache_directory)
        options_digest = options_fingerprint(scan_options) if cache is not None else ""
        detector_ids = tuple(detector.id for detector in self._eligible_detectors(scan_options))
        single_artifact = len(artifacts) == 1

        outcomes = self._run_detectors(
            artifacts,
            descriptors,
            context,
            budget=budget,
            cache=cache,
            options_digest=options_digest,
            detector_ids=detector_ids,
            single_artifact=single_artifact,
        )

        findings: list[Finding] = []
        detectors_run: set[str] = set()
        mutated_artifacts: list[str] = []
        for artifact, outcome in zip(artifacts, outcomes, strict=True):
            findings.extend(outcome.findings)
            diagnostics.extend(outcome.diagnostics)
            detectors_run.update(outcome.detectors_run)
            if outcome.mutated:
                mutated_artifacts.append(artifact.display_path)
        del budget

        mutated_set = set(mutated_artifacts)
        for artifact, descriptor in zip(artifacts, descriptors, strict=True):
            if descriptor.sha256 is None or artifact.display_path in mutated_set:
                continue
            try:
                final_hash = artifact.sha256(scan_options.max_file_size)
            except (OSError, TrueAIError):
                final_hash = None
            if final_hash != descriptor.sha256:
                mutated_artifacts.append(artifact.display_path)
                mutated_set.add(artifact.display_path)
                diagnostics.append(self._mutation_diagnostic(artifact))

        root_artifact = artifacts[0]
        if root_artifact.path is not None and root_artifact.artifact_type in _CONTAINER_TYPES:
            try:
                final_discovery = ArtifactDiscovery(discovery.options)
                final_paths = final_discovery.inventory(root_artifact.path)
                initial_paths = {artifact.display_path for artifact in artifacts}
                # A path the first pass could not identify — unreadable, or
                # deleted between the walk and the open — is absent from
                # `initial_paths` but present in a path-only sweep. Excluding
                # what the first pass already reported keeps a permission error
                # from being announced as a detector mutating the repository.
                unidentified = {issue.path for issue in discovery.issues}
                added_paths = sorted(final_paths - initial_paths - unidentified)
            except (OSError, TrueAIError):
                added_paths = ["<directory inventory became unreadable>"]
            if added_paths and root_artifact.display_path not in mutated_set:
                preview = ", ".join(added_paths[:5])
                if len(added_paths) > 5:
                    preview += f", and {len(added_paths) - 5} more"
                mutated_artifacts.append(root_artifact.display_path)
                mutated_set.add(root_artifact.display_path)
                diagnostics.append(
                    ScanDiagnostic(
                        code="detector_mutation",
                        message=(
                            "New artifact paths appeared while detectors were running "
                            f"({preview}). In-process third-party detectors are trusted code; "
                            "discard this report and restore the source before continuing."
                        ),
                        artifact_path=root_artifact.display_path,
                        severity=Severity.CRITICAL,
                    )
                )

        ordered_findings = tuple(sorted(findings, key=self._finding_sort_key))
        decisions: tuple[PolicyDecision, ...] = ()
        review_count = 0
        violation_count = 0
        if policy is not None:
            evaluation = PolicyEngine().evaluate(ordered_findings, policy)
            decisions = evaluation.decisions
            review_count = evaluation.review_count
            violation_count = evaluation.violation_count

        summary = ScanSummary(
            artifact_count=len(descriptors),
            finding_count=len(ordered_findings),
            by_confidence_type=dict(
                sorted(Counter(item.confidence_type.value for item in ordered_findings).items())
            ),
            by_category=dict(
                sorted(Counter(item.category.value for item in ordered_findings).items())
            ),
            by_severity=dict(
                sorted(Counter(item.severity.value for item in ordered_findings).items())
            ),
            review_count=review_count,
            violation_count=violation_count,
        )
        return ScanReport(
            artifact=descriptors[0],
            artifacts=descriptors,
            summary=summary,
            findings=ordered_findings,
            diagnostics=tuple(diagnostics),
            detectors_run=tuple(sorted(detectors_run)),
            policy=policy.policy if policy else None,
            policy_decisions=decisions,
            integrity=(
                IntegrityReport(
                    status=IntegrityStatus.FAIL,
                    explanation=(
                        "One or more artifacts changed during scanning: "
                        + ", ".join(mutated_artifacts)
                    ),
                )
                if mutated_artifacts
                else IntegrityReport(
                    status=IntegrityStatus.NOT_MODIFIED,
                    explanation="Scan-only operation; the artifact was not modified.",
                )
            ),
        )

    def scan_text(
        self,
        text: str,
        *,
        name: str = "<text-stream>",
        options: ScanOptions | None = None,
        policy: PolicyProfile | None = None,
    ) -> ScanReport:
        """Scan an in-memory text stream through the same public pipeline."""

        return self.scan(Artifact.from_text(text, name), options=options, policy=policy)

    # -- detector execution ----------------------------------------------------------

    def _run_detectors(
        self,
        artifacts: list[Artifact],
        descriptors: tuple[ArtifactDescriptor, ...],
        context: ScanContext,
        *,
        budget: _FindingBudget,
        cache: ScanCache | None,
        options_digest: str,
        detector_ids: tuple[str, ...],
        single_artifact: bool,
    ) -> list[_ArtifactOutcome]:
        """Inspect every artifact, sequentially or in parallel, in a stable order."""

        def inspect(index: int) -> _ArtifactOutcome:
            return self._scan_artifact(
                artifacts[index],
                descriptors[index],
                context,
                cache=cache,
                options_digest=options_digest,
                detector_ids=detector_ids,
                single_artifact=single_artifact,
            )

        def charge(index: int, outcome: _ArtifactOutcome) -> None:
            """Apply the global budget to one artifact, in artifact order."""

            granted, hit_limit = budget.take(len(outcome.findings))
            if granted < len(outcome.findings):
                del outcome.findings[granted:]
            if hit_limit:
                outcome.diagnostics.append(
                    self._budget_diagnostic(artifacts[index], context.options)
                )
                outcome.cacheable = False

        workers = min(context.options.max_workers, len(artifacts))
        outcomes: list[_ArtifactOutcome] = []
        if workers <= 1:
            for index in range(len(artifacts)):
                if budget.exhausted:
                    break
                outcome = inspect(index)
                charge(index, outcome)
                self._store_in_cache(cache, outcome)
                outcomes.append(outcome)
        else:
            # A bounded submission window keeps results arriving in order while
            # several artifacts are in flight, so the budget is charged in artifact
            # order and work still stops once it is full.
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="trueai-scan") as pool:
                pending: deque[Future[_ArtifactOutcome]] = deque()
                submitted = 0
                window = workers * 2
                while submitted < len(artifacts) and len(pending) < window:
                    pending.append(pool.submit(inspect, submitted))
                    submitted += 1
                index = 0
                while pending:
                    outcome = pending.popleft().result()
                    charge(index, outcome)
                    self._store_in_cache(cache, outcome)
                    outcomes.append(outcome)
                    index += 1
                    if budget.exhausted:
                        for future in pending:
                            future.cancel()
                        break
                    if submitted < len(artifacts):
                        pending.append(pool.submit(inspect, submitted))
                        submitted += 1
        # Artifacts beyond an exhausted budget contribute nothing; the report is
        # already marked incomplete by the budget diagnostic.
        outcomes.extend(_ArtifactOutcome() for _ in range(len(artifacts) - len(outcomes)))
        return outcomes

    def _scan_artifact(
        self,
        artifact: Artifact,
        descriptor: ArtifactDescriptor,
        context: ScanContext,
        *,
        cache: ScanCache | None,
        options_digest: str,
        detector_ids: tuple[str, ...],
        single_artifact: bool,
    ) -> _ArtifactOutcome:
        """Run every eligible detector against one artifact.

        The per-detector buffer caps what any single detector may produce. The
        global budget is applied afterwards, in artifact order, so this runs
        without needing to coordinate with the other workers.
        """

        options = context.options
        outcome = _ArtifactOutcome()
        if artifact.size is not None and artifact.size > options.max_file_size:
            outcome.diagnostics.append(
                ScanDiagnostic(
                    code="artifact_too_large",
                    message=(
                        f"Skipped {artifact.size} byte file; limit is "
                        f"{options.max_file_size} bytes."
                    ),
                    artifact_path=artifact.display_path,
                    severity=Severity.HIGH,
                )
            )
            outcome.cacheable = False
            return outcome

        cache_key = self._cache_key(artifact, descriptor, cache, options_digest, detector_ids)
        outcome.cache_key = cache_key
        if cache is not None and cache_key is not None:
            cached = cache.load(cache_key)
            if cached is not None:
                outcome.findings.extend(cached.findings)
                outcome.diagnostics.extend(cached.diagnostics)
                outcome.detectors_run.update(cached.detectors_run)
                outcome.cacheable = False
                return outcome

        supported = False
        for detector in self._eligible_detectors(options):
            if not detector.supports(artifact):
                continue
            supported = True
            outcome.detectors_run.add(detector.id)
            try:
                detector_findings = detector.scan(artifact, context)
                outcome.findings.extend(detector_findings)
                if any("scan-incomplete" in finding.tags for finding in detector_findings):
                    outcome.diagnostics.append(
                        ScanDiagnostic(
                            code="detector_scan_truncated",
                            message=f"Detector {detector.id} reported incomplete coverage.",
                            artifact_path=artifact.display_path,
                            severity=Severity.HIGH,
                        )
                    )
            except ArtifactTooLargeError as exc:
                outcome.diagnostics.append(
                    ScanDiagnostic(
                        code=exc.code,
                        message=str(exc),
                        artifact_path=artifact.display_path,
                        severity=Severity.HIGH,
                    )
                )
            except TrueAIError as exc:
                outcome.diagnostics.append(
                    ScanDiagnostic(
                        code=exc.code,
                        message=str(exc),
                        artifact_path=artifact.display_path,
                        severity=Severity.HIGH,
                    )
                )
            except Exception as exc:  # detector isolation is an engine boundary
                outcome.diagnostics.append(
                    ScanDiagnostic(
                        code="detector_failure",
                        message=(
                            f"Detector {detector.id} failed safely: {type(exc).__name__}: {exc}"
                        ),
                        artifact_path=artifact.display_path,
                        severity=Severity.HIGH,
                    )
                )

        if not supported and single_artifact and artifact.artifact_type not in _CONTAINER_TYPES:
            outcome.diagnostics.append(
                ScanDiagnostic(
                    code="unsupported_artifact",
                    message=f"No enabled detector supports {artifact.artifact_type.value}.",
                    artifact_path=artifact.display_path,
                    severity=Severity.HIGH,
                )
            )

        if descriptor.sha256 is not None:
            try:
                after_hash = artifact.sha256(options.max_file_size)
            except (OSError, TrueAIError):
                after_hash = None
            if after_hash != descriptor.sha256:
                outcome.mutated = True
                outcome.diagnostics.append(self._mutation_diagnostic(artifact))

        return outcome

    def _eligible_detectors(self, options: ScanOptions) -> tuple[Detector, ...]:
        """Return the detectors this configuration allows, in registration order."""

        eligible: list[Detector] = []
        for detector in self.registry.detectors():
            if (
                options.enabled_detectors is not None
                and detector.id not in options.enabled_detectors
            ):
                continue
            if detector.id in options.disabled_detectors:
                continue
            if detector.experimental and not options.include_experimental:
                continue
            eligible.append(detector)
        return tuple(eligible)

    @staticmethod
    def _cache_key(
        artifact: Artifact,
        descriptor: ArtifactDescriptor,
        cache: ScanCache | None,
        options_digest: str,
        detector_ids: tuple[str, ...],
    ) -> str | None:
        if cache is None or descriptor.sha256 is None:
            return None
        if artifact.artifact_type in _CONTAINER_TYPES:
            # A directory's findings depend on state outside its own bytes.
            return None
        return cache.key(
            content_sha256=descriptor.sha256,
            logical_path=artifact.display_path,
            artifact_type=artifact.artifact_type,
            detector_ids=detector_ids,
            options_digest=options_digest,
        )

    @staticmethod
    def _store_in_cache(cache: ScanCache | None, outcome: _ArtifactOutcome) -> None:
        """Persist a result only when it is a complete, trustworthy observation."""

        if cache is None or outcome.cache_key is None or not outcome.cacheable:
            return
        if outcome.mutated:
            return
        if any(
            diagnostic.severity in {Severity.HIGH, Severity.CRITICAL}
            for diagnostic in outcome.diagnostics
        ):
            return
        cache.store(
            outcome.cache_key,
            CachedArtifactResult(
                findings=tuple(outcome.findings),
                diagnostics=tuple(outcome.diagnostics),
                detectors_run=tuple(sorted(outcome.detectors_run)),
            ),
        )

    @staticmethod
    def _describe(artifact: Artifact, limit: int) -> ArtifactDescriptor:
        try:
            digest = artifact.sha256(limit)
        except (OSError, ArtifactTooLargeError):
            digest = None
        return ArtifactDescriptor(
            path=artifact.display_path,
            artifact_type=artifact.artifact_type,
            media_type=artifact.media_type,
            size=artifact.size,
            sha256=digest,
        )

    @staticmethod
    def _finding_sort_key(finding: Finding) -> tuple[str, int, str, str]:
        location = finding.location
        offset = location.offset if location and location.offset is not None else -1
        return (finding.artifact_path.casefold(), offset, finding.detector_id, finding.id)

    @staticmethod
    def _budget_diagnostic(artifact: Artifact, options: ScanOptions) -> ScanDiagnostic:
        return ScanDiagnostic(
            code="finding_limit_exceeded",
            message=(
                f"Finding budget {options.max_findings} was exhausted; the report is incomplete."
            ),
            artifact_path=artifact.display_path,
            severity=Severity.HIGH,
        )

    @staticmethod
    def _mutation_diagnostic(artifact: Artifact) -> ScanDiagnostic:
        return ScanDiagnostic(
            code="detector_mutation",
            message=(
                "The artifact changed while detectors were running. In-process third-party "
                "detectors are trusted code; discard this report and restore the source before "
                "continuing."
            ),
            artifact_path=artifact.display_path,
            severity=Severity.CRITICAL,
        )
