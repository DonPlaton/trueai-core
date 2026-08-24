"""Explicit detector registration and reviewed third-party discovery."""

from __future__ import annotations

from trueai.core.errors import DetectorRegistrationError
from trueai.core.models import FindingCategory
from trueai.detectors.base import Detector
from trueai.plugins.host import (
    DiscoveryResult,
    PluginHost,
    PluginIsolation,
    PluginRejection,
)
from trueai.plugins.manifest import CapabilityPolicy


class DetectorRegistry:
    """Mutable registry; engines receive isolated instances."""

    def __init__(self) -> None:
        self._detectors: dict[str, Detector] = {}
        self._disabled: set[str] = set()
        #: Result of the last plugin discovery, so a scan can report what was
        #: refused instead of silently running with fewer detectors.
        self.plugin_discovery: DiscoveryResult = DiscoveryResult((), (), (), ())

    def register(self, detector: Detector, *, enabled: bool = True, replace: bool = False) -> None:
        """Register a detector explicitly."""

        if detector.id in self._detectors and not replace:
            raise DetectorRegistrationError(f"Detector already registered: {detector.id}")
        if not detector.id or detector.id == "base":
            raise DetectorRegistrationError("Detector must define a stable non-base id")
        self._detectors[detector.id] = detector
        if enabled:
            self._disabled.discard(detector.id)
        else:
            self._disabled.add(detector.id)

    def unregister(self, detector_id: str) -> None:
        """Remove a detector registration."""

        self._detectors.pop(detector_id, None)
        self._disabled.discard(detector_id)

    def enable(self, detector_id: str) -> None:
        """Enable a registered detector."""

        if detector_id not in self._detectors:
            raise DetectorRegistrationError(f"Unknown detector: {detector_id}")
        self._disabled.discard(detector_id)

    def disable(self, detector_id: str) -> None:
        """Disable a registered detector."""

        if detector_id not in self._detectors:
            raise DetectorRegistrationError(f"Unknown detector: {detector_id}")
        self._disabled.add(detector_id)

    def discover(
        self,
        *,
        policy: CapabilityPolicy | None = None,
        isolation: PluginIsolation = PluginIsolation.SUBPROCESS,
        timeout: float | None = None,
        search_path: tuple[str, ...] = (),
    ) -> list[str]:
        """Load third-party detectors the host policy allows.

        Discovery never partially applies. Every plugin is reviewed first and only
        the accepted set is registered, so a refused plugin, one that does not
        implement the protocol, or one whose id collides with a detector that is
        already registered is recorded in :attr:`plugin_discovery` and skipped.
        None of them can abort discovery and take the scan down with it.
        """

        host_arguments: dict[str, object] = {"policy": policy, "isolation": isolation}
        if timeout is not None:
            host_arguments["timeout"] = timeout
        if search_path:
            host_arguments["search_path"] = search_path
        host = PluginHost(**host_arguments)  # type: ignore[arg-type]
        result = host.discover()

        accepted: list[Detector] = []
        rejections = list(result.rejections)
        claimed: set[str] = set(self._detectors)
        for detector in result.detectors:
            entry_point = getattr(detector, "entry_point", "")
            if not isinstance(detector, Detector):
                rejections.append(
                    PluginRejection(
                        detector_id=str(getattr(detector, "id", detector)),
                        entry_point=str(entry_point),
                        reason="The plugin does not implement the Detector protocol.",
                    )
                )
                continue
            if detector.id in claimed:
                rejections.append(
                    PluginRejection(
                        detector_id=detector.id,
                        entry_point=str(entry_point),
                        reason=(
                            "Another registered detector already uses this id. A plugin "
                            "cannot take over an id that is already claimed."
                        ),
                    )
                )
                continue
            claimed.add(detector.id)
            accepted.append(detector)

        self.plugin_discovery = DiscoveryResult(
            detectors=tuple(accepted),
            manifests=result.manifests,
            decisions=result.decisions,
            rejections=tuple(rejections),
        )
        loaded: list[str] = []
        for detector in accepted:
            self.register(detector)
            loaded.append(detector.id)
        return loaded

    def detectors(
        self,
        *,
        provider: str | None = None,
        category: FindingCategory | None = None,
        include_disabled: bool = False,
    ) -> tuple[Detector, ...]:
        """List registrations with stable ordering and optional grouping filters."""

        result = []
        for detector_id in sorted(self._detectors):
            detector = self._detectors[detector_id]
            if not include_disabled and detector_id in self._disabled:
                continue
            if provider is not None and detector.provider != provider:
                continue
            if category is not None and category not in detector.categories:
                continue
            result.append(detector)
        return tuple(result)

    def is_enabled(self, detector_id: str) -> bool:
        """Return the current enabled state."""

        return detector_id in self._detectors and detector_id not in self._disabled

    def get(self, detector_id: str) -> Detector:
        """Return a registered detector."""

        try:
            return self._detectors[detector_id]
        except KeyError as exc:
            raise DetectorRegistrationError(f"Unknown detector: {detector_id}") from exc
