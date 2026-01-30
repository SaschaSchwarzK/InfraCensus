from __future__ import annotations

from typing import Any

from collector.agent.job_poller import ScanJob
from collector.backends.base import ScannerBackend
from collector.scanners.base import ScanResult
from collector.scanners.registry import ScannerRegistry


class RegistryScannerBackend(ScannerBackend):
    def __init__(self, registry: ScannerRegistry) -> None:
        self._registry = registry

    def initialize(self) -> None:
        return None

    def supports(self, scan_type: str) -> bool:
        return self._registry.get(scan_type) is not None

    async def execute(
        self,
        job: ScanJob,
        targets: list[str],
        params: dict[str, Any],
    ) -> list[ScanResult]:
        scanner = self._registry.get(job.scan_type)
        if scanner is None:
            return []
        return await scanner.scan(targets, params)

    def cleanup(self) -> None:
        return None
