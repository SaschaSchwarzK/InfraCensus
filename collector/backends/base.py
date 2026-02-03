from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from collector.agent.job_poller import ScanJob
from collector.scanners.base import ScanResult


class ScannerBackend(ABC):
    @abstractmethod
    def initialize(self) -> None:
        """Initialize the backend."""

    @abstractmethod
    def supports(self, scan_type: str) -> bool:
        """Return True if this backend supports the scan type."""

    @abstractmethod
    async def execute(
        self,
        job: ScanJob,
        targets: list[str],
        params: dict[str, Any],
    ) -> list[ScanResult]:
        """Execute a scan job."""

    @abstractmethod
    def cleanup(self) -> None:
        """Clean up resources."""
