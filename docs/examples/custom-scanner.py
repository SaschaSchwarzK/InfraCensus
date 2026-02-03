from __future__ import annotations

from typing import Any

from collector.scanners.base import BaseScanner, ScanResult


class CustomScanner(BaseScanner):
    name = "custom"

    async def scan(
        self, targets: list[str], params: dict[str, Any]
    ) -> list[ScanResult]:
        results: list[ScanResult] = []
        for target in targets:
            results.append(
                ScanResult(
                    ip=target,
                    success=True,
                    duration_ms=1,
                    data={"message": "custom scanner placeholder"},
                    error=None,
                )
            )
        return results
