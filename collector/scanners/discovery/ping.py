from __future__ import annotations

import asyncio
import subprocess
import time
from typing import Any

from collector.scanners.base import BaseScanner, ScanResult


class PingScanner(BaseScanner):
    name = "ping"
    required_tools = ["ping"]

    async def scan(self, targets: list[str], params: dict[str, Any]) -> list[ScanResult]:
        results = []
        timeout = int(params.get("timeout", 5))
        for target in targets:
            start = time.perf_counter()
            success = await _ping_target(target, timeout)
            results.append(
                ScanResult(
                    ip=target,
                    success=success,
                    duration_ms=int((time.perf_counter() - start) * 1000),
                    data={"status": "probe", "scanner": self.name},
                    error=None if success else "unreachable",
                )
            )
        return results


async def _ping_target(target: str, timeout: int) -> bool:
    def _run() -> bool:
        try:
            completed = subprocess.run(
                ["ping", "-c", "1", "-W", str(timeout), target],
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            return False
        return completed.returncode == 0

    return await asyncio.to_thread(_run)
