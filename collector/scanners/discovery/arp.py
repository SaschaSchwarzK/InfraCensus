from __future__ import annotations

import asyncio
import subprocess
import time
from typing import Any

from collector.scanners.base import BaseScanner, ScanResult


class ArpScanner(BaseScanner):
    name = "arp"
    required_tools = ["arp"]

    async def scan(self, targets: list[str], params: dict[str, Any]) -> list[ScanResult]:
        results = []
        timeout = int(params.get("timeout", 5))
        for target in targets:
            start = time.perf_counter()
            found, output = await _lookup_arp(target, timeout)
            results.append(
                ScanResult(
                    ip=target,
                    success=found,
                    duration_ms=int((time.perf_counter() - start) * 1000),
                    data={"status": "probe", "scanner": self.name, "output": output},
                    error=None if found else "not_found",
                )
            )
        return results


async def _lookup_arp(target: str, timeout: int) -> tuple[bool, str]:
    def _run() -> tuple[bool, str]:
        try:
            completed = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False, ""
        output = (completed.stdout or "")[:2000]
        found = target in output
        return found, output

    return await asyncio.to_thread(_run)
