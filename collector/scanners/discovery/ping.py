from __future__ import annotations

import asyncio
import ipaddress
import re
import shutil
import subprocess  # nosec B404
import time
from typing import Any

from collector.scanners.base import BaseScanner, ScanResult


class PingScanner(BaseScanner):
    name = "ping"
    required_tools = ["ping"]

    async def scan(
        self, targets: list[str], params: dict[str, Any]
    ) -> list[ScanResult]:
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
    # Validate target to prevent command injection
    if not target or any(
        char in target for char in [";", "&", "|", "`", "$", "\n", "\r"]
    ):
        return False
    if target.startswith("-"):
        return False
    try:
        ipaddress.ip_address(target)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9.-]+", target):
            return False

    def _run() -> bool:
        ping_path = shutil.which("ping")
        if not ping_path:
            return False
        try:
            completed = subprocess.run(
                [ping_path, "-c", "1", "-W", str(timeout), target],  # nosec B603
                capture_output=True,
                text=True,
                timeout=timeout + 2,  # Add buffer to subprocess timeout
            )
        except (
            FileNotFoundError,
            subprocess.TimeoutExpired,
            OSError,
            ValueError,
        ):
            # Handle missing ping command, timeouts, OS errors, and invalid arguments
            return False
        return completed.returncode == 0

    return await asyncio.to_thread(_run)
