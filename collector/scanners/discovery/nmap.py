from __future__ import annotations

import asyncio
import subprocess
import time
from typing import Any

from collector.scanners.base import BaseScanner, ScanResult


class NmapScanner(BaseScanner):
    name = "nmap"
    required_tools = ["nmap"]

    async def scan(
        self, targets: list[str], params: dict[str, Any]
    ) -> list[ScanResult]:
        results = []
        timeout = int(params.get("timeout", 30))
        for target in targets:
            start = time.perf_counter()
            success, output = await _run_nmap(target, timeout)
            results.append(
                ScanResult(
                    ip=target,
                    success=success,
                    duration_ms=int((time.perf_counter() - start) * 1000),
                    data={"status": "probe", "scanner": self.name, "output": output},
                    error=None if success else "nmap_failed",
                )
            )
        return results


async def _run_nmap(target: str, timeout: int) -> tuple[bool, str]:
    if not target or any(ch in target for ch in [";", "&", "|", "`", "$", "\n"]):
        return False, "invalid_target"

    def _run() -> tuple[bool, str]:
        try:
            completed = subprocess.run(
                ["nmap", "-sn", "-oX", "-", target],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            return False, "nmap_not_found"
        except subprocess.TimeoutExpired as exc:
            output = (exc.stdout or "") + (exc.stderr or "")
            return False, output[:4000]
        output = (completed.stdout or "") + (completed.stderr or "")
        return completed.returncode == 0, output[:4000]

    return await asyncio.to_thread(_run)
