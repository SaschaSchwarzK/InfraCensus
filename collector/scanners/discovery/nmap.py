from __future__ import annotations

import asyncio
import ipaddress
import re
import shutil
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
        timeout = int(params.get("timeout", 30))

        # Process targets concurrently for better performance
        tasks = []
        for target in targets:
            task = asyncio.create_task(self._scan_single_target(target, timeout))
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle any exceptions that occurred
        final_results: list[ScanResult] = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                final_results.append(
                    ScanResult(
                        ip=targets[i],
                        success=False,
                        duration_ms=0,
                        data={"status": "error", "scanner": self.name},
                        error=str(result),
                    )
                )
            else:
                if isinstance(result, ScanResult):
                    final_results.append(result)
                else:
                    final_results.append(
                        ScanResult(
                            ip=targets[i],
                            success=False,
                            duration_ms=0,
                            data={"status": "error", "scanner": self.name},
                            error="invalid_scan_result",
                        )
                    )

        return final_results

    async def _scan_single_target(self, target: str, timeout: int) -> ScanResult:
        start = time.perf_counter()
        success, output = await _run_nmap(target, timeout)
        return ScanResult(
            ip=target,
            success=success,
            duration_ms=int((time.perf_counter() - start) * 1000),
            data={"status": "probe", "scanner": self.name, "output": output},
            error=None if success else "nmap_failed",
        )


async def _run_nmap(target: str, timeout: int) -> tuple[bool, str]:
    if not target or any(ch in target for ch in [";", "&", "|", "`", "$", "\n"]):
        return False, "invalid_target"
    if target.startswith("-"):
        return False, "invalid_target"
    try:
        ipaddress.ip_address(target)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9.-]+", target):
            return False, "invalid_target"

    def _run() -> tuple[bool, str]:
        nmap_path = shutil.which("nmap")
        if not nmap_path:
            return False, "nmap_not_found"
        try:
            completed = subprocess.run(
                [nmap_path, "-sn", "-oX", "-", target],  # nosec B603
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError:
            return False, "nmap_not_found"
        except subprocess.TimeoutExpired as exc:
            stdout = (
                exc.stdout.decode(errors="replace")
                if isinstance(exc.stdout, bytes)
                else (exc.stdout or "")
            )
            stderr = (
                exc.stderr.decode(errors="replace")
                if isinstance(exc.stderr, bytes)
                else (exc.stderr or "")
            )
            output = stdout + stderr
            return False, output[:4000]
        stdout = (
            completed.stdout.decode(errors="replace")
            if isinstance(completed.stdout, bytes)
            else (completed.stdout or "")
        )
        stderr = (
            completed.stderr.decode(errors="replace")
            if isinstance(completed.stderr, bytes)
            else (completed.stderr or "")
        )
        output = stdout + stderr
        return completed.returncode == 0, output[:4000]

    return await asyncio.to_thread(_run)
