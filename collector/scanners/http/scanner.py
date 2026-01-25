from __future__ import annotations

import asyncio
import time
from typing import Any

from collector.scanners.base import BaseScanner, ScanResult


class HttpScanner(BaseScanner):
    name = "http"

    async def scan(self, targets: list[str], params: dict[str, Any]) -> list[ScanResult]:
        results = []
        timeout = int(params.get("timeout", 10))
        port = int(params.get("port", 80))
        for target in targets:
            start = time.perf_counter()
            success = await _tcp_probe(target, port, timeout)
            results.append(
                ScanResult(
                    ip=target,
                    success=success,
                    duration_ms=int((time.perf_counter() - start) * 1000),
                    data={"status": "probe", "scanner": self.name, "port": port},
                    error=None if success else "unreachable",
                )
            )
        return results


async def _tcp_probe(target: str, port: int, timeout: int) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port),
            timeout=timeout,
        )
    except (OSError, asyncio.TimeoutError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return True
