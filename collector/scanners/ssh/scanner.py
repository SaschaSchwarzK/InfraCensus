from __future__ import annotations

import asyncio
import time
from typing import Any

from collector.scanners.base import BaseScanner, ScanResult


class SshScanner(BaseScanner):
    name = "ssh"

    async def scan(self, targets: list[str], params: dict[str, Any]) -> list[ScanResult]:
        results = []
        timeout = int(params.get("timeout", 10))
        port = int(params.get("port", 22))
        credentials = params.get("credentials_by_target") or {}
        for target in targets:
            start = time.perf_counter()
            success = await _tcp_probe(target, port, timeout)
            target_creds = credentials.get(target) or []
            key_material = target_creds[0].get("ssh_key") if target_creds else None
            results.append(
                ScanResult(
                    ip=target,
                    success=success,
                    duration_ms=int((time.perf_counter() - start) * 1000),
                    data={
                        "status": "probe",
                        "scanner": self.name,
                        "port": port,
                        "credential_source": "central" if key_material else "missing",
                    },
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
