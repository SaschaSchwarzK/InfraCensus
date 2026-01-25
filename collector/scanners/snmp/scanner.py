from __future__ import annotations

import asyncio
import socket
import time
from typing import Any

from collector.scanners.base import BaseScanner, ScanResult


class SnmpScanner(BaseScanner):
    name = "snmp"

    async def scan(self, targets: list[str], params: dict[str, Any]) -> list[ScanResult]:
        results = []
        timeout = int(params.get("timeout", 5))
        for target in targets:
            start = time.perf_counter()
            success = await _udp_probe(target, 161, timeout)
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


async def _udp_probe(target: str, port: int, timeout: int) -> bool:
    def _run() -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b"\x00", (target, port))
            return True
        except OSError:
            return False
        finally:
            try:
                sock.close()
            except Exception:
                pass

    return await asyncio.to_thread(_run)
