from __future__ import annotations

import asyncio
import ipaddress
import time
from typing import Any

from collector.scanners.base import BaseScanner, ScanResult


class SshScanner(BaseScanner):
    name = "ssh"

    async def scan(
        self, targets: list[str], params: dict[str, Any]
    ) -> list[ScanResult]:
        results = []
        timeout = int(params.get("timeout", 10))
        port = int(params.get("port", 22))

        # Validate port to prevent SSRF
        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid port: {port}")

        credentials = params.get("credentials_by_target") or {}
        for target in targets:
            # Validate target to prevent SSRF
            if not _is_valid_target(target):
                results.append(
                    ScanResult(
                        ip=target,
                        success=False,
                        duration_ms=0,
                        data={"status": "invalid_target", "scanner": self.name},
                        error="Invalid target address",
                    )
                )
                continue

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


def _is_valid_target(target: str) -> bool:
    """Validate target to prevent SSRF attacks."""
    try:
        ip = ipaddress.ip_address(target)
        # Block private/internal addresses
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
        # Block multicast and reserved ranges
        if ip.is_multicast or ip.is_reserved:
            return False
        return True
    except ValueError:
        # If not a valid IP, reject it
        return False


async def _tcp_probe(target: str, port: int, timeout: int) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port),
            timeout=timeout,
        )
    except (TimeoutError, OSError):
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, OSError, RuntimeError):
        pass
    return True
