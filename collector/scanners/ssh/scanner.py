"""Improved SSH scanner with banner grabbing and version detection."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from typing import Any

from collector.scanners.base import BaseScanner, ScanResult


class SshScanner(BaseScanner):
    """Enhanced SSH scanner that grabs SSH banners and identifies versions."""

    name = "ssh"

    async def scan(
        self, targets: list[str], params: dict[str, Any]
    ) -> list[ScanResult]:
        """
        Scan targets for SSH services.

        Args:
            targets: List of IP addresses to scan
            params: Scan parameters including:
                - timeout: Connection timeout in seconds (default: 10)
                - port: SSH port (default: 22)
                - grab_banner: Whether to grab SSH banner (default: True)

        Returns:
            List of ScanResult objects with SSH metadata
        """
        timeout = int(params.get("timeout", 10))
        port = int(params.get("port", 22))
        grab_banner = params.get("grab_banner", True)

        # Validate port
        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid port: {port}")

        credentials = params.get("credentials_by_target") or {}

        # Scan all targets concurrently
        tasks = []
        for target in targets:
            task = asyncio.create_task(
                self._scan_target(target, port, timeout, grab_banner, credentials)
            )
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results and handle exceptions
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
            elif isinstance(result, ScanResult):
                final_results.append(result)

        return final_results

    async def _scan_target(
        self,
        target: str,
        port: int,
        timeout: int,
        grab_banner: bool,
        credentials: dict[str, list[dict[str, object]]],
    ) -> ScanResult:
        """Scan a single target for SSH service."""
        # Validate target
        if not self._is_valid_target(target):
            return ScanResult(
                ip=target,
                success=False,
                duration_ms=0,
                data={"status": "invalid_target", "scanner": self.name},
                error="Invalid target address",
            )

        start = time.perf_counter()
        target_creds = credentials.get(target) or []
        has_credentials = (
            bool(
                target_creds
                and target_creds[0].get("ssh_key")
                or target_creds[0].get("password")
            )
            if target_creds
            else False
        )

        try:
            # Connect to SSH port
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=timeout,
            )

            banner = None
            ssh_version = None
            server_software = None

            if grab_banner:
                try:
                    # Read SSH banner (should be first line)
                    banner_bytes = await asyncio.wait_for(
                        reader.readline(),
                        timeout=3,
                    )
                    banner = banner_bytes.decode("utf-8", errors="ignore").strip()

                    # Parse SSH banner format: SSH-<version>-<software>
                    banner_match = re.match(
                        r"SSH-([0-9.]+)-(.+)", banner, re.IGNORECASE
                    )
                    if banner_match:
                        ssh_version = banner_match.group(1)
                        server_software = banner_match.group(2)

                except (TimeoutError, UnicodeDecodeError):
                    pass

            # Clean up connection
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2)
            except TimeoutError:
                pass

            duration_ms = int((time.perf_counter() - start) * 1000)

            return ScanResult(
                ip=target,
                success=True,
                duration_ms=duration_ms,
                data={
                    "status": "up",
                    "scanner": self.name,
                    "port": port,
                    "protocol": "ssh",
                    "banner": banner or "unknown",
                    "ssh_version": ssh_version or "unknown",
                    "server_software": server_software or "unknown",
                    "credential_source": "central" if has_credentials else "missing",
                },
                error=None,
            )

        except TimeoutError:
            duration_ms = int((time.perf_counter() - start) * 1000)
            return ScanResult(
                ip=target,
                success=False,
                duration_ms=duration_ms,
                data={
                    "status": "timeout",
                    "scanner": self.name,
                    "port": port,
                    "protocol": "ssh",
                    "credential_source": "central" if has_credentials else "missing",
                },
                error="Connection timeout",
            )

        except (ConnectionRefusedError, OSError) as e:
            duration_ms = int((time.perf_counter() - start) * 1000)
            return ScanResult(
                ip=target,
                success=False,
                duration_ms=duration_ms,
                data={
                    "status": "unreachable",
                    "scanner": self.name,
                    "port": port,
                    "protocol": "ssh",
                    "credential_source": "central" if has_credentials else "missing",
                },
                error=f"Connection error: {str(e)}",
            )

    def _is_valid_target(self, target: str) -> bool:
        """
        Validate target to prevent SSRF attacks.

        Args:
            target: IP address to validate

        Returns:
            True if target is valid and safe to scan
        """
        try:
            ip = ipaddress.ip_address(target)
            # Allow private addresses for internal network scanning
            # Block only loopback, link-local, multicast, and reserved ranges
            if ip.is_loopback or ip.is_link_local:
                return False
            if ip.is_multicast or ip.is_reserved:
                return False
            return True
        except ValueError:
            # Not a valid IP address
            return False
