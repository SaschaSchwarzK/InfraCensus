"""Improved NETCONF scanner with XML capability exchange and parsing."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import time
from typing import Any

from collector.scanners.base import BaseScanner, ScanResult


class NetconfScanner(BaseScanner):
    """Enhanced NETCONF scanner that performs capability exchange and extracts device info."""

    name = "netconf"

    # NETCONF message delimiters
    HELLO_START = '<?xml version="1.0" encoding="UTF-8"?><hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">'
    HELLO_END = "</hello>]]>]]>"
    MSG_DELIMITER = "]]>]]>"

    async def scan(
        self, targets: list[str], params: dict[str, Any]
    ) -> list[ScanResult]:
        """
        Scan targets for NETCONF services.

        Args:
            targets: List of IP addresses to scan
            params: Scan parameters including:
                - timeout: Connection timeout in seconds (default: 10)
                - port: NETCONF port (default: 830)
                - exchange_capabilities: Perform NETCONF hello exchange (default: True)

        Returns:
            List of ScanResult objects with NETCONF metadata
        """
        timeout = int(params.get("timeout", 10))
        port = int(params.get("port", 830))
        exchange_capabilities = params.get("exchange_capabilities", True)

        # Validate port
        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid port: {port}")

        # Scan all targets concurrently
        tasks = []
        for target in targets:
            task = asyncio.create_task(
                self._scan_target(target, port, timeout, exchange_capabilities)
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
        self, target: str, port: int, timeout: int, exchange_capabilities: bool
    ) -> ScanResult:
        """Scan a single target for NETCONF service."""
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

        try:
            # Connect to NETCONF port
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=timeout,
            )

            capabilities: list[str] = []
            session_id: str | None = None

            if exchange_capabilities:
                try:
                    # Send NETCONF hello message
                    hello_msg = self._build_hello_message()
                    writer.write(hello_msg.encode("utf-8"))
                    await writer.drain()

                    # Read response (with timeout)
                    response = await asyncio.wait_for(
                        self._read_netconf_message(reader),
                        timeout=5,
                    )

                    # Parse capabilities from hello response
                    capabilities, session_id = self._parse_hello_response(response)

                except TimeoutError:
                    pass  # Connection works but no proper NETCONF response

            # Clean up connection
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2)
            except TimeoutError:
                pass

            duration_ms = int((time.perf_counter() - start) * 1000)

            # Determine if this is a valid NETCONF service
            is_netconf = bool(capabilities or session_id)

            return ScanResult(
                ip=target,
                success=is_netconf,
                duration_ms=duration_ms,
                data={
                    "status": "up" if is_netconf else "open_port",
                    "scanner": self.name,
                    "port": port,
                    "protocol": "netconf" if is_netconf else "unknown",
                    "capabilities": capabilities,
                    "session_id": session_id or "unknown",
                    "capability_count": len(capabilities),
                    "base_1_0": "urn:ietf:params:netconf:base:1.0" in capabilities,
                    "base_1_1": "urn:ietf:params:netconf:base:1.1" in capabilities,
                },
                error=None if is_netconf else "Port open but no NETCONF response",
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
                    "protocol": "netconf",
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
                    "protocol": "netconf",
                },
                error=f"Connection error: {str(e)}",
            )

    def _build_hello_message(self) -> str:
        """Build a NETCONF hello message."""
        return f"""{self.HELLO_START}
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
    <capability>urn:ietf:params:netconf:base:1.1</capability>
  </capabilities>
{self.HELLO_END}"""

    async def _read_netconf_message(self, reader: asyncio.StreamReader) -> str:
        """Read a complete NETCONF message (until delimiter)."""
        data = bytearray()
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                break
            data.extend(chunk)

            # Check for message delimiter
            decoded = data.decode("utf-8", errors="ignore")
            if self.MSG_DELIMITER in decoded:
                # Return message without delimiter
                return decoded.split(self.MSG_DELIMITER)[0]

            # Prevent reading too much data
            if len(data) > 1024 * 1024:  # 1MB limit
                break

        return data.decode("utf-8", errors="ignore")

    def _parse_hello_response(self, response: str) -> tuple[list[str], str | None]:
        """
        Parse NETCONF hello response and extract capabilities.

        Args:
            response: XML hello response string

        Returns:
            Tuple of (capabilities list, session_id)
        """
        capabilities = []
        session_id = None

        # Extract session ID
        session_match = re.search(r"<session-id>(\d+)</session-id>", response)
        if session_match:
            session_id = session_match.group(1)

        # Extract capabilities
        capability_pattern = r"<capability>([^<]+)</capability>"
        capability_matches = re.findall(capability_pattern, response)

        for cap in capability_matches:
            cap = cap.strip()
            if cap:
                capabilities.append(cap)

        return capabilities, session_id

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
