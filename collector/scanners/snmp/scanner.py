"""Improved SNMP scanner with actual SNMP queries and OID parsing."""

from __future__ import annotations

import asyncio
import ipaddress
import time
from typing import Any

from collector.scanners.base import BaseScanner, ScanResult


class SnmpScanner(BaseScanner):
    """Enhanced SNMP scanner that performs actual SNMP queries and parses responses."""

    name = "snmp"
    required_tools = []

    # Common SNMP OIDs
    OID_SYSTEM_DESCR = "1.3.6.1.2.1.1.1.0"  # sysDescr
    OID_SYSTEM_UPTIME = "1.3.6.1.2.1.1.3.0"  # sysUpTime
    OID_SYSTEM_CONTACT = "1.3.6.1.2.1.1.4.0"  # sysContact
    OID_SYSTEM_NAME = "1.3.6.1.2.1.1.5.0"  # sysName
    OID_SYSTEM_LOCATION = "1.3.6.1.2.1.1.6.0"  # sysLocation

    async def scan(
        self, targets: list[str], params: dict[str, Any]
    ) -> list[ScanResult]:
        """
        Scan targets for SNMP services.

        Args:
            targets: List of IP addresses to scan
            params: Scan parameters including:
                - timeout: Query timeout in seconds (default: 5)
                - port: SNMP port (default: 161)
                - retries: Number of retries (default: 2)
                - community: Default community string (default: "public")

        Returns:
            List of ScanResult objects with SNMP data
        """
        timeout = int(params.get("timeout", 5))
        port = int(params.get("port", 161))
        retries = int(params.get("retries", 2))
        default_community = params.get("community", "public")

        # Validate port
        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid port: {port}")

        credentials = params.get("credentials_by_target") or {}

        # Scan all targets concurrently
        tasks = []
        for target in targets:
            task = asyncio.create_task(
                self._scan_target(
                    target, port, timeout, retries, default_community, credentials
                )
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
        retries: int,
        default_community: str,
        credentials: dict[str, list[dict[str, object]]],
    ) -> ScanResult:
        """Scan a single target for SNMP service."""
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

        # Get community string from credentials or use default
        target_creds = credentials.get(target) or []
        community = (
            str(target_creds[0].get("community"))
            if target_creds and target_creds[0].get("community")
            else default_community
        )

        # Try SNMP query with retries
        snmp_data = None
        last_error = None

        for attempt in range(retries + 1):
            try:
                snmp_data = await self._snmp_get(target, port, community, timeout)
                if snmp_data:
                    break
            except Exception as e:
                last_error = str(e)
                if attempt < retries:
                    await asyncio.sleep(0.5)

        duration_ms = int((time.perf_counter() - start) * 1000)

        if snmp_data:
            return ScanResult(
                ip=target,
                success=True,
                duration_ms=duration_ms,
                data={
                    "status": "up",
                    "scanner": self.name,
                    "port": port,
                    "protocol": "snmp",
                    "community": community,
                    "credential_source": "central"
                    if target_creds and target_creds[0].get("community")
                    else "default",
                    **snmp_data,
                },
                error=None,
            )
        else:
            return ScanResult(
                ip=target,
                success=False,
                duration_ms=duration_ms,
                data={
                    "status": "unreachable",
                    "scanner": self.name,
                    "port": port,
                    "protocol": "snmp",
                    "community": community,
                    "credential_source": "central"
                    if target_creds and target_creds[0].get("community")
                    else "default",
                },
                error=last_error or "No SNMP response",
            )

    async def _snmp_get(
        self, target: str, port: int, community: str, timeout: int
    ) -> dict[str, Any] | None:
        """
        Perform SNMP GET request and parse response.

        This is a simplified SNMP v1/v2c implementation.
        For production use, consider using a proper SNMP library like pysnmp.
        """

        def _build_snmp_get_request(community: str, oid: str) -> bytes:
            """Build a simple SNMP v2c GET request."""
            # Convert OID string to bytes
            oid_parts = [int(x) for x in oid.split(".")]
            oid_bytes = bytearray()
            oid_bytes.append(oid_parts[0] * 40 + oid_parts[1])
            for part in oid_parts[2:]:
                if part < 128:
                    oid_bytes.append(part)
                else:
                    # Encode larger numbers
                    encoded: list[int] = []
                    while part > 0:
                        encoded.insert(0, (part & 0x7F) | 0x80)
                        part >>= 7
                    encoded[-1] &= 0x7F
                    oid_bytes.extend(encoded)

            # Build SNMP packet structure (simplified)
            # This is a basic implementation - production code should use a proper library
            community_bytes = community.encode("utf-8")

            # OID (Object Identifier)
            oid_tlv = bytes([0x06, len(oid_bytes)]) + bytes(oid_bytes)

            # NULL value for GET request
            null_tlv = bytes([0x05, 0x00])

            # Variable binding
            varbind = bytes([0x30, len(oid_tlv) + len(null_tlv)]) + oid_tlv + null_tlv

            # Variable binding list
            varbind_list = bytes([0x30, len(varbind)]) + varbind

            # PDU (GET request)
            request_id = bytes([0x02, 0x01, 0x01])  # Request ID
            error_status = bytes([0x02, 0x01, 0x00])  # Error status
            error_index = bytes([0x02, 0x01, 0x00])  # Error index

            pdu_data = request_id + error_status + error_index + varbind_list
            pdu = bytes([0xA0, len(pdu_data)]) + pdu_data

            # SNMP message
            version = bytes([0x02, 0x01, 0x01])  # SNMPv2c
            community_tlv = bytes([0x04, len(community_bytes)]) + community_bytes

            message_data = version + community_tlv + pdu
            message = bytes([0x30, len(message_data)]) + message_data

            return message

        def _parse_snmp_response(data: bytes) -> dict[str, str] | None:
            """Parse SNMP response (simplified)."""
            try:
                # Very basic parsing - production code should use proper ASN.1 parser
                # This just tries to extract string values from the response
                result = {}

                # Look for string values (0x04 type)
                i = 0
                while i < len(data) - 2:
                    if data[i] == 0x04:  # OCTET STRING type
                        length = data[i + 1]
                        if i + 2 + length <= len(data):
                            value = data[i + 2 : i + 2 + length]
                            try:
                                decoded = value.decode("utf-8", errors="ignore")
                                if decoded and decoded.isprintable():
                                    # Store first meaningful string as system description
                                    if (
                                        "system_description" not in result
                                        and len(decoded) > 5
                                    ):
                                        result["system_description"] = decoded[:200]
                                    break
                            except (UnicodeDecodeError, ValueError):
                                decoded = ""
                        i += 2 + length
                    else:
                        i += 1

                return result if result else None
            except (ValueError, IndexError):
                return None

        # Perform SNMP query
        try:
            # Build request for sysDescr OID
            request = _build_snmp_get_request(community, self.OID_SYSTEM_DESCR)

            # Send UDP request
            loop = asyncio.get_event_loop()
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: SNMPProtocol(),
                remote_addr=(target, port),
            )

            try:
                # Send request
                transport.sendto(request)

                # Wait for response
                response = await asyncio.wait_for(
                    protocol.response_received,
                    timeout=timeout,
                )

                # Parse response
                return _parse_snmp_response(response)

            finally:
                transport.close()

        except TimeoutError:
            return None
        except Exception:
            return None

    def _is_valid_target(self, target: str) -> bool:
        """
        Validate target IP address.

        Args:
            target: IP address to validate

        Returns:
            True if target is valid
        """
        try:
            ip = ipaddress.ip_address(target)
            # Allow private addresses for internal network scanning
            if ip.is_loopback or ip.is_link_local:
                return False
            if ip.is_multicast or ip.is_reserved:
                return False
            return True
        except ValueError:
            return False


class SNMPProtocol(asyncio.DatagramProtocol):
    """Simple UDP protocol for SNMP communication."""

    def __init__(self) -> None:
        self.response_received: asyncio.Future[bytes] = asyncio.Future()
        self.transport: asyncio.BaseTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Called when connection is established."""
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        """Called when a datagram is received."""
        if not self.response_received.done():
            self.response_received.set_result(data)

    def error_received(self, exc: Exception) -> None:
        """Called when an error is received."""
        if not self.response_received.done():
            self.response_received.set_exception(exc)

    def connection_lost(self, exc: Exception | None) -> None:
        """Called when connection is lost."""
        if not self.response_received.done():
            if exc:
                self.response_received.set_exception(exc)
            else:
                self.response_received.set_exception(ConnectionError("Connection lost"))
