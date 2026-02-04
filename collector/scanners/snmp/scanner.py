"""Improved SNMP scanner with actual SNMP queries and OID parsing."""

from __future__ import annotations

import asyncio
import ipaddress
import time
from typing import Any

from pysnmp.hlapi.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    getCmd,
    usmAesCfb128Protocol,
    usmDESPrivProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmNoAuthProtocol,
    usmNoPrivProtocol,
)

from collector.scanners.base import BaseScanner, ScanResult
from collector.scanners.utils import is_valid_hostname

_AUTH_PROTOCOLS = {
    "sha": usmHMACSHAAuthProtocol,
    "md5": usmHMACMD5AuthProtocol,
    "none": usmNoAuthProtocol,
}

_PRIV_PROTOCOLS = {
    "aes": usmAesCfb128Protocol,
    "des": usmDESPrivProtocol,
    "none": usmNoPrivProtocol,
}


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
        has_creds = bool(target_creds)
        community = (
            str(target_creds[0].get("community"))
            if target_creds and target_creds[0].get("community")
            else default_community
        )

        v3_params = None
        if target_creds and target_creds[0].get("username"):
            v3_params = {
                "username": target_creds[0].get("username"),
                "auth_key": target_creds[0].get("auth_key"),
                "priv_key": target_creds[0].get("priv_key"),
                "auth_protocol": target_creds[0].get("auth_protocol"),
                "priv_protocol": target_creds[0].get("priv_protocol"),
            }

        # Try SNMP query with retries
        snmp_data = None
        last_error = None

        for attempt in range(retries + 1):
            try:
                snmp_data = await self._snmp_get(
                    target, port, community, timeout, v3_params
                )
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
                    "credential_source": "central" if has_creds else "default",
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
                    "credential_source": "central" if has_creds else "default",
                },
                error=last_error or "No SNMP response",
            )

    async def _snmp_get(
        self,
        target: str,
        port: int,
        community: str,
        timeout: int,
        v3_params: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Perform SNMP GET request and parse response using pysnmp."""
        oids = [
            self.OID_SYSTEM_DESCR,
            self.OID_SYSTEM_UPTIME,
            self.OID_SYSTEM_CONTACT,
            self.OID_SYSTEM_NAME,
            self.OID_SYSTEM_LOCATION,
        ]

        if v3_params and v3_params.get("username"):
            username = str(v3_params.get("username"))
            auth_key = v3_params.get("auth_key")
            priv_key = v3_params.get("priv_key")
            auth_protocol = _AUTH_PROTOCOLS.get(
                str(v3_params.get("auth_protocol", "sha")).lower(),
                usmHMACSHAAuthProtocol,
            )
            priv_protocol = _PRIV_PROTOCOLS.get(
                str(v3_params.get("priv_protocol", "aes")).lower(),
                usmAesCfb128Protocol,
            )
            if auth_key:
                if priv_key:
                    user = UsmUserData(
                        username,
                        str(auth_key),
                        str(priv_key),
                        authProtocol=auth_protocol,
                        privProtocol=priv_protocol,
                    )
                else:
                    user = UsmUserData(
                        username,
                        str(auth_key),
                        authProtocol=auth_protocol,
                        privProtocol=usmNoPrivProtocol,
                    )
            else:
                user = UsmUserData(
                    username,
                    authProtocol=usmNoAuthProtocol,
                    privProtocol=usmNoPrivProtocol,
                )
        else:
            user = CommunityData(community, mpModel=1)

        transport = UdpTransportTarget((target, port), timeout=timeout, retries=0)
        error_indication, error_status, error_index, var_binds = await getCmd(
            SnmpEngine(),
            user,
            transport,
            ContextData(),
            *[ObjectType(ObjectIdentity(oid)) for oid in oids],
        )

        if error_indication or error_status:
            return None

        result: dict[str, Any] = {}
        for oid, value in var_binds:
            oid_str = str(oid)
            if oid_str == self.OID_SYSTEM_DESCR:
                result["system_description"] = str(value)
            elif oid_str == self.OID_SYSTEM_UPTIME:
                result["system_uptime"] = str(value)
            elif oid_str == self.OID_SYSTEM_CONTACT:
                result["system_contact"] = str(value)
            elif oid_str == self.OID_SYSTEM_NAME:
                result["system_name"] = str(value)
            elif oid_str == self.OID_SYSTEM_LOCATION:
                result["system_location"] = str(value)
            else:
                result[oid_str] = str(value)

        return result or None

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
            return is_valid_hostname(target)


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
