"""Network device scanner using vendor-specific modules."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from collector.scanners.base import BaseScanner, ScanResult
from collector.scanners.vendors import get_registry, register_default_scanners


class NetworkDeviceScanner(BaseScanner):
    """
    Scanner for network devices using vendor-specific modules.

    Automatically detects device vendor and collects:
    - Device information (model, serial, version)
    - Interface details
    - CDP/LLDP neighbors
    - Hardware modules
    - ARP table
    - MAC address table
    """

    name = "network_device"

    def __init__(self) -> None:
        super().__init__()
        # Ensure default scanners are registered
        register_default_scanners()
        self.registry = get_registry()

    async def scan(
        self, targets: list[str], params: dict[str, Any]
    ) -> list[ScanResult]:
        """
        Scan network devices.

        Args:
            targets: List of device IPs/hostnames
            params: Scan parameters including:
                - timeout: Connection timeout (default: 30)
                - port: SSH port (default: 22)
                - credentials_by_target: Dict mapping targets to credentials
                - enable_password: Enable password for privilege escalation

        Returns:
            List of ScanResult objects
        """
        timeout = int(params.get("timeout", 30))
        port = int(params.get("port", 22))
        enable_password = params.get("enable_password")

        # Get credentials
        credentials = params.get("credentials_by_target", {})

        # Scan all targets concurrently
        tasks = []
        for target in targets:
            task = asyncio.create_task(
                self._scan_device(
                    target, credentials.get(target, []), port, timeout, enable_password
                )
            )
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
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

    async def _scan_device(
        self,
        target: str,
        credentials: list[dict[str, Any]],
        port: int,
        timeout: int,
        enable_password: str | None,
    ) -> ScanResult:
        """Scan a single network device."""
        start = time.perf_counter()

        # Extract credentials
        if not credentials:
            return ScanResult(
                ip=target,
                success=False,
                duration_ms=int((time.perf_counter() - start) * 1000),
                data={"status": "no_credentials", "scanner": self.name},
                error="No credentials provided",
            )

        cred = credentials[0]
        username = cred.get("username")
        password = cred.get("password")
        ssh_key = cred.get("ssh_key")

        if not username:
            return ScanResult(
                ip=target,
                success=False,
                duration_ms=int((time.perf_counter() - start) * 1000),
                data={"status": "invalid_credentials", "scanner": self.name},
                error="Username not provided",
            )

        # Use enable password from params or credentials
        enable_pwd = enable_password or cred.get("enable_password")

        try:
            # Auto-detect and scan
            scanner, result = await self.registry.detect_and_scan(
                host=target,
                username=username,
                password=password,
                ssh_key=ssh_key,
                enable_password=enable_pwd,
                port=port,
                timeout=timeout,
            )

            duration_ms = int((time.perf_counter() - start) * 1000)

            if not result.success:
                return ScanResult(
                    ip=target,
                    success=False,
                    duration_ms=duration_ms,
                    data={
                        "status": "scan_failed",
                        "scanner": self.name,
                        "vendor_scanner": scanner.vendor_name if scanner else "unknown",
                    },
                    error=result.error or "Scan failed",
                )

            # Build successful result data
            data: dict[str, Any] = {
                "status": "success",
                "scanner": self.name,
                "vendor_scanner": scanner.vendor_name if scanner else "unknown",
            }

            # Add device info
            if result.device_info:
                data["device"] = {
                    "hostname": result.device_info.hostname,
                    "model": result.device_info.model,
                    "serial_number": result.device_info.serial_number,
                    "os_version": result.device_info.os_version,
                    "uptime": result.device_info.uptime,
                    "vendor": result.device_info.vendor,
                    "device_type": result.device_info.device_type,
                }

            # Add interfaces
            if result.interfaces:
                data["interfaces"] = [
                    {
                        "name": intf.name,
                        "status": intf.status,
                        "ip_address": intf.ip_address,
                        "mac_address": intf.mac_address,
                        "description": intf.description,
                        "speed": intf.speed,
                        "duplex": intf.duplex,
                        "vlan": intf.vlan,
                    }
                    for intf in result.interfaces
                ]
                data["interface_count"] = len(result.interfaces)
                data["interfaces_up"] = sum(
                    1 for intf in result.interfaces if intf.status == "up"
                )

            # Add neighbors
            if result.neighbors:
                data["neighbors"] = [
                    {
                        "local_interface": nbr.local_interface,
                        "remote_device": nbr.remote_device,
                        "remote_interface": nbr.remote_interface,
                        "remote_ip": nbr.remote_ip,
                        "platform": nbr.platform,
                        "capabilities": nbr.capabilities,
                        "protocol": nbr.protocol,
                    }
                    for nbr in result.neighbors
                ]
                data["neighbor_count"] = len(result.neighbors)

            # Add modules
            if result.modules:
                data["modules"] = [
                    {
                        "slot": mod.slot,
                        "model": mod.model,
                        "serial_number": mod.serial_number,
                        "description": mod.description,
                        "status": mod.status,
                    }
                    for mod in result.modules
                ]
                data["module_count"] = len(result.modules)

            # Add ARP table summary
            if result.arp_table:
                data["arp_entries"] = len(result.arp_table)
                # Include first 100 entries
                data["arp_table"] = [
                    {
                        "ip_address": entry.ip_address,
                        "mac_address": entry.mac_address,
                        "interface": entry.interface,
                        "age": entry.age,
                    }
                    for entry in result.arp_table[:100]
                ]

            # Add MAC table summary
            if result.mac_table:
                data["mac_entries"] = len(result.mac_table)
                # Include first 100 entries
                data["mac_table"] = [
                    {
                        "mac_address": entry.mac_address,
                        "vlan": entry.vlan,
                        "interface": entry.interface,
                        "type": entry.type,
                    }
                    for entry in result.mac_table[:100]
                ]

            return ScanResult(
                ip=target,
                success=True,
                duration_ms=duration_ms,
                data=data,
                error=None,
            )

        except Exception as e:
            duration_ms = int((time.perf_counter() - start) * 1000)
            return ScanResult(
                ip=target,
                success=False,
                duration_ms=duration_ms,
                data={
                    "status": "exception",
                    "scanner": self.name,
                },
                error=str(e),
            )
