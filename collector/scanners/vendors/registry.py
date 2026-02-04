"""Vendor scanner registry and auto-detection."""

from __future__ import annotations

import logging
from typing import Any

from collector.scanners.vendors.base import VendorScanner

logger = logging.getLogger(__name__)


class VendorScannerRegistry:
    """Registry for vendor-specific device scanners."""

    def __init__(self) -> None:
        self._scanners: list[type[VendorScanner]] = []

    def register(self, scanner_class: type[VendorScanner]) -> None:
        """Register a vendor scanner class."""
        self._scanners.append(scanner_class)

    def get_all_scanners(self) -> list[type[VendorScanner]]:
        """Get all registered scanner classes."""
        return self._scanners.copy()

    async def detect_and_scan(
        self,
        host: str,
        username: str,
        password: str | None = None,
        ssh_key: str | None = None,
        enable_password: str | None = None,
        port: int = 22,
        timeout: int = 30,
    ) -> tuple[VendorScanner | None, Any]:
        """
        Auto-detect device vendor and scan.

        Args:
            host: Device IP or hostname
            username: SSH username
            password: SSH password
            ssh_key: SSH private key
            enable_password: Enable password
            port: SSH port
            timeout: Connection timeout

        Returns:
            Tuple of (scanner instance, scan result)
        """
        from collector.scanners.vendors.base import DeviceScanResult

        if not self._scanners:
            return None, DeviceScanResult(
                success=False,
                error="No compatible vendor scanner found for device",
            )

        conn = None
        try:
            # Establish a single connection for detection and scanning
            conn = await self._scanners[0]()._connect(
                host, username, password, ssh_key, port, timeout
            )

            # Try each registered scanner using the same connection
            for scanner_class in self._scanners:
                scanner = scanner_class()
                try:
                    if await scanner.detect_device_type(conn):
                        result = await scanner._scan_with_connection(
                            conn=conn,
                            enable_password=enable_password,
                        )
                        return scanner, result
                except Exception as exc:
                    logger.debug("vendor.scanner.error", exc_info=exc)
                    continue
        finally:
            if conn:
                await conn.close()

        # No scanner could handle this device
        return None, DeviceScanResult(
            success=False,
            error="No compatible vendor scanner found for device",
        )


# Global registry instance
_global_registry = VendorScannerRegistry()


def get_registry() -> VendorScannerRegistry:
    """Get the global vendor scanner registry."""
    return _global_registry


def register_default_scanners() -> None:
    """Register all default vendor scanners."""
    from collector.scanners.vendors.cisco_asa import CiscoASAScanner
    from collector.scanners.vendors.cisco_ios import CiscoIOSScanner
    from collector.scanners.vendors.paloalto import PaloAltoScanner

    registry = get_registry()

    # Register in order of specificity (most specific first)
    registry.register(CiscoASAScanner)
    registry.register(PaloAltoScanner)
    registry.register(CiscoIOSScanner)  # Most generic Cisco, check last
