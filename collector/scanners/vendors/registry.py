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

        # Try each registered scanner
        for scanner_class in self._scanners:
            scanner = scanner_class()

            try:
                # Try to detect if this scanner can handle the device
                # We need to connect first
                conn = await scanner._connect(
                    host, username, password, ssh_key, port, timeout
                )

                try:
                    if await scanner.detect_device_type(conn):
                        # This scanner can handle it, close connection and do full scan
                        await conn.close()

                        result = await scanner.scan_device(
                            host=host,
                            username=username,
                            password=password,
                            ssh_key=ssh_key,
                            enable_password=enable_password,
                            port=port,
                            timeout=timeout,
                        )
                        return scanner, result
                finally:
                    await conn.close()

            except Exception as exc:
                # This scanner failed, try next
                logger.debug("vendor.scanner.error", exc_info=exc)
                continue

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
