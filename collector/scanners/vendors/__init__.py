"""Vendor scanner package initialization."""

from collector.scanners.vendors.base import (
    ArpEntry,
    DeviceInfo,
    DeviceScanResult,
    InterfaceInfo,
    MacEntry,
    ModuleInfo,
    NeighborInfo,
    SSHConnection,
    VendorScanner,
)
from collector.scanners.vendors.cisco_asa import CiscoASAScanner
from collector.scanners.vendors.cisco_ios import CiscoIOSScanner
from collector.scanners.vendors.paloalto import PaloAltoScanner
from collector.scanners.vendors.registry import (
    VendorScannerRegistry,
    get_registry,
    register_default_scanners,
)

__all__ = [
    # Base classes
    "VendorScanner",
    "SSHConnection",
    "DeviceInfo",
    "InterfaceInfo",
    "NeighborInfo",
    "ModuleInfo",
    "ArpEntry",
    "MacEntry",
    "DeviceScanResult",
    # Vendor scanners
    "CiscoIOSScanner",
    "CiscoASAScanner",
    "PaloAltoScanner",
    # Registry
    "VendorScannerRegistry",
    "get_registry",
    "register_default_scanners",
]
