"""Cisco ASA firewall scanner."""

from __future__ import annotations

import logging
import re

from collector.scanners.vendors.base import (
    ArpEntry,
    DeviceInfo,
    InterfaceInfo,
    MacEntry,
    ModuleInfo,
    NeighborInfo,
    SSHConnection,
    VendorScanner,
    extract_field,
)

logger = logging.getLogger(__name__)


class CiscoASAScanner(VendorScanner):
    """Scanner for Cisco ASA firewall devices."""

    vendor_name = "Cisco ASA"
    device_types = ["firewall", "asa"]

    async def detect_device_type(self, conn: SSHConnection) -> bool:
        """Detect if device is Cisco ASA."""
        try:
            output = await conn.execute_command("show version")
            indicators = [
                "Cisco Adaptive Security Appliance",
                "Cisco ASA",
                "ASA Version",
            ]
            return any(indicator in output for indicator in indicators)
        except Exception:
            return False

    async def collect_device_info(self, conn: SSHConnection) -> DeviceInfo:
        """Collect device information from Cisco ASA."""
        try:
            show_version = await conn.execute_command("show version")
            show_inventory = await conn.execute_command("show inventory")

            # Extract hostname
            hostname = extract_field(show_version, r"(\S+)\s+up")

            # Extract model
            model = extract_field(show_version, r"Hardware:\s+(\S+)") or extract_field(
                show_inventory, r"PID:\s*(\S+)"
            )

            # Extract serial number
            serial = extract_field(
                show_version, r"Serial Number:\s*(\S+)"
            ) or extract_field(show_inventory, r"SN:\s*(\S+)")

            # Extract OS version
            os_version = extract_field(
                show_version, r"(?:Cisco )?ASA Version\s+([^\n]+)"
            )

            # Extract uptime
            uptime = extract_field(show_version, r"(\S+)\s+up\s+(.+?)(?:\n|$)", 2)

            return DeviceInfo(
                hostname=hostname,
                model=model,
                serial_number=serial,
                os_version=os_version,
                uptime=uptime,
                vendor="Cisco",
                device_type="asa",
            )

        except Exception:
            return DeviceInfo(vendor="Cisco", device_type="asa")

    async def collect_interfaces(self, conn: SSHConnection) -> list[InterfaceInfo]:
        """Collect interface information from ASA."""
        interfaces = []

        try:
            # Get interface summary
            show_int_ip_brief = await conn.execute_command("show interface ip brief")

            # Parse interface brief
            for line in show_int_ip_brief.split("\n"):
                line = line.strip()
                if not line or "Interface" in line:
                    continue

                # Format: Interface IP-Address OK? Method Status Protocol
                parts = line.split()
                if len(parts) >= 6:
                    interface = InterfaceInfo(
                        name=parts[0],
                        ip_address=parts[1] if parts[1] != "unassigned" else None,
                        status=parts[4],
                    )
                    interfaces.append(interface)

            # Get detailed interface info
            show_interface = await conn.execute_command("show interface")

            current_interface = None
            for line in show_interface.split("\n"):
                # New interface
                if re.match(r"^Interface \S+", line):
                    match = re.search(r"Interface (\S+)", line)
                    if match:
                        current_interface = match.group(1)

                # MAC address
                elif current_interface and "MAC address" in line:
                    mac = extract_field(line, r"MAC address (\S+)")
                    for intf in interfaces:
                        if intf.name == current_interface:
                            intf.mac_address = mac
                            break

                # Description (nameif)
                elif current_interface and "nameif" in line.lower():
                    desc = extract_field(line, r"nameif (\S+)")
                    for intf in interfaces:
                        if intf.name == current_interface:
                            intf.description = desc
                            break

                # Security level (ASA-specific)
                elif current_interface and "Security level" in line:
                    sec_level = extract_field(line, r"Security level (\d+)")
                    for intf in interfaces:
                        if intf.name == current_interface:
                            if intf.description:
                                intf.description += f" (sec:{sec_level})"
                            else:
                                intf.description = f"Security level: {sec_level}"
                            break

                # Speed and duplex
                elif current_interface and "duplex" in line.lower():
                    for intf in interfaces:
                        if intf.name == current_interface:
                            intf.duplex = extract_field(line, r"(\w+)-duplex")
                            intf.speed = extract_field(line, r"(\d+\w+)")
                            break

        except Exception as exc:
            logger.debug("vendor.scanner.error", exc_info=exc)

        return interfaces

    async def collect_neighbors(self, conn: SSHConnection) -> list[NeighborInfo]:
        """Collect CDP/LLDP neighbor information from ASA."""
        neighbors = []

        # ASA primarily uses CDP
        try:
            cdp_output = await conn.execute_command("show cdp neighbor detail")
            neighbors.extend(self._parse_cdp_neighbors(cdp_output))
        except Exception as exc:
            logger.debug("vendor.scanner.error", exc_info=exc)

        return neighbors

    def _parse_cdp_neighbors(self, output: str) -> list[NeighborInfo]:
        """Parse CDP neighbor details."""
        neighbors = []
        current_neighbor: dict[str, str] = {}

        for line in output.split("\n"):
            line = line.strip()

            if "Device ID:" in line:
                if current_neighbor:
                    neighbors.append(self._build_neighbor(current_neighbor))
                current_neighbor = {"device_id": line.split("Device ID:", 1)[1].strip()}

            elif "IP Address:" in line or "IPv4 Address:" in line:
                ip = line.split(":", 1)[1].strip()
                current_neighbor["ip"] = ip

            elif "Platform:" in line:
                platform = line.split("Platform:", 1)[1].strip()
                if "," in platform:
                    platform = platform.split(",", 1)[0].strip()
                current_neighbor["platform"] = platform

            elif "Interface:" in line:
                parts = line.split(",")
                if parts:
                    local = parts[0].split("Interface:", 1)[1].strip()
                    current_neighbor["local_interface"] = local
                if len(parts) > 1 and "Port ID" in parts[1]:
                    remote = parts[1].split(":", 1)[1].strip()
                    current_neighbor["remote_interface"] = remote

            elif "Capabilities:" in line:
                caps = line.split("Capabilities:", 1)[1].strip()
                current_neighbor["capabilities"] = caps

        # Add last neighbor
        if current_neighbor:
            neighbors.append(self._build_neighbor(current_neighbor))

        return neighbors

    def _build_neighbor(self, data: dict) -> NeighborInfo:
        """Build NeighborInfo from parsed data."""
        capabilities = []
        if "capabilities" in data:
            caps_str = data["capabilities"]
            capabilities = [c.strip() for c in caps_str.split() if c.strip()]

        return NeighborInfo(
            local_interface=data.get("local_interface", "unknown"),
            remote_device=data.get("device_id", "unknown"),
            remote_interface=data.get("remote_interface", "unknown"),
            remote_ip=data.get("ip"),
            platform=data.get("platform"),
            capabilities=capabilities if capabilities else None,
            protocol="cdp",
        )

    async def collect_modules(self, conn: SSHConnection) -> list[ModuleInfo]:
        """Collect hardware module information from ASA."""
        modules = []

        try:
            # ASA inventory
            inventory_output = await conn.execute_command("show inventory")

            current_module: dict[str, str | None] = {}
            for line in inventory_output.split("\n"):
                line = line.strip()

                if line.startswith("Name:"):
                    if current_module:
                        modules.append(self._build_module(current_module))
                    name = extract_field(line, r'Name:\s*"([^"]+)"')
                    current_module = {"name": name}

                elif "PID:" in line and current_module:
                    pid = extract_field(line, r"PID:\s*(\S+)")
                    sn = extract_field(line, r"SN:\s*(\S+)")
                    current_module["model"] = pid
                    current_module["serial"] = sn

                elif "DESCR:" in line and current_module:
                    desc = extract_field(line, r'DESCR:\s*"([^"]+)"')
                    current_module["description"] = desc

            # Add last module
            if current_module:
                modules.append(self._build_module(current_module))

        except Exception as exc:
            logger.debug("vendor.scanner.error", exc_info=exc)

        return modules

    def _build_module(self, data: dict) -> ModuleInfo:
        """Build ModuleInfo from parsed data."""
        slot = data.get("name", "chassis")
        slot_match = re.search(r"slot\s*(\d+)", slot, re.IGNORECASE)
        if slot_match:
            slot = slot_match.group(1)

        return ModuleInfo(
            slot=slot,
            model=data.get("model", "unknown"),
            serial_number=data.get("serial"),
            description=data.get("description"),
            status="ok",
        )

    async def collect_arp_table(self, conn: SSHConnection) -> list[ArpEntry]:
        """Collect ARP table from ASA."""
        arp_entries = []

        try:
            arp_output = await conn.execute_command("show arp")

            # Parse ARP table
            # Format: interface IP_address MAC_address age
            for line in arp_output.split("\n"):
                line = line.strip()
                if not line or "Interface" in line or "MAC" in line:
                    continue

                parts = line.split()
                if len(parts) >= 3:
                    # ASA format: interface ip mac [age]
                    arp_entries.append(
                        ArpEntry(
                            interface=parts[0],
                            ip_address=parts[1],
                            mac_address=parts[2],
                            age=parts[3] if len(parts) > 3 else None,
                        )
                    )

        except Exception as exc:
            logger.debug("vendor.scanner.error", exc_info=exc)

        return arp_entries

    async def collect_mac_table(self, conn: SSHConnection) -> list[MacEntry]:
        """
        Collect MAC address table from ASA.

        Note: ASA doesn't have a traditional MAC address table like switches.
        This returns bridge group MAC addresses if available.
        """
        mac_entries = []

        try:
            # ASA uses bridge groups for transparent mode
            mac_output = await conn.execute_command("show mac-address-table")

            for line in mac_output.split("\n"):
                line = line.strip()
                if not line or "VLAN" in line or "Mac" in line or "---" in line:
                    continue

                parts = line.split()
                if len(parts) >= 3:
                    # Parse bridge group MAC table
                    mac_entries.append(
                        MacEntry(
                            vlan=parts[0] if parts[0].isdigit() else "1",
                            mac_address=parts[1],
                            interface=parts[2],
                            type=parts[3] if len(parts) > 3 else "dynamic",
                        )
                    )

        except Exception as exc:
            # ASA in routed mode won't have MAC table
            logger.debug("vendor.scanner.error", exc_info=exc)

        return mac_entries
