"""Cisco IOS device scanner."""

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


class CiscoIOSScanner(VendorScanner):
    """Scanner for Cisco IOS/IOS-XE devices (routers, switches)."""

    vendor_name = "Cisco IOS"
    device_types = ["router", "switch", "catalyst"]

    async def detect_device_type(self, conn: SSHConnection) -> bool:
        """Detect if device is Cisco IOS."""
        try:
            output = await conn.execute_command("show version")
            # Check for Cisco IOS indicators
            indicators = [
                "Cisco IOS Software",
                "IOS-XE Software",
                "Cisco Internetwork Operating System",
            ]
            return any(indicator in output for indicator in indicators)
        except Exception:
            return False

    async def collect_device_info(self, conn: SSHConnection) -> DeviceInfo:
        """Collect device information from Cisco IOS."""
        try:
            show_version = await conn.execute_command("show version")
            show_inventory = await conn.execute_command("show inventory")

            # Extract hostname
            hostname = extract_field(show_version, r"(\S+)\s+uptime is")

            # Extract model - try multiple patterns
            model = (
                extract_field(show_version, r"cisco (\S+) \(.+\) processor")
                or extract_field(show_version, r"Model number\s*:\s*(\S+)")
                or extract_field(show_inventory, r"PID:\s*(\S+)\s*,")
            )

            # Extract serial number
            serial = extract_field(
                show_version, r"Processor board ID (\S+)", 1
            ) or extract_field(show_inventory, r"SN:\s*(\S+)")

            # Extract OS version
            os_version = extract_field(
                show_version,
                r"Cisco IOS Software.*Version\s+([^,\n]+)",
            ) or extract_field(show_version, r"IOS-XE Software.*Version\s+([^,\n]+)")

            # Extract uptime
            uptime = extract_field(show_version, r"uptime is (.+?)(?:\n|$)")

            return DeviceInfo(
                hostname=hostname,
                model=model,
                serial_number=serial,
                os_version=os_version,
                uptime=uptime,
                vendor="Cisco",
                device_type="ios",
            )

        except Exception:
            return DeviceInfo(vendor="Cisco", device_type="ios")

    async def collect_interfaces(self, conn: SSHConnection) -> list[InterfaceInfo]:
        """Collect interface information."""
        interfaces = []

        try:
            # Get interface status
            show_ip_int_brief = await conn.execute_command("show ip interface brief")

            # Parse interface brief output
            for line in show_ip_int_brief.split("\n"):
                line = line.strip()
                if not line or "Interface" in line:
                    continue

                # Parse format: Interface IP-Address OK? Method Status Protocol
                parts = line.split()
                if len(parts) >= 6:
                    interface = InterfaceInfo(
                        name=parts[0],
                        ip_address=parts[1] if parts[1] != "unassigned" else None,
                        status=parts[4],
                    )
                    interfaces.append(interface)

            # Get detailed interface info
            show_interfaces = await conn.execute_command("show interfaces")

            # Parse detailed interface output for each interface
            current_interface = None
            for line in show_interfaces.split("\n"):
                # New interface section
                if re.match(r"^\S+.*is (up|down)", line):
                    match = re.match(r"^(\S+)", line)
                    if match:
                        current_interface = match.group(1)
                        # Find this interface in our list
                        for intf in interfaces:
                            if intf.name == current_interface:
                                # Update status from detailed output
                                if "administratively down" in line.lower():
                                    intf.status = "admin down"
                                break

                # Extract MAC address
                elif current_interface and "address is" in line.lower():
                    mac = extract_field(line, r"address is (\S+)")
                    if mac:
                        for intf in interfaces:
                            if intf.name == current_interface:
                                intf.mac_address = mac
                                break

                # Extract description
                elif current_interface and "Description:" in line:
                    desc = line.split("Description:", 1)[1].strip()
                    for intf in interfaces:
                        if intf.name == current_interface:
                            intf.description = desc
                            break

                # Extract speed/duplex
                elif current_interface and (
                    "duplex" in line.lower() or "speed" in line.lower()
                ):
                    for intf in interfaces:
                        if intf.name == current_interface:
                            if "duplex" in line.lower():
                                intf.duplex = extract_field(line, r"(\w+)-duplex")
                            if "speed" in line.lower():
                                intf.speed = extract_field(
                                    line, r"(\d+\w+/s)"
                                ) or extract_field(line, r"BW (\d+)")
                            break

        except Exception as exc:
            logger.debug("vendor.scanner.error", exc_info=exc)

        return interfaces

    async def collect_neighbors(self, conn: SSHConnection) -> list[NeighborInfo]:
        """Collect CDP and LLDP neighbor information."""
        neighbors = []

        # Try CDP first
        try:
            cdp_output = await conn.execute_command("show cdp neighbors detail")
            neighbors.extend(self._parse_cdp_neighbors(cdp_output))
        except Exception as exc:
            logger.debug("vendor.scanner.error", exc_info=exc)

        # Try LLDP as fallback/additional
        try:
            lldp_output = await conn.execute_command("show lldp neighbors detail")
            neighbors.extend(self._parse_lldp_neighbors(lldp_output))
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
                    neighbors.append(self._build_neighbor(current_neighbor, "cdp"))
                current_neighbor = {"device_id": line.split("Device ID:", 1)[1].strip()}

            elif "IP address:" in line:
                current_neighbor["ip"] = line.split("IP address:", 1)[1].strip()

            elif "Platform:" in line:
                platform = line.split("Platform:", 1)[1].strip()
                caps = None
                if "Capabilities:" in platform:
                    platform_part, caps_part = platform.split("Capabilities:", 1)
                    platform = platform_part.strip().rstrip(",")
                    caps = caps_part.strip()
                # Extract just the platform part before capabilities
                if "," in platform:
                    platform = platform.split(",", 1)[0].strip()
                current_neighbor["platform"] = platform
                if caps:
                    current_neighbor["capabilities"] = caps

            elif "Interface:" in line:
                # Format: "Interface: GigabitEthernet0/0,  Port ID (outgoing port): GigabitEthernet0/1"
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
            neighbors.append(self._build_neighbor(current_neighbor, "cdp"))

        return neighbors

    def _parse_lldp_neighbors(self, output: str) -> list[NeighborInfo]:
        """Parse LLDP neighbor details."""
        neighbors = []
        current_neighbor: dict[str, str] = {}

        for line in output.split("\n"):
            line = line.strip()

            if "System Name:" in line:
                if current_neighbor:
                    neighbors.append(self._build_neighbor(current_neighbor, "lldp"))
                current_neighbor = {
                    "device_id": line.split("System Name:", 1)[1].strip()
                }

            elif "Local Intf:" in line:
                current_neighbor["local_interface"] = line.split("Local Intf:", 1)[
                    1
                ].strip()

            elif "Port id:" in line:
                current_neighbor["remote_interface"] = line.split("Port id:", 1)[
                    1
                ].strip()

            elif "System Description:" in line:
                current_neighbor["platform"] = line.split("System Description:", 1)[
                    1
                ].strip()

            elif "Management Addresses:" in line:
                # Next line usually has the IP
                pass

        # Add last neighbor
        if current_neighbor:
            neighbors.append(self._build_neighbor(current_neighbor, "lldp"))

        return neighbors

    def _build_neighbor(self, data: dict, protocol: str) -> NeighborInfo:
        """Build NeighborInfo from parsed data."""
        capabilities = []
        if "capabilities" in data:
            # Parse capabilities like "Router Switch IGMP"
            caps_str = data["capabilities"]
            capabilities = [c.strip() for c in caps_str.split() if c.strip()]

        return NeighborInfo(
            local_interface=data.get("local_interface", "unknown"),
            remote_device=data.get("device_id", "unknown"),
            remote_interface=data.get("remote_interface", "unknown"),
            remote_ip=data.get("ip"),
            platform=data.get("platform"),
            capabilities=capabilities if capabilities else None,
            protocol=protocol,
        )

    async def collect_modules(self, conn: SSHConnection) -> list[ModuleInfo]:
        """Collect hardware module information."""
        modules = []

        try:
            # Try show inventory for detailed module info
            inventory_output = await conn.execute_command("show inventory")

            current_module: dict[str, str | None] = {}
            for line in inventory_output.split("\n"):
                line = line.strip()

                if line.startswith("NAME:"):
                    if current_module:
                        modules.append(self._build_module(current_module))
                    # Parse: NAME: "Chassis", DESCR: "Cisco..."
                    name = extract_field(line, r'NAME:\s*"([^"]+)"')
                    current_module = {"name": name}

                elif "PID:" in line and current_module:
                    # Parse: PID: WS-C3850-24P , VID: V01 , SN: FCW1234A1BC
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

            # Also try show module for chassis-based systems
            try:
                module_output = await conn.execute_command("show module")
                # Parse module output for slot-based information
                for line in module_output.split("\n"):
                    if re.match(r"^\s*\d+\s+", line):  # Line starts with slot number
                        parts = line.split()
                        if len(parts) >= 3:
                            modules.append(
                                ModuleInfo(
                                    slot=parts[0],
                                    model=parts[1],
                                    status=parts[2] if len(parts) > 2 else None,
                                )
                            )
            except Exception as exc:
                logger.debug("vendor.scanner.error", exc_info=exc)

        except Exception as exc:
            logger.debug("vendor.scanner.error", exc_info=exc)

        return modules

    def _build_module(self, data: dict) -> ModuleInfo:
        """Build ModuleInfo from parsed data."""
        # Use name as slot identifier
        slot = data.get("name", "unknown")
        # Extract slot number if present
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
        """Collect ARP table."""
        arp_entries = []

        try:
            arp_output = await conn.execute_command("show ip arp")

            # Parse ARP table
            # Format: Protocol  Address          Age (min)  Hardware Addr   Type   Interface
            for line in arp_output.split("\n"):
                line = line.strip()
                if not line or "Protocol" in line or "Address" in line:
                    continue

                parts = line.split()
                if len(parts) >= 5:
                    # Handle both formats
                    if parts[0].lower() == "internet":
                        arp_entries.append(
                            ArpEntry(
                                ip_address=parts[1],
                                mac_address=parts[3],
                                interface=parts[5] if len(parts) > 5 else parts[4],
                                age=parts[2],
                                type=parts[4] if len(parts) > 5 else None,
                            )
                        )

        except Exception as exc:
            logger.debug("vendor.scanner.error", exc_info=exc)

        return arp_entries

    async def collect_mac_table(self, conn: SSHConnection) -> list[MacEntry]:
        """Collect MAC address table."""
        mac_entries = []

        try:
            mac_output = await conn.execute_command("show mac address-table")

            # Parse MAC address table
            # Format varies: VLAN  Mac Address      Type       Ports
            for line in mac_output.split("\n"):
                line = line.strip()
                if (
                    not line
                    or "VLAN" in line
                    or "Mac Address" in line
                    or "----" in line
                    or "Total" in line
                ):
                    continue

                parts = line.split()
                if len(parts) >= 4:
                    # Check if first part is a VLAN number
                    if parts[0].isdigit() or parts[0].lower() == "all":
                        vlan = parts[0]
                        mac = parts[1]
                        mac_type = parts[2]
                        interface = " ".join(parts[3:])  # Port name might have spaces

                        mac_entries.append(
                            MacEntry(
                                vlan=vlan,
                                mac_address=mac,
                                interface=interface,
                                type=mac_type.lower(),
                            )
                        )

        except Exception as exc:
            logger.debug("vendor.scanner.error", exc_info=exc)

        return mac_entries
