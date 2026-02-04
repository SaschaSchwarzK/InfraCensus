"""Palo Alto Networks firewall scanner."""

from __future__ import annotations

import logging

from collector.scanners.vendors.base import (
    ArpEntry,
    DeviceInfo,
    InterfaceInfo,
    MacEntry,
    ModuleInfo,
    NeighborInfo,
    SSHConnection,
    VendorScanner,
)

logger = logging.getLogger(__name__)


class PaloAltoScanner(VendorScanner):
    """Scanner for Palo Alto Networks firewall devices."""

    vendor_name = "Palo Alto Networks"
    device_types = ["firewall", "pan"]

    async def detect_device_type(self, conn: SSHConnection) -> bool:
        """Detect if device is Palo Alto."""
        try:
            output = await conn.execute_command("show system info")
            indicators = [
                "Palo Alto Networks",
                "model:",
                "sw-version:",
            ]
            return any(indicator in output for indicator in indicators)
        except Exception:
            return False

    async def collect_device_info(self, conn: SSHConnection) -> DeviceInfo:
        """Collect device information from Palo Alto."""
        try:
            system_info = await conn.execute_command("show system info")

            # Parse system info (key: value format)
            info_dict = {}
            for line in system_info.split("\n"):
                if ":" in line:
                    key, value = line.split(":", 1)
                    info_dict[key.strip().lower()] = value.strip()

            hostname = info_dict.get("hostname", info_dict.get("devicename"))
            model = info_dict.get("model")
            serial = info_dict.get("serial")
            os_version = info_dict.get("sw-version")
            uptime = info_dict.get("uptime")

            return DeviceInfo(
                hostname=hostname,
                model=model,
                serial_number=serial,
                os_version=os_version,
                uptime=uptime,
                vendor="Palo Alto Networks",
                device_type="firewall",
            )

        except Exception:
            return DeviceInfo(vendor="Palo Alto Networks", device_type="firewall")

    async def collect_interfaces(self, conn: SSHConnection) -> list[InterfaceInfo]:
        """Collect interface information from Palo Alto."""
        interfaces = []

        try:
            # Get interface info - PAN outputs in different formats
            show_interface = await conn.execute_command("show interface all")

            current_interface = None
            current_info: dict[str, str] = {}

            for line in show_interface.split("\n"):
                line = line.strip()

                # Interface header
                if line and not line.startswith(" ") and ":" in line:
                    # Save previous interface
                    if current_interface and current_info:
                        interfaces.append(
                            self._build_interface(current_interface, current_info)
                        )

                    # Start new interface
                    current_interface = line.split(":")[0].strip()
                    current_info = {}

                # Interface properties (indented)
                elif current_interface and line and ":" in line:
                    key, value = line.split(":", 1)
                    current_info[key.strip().lower()] = value.strip()

            # Add last interface
            if current_interface and current_info:
                interfaces.append(
                    self._build_interface(current_interface, current_info)
                )

            # Also try logical interface info
            try:
                logical_int = await conn.execute_command("show interface logical")
                # Parse logical interface output
                # This has format: name id vsys zone forwarding tag address
                for line in logical_int.split("\n"):
                    if line and not line.startswith("name"):
                        parts = line.split()
                        if len(parts) >= 2:
                            name = parts[0]
                            # Find matching interface and add zone info
                            for intf in interfaces:
                                if intf.name == name:
                                    if len(parts) > 3:
                                        zone = parts[3]
                                        if intf.description:
                                            intf.description += f" [Zone: {zone}]"
                                        else:
                                            intf.description = f"Zone: {zone}"
                                    break

            except Exception as exc:
                logger.debug("vendor.scanner.error", exc_info=exc)

        except Exception as exc:
            logger.debug("vendor.scanner.error", exc_info=exc)

        return interfaces

    def _build_interface(self, name: str, info: dict) -> InterfaceInfo:
        """Build InterfaceInfo from parsed interface data."""
        status = "up" if info.get("link state") == "up" else "down"

        # Get IP address
        ip_addr = info.get("ip", info.get("addr"))
        if ip_addr and "/" in ip_addr:
            ip_addr = ip_addr.split("/")[0]  # Remove subnet mask

        return InterfaceInfo(
            name=name,
            status=status,
            ip_address=ip_addr,
            mac_address=info.get("mac"),
            speed=info.get("speed"),
            duplex=info.get("duplex"),
            description=info.get("mode"),  # layer3, layer2, etc.
        )

    async def collect_neighbors(self, conn: SSHConnection) -> list[NeighborInfo]:
        """Collect LLDP neighbor information from Palo Alto."""
        neighbors = []

        try:
            # Palo Alto uses LLDP
            lldp_output = await conn.execute_command("show lldp neighbors all")
            neighbors.extend(self._parse_lldp_neighbors(lldp_output))
        except Exception as exc:
            logger.debug("vendor.scanner.error", exc_info=exc)

        return neighbors

    def _parse_lldp_neighbors(self, output: str) -> list[NeighborInfo]:
        """Parse LLDP neighbor information."""
        neighbors = []

        # Parse table format
        # Format: Local Port  Neighbor   Neighbor Port   Capability
        in_table = False
        for line in output.split("\n"):
            line = line.strip()

            # Skip until we find the table header
            if "Local Port" in line and "Neighbor" in line:
                in_table = True
                continue

            if not in_table or not line or line.startswith("-"):
                continue

            parts = line.split()
            if len(parts) >= 3:
                local_port = parts[0]
                neighbor = parts[1]
                remote_port = parts[2]
                capabilities = parts[3:] if len(parts) > 3 else []

                neighbors.append(
                    NeighborInfo(
                        local_interface=local_port,
                        remote_device=neighbor,
                        remote_interface=remote_port,
                        capabilities=capabilities if capabilities else None,
                        protocol="lldp",
                    )
                )

        return neighbors

    async def collect_modules(self, conn: SSHConnection) -> list[ModuleInfo]:
        """Collect hardware module information from Palo Alto."""
        modules = []

        try:
            # Get chassis inventory
            chassis_output = await conn.execute_command("show chassis inventory")

            # Parse inventory output
            current_module: dict[str, str] = {}
            for line in chassis_output.split("\n"):
                line = line.strip()

                if "Chassis:" in line or "Slot" in line:
                    if current_module:
                        modules.append(self._build_module(current_module))
                    current_module = {"slot": line.split(":")[0].strip()}

                elif current_module and ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip().lower()
                    value = value.strip()

                    if "serial" in key:
                        current_module["serial"] = value
                    elif "description" in key or "descr" in key:
                        current_module["description"] = value
                    elif "part" in key or "model" in key:
                        current_module["model"] = value

            # Add last module
            if current_module:
                modules.append(self._build_module(current_module))

        except Exception as exc:
            logger.debug("vendor.scanner.error", exc_info=exc)

        return modules

    def _build_module(self, data: dict) -> ModuleInfo:
        """Build ModuleInfo from parsed data."""
        return ModuleInfo(
            slot=data.get("slot", "unknown"),
            model=data.get("model", "unknown"),
            serial_number=data.get("serial"),
            description=data.get("description"),
            status="ok",
        )

    async def collect_arp_table(self, conn: SSHConnection) -> list[ArpEntry]:
        """Collect ARP table from Palo Alto."""
        arp_entries = []

        try:
            # Get ARP table
            arp_output = await conn.execute_command("show arp all")

            # Parse ARP table
            # Format: interface ip hw-address port status ttl
            in_table = False
            for line in arp_output.split("\n"):
                line = line.strip()

                # Find table start
                if "interface" in line.lower() and "hw-address" in line.lower():
                    in_table = True
                    continue

                if not in_table or not line or line.startswith("-"):
                    continue

                parts = line.split()
                if len(parts) >= 3:
                    # Format can vary, but typically:
                    # interface ip mac [port] [status] [ttl]
                    arp_entries.append(
                        ArpEntry(
                            interface=parts[0],
                            ip_address=parts[1],
                            mac_address=parts[2],
                            age=parts[5] if len(parts) > 5 else None,
                            type=parts[4] if len(parts) > 4 else None,
                        )
                    )

        except Exception as exc:
            logger.debug("vendor.scanner.error", exc_info=exc)

        return arp_entries

    async def collect_mac_table(self, conn: SSHConnection) -> list[MacEntry]:
        """Collect MAC address table from Palo Alto."""
        mac_entries = []

        try:
            # Get MAC table
            mac_output = await conn.execute_command("show mac all")

            # Parse MAC table
            in_table = False
            for line in mac_output.split("\n"):
                line = line.strip()

                # Find table start
                if "interface" in line.lower() and "mac" in line.lower():
                    in_table = True
                    continue

                if not in_table or not line or line.startswith("-"):
                    continue

                parts = line.split()
                if len(parts) >= 3:
                    # Format: interface vlan mac [port] [status]
                    mac_entries.append(
                        MacEntry(
                            interface=parts[0],
                            vlan=parts[1] if len(parts) > 1 else "1",
                            mac_address=parts[2] if len(parts) > 2 else parts[1],
                            type="dynamic",
                        )
                    )

        except Exception as exc:
            logger.debug("vendor.scanner.error", exc_info=exc)

        return mac_entries
