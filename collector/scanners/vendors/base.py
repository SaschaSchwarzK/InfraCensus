"""Base classes for vendor-specific device scanners."""

from __future__ import annotations

import asyncio
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import asyncssh


@dataclass
class DeviceInfo:
    """Device information collected from network device."""

    hostname: str | None = None
    model: str | None = None
    serial_number: str | None = None
    os_version: str | None = None
    uptime: str | None = None
    vendor: str | None = None
    device_type: str | None = None


@dataclass
class InterfaceInfo:
    """Network interface information."""

    name: str
    status: str
    description: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    speed: str | None = None
    duplex: str | None = None
    vlan: str | None = None


@dataclass
class NeighborInfo:
    """CDP/LLDP neighbor information."""

    local_interface: str
    remote_device: str
    remote_interface: str
    remote_ip: str | None = None
    platform: str | None = None
    capabilities: list[str] | None = None
    protocol: str = "unknown"  # cdp, lldp, etc


@dataclass
class ModuleInfo:
    """Hardware module/card information."""

    slot: str
    model: str
    serial_number: str | None = None
    description: str | None = None
    status: str | None = None


@dataclass
class ArpEntry:
    """ARP table entry."""

    ip_address: str
    mac_address: str
    interface: str
    age: str | None = None
    type: str | None = None


@dataclass
class MacEntry:
    """MAC address table entry."""

    mac_address: str
    vlan: str
    interface: str
    type: str | None = None  # dynamic, static, etc


@dataclass
class DeviceScanResult:
    """Complete device scan result."""

    success: bool
    device_info: DeviceInfo | None = None
    interfaces: list[InterfaceInfo] | None = None
    neighbors: list[NeighborInfo] | None = None
    modules: list[ModuleInfo] | None = None
    arp_table: list[ArpEntry] | None = None
    mac_table: list[MacEntry] | None = None
    error: str | None = None
    raw_output: dict[str, str] | None = None  # For debugging


class SSHConnection:
    """Wrapper for SSH connection with command execution."""

    def __init__(
        self,
        conn: asyncssh.SSHClientConnection,
        username: str,
        enable_password: str | None = None,
    ):
        self.conn = conn
        self.username = username
        self.enable_password = enable_password
        self._in_enable_mode = False

    async def execute_command(
        self, command: str, timeout: int = 30, expect_prompt: str | None = None
    ) -> str:
        """
        Execute a command and return output.

        Args:
            command: Command to execute
            timeout: Command timeout in seconds
            expect_prompt: Expected prompt pattern after command

        Returns:
            Command output as string
        """
        try:
            result = await asyncio.wait_for(
                self.conn.run(command, check=False), timeout=timeout
            )
            output = result.stdout if result.stdout else ""
            return (
                output.decode("utf-8", errors="ignore")
                if isinstance(output, bytes)
                else output
            )
        except TimeoutError:
            raise TimeoutError(f"Command timed out: {command}")
        except Exception as e:
            raise RuntimeError(f"Command execution failed: {str(e)}")

    async def execute_commands(
        self, commands: list[str], timeout: int = 30
    ) -> dict[str, str]:
        """
        Execute multiple commands and return outputs.

        Args:
            commands: List of commands to execute
            timeout: Timeout per command

        Returns:
            Dictionary mapping commands to their outputs
        """
        results = {}
        for cmd in commands:
            try:
                results[cmd] = await self.execute_command(cmd, timeout)
            except Exception as e:
                results[cmd] = f"ERROR: {str(e)}"
        return results

    async def enter_enable_mode(self) -> bool:
        """Enter privileged exec mode (for Cisco-like devices)."""
        if self._in_enable_mode:
            return True

        if not self.enable_password:
            return False

        try:
            await self.execute_command("enable")
            await self.execute_command(self.enable_password)
            self._in_enable_mode = True
            return True
        except Exception:
            return False

    async def close(self) -> None:
        """Close SSH connection."""
        if self.conn:
            self.conn.close()
            await self.conn.wait_closed()


class VendorScanner(ABC):
    """Base class for vendor-specific device scanners."""

    vendor_name: str = "unknown"
    device_types: list[str] = []

    @abstractmethod
    async def detect_device_type(self, conn: SSHConnection) -> bool:
        """
        Detect if this scanner can handle the device.

        Args:
            conn: SSH connection to device

        Returns:
            True if this scanner can handle the device
        """
        pass

    @abstractmethod
    async def collect_device_info(self, conn: SSHConnection) -> DeviceInfo:
        """Collect basic device information."""
        pass

    @abstractmethod
    async def collect_interfaces(self, conn: SSHConnection) -> list[InterfaceInfo]:
        """Collect interface information."""
        pass

    @abstractmethod
    async def collect_neighbors(self, conn: SSHConnection) -> list[NeighborInfo]:
        """Collect CDP/LLDP neighbor information."""
        pass

    @abstractmethod
    async def collect_modules(self, conn: SSHConnection) -> list[ModuleInfo]:
        """Collect hardware module information."""
        pass

    @abstractmethod
    async def collect_arp_table(self, conn: SSHConnection) -> list[ArpEntry]:
        """Collect ARP table."""
        pass

    @abstractmethod
    async def collect_mac_table(self, conn: SSHConnection) -> list[MacEntry]:
        """Collect MAC address table."""
        pass

    async def _scan_with_connection(
        self,
        conn: SSHConnection,
        enable_password: str | None = None,
    ) -> DeviceScanResult:
        """Run scan steps using an existing SSH connection."""
        try:
            if enable_password:
                await conn.enter_enable_mode()

            device_info = await self.collect_device_info(conn)
            interfaces = await self.collect_interfaces(conn)
            neighbors = await self.collect_neighbors(conn)
            modules = await self.collect_modules(conn)
            arp_table = await self.collect_arp_table(conn)
            mac_table = await self.collect_mac_table(conn)

            return DeviceScanResult(
                success=True,
                device_info=device_info,
                interfaces=interfaces,
                neighbors=neighbors,
                modules=modules,
                arp_table=arp_table,
                mac_table=mac_table,
            )
        except Exception as e:
            return DeviceScanResult(success=False, error=str(e))

    async def scan_device(
        self,
        host: str,
        username: str,
        password: str | None = None,
        ssh_key: str | None = None,
        enable_password: str | None = None,
        port: int = 22,
        timeout: int = 30,
    ) -> DeviceScanResult:
        """
        Perform complete device scan.

        Args:
            host: Device IP or hostname
            username: SSH username
            password: SSH password (if not using key)
            ssh_key: SSH private key string (if not using password)
            enable_password: Enable/privileged mode password
            port: SSH port
            timeout: Connection timeout

        Returns:
            DeviceScanResult with collected information
        """
        conn = None
        try:
            # Establish SSH connection
            conn = await self._connect(host, username, password, ssh_key, port, timeout)

            # Verify we can handle this device
            if not await self.detect_device_type(conn):
                return DeviceScanResult(
                    success=False,
                    error=f"Device not compatible with {self.vendor_name} scanner",
                )

            return await self._scan_with_connection(
                conn=conn,
                enable_password=enable_password,
            )

        except Exception as e:
            return DeviceScanResult(success=False, error=str(e))

        finally:
            if conn:
                await conn.close()

    async def _connect(
        self,
        host: str,
        username: str,
        password: str | None,
        ssh_key: str | None,
        port: int,
        timeout: int,
    ) -> SSHConnection:
        """Establish SSH connection to device."""
        try:
            # Prepare connection options
            kwargs: dict[str, Any] = {
                "host": host,
                "port": port,
                "username": username,
                "known_hosts": None,  # Disable host key checking for network devices
                "connect_timeout": timeout,
            }

            if ssh_key:
                # Use SSH key authentication
                kwargs["client_keys"] = [ssh_key]
            elif password:
                # Use password authentication
                kwargs["password"] = password
            else:
                raise ValueError("Either password or ssh_key must be provided")

            # Connect
            conn = await asyncssh.connect(**kwargs)
            return SSHConnection(conn, username)

        except asyncssh.Error as e:
            raise ConnectionError(f"SSH connection failed: {str(e)}")


def parse_table_output(
    output: str, headers: list[str], separator: str = r"\s{2,}"
) -> list[dict[str, str]]:
    """
    Parse CLI table output into list of dictionaries.

    Args:
        output: Raw CLI output
        headers: Expected column headers
        separator: Regex pattern for column separator

    Returns:
        List of dictionaries with parsed data
    """
    lines = output.strip().split("\n")
    if not lines:
        return []

    # Skip until we find the header line
    header_idx = -1
    for i, line in enumerate(lines):
        # Check if line contains all headers
        if all(h.lower() in line.lower() for h in headers):
            header_idx = i
            break

    if header_idx == -1:
        return []

    # Parse data rows
    results = []
    for line in lines[header_idx + 1 :]:
        line = line.strip()
        if not line or line.startswith("-"):
            continue

        # Split by separator
        parts = re.split(separator, line)
        if len(parts) >= len(headers):
            row = {}
            for i, header in enumerate(headers):
                row[header] = parts[i].strip() if i < len(parts) else ""
            results.append(row)

    return results


def extract_field(output: str, pattern: str, group: int = 1) -> str | None:
    """
    Extract a field from output using regex.

    Args:
        output: Text to search
        pattern: Regex pattern
        group: Group number to extract

    Returns:
        Extracted value or None
    """
    match = re.search(pattern, output, re.IGNORECASE | re.MULTILINE)
    if match:
        value = match.group(group).strip()
        return value.rstrip(",")
    return None
