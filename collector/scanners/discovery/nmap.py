"""Improved Nmap scanner with proper XML parsing and result extraction."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import shlex
import shutil
import subprocess  # nosec B404
import time
from typing import Any

from defusedxml import ElementTree as ET

from collector.scanners.base import BaseScanner, ScanResult
from collector.scanners.utils import is_valid_hostname


class NmapScanner(BaseScanner):
    """Enhanced Nmap scanner that parses XML output and extracts detailed information."""

    name = "nmap"
    required_tools = ["nmap"]

    async def scan(
        self, targets: list[str], params: dict[str, Any]
    ) -> list[ScanResult]:
        """
        Scan targets using Nmap and parse results.

        Args:
            targets: List of IP addresses to scan
            params: Scan parameters including:
                - timeout: Scan timeout in seconds (default: 30)
                - scan_type: Type of scan (default: "host_discovery")
                  Options: "host_discovery", "port_scan", "service_detection"
                - ports: Ports to scan (default: "1-1000")
                - arguments: Additional nmap arguments (optional)

        Returns:
            List of ScanResult objects with parsed Nmap data
        """
        timeout = int(params.get("timeout", 30))
        scan_type = params.get("scan_type", "host_discovery")
        ports = params.get("ports", "1-1000")
        extra_args = params.get("arguments", "")

        # Build nmap arguments based on scan type
        nmap_args = self._build_nmap_args(scan_type, ports, extra_args)

        # Process targets concurrently
        tasks = []
        for target in targets:
            task = asyncio.create_task(
                self._scan_single_target(target, timeout, nmap_args)
            )
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle any exceptions that occurred
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

    def _build_nmap_args(
        self, scan_type: str, ports: str, extra_args: str
    ) -> list[str]:
        """Build nmap command arguments based on scan type."""
        args = []

        if scan_type == "host_discovery":
            args.extend(["-sn"])  # Ping scan only
        elif scan_type == "port_scan":
            args.extend(["-sS", "-p", ports])  # SYN scan with specified ports
        elif scan_type == "service_detection":
            args.extend(["-sV", "-p", ports])  # Version detection with specified ports
        else:
            # Default to host discovery
            args.extend(["-sn"])

        # Add extra arguments if provided (validate first)
        if extra_args:
            # Basic validation to prevent command injection
            if not self._validate_nmap_args(extra_args):
                raise ValueError(f"Invalid nmap arguments: {extra_args}")
            args.extend(shlex.split(extra_args))

        # Always request XML output
        args.extend(["-oX", "-"])

        return args

    def _validate_nmap_args(self, args: str) -> bool:
        """Validate extra nmap arguments to prevent command injection."""
        # Block dangerous characters and patterns
        dangerous = [";", "&", "|", "`", "$", "\n", "\r", "&&", "||"]
        for char in dangerous:
            if char in args:
                return False

        # Only allow known safe nmap options
        allowed_patterns = [
            r"^-s[STUACPOVN]$",  # Scan types (-sS, -sT, -sV, etc.)
            r"^-p-?[\d,-]+$",  # Port specifications (e.g., -p80,443, -p-)
            r"^--[\w-]+(=[\w,-]+)?$",  # Long options (e.g., --script=default)
            r"^-F$",  # Fast scan
            r"^-A$",  # Aggressive scan
            r"^-O$",  # OS Detection
            r"^-T[0-5]$",  # Timing template
            r"^-n$",  # No DNS resolution
            r"^-R$",  # Reverse DNS resolution
            r"^-v+$",  # Verbosity
            r"^-d+$",  # Debugging
        ]

        for arg in shlex.split(args):
            if not any(re.match(pattern, arg) for pattern in allowed_patterns):
                return False

        return True

    async def _scan_single_target(
        self, target: str, timeout: int, nmap_args: list[str]
    ) -> ScanResult:
        """Scan a single target with Nmap."""
        start = time.perf_counter()
        success, xml_output, error = await self._run_nmap(target, timeout, nmap_args)

        if not success:
            return ScanResult(
                ip=target,
                success=False,
                duration_ms=int((time.perf_counter() - start) * 1000),
                data={"status": "error", "scanner": self.name},
                error=error or "nmap_failed",
            )

        # Parse XML output
        parsed_data = self._parse_nmap_xml(xml_output, target)

        return ScanResult(
            ip=target,
            success=parsed_data.get("host_up", False),
            duration_ms=int((time.perf_counter() - start) * 1000),
            data={
                "status": "up" if parsed_data.get("host_up") else "down",
                "scanner": self.name,
                **parsed_data,
            },
            error=None if parsed_data.get("host_up") else "host_down",
        )

    async def _run_nmap(
        self, target: str, timeout: int, nmap_args: list[str]
    ) -> tuple[bool, str, str | None]:
        """Execute nmap command and return results."""
        # Validate target
        if not target or any(ch in target for ch in [";", "&", "|", "`", "$", "\n"]):
            return False, "", "invalid_target"
        if target.startswith("-"):
            return False, "", "invalid_target"

        try:
            ip = ipaddress.ip_address(target)
            if ip.is_loopback or ip.is_link_local:
                return False, "", "invalid_target"
            if ip.is_multicast or ip.is_reserved:
                return False, "", "invalid_target"
        except ValueError:
            if not is_valid_hostname(target):
                return False, "", "invalid_target"

        def _run() -> tuple[bool, str, str | None]:
            nmap_path = shutil.which("nmap")
            if not nmap_path:
                return False, "", "nmap_not_found"

            try:
                # Build complete command
                cmd = [nmap_path] + nmap_args + [target]

                completed = subprocess.run(
                    cmd,  # nosec B603
                    capture_output=True,
                    text=True,
                    timeout=timeout + 5,  # Add buffer
                )

                stdout = completed.stdout or ""
                stderr = completed.stderr or ""

                # Nmap returns 0 on success
                success = completed.returncode == 0

                return success, stdout, None if success else stderr[:1000]

            except subprocess.TimeoutExpired as exc:
                stdout = (
                    exc.stdout.decode(errors="replace")
                    if isinstance(exc.stdout, bytes)
                    else (exc.stdout or "")
                )
                return False, stdout[:4000], "timeout"

            except FileNotFoundError:
                return False, "", "nmap_not_found"

            except Exception as e:
                return False, "", str(e)

        return await asyncio.to_thread(_run)

    def _parse_nmap_xml(self, xml_output: str, target: str) -> dict[str, Any]:
        """Parse Nmap XML output and extract useful information."""
        data: dict[str, Any] = {
            "host_up": False,
            "ports": [],
            "os": "unknown",
            "hostnames": [],
        }

        if not xml_output:
            return data

        try:
            root = ET.fromstring(xml_output)

            # Find host element
            host = None
            for candidate in root.findall(".//host"):
                addr = candidate.find("address")
                if addr is not None and addr.get("addr") == target:
                    host = candidate
                    break
            if host is None:
                host = root.find(".//host")

            if host is None:
                return data

            # Check if host is up
            status = host.find("status")
            if status is not None:
                data["host_up"] = status.get("state") == "up"

            # Extract hostnames
            hostnames = host.find("hostnames")
            if hostnames is not None:
                for hostname in hostnames.findall("hostname"):
                    name = hostname.get("name")
                    if name:
                        data["hostnames"].append(name)

            # Extract OS information
            os_elem = host.find(".//osmatch")
            if os_elem is not None:
                os_name = os_elem.get("name")
                os_accuracy = os_elem.get("accuracy")
                if os_name:
                    data["os"] = f"{os_name} ({os_accuracy}% accuracy)"

            # Extract port information
            ports = host.find("ports")
            if ports is not None:
                for port in ports.findall("port"):
                    port_id = port.get("portid")
                    protocol = port.get("protocol")

                    state = port.find("state")
                    state_str = state.get("state") if state is not None else "unknown"

                    service = port.find("service")
                    service_name = "unknown"
                    service_version = "unknown"
                    if service is not None:
                        service_name = service.get("name", "unknown")
                        product = service.get("product", "")
                        version = service.get("version", "")
                        if product or version:
                            service_version = f"{product} {version}".strip()

                    port_data = {
                        "port": int(port_id) if port_id else 0,
                        "protocol": protocol or "unknown",
                        "state": state_str,
                        "service": service_name,
                        "version": service_version,
                    }
                    data["ports"].append(port_data)

            # Add summary statistics
            data["open_ports"] = sum(
                1 for p in data["ports"] if p.get("state") == "open"
            )
            data["filtered_ports"] = sum(
                1 for p in data["ports"] if p.get("state") == "filtered"
            )

        except ET.ParseError as e:
            data["parse_error"] = f"XML parse error: {str(e)}"
        except Exception as e:
            data["parse_error"] = f"Error parsing nmap output: {str(e)}"

        return data
