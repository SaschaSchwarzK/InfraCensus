"""Improved HTTP scanner with proper protocol detection and parsing."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import ssl
import time
from typing import Any

import aiohttp

from collector.scanners.base import BaseScanner, ScanResult
from collector.scanners.utils import is_valid_hostname


class HttpScanner(BaseScanner):
    """Enhanced HTTP scanner that performs real HTTP requests and extracts metadata."""

    name = "http"

    async def scan(
        self, targets: list[str], params: dict[str, Any]
    ) -> list[ScanResult]:
        """
        Scan targets for HTTP/HTTPS services.

        Args:
            targets: List of IP addresses or hostnames to scan
            params: Scan parameters including:
                - timeout: Request timeout in seconds (default: 10)
                - port: Port to scan (default: 80)
                - use_https: Whether to use HTTPS (default: False)
                - follow_redirects: Whether to follow redirects (default: True)
                - max_redirects: Maximum number of redirects (default: 3)
                - verify_ssl: Whether to verify SSL certificates (default: False)

        Returns:
            List of ScanResult objects with HTTP metadata
        """
        timeout = int(params.get("timeout", 10))
        port = int(params.get("port", 80))
        use_https = params.get("use_https", False)
        follow_redirects = params.get("follow_redirects", True)
        max_redirects = int(params.get("max_redirects", 3))
        verify_ssl = params.get("verify_ssl", False)

        # Validate port
        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid port: {port}")

        # Create SSL context for HTTPS
        ssl_context = None
        if use_https:
            ssl_context = ssl.create_default_context()
            if not verify_ssl:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

        # Configure aiohttp client
        connector = aiohttp.TCPConnector(
            limit=50,
            limit_per_host=10,
            ttl_dns_cache=300,
            ssl=ssl_context if ssl_context is not None else False,
        )

        client_timeout = aiohttp.ClientTimeout(
            total=timeout,
            connect=timeout // 2,
            sock_read=timeout // 2,
        )

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=client_timeout,
            connector_owner=True,
        ) as session:
            # Scan all targets concurrently
            tasks = []
            for target in targets:
                task = asyncio.create_task(
                    self._scan_target(
                        session,
                        target,
                        port,
                        use_https,
                        follow_redirects,
                        max_redirects,
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
        session: aiohttp.ClientSession,
        target: str,
        port: int,
        use_https: bool,
        follow_redirects: bool,
        max_redirects: int,
    ) -> ScanResult:
        """Scan a single target for HTTP/HTTPS service."""
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
        scheme = "https" if use_https else "http"
        url = f"{scheme}://{target}:{port}/"

        try:
            async with session.get(
                url,
                allow_redirects=follow_redirects,
                max_redirects=max_redirects,
            ) as response:
                # Extract response data
                content_length = response.headers.get("Content-Length", "unknown")
                server = response.headers.get("Server", "unknown")
                content_type = response.headers.get("Content-Type", "unknown")

                # Try to read a snippet of the response body
                body_snippet = ""
                try:
                    body_bytes = await asyncio.wait_for(
                        response.content.read(1024), timeout=2
                    )
                    body_snippet = body_bytes.decode("utf-8", errors="ignore")[:500]
                except (TimeoutError, UnicodeDecodeError):
                    pass

                # Extract title from HTML if present
                title = "unknown"
                if "text/html" in content_type.lower() and body_snippet:
                    title_match = re.search(
                        r"<title>(.*?)</title>", body_snippet, re.IGNORECASE
                    )
                    if title_match:
                        title = title_match.group(1).strip()[:100]

                duration_ms = int((time.perf_counter() - start) * 1000)

                return ScanResult(
                    ip=target,
                    success=True,
                    duration_ms=duration_ms,
                    data={
                        "status": "up",
                        "scanner": self.name,
                        "port": port,
                        "protocol": scheme,
                        "status_code": response.status,
                        "server": server,
                        "content_type": content_type,
                        "content_length": content_length,
                        "title": title,
                        "url": str(response.url),
                        "response_headers": dict(response.headers),
                    },
                    error=None,
                )

        except aiohttp.ClientSSLError as e:
            duration_ms = int((time.perf_counter() - start) * 1000)
            return ScanResult(
                ip=target,
                success=False,
                duration_ms=duration_ms,
                data={
                    "status": "ssl_error",
                    "scanner": self.name,
                    "port": port,
                    "protocol": scheme,
                },
                error=f"SSL error: {str(e)}",
            )

        except aiohttp.ClientConnectionError as e:
            duration_ms = int((time.perf_counter() - start) * 1000)
            return ScanResult(
                ip=target,
                success=False,
                duration_ms=duration_ms,
                data={
                    "status": "connection_error",
                    "scanner": self.name,
                    "port": port,
                    "protocol": scheme,
                },
                error=f"Connection error: {str(e)}",
            )

        except TimeoutError:
            duration_ms = int((time.perf_counter() - start) * 1000)
            return ScanResult(
                ip=target,
                success=False,
                duration_ms=duration_ms,
                data={
                    "status": "timeout",
                    "scanner": self.name,
                    "port": port,
                    "protocol": scheme,
                },
                error="Request timeout",
            )

        except Exception as e:
            duration_ms = int((time.perf_counter() - start) * 1000)
            return ScanResult(
                ip=target,
                success=False,
                duration_ms=duration_ms,
                data={
                    "status": "error",
                    "scanner": self.name,
                    "port": port,
                    "protocol": scheme,
                },
                error=str(e),
            )

    def _is_valid_target(self, target: str) -> bool:
        """
        Validate target to prevent SSRF attacks.

        Args:
            target: IP address or hostname to validate

        Returns:
            True if target is valid and safe to scan
        """
        # Try to parse as IP address
        try:
            ip = ipaddress.ip_address(target)
            # Allow private addresses for internal network scanning
            # Block only loopback, link-local, multicast, and reserved ranges
            if ip.is_loopback or ip.is_link_local:
                return False
            if ip.is_multicast or ip.is_reserved:
                return False
            return True
        except ValueError:
            # Not an IP address, validate as hostname
            # Allow hostnames for flexibility but validate format
            return is_valid_hostname(target)
