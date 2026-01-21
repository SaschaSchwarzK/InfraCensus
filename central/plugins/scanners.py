from __future__ import annotations

from typing import Any

from central.plugins.base import ScannerPlugin


class NetworkDiscoveryScanner(ScannerPlugin):
    name = "network-discovery"
    version = "0.1.0"

    def configure(self, settings: dict[str, Any]) -> None:
        self.settings = settings

    def run(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {"status": "stub", "targets": payload}


class SnmpScanner(ScannerPlugin):
    name = "snmp"
    version = "0.1.0"

    def configure(self, settings: dict[str, Any]) -> None:
        self.settings = settings

    def run(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {"status": "stub", "protocol": "snmp", "targets": payload}


class SshScanner(ScannerPlugin):
    name = "ssh"
    version = "0.1.0"

    def configure(self, settings: dict[str, Any]) -> None:
        self.settings = settings

    def run(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {"status": "stub", "protocol": "ssh", "targets": payload}


class HttpScanner(ScannerPlugin):
    name = "http"
    version = "0.1.0"

    def configure(self, settings: dict[str, Any]) -> None:
        self.settings = settings

    def run(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {"status": "stub", "protocol": "http", "targets": payload}


class NetconfScanner(ScannerPlugin):
    name = "netconf"
    version = "0.1.0"

    def configure(self, settings: dict[str, Any]) -> None:
        self.settings = settings

    def run(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {"status": "stub", "protocol": "netconf", "targets": payload}
