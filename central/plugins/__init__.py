"""Plugin registration entry point."""

from central.plugins.base import ExporterPlugin, Plugin, ScannerPlugin
from central.plugins.loader import load_plugins
from central.plugins.registry import registry
from central.plugins.scanners import (
    HttpScanner,
    NetconfScanner,
    NetworkDiscoveryScanner,
    SnmpScanner,
    SshScanner,
)

__all__ = [
    "ExporterPlugin",
    "HttpScanner",
    "NetconfScanner",
    "NetworkDiscoveryScanner",
    "Plugin",
    "ScannerPlugin",
    "SnmpScanner",
    "SshScanner",
    "load_plugins",
    "registry",
]

registry.register(NetworkDiscoveryScanner)
registry.register(SnmpScanner)
registry.register(SshScanner)
registry.register(HttpScanner)
registry.register(NetconfScanner)
