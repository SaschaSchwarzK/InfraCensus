from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PluginSettings:
    modules: tuple[str, ...] = ("central.plugins.scanners", "central.plugins.exporters")
    default_scanner: str = "network-discovery"
