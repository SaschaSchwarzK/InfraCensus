from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Plugin(ABC):
    """Base contract for all plugins."""

    name: str
    version: str
    plugin_type: str

    @abstractmethod
    def configure(self, settings: dict[str, Any]) -> None:
        """Configure the plugin with runtime settings."""

    @abstractmethod
    def run(self, payload: dict[str, Any]) -> Any:
        """Execute the plugin's primary action."""


class ScannerPlugin(Plugin):
    plugin_type = "scanner"


class ExporterPlugin(Plugin):
    plugin_type = "exporter"
