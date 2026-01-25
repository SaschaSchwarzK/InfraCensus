from __future__ import annotations

from typing import Any

from central.plugins.base import ExporterPlugin


class NetBoxExporter(ExporterPlugin):
    name = "netbox"
    version = "0.1.0"

    def configure(self, settings: dict[str, Any]) -> None:
        self.settings = settings

    def run(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {"status": "stub", "destination": "netbox", "payload": payload}
