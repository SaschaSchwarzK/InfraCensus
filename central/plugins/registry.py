from __future__ import annotations

from typing import Any

from central.plugins.base import Plugin


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, type[Plugin]] = {}

    def register(self, plugin_cls: type[Plugin]) -> None:
        name = getattr(plugin_cls, "name", None)
        if not name:
            raise ValueError("Plugin class must define a non-empty name")
        self._plugins[name] = plugin_cls

    def create(self, name: str, settings: dict[str, Any] | None = None) -> Plugin:
        plugin_cls = self._plugins.get(name)
        if not plugin_cls:
            raise KeyError(f"Unknown plugin: {name}")
        plugin = plugin_cls()
        if settings is not None:
            plugin.configure(settings)
        return plugin

    def list(self) -> list[str]:
        return sorted(self._plugins.keys())


registry = PluginRegistry()
