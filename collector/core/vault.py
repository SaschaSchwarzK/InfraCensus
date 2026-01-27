from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import time

import httpx


@dataclass(frozen=True)
class VaultSettings:
    addr: str | None
    token: str | None
    kv_mount: str
    namespace: str | None
    cache_ttl_seconds: int


class VaultClient:
    def __init__(self, settings: VaultSettings) -> None:
        self._settings = settings
        self._client = httpx.AsyncClient(timeout=10)
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}

    async def close(self) -> None:
        await self._client.aclose()

    async def read_secret(self, path: str) -> dict[str, Any] | None:
        if not self._settings.addr or not self._settings.token:
            return None
        cached = self._cache.get(path)
        if cached and cached[0] > time.time():
            return cached[1]
        url = f"{self._settings.addr.rstrip('/')}/v1/{self._settings.kv_mount}/data/{path.lstrip('/')}"
        headers = {"X-Vault-Token": self._settings.token}
        if self._settings.namespace:
            headers["X-Vault-Namespace"] = self._settings.namespace
        response = await self._client.get(url, headers=headers)
        if response.status_code != 200:
            return None
        payload = response.json()
        data = payload.get("data", {}).get("data", {})
        self._cache[path] = (time.time() + self._settings.cache_ttl_seconds, data)
        return data

    def clear_cache(self) -> None:
        self._cache.clear()
