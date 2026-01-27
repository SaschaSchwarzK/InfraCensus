from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


@dataclass(frozen=True)
class VaultSettings:
    addr: str | None
    token: str | None
    kv_mount: str
    namespace: str | None = None


class VaultClient:
    def __init__(self, settings: VaultSettings) -> None:
        self._settings = settings
        self._client = httpx.Client(timeout=10)

    def read_secret(self, path: str) -> dict[str, Any] | None:
        if not self._settings.addr or not self._settings.token:
            return None
        url = f"{self._settings.addr.rstrip('/')}/v1/{self._settings.kv_mount}/data/{path.lstrip('/')}"
        headers = {"X-Vault-Token": self._settings.token}
        if self._settings.namespace:
            headers["X-Vault-Namespace"] = self._settings.namespace
        response = self._client.get(url, headers=headers)
        if response.status_code != 200:
            return None
        payload = response.json()
        return payload.get("data", {}).get("data", {})

    def write_secret(self, path: str, payload: dict[str, Any]) -> bool:
        if not self._settings.addr or not self._settings.token:
            return False
        url = f"{self._settings.addr.rstrip('/')}/v1/{self._settings.kv_mount}/data/{path.lstrip('/')}"
        headers = {"X-Vault-Token": self._settings.token}
        if self._settings.namespace:
            headers["X-Vault-Namespace"] = self._settings.namespace
        response = self._client.post(url, headers=headers, json={"data": payload})
        return response.status_code in {200, 204}
