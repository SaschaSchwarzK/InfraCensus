from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Any


class LocalStorage:
    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._locks: dict[str, Lock] = {}
        self._locks_lock = Lock()

    def _get_lock(self, name: str) -> Lock:
        with self._locks_lock:
            if name not in self._locks:
                self._locks[name] = Lock()
            return self._locks[name]

    def load_json(self, name: str) -> dict[str, Any] | None:
        path = self.root / name
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def save_json(self, name: str, payload: dict[str, Any]) -> None:
        path = self.root / name
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def update_json(self, name: str, update: dict[str, Any]) -> dict[str, Any]:
        with self._get_lock(name):
            payload = self.load_json(name) or {}
            payload.update(update)
            self.save_json(name, payload)
            return payload
