from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Any


class LocalStorage:
    def __init__(self, root: str) -> None:
        # Validate root path to prevent path traversal
        if not root or not isinstance(root, str):
            raise ValueError("Invalid root path")

        # Resolve and validate the root path
        root_path = Path(root).resolve()

        # Ensure no path traversal sequences in resolved path
        if ".." in root_path.parts:
            raise ValueError(f"Path traversal detected in root path: {root}")

        self.root = root_path
        self.root.mkdir(parents=True, exist_ok=True)
        self._locks: dict[str, Lock] = {}
        self._locks_lock = Lock()

    def _get_lock(self, name: str) -> Lock:
        with self._locks_lock:
            if name not in self._locks:
                self._locks[name] = Lock()
            return self._locks[name]

    def _validate_name(self, name: str) -> str:
        """Validate filename to prevent path traversal attacks."""
        if not name or not isinstance(name, str):
            raise ValueError("Invalid filename")

        # Ensure the resolved path stays within the storage root
        candidate = (self.root / name).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise ValueError(
                f"Invalid filename contains path traversal: {name}"
            ) from exc
        if candidate.is_dir():
            raise ValueError(f"Invalid filename is a directory: {name}")
        return name

    def load_json(self, name: str) -> dict[str, Any] | None:
        clean_name = self._validate_name(name)
        path = self.root / clean_name
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def save_json(self, name: str, payload: dict[str, Any]) -> None:
        clean_name = self._validate_name(name)
        path = self.root / clean_name
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def update_json(self, name: str, update: dict[str, Any]) -> dict[str, Any]:
        clean_name = self._validate_name(name)
        with self._get_lock(clean_name):
            payload = self.load_json(clean_name) or {}
            payload.update(update)
            self.save_json(clean_name, payload)
            return payload
