from __future__ import annotations

from collector.backends.base import ScannerBackend


class BackendRegistry:
    def __init__(self) -> None:
        self._backends: dict[str, ScannerBackend] = {}

    def register(self, name: str, backend: ScannerBackend) -> None:
        self._backends[name] = backend

    def get_backend_for_type(self, scan_type: str) -> ScannerBackend | None:
        for backend in self._backends.values():
            if backend.supports(scan_type):
                return backend
        return None

    def cleanup(self) -> None:
        for backend in self._backends.values():
            backend.cleanup()
