from __future__ import annotations

from threading import RLock

from collector.scanners.base import BaseScanner


class ScannerRegistry:
    def __init__(self) -> None:
        self._scanners: dict[str, BaseScanner] = {}
        self._lock = RLock()

    def register(self, scanner: BaseScanner) -> None:
        if not scanner.name:
            raise ValueError("Scanner must have a name")
        with self._lock:
            self._scanners[scanner.name] = scanner

    def get(self, name: str) -> BaseScanner | None:
        with self._lock:
            return self._scanners.get(name)

    def list(self) -> list[str]:
        with self._lock:
            return sorted(self._scanners.keys())
