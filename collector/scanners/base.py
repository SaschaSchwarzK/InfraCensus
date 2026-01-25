from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any
import os

from collector.utils.network import is_valid_target


@dataclass(frozen=True)
class ScanResult:
    ip: str
    success: bool
    duration_ms: int
    data: dict[str, Any]
    error: str | None = None


class BaseScanner(ABC):
    name: str
    required_tools: list[str] = []

    @abstractmethod
    async def scan(self, targets: list[str], params: dict[str, Any]) -> list[ScanResult]:
        raise NotImplementedError

    def validate_target(self, target: str) -> bool:
        return is_valid_target(target)

    @property
    def version(self) -> str:
        return os.getenv("COLLECTOR_SCANNER_VERSION", "0.1.0")
