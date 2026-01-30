from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass


@dataclass
class RateLimitState:
    window_start: float
    count: int


class CollectorRateLimiter:
    def __init__(self, max_per_hour: int) -> None:
        self.max_per_hour = max_per_hour
        self._states: dict[object, RateLimitState] = {}
        self._lock = asyncio.Lock()

    async def update_limit(self, max_per_hour: int, reset: bool = False) -> None:
        async with self._lock:
            self.max_per_hour = max_per_hour
            if reset:
                self._states = {}

    async def allow(self, key: object) -> bool:
        now = time.monotonic()
        async with self._lock:
            state = self._states.get(key)
            if not state or now - state.window_start >= 3600:
                self._states[key] = RateLimitState(window_start=now, count=1)
                return True
            state.count += 1
            return state.count <= self.max_per_hour
