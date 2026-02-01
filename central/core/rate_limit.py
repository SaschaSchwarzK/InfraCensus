from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from dataclasses import dataclass


@dataclass
class RateLimitState:
    window_start: float
    count: int


class CollectorRateLimiter:
    def __init__(
        self,
        max_per_hour: int,
        max_tracked_keys: int = 10000,
        cleanup_interval_seconds: int = 3600,
    ) -> None:
        self.max_per_hour = max_per_hour
        self._states: OrderedDict[object, RateLimitState] = OrderedDict()
        self._lock = asyncio.Lock()
        self._max_tracked_keys = max_tracked_keys
        self._cleanup_interval_seconds = cleanup_interval_seconds
        self._last_cleanup = time.monotonic()

    async def update_limit(self, max_per_hour: int, reset: bool = False) -> None:
        async with self._lock:
            self.max_per_hour = max_per_hour
            if reset:
                self._states.clear()

    async def allow(self, key: object) -> bool:
        now = time.monotonic()
        async with self._lock:
            if now - self._last_cleanup >= self._cleanup_interval_seconds:
                self._cleanup_stale_entries(now)
                self._last_cleanup = now
            state = self._states.get(key)
            if not state or now - state.window_start >= 3600:
                if len(self._states) >= self._max_tracked_keys:
                    self._states.popitem(last=False)
                self._states[key] = RateLimitState(window_start=now, count=1)
                self._states.move_to_end(key)
                return True
            state.count += 1
            self._states.move_to_end(key)
            return state.count <= self.max_per_hour

    def _cleanup_stale_entries(self, now: float) -> None:
        cutoff = now - 3600
        stale_keys = [
            key
            for key, state in self._states.items()
            if state.window_start < cutoff
        ]
        for key in stale_keys:
            del self._states[key]
