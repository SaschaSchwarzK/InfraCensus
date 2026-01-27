from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any


@dataclass
class RateLimitState:
    window_start: float
    count: int


class CollectorRateLimiter:
    def __init__(self, max_per_hour: int) -> None:
        self.max_per_hour = max_per_hour
        self._states: dict[object, RateLimitState] = {}

    def allow(self, key: object) -> bool:
        now = time.monotonic()
        state = self._states.get(key)
        if not state or now - state.window_start >= 3600:
            self._states[key] = RateLimitState(window_start=now, count=1)
            return True
        state.count += 1
        return state.count <= self.max_per_hour
