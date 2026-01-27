from __future__ import annotations

import asyncio
from typing import Any

from fastapi import WebSocket


class JobStatusHub:
    def __init__(self) -> None:
        self._connections: dict[str, set[WebSocket]] = {}
        self._last_status: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, job_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            self._connections.setdefault(job_id, set()).add(websocket)
            last = self._last_status.get(job_id)
        if last:
            await websocket.send_json(last)

    async def disconnect(self, job_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            sockets = self._connections.get(job_id)
            if not sockets:
                return
            sockets.discard(websocket)
            if not sockets:
                self._connections.pop(job_id, None)

    async def broadcast(self, job_id: str, payload: dict[str, Any]) -> None:
        async with self._lock:
            self._last_status[job_id] = payload
            sockets = list(self._connections.get(job_id, set()))
        for socket in sockets:
            try:
                await socket.send_json(payload)
            except Exception:
                await self.disconnect(job_id, socket)


job_status_hub = JobStatusHub()
