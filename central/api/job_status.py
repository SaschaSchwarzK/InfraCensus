from __future__ import annotations

import asyncio
from typing import Any

from fastapi import WebSocket
from fastapi.websockets import WebSocketDisconnect


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
            try:
                await websocket.send_json(last)
            except (WebSocketDisconnect, ConnectionError, RuntimeError):
                await self.disconnect(job_id, websocket)

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
        
        async def _send_to_socket(socket: WebSocket) -> None:
            try:
                await socket.send_json(payload)
            except (WebSocketDisconnect, ConnectionError, RuntimeError):
                await self.disconnect(job_id, socket)
        
        if sockets:
            await asyncio.gather(*[_send_to_socket(socket) for socket in sockets], return_exceptions=True)


job_status_hub = JobStatusHub()
