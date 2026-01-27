from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from central.api.job_status import job_status_hub
from central.core.auth import parse_api_keys
from central.core.config import settings

router = APIRouter(prefix="/jobs", tags=["jobs"])


@router.websocket("/{job_id}/status")
async def job_status_stream(websocket: WebSocket, job_id: str):
    if not _is_authorized(websocket):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    await job_status_hub.connect(job_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await job_status_hub.disconnect(job_id, websocket)


def _is_authorized(websocket: WebSocket) -> bool:
    key = (
        websocket.query_params.get("api_key")
        or websocket.headers.get("x-api-key")
        or _bearer_token(websocket)
    )
    if not key:
        return False
    scopes = parse_api_keys(settings.api_keys).get(key, set())
    return "jobs:read" in scopes or "*" in scopes


def _bearer_token(websocket: WebSocket) -> str | None:
    header = websocket.headers.get("authorization") or ""
    if header.lower().startswith("bearer "):
        return header.split(" ", 1)[1].strip()
    return None
