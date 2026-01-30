from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from central.api.job_status import job_status_hub
from central.core.audit import log_security_event
from central.core.auth import get_api_key_scopes
from central.core.config import settings

router = APIRouter(prefix="/jobs", tags=["jobs"])


@router.websocket("/{job_id}/status")
async def job_status_stream(websocket: WebSocket, job_id: str) -> None:
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
        log_security_event(
            action="jobs.websocket.denied",
            outcome="denied",
            details={"reason": "missing_api_key"},
        )
        return False
    scopes = get_api_key_scopes(settings.api_keys, key, settings.api_key_pepper)
    allowed = "jobs:read" in scopes or "*" in scopes
    if not allowed:
        log_security_event(
            action="jobs.websocket.denied",
            outcome="denied",
            details={"reason": "insufficient_scope"},
        )
    return allowed


def _bearer_token(websocket: WebSocket) -> str | None:
    header = websocket.headers.get("authorization") or ""
    if header.lower().startswith("bearer "):
        return header.split(" ", 1)[1].strip()
    return None
