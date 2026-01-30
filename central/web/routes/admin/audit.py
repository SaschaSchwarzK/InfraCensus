from __future__ import annotations

from collections.abc import Iterable

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

from central.db.models import AuditLog, User
from central.db.session import get_session
from central.web.auth import require_superadmin
from central.web.routes.common import (
    WebResponse,
    _format_dt,
    _paginate_query,
    _pagination_params,
    _safe_query,
    _wants_json,
    templates,
)

router = APIRouter()


@router.get("/admin/audit", response_class=HTMLResponse)
def admin_audit(request: Request) -> WebResponse:
    user = require_superadmin(request)
    if not isinstance(user, User):
        return user

    def fetch() -> Iterable[AuditLog]:
        with get_session() as session:
            query = session.query(AuditLog)
            action_filter = request.query_params.get("action")
            entity_type_filter = request.query_params.get("entity_type")
            actor_filter = request.query_params.get("actor_user_id")
            entity_id_filter = request.query_params.get("entity_id")
            if action_filter:
                query = query.filter(AuditLog.action.ilike(f"%{action_filter}%"))
            if entity_type_filter:
                query = query.filter(AuditLog.entity_type == entity_type_filter)
            if actor_filter:
                try:
                    query = query.filter(AuditLog.actor_user_id == int(actor_filter))
                except ValueError:
                    pass
            if entity_id_filter:
                try:
                    query = query.filter(AuditLog.entity_id == int(entity_id_filter))
                except ValueError:
                    pass
            query = query.order_by(AuditLog.created_at.desc())
            query, _, _ = _paginate_query(query, request)
            return query.all()

    def fetch_users() -> Iterable[User]:
        with get_session() as session:
            return session.query(User).all()

    entries, error = _safe_query(fetch)
    users, _ = _safe_query(fetch_users)
    user_map = {u.id: {"email": u.email, "full_name": u.full_name} for u in users}
    if _wants_json(request):
        limit, offset = _pagination_params(request)
        return JSONResponse(
            {
                "entries": [
                    {
                        "id": entry.id,
                        "actor_user_id": entry.actor_user_id,
                        "actor_email": (user_map.get(entry.actor_user_id) or {}).get(
                            "email"
                        ),
                        "actor_name": (user_map.get(entry.actor_user_id) or {}).get(
                            "full_name"
                        ),
                        "action": entry.action,
                        "entity_type": entry.entity_type,
                        "entity_id": entry.entity_id,
                        "details": entry.details,
                        "created_at": _format_dt(entry.created_at),
                    }
                    for entry in entries
                ],
                "error": error,
                "limit": limit,
                "offset": offset,
            }
        )
    return templates.TemplateResponse(
        "admin_audit.html",
        {
            "request": request,
            "entries": entries,
            "error": error,
            "user": user,
            "user_map": user_map,
        },
    )
