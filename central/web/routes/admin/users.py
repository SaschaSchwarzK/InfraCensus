from __future__ import annotations

from collections.abc import Iterable
from json import JSONDecodeError

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse

from central.core.audit import log_audit, log_security_event
from central.db.models import User
from central.db.session import get_session
from central.web.auth import require_superadmin
from central.web.routes.common import (
    WebResponse,
    _format_dt,
    _paginate_query,
    _pagination_params,
    _redirect_with_message,
    _safe_query,
    _wants_json,
    templates,
)

router = APIRouter()


def _build_user_query(session, request):
    """Build user query with filters applied."""
    query = session.query(User)
    email_filter = request.query_params.get("email")
    superadmin_filter = request.query_params.get("superadmin")
    if email_filter:
        # Sanitize email filter to prevent SQL injection
        email_filter = email_filter.replace("%", "\\%").replace("_", "\\_")
        query = query.filter(User.email.ilike(f"%{email_filter}%"))
    if superadmin_filter in {"true", "false"}:
        query = query.filter(User.is_superadmin == (superadmin_filter == "true"))
    return query.order_by(User.email)


@router.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request) -> WebResponse:
    user = require_superadmin(request)
    if not isinstance(user, User):
        return user

    def fetch() -> Iterable[User]:
        with get_session() as session:
            query = _build_user_query(session, request)
            query, _, _ = _paginate_query(query, request)
            return query.all()

    users, error = _safe_query(fetch)
    if _wants_json(request):
        limit, offset = _pagination_params(request)
        return JSONResponse(
            {
                "users": [
                    {
                        "id": u.id,
                        "email": u.email,
                        "full_name": u.full_name,
                        "display_name": u.full_name or u.email,
                        "is_superadmin": u.is_superadmin,
                        "is_auditor": u.is_auditor,
                        "created_at": _format_dt(u.created_at),
                    }
                    for u in users
                ],
                "error": error,
                "limit": limit,
                "offset": offset,
            }
        )
    return templates.TemplateResponse(
        "admin_users.html",
        {"request": request, "users": users, "error": error, "user": user},
    )


@router.post("/admin/users/{user_id}/flags", response_model=None)
async def admin_user_update_flags(
    request: Request,
    user_id: int,
    is_superadmin: str | None = Form(None),
    is_auditor: str | None = Form(None),
) -> WebResponse:
    user = require_superadmin(request)
    if not isinstance(user, User):
        return user
    wants_json = "application/json" in request.headers.get("accept", "")
    if is_superadmin is None and is_auditor is None:
        try:
            payload = await request.json()
            is_superadmin = str(payload.get("is_superadmin")) if payload else None
            is_auditor = str(payload.get("is_auditor")) if payload else None
        except (JSONDecodeError, ValueError, TypeError):
            is_superadmin = None
            is_auditor = None
    superadmin_value = True if is_superadmin in {"true", "1", "yes", "on"} else False
    auditor_value = True if is_auditor in {"true", "1", "yes", "on"} else False
    with get_session() as session:
        target = session.query(User).filter(User.id == user_id).one_or_none()
        if not target:
            if wants_json:
                return JSONResponse({"error": "User not found"}, status_code=404)
            return _redirect_with_message("/admin/users", "User not found")
        target.is_superadmin = superadmin_value
        target.is_auditor = auditor_value
        log_security_event(
            action="user.flags_update",
            outcome="success",
            actor_user_id=request.session.get("user_id"),
            details={
                "target_user_id": target.id,
                "is_superadmin": target.is_superadmin,
                "is_auditor": target.is_auditor,
            },
            session=session,
        )
        log_audit(
            actor_user_id=user.id,
            action="admin.user.flags",
            entity_type="user",
            entity_id=target.id,
            details={
                "is_superadmin": target.is_superadmin,
                "is_auditor": target.is_auditor,
            },
            session=session,
        )
    if wants_json:
        return JSONResponse(
            {
                "status": "updated",
                "user_id": user_id,
                "is_superadmin": superadmin_value,
                "is_auditor": auditor_value,
            }
        )
    return _redirect_with_message("/admin/users", "User updated")
