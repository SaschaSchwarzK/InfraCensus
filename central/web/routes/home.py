from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from central.db.models import Collector, InventoryDevice, Tenant, TenantUser, User
from central.db.session import get_session
from central.web.auth import require_user
from central.web.routes.common import WebResponse, _wants_json, templates

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def home(request: Request) -> WebResponse:
    user = require_user(request)
    if not isinstance(user, User):
        return user

    def fetch_stats() -> dict[str, int]:
        with get_session() as session:
            tenant_count = (
                session.query(Tenant)
                .join(TenantUser, TenantUser.tenant_id == Tenant.id)
                .filter(TenantUser.user_id == user.id)
                .count()
            )
            collector_count = (
                session.query(Collector)
                .join(Tenant, Tenant.id == Collector.tenant_id)
                .join(TenantUser, TenantUser.tenant_id == Tenant.id)
                .filter(TenantUser.user_id == user.id)
                .count()
            )
            device_count = (
                session.query(InventoryDevice)
                .join(TenantUser, TenantUser.tenant_id == InventoryDevice.tenant_id)
                .filter(TenantUser.user_id == user.id)
                .count()
            )
            return {
                "tenants": tenant_count,
                "collectors": collector_count,
                "devices": device_count,
            }

    stats, error = {}, None
    try:
        stats = fetch_stats()
    except SQLAlchemyError as exc:  # pragma: no cover - guard for missing migrations
        error = str(exc)
        stats = {"tenants": 0, "collectors": 0, "devices": 0}

    db_status = "online" if error is None else "error"
    if _wants_json(request):
        return JSONResponse(
            {
                "status": "ok" if error is None else "error",
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "is_superadmin": user.is_superadmin,
                },
                "stats": stats,
                "db_status": db_status,
                "error": error,
            }
        )
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "user": user,
            "stats": stats,
            "db_status": db_status,
            "error": error,
        },
    )
