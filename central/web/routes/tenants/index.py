from __future__ import annotations

from collections.abc import Iterable

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

from central.db.models import Tenant, TenantUser, User
from central.db.session import get_session
from central.web.auth import require_user
from central.web.routes.common import (
    WebResponse,
    _paginate_query,
    _pagination_params,
    _safe_query,
    _wants_json,
    templates,
)

router = APIRouter()


@router.get("/tenants", response_class=HTMLResponse)
def tenant_list(request: Request) -> WebResponse:
    user = require_user(request)
    if not isinstance(user, User):
        return user

    def fetch() -> Iterable[Tenant]:
        with get_session() as session:
            query = (
                session.query(Tenant)
                .join(TenantUser, TenantUser.tenant_id == Tenant.id)
                .filter(TenantUser.user_id == user.id)
            )
            name_filter = request.query_params.get("name")
            if name_filter:
                query = query.filter(Tenant.name.ilike(f"%{name_filter}%"))
            query = query.order_by(Tenant.name)
            query, _, _ = _paginate_query(query, request)
            return query.all()

    tenants, error = _safe_query(fetch)
    if _wants_json(request):
        limit, offset = _pagination_params(request)
        return JSONResponse(
            {
                "tenants": [
                    {"id": tenant.id, "name": tenant.name} for tenant in tenants
                ],
                "error": error,
                "limit": limit,
                "offset": offset,
            }
        )
    return templates.TemplateResponse(
        "tenants.html",
        {"request": request, "tenants": tenants, "error": error, "user": user},
    )
