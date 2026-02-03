from __future__ import annotations

from collections.abc import Iterable
from json import JSONDecodeError

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse

from central.core.audit import log_audit
from central.db.models import Network, Site, Tenant, User, UserRole
from central.db.session import get_session
from central.web.auth import require_tenant_role
from central.web.routes.common import (
    WebResponse,
    _format_dt,
    _is_valid_timezone,
    _paginate_query,
    _pagination_params,
    _redirect_with_message,
    _safe_query,
    _wants_json,
    templates,
)

router = APIRouter()


@router.get("/tenants/{tenant_id}/sites", response_class=HTMLResponse)
def tenant_sites(request: Request, tenant_id: int) -> WebResponse:
    user = require_tenant_role(request, tenant_id, UserRole.read_only)
    if not isinstance(user, User):
        return user

    def fetch() -> Iterable[Site]:
        with get_session() as session:
            query = session.query(Site).filter(Site.tenant_id == tenant_id)
            name_filter = request.query_params.get("name")
            code_filter = request.query_params.get("code")
            if name_filter:
                # Sanitize name filter to prevent SQL injection
                name_filter = name_filter.replace("%", "\\%").replace("_", "\\_")
                query = query.filter(Site.name.ilike(f"%{name_filter}%"))
            if code_filter:
                # Sanitize code filter to prevent SQL injection
                code_filter = code_filter.replace("%", "\\%").replace("_", "\\_")
                query = query.filter(Site.code.ilike(f"%{code_filter}%"))
            query = query.order_by(Site.name)
            query, _, _ = _paginate_query(query, request)
            return query.all()

    def fetch_tenant() -> Iterable[Tenant]:
        with get_session() as session:
            return session.query(Tenant).filter(Tenant.id == tenant_id).all()

    sites, error = _safe_query(fetch)
    tenants, _ = _safe_query(fetch_tenant)
    tenant = tenants[0] if tenants else None
    if _wants_json(request):
        limit, offset = _pagination_params(request)
        return JSONResponse(
            {
                "tenant_id": tenant_id,
                "tenant_name": tenant.name if tenant else None,
                "sites": [
                    {
                        "id": site.id,
                        "name": site.name,
                        "timezone": site.timezone,
                        "code": site.code,
                        "description": site.description,
                        "created_at": _format_dt(site.created_at),
                    }
                    for site in sites
                ],
                "error": error,
                "limit": limit,
                "offset": offset,
            }
        )
    return templates.TemplateResponse(
        "tenant_sites.html",
        {
            "request": request,
            "sites": sites,
            "tenant_id": tenant_id,
            "tenant_name": tenant.name if tenant else None,
            "error": error,
            "user": user,
            "message": request.query_params.get("message"),
        },
    )


@router.post("/tenants/{tenant_id}/sites", response_model=None)
async def tenant_site_create(
    request: Request,
    tenant_id: int,
    name: str | None = Form(None),
    timezone: str | None = Form(None),
    code: str | None = Form(None),
    description: str | None = Form(None),
) -> WebResponse:
    user = require_tenant_role(request, tenant_id, UserRole.read_write)
    if not isinstance(user, User):
        return user
    wants_json = "application/json" in request.headers.get("accept", "")
    if not name:
        try:
            payload = await request.json()
            name = payload.get("name") if payload else None
            timezone = payload.get("timezone") if payload else timezone
            code = payload.get("code") if payload else code
            description = payload.get("description") if payload else description
        except (JSONDecodeError, ValueError, TypeError):
            name = None
    if not name:
        if wants_json:
            return JSONResponse({"error": "Name is required"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/sites",
            "Name is required",
        )
    if not timezone:
        if wants_json:
            return JSONResponse({"error": "Timezone is required"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/sites",
            "Timezone is required",
        )
    if not _is_valid_timezone(timezone):
        if wants_json:
            return JSONResponse({"error": "Invalid timezone"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/sites",
            "Invalid timezone",
        )
    with get_session() as session:
        site = Site(
            tenant_id=tenant_id,
            name=name.strip(),
            timezone=timezone.strip(),
            code=(code or "").strip() or None,
            description=(description or "").strip() or None,
        )
        session.add(site)
        session.flush()
        log_audit(
            actor_user_id=user.id,
            action="tenant.site.create",
            entity_type="site",
            entity_id=site.id,
            details={"name": site.name},
            session=session,
        )
    if wants_json:
        return JSONResponse(
            {"status": "created", "site_id": site.id, "name": site.name}
        )
    return _redirect_with_message(
        f"/tenants/{tenant_id}/sites",
        f"Site {name} created",
    )


@router.get("/tenants/{tenant_id}/sites/{site_id}", response_class=HTMLResponse)
def tenant_site_edit(request: Request, tenant_id: int, site_id: int) -> WebResponse:
    user = require_tenant_role(request, tenant_id, UserRole.read_write)
    if not isinstance(user, User):
        return user

    def fetch() -> Iterable[Site]:
        with get_session() as session:
            return (
                session.query(Site)
                .filter(Site.id == site_id, Site.tenant_id == tenant_id)
                .all()
            )

    sites, error = _safe_query(fetch)
    site = sites[0] if sites else None

    def fetch_tenant() -> Iterable[Tenant]:
        with get_session() as session:
            return session.query(Tenant).filter(Tenant.id == tenant_id).all()

    tenants, _ = _safe_query(fetch_tenant)
    tenant = tenants[0] if tenants else None
    if _wants_json(request):
        if not site:
            return JSONResponse({"error": "Site not found"}, status_code=404)
        return JSONResponse(
            {
                "tenant_id": tenant_id,
                "tenant_name": tenant.name if tenant else None,
                "site": {
                    "id": site.id,
                    "name": site.name,
                    "timezone": site.timezone,
                    "code": site.code,
                    "description": site.description,
                    "created_at": _format_dt(site.created_at),
                },
                "error": error,
            }
        )
    return templates.TemplateResponse(
        "tenant_site_edit.html",
        {
            "request": request,
            "site": site,
            "tenant_id": tenant_id,
            "tenant_name": tenant.name if tenant else None,
            "error": error,
            "user": user,
        },
    )


@router.post("/tenants/{tenant_id}/sites/{site_id}", response_model=None)
async def tenant_site_update(
    request: Request,
    tenant_id: int,
    site_id: int,
    name: str | None = Form(None),
    timezone: str | None = Form(None),
    code: str | None = Form(None),
    description: str | None = Form(None),
) -> WebResponse:
    user = require_tenant_role(request, tenant_id, UserRole.read_write)
    if not isinstance(user, User):
        return user
    wants_json = "application/json" in request.headers.get("accept", "")
    if not name:
        try:
            payload = await request.json()
            name = payload.get("name") if payload else None
            timezone = payload.get("timezone") if payload else timezone
            code = payload.get("code") if payload else code
            description = payload.get("description") if payload else description
        except (JSONDecodeError, ValueError, TypeError):
            name = None
    if not name:
        if wants_json:
            return JSONResponse({"error": "Name is required"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/sites",
            "Name is required",
        )
    if not timezone:
        if wants_json:
            return JSONResponse({"error": "Timezone is required"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/sites",
            "Timezone is required",
        )
    if not _is_valid_timezone(timezone):
        if wants_json:
            return JSONResponse({"error": "Invalid timezone"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/sites",
            "Invalid timezone",
        )
    with get_session() as session:
        site = (
            session.query(Site)
            .filter(Site.id == site_id, Site.tenant_id == tenant_id)
            .one_or_none()
        )
        if not site:
            if wants_json:
                return JSONResponse({"error": "Site not found"}, status_code=404)
            return _redirect_with_message(
                f"/tenants/{tenant_id}/sites",
                "Site not found",
            )
        site.name = name.strip()
        site.timezone = timezone.strip()
        site.code = (code or "").strip() or None
        site.description = (description or "").strip() or None
        log_audit(
            actor_user_id=user.id,
            action="tenant.site.update",
            entity_type="site",
            entity_id=site.id,
            details={"name": site.name},
            session=session,
        )
    if wants_json:
        return JSONResponse(
            {"status": "updated", "site_id": site.id, "name": site.name}
        )
    return _redirect_with_message(
        f"/tenants/{tenant_id}/sites",
        f"Site {name} updated",
    )


@router.post("/tenants/{tenant_id}/sites/{site_id}/delete", response_model=None)
def tenant_site_delete(
    request: Request,
    tenant_id: int,
    site_id: int,
    confirm_name: str = Form(...),
) -> WebResponse:
    user = require_tenant_role(request, tenant_id, UserRole.read_write)
    if not isinstance(user, User):
        return user
    wants_json = "application/json" in request.headers.get("accept", "")
    with get_session() as session:
        site = (
            session.query(Site)
            .filter(Site.id == site_id, Site.tenant_id == tenant_id)
            .one_or_none()
        )
        if not site:
            if wants_json:
                return JSONResponse({"error": "Site not found"}, status_code=404)
            return _redirect_with_message(
                f"/tenants/{tenant_id}/sites",
                "Site not found",
            )
        if confirm_name.strip() != site.name:
            if wants_json:
                return JSONResponse(
                    {"error": "Site name confirmation does not match"},
                    status_code=400,
                )
            return _redirect_with_message(
                f"/tenants/{tenant_id}/sites",
                "Site name confirmation does not match",
            )
        network_count = (
            session.query(Network).filter(Network.site_id == site_id).count()
        )
        if network_count:
            if wants_json:
                return JSONResponse(
                    {"error": "Delete blocked: site has networks"},
                    status_code=409,
                )
            return _redirect_with_message(
                f"/tenants/{tenant_id}/sites",
                "Delete blocked: site has networks",
            )
        session.delete(site)
        log_audit(
            actor_user_id=user.id,
            action="tenant.site.delete",
            entity_type="site",
            entity_id=site_id,
            details={"name": site.name},
            session=session,
        )
    if wants_json:
        return JSONResponse({"status": "deleted", "site_id": site_id})
    return _redirect_with_message(
        f"/tenants/{tenant_id}/sites",
        "Site deleted",
    )
