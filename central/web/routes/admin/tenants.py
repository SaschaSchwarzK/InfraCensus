from __future__ import annotations

from collections.abc import Iterable
from json import JSONDecodeError

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from central.core.audit import log_audit, log_security_event
from central.db.models import Collector, Tenant, TenantUser, User, UserRole
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


@router.get("/admin/tenants", response_class=HTMLResponse)
def admin_tenants(request: Request) -> WebResponse:
    user = require_superadmin(request)
    if not isinstance(user, User):
        return user

    def fetch() -> Iterable[Tenant]:
        with get_session() as session:
            query = session.query(Tenant)
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
                    {
                        "id": tenant.id,
                        "name": tenant.name,
                        "description": tenant.description,
                        "default_scanner": tenant.default_scanner,
                        "default_scan_interval_minutes": tenant.default_scan_interval_minutes,
                        "created_at": _format_dt(tenant.created_at),
                    }
                    for tenant in tenants
                ],
                "error": error,
                "limit": limit,
                "offset": offset,
            }
        )
    return templates.TemplateResponse(
        "admin_tenants.html",
        {
            "request": request,
            "tenants": tenants,
            "error": error,
            "user": user,
            "message": request.query_params.get("message"),
        },
    )


@router.post("/admin/tenants", response_model=None)
async def admin_tenant_create(
    request: Request,
    name: str | None = Form(None),
    description: str | None = Form(None),
    default_scanner: str | None = Form(None),
    default_scan_interval_minutes: str | None = Form(None),
) -> WebResponse:
    user = require_superadmin(request)
    if not isinstance(user, User):
        return user
    wants_json = "application/json" in request.headers.get("accept", "")
    if not name:
        try:
            payload = await request.json()
            name = payload.get("name") if payload else None
            description = payload.get("description") if payload else description
            default_scanner = (
                payload.get("default_scanner") if payload else default_scanner
            )
            default_scan_interval_minutes = (
                str(payload.get("default_scan_interval_minutes"))
                if payload and payload.get("default_scan_interval_minutes") is not None
                else default_scan_interval_minutes
            )
        except (JSONDecodeError, ValueError, TypeError):
            name = None
    if not name:
        if wants_json:
            return JSONResponse({"error": "Name is required"}, status_code=400)
        return RedirectResponse(
            url="/admin/tenants?message=Name%20is%20required", status_code=302
        )
    with get_session() as session:
        interval = (
            int(default_scan_interval_minutes)
            if default_scan_interval_minutes
            else None
        )
        tenant = Tenant(
            name=name.strip(),
            description=(description or "").strip() or None,
            default_scanner=(default_scanner or "").strip() or None,
            default_scan_interval_minutes=interval,
        )
        session.add(tenant)
        session.flush()
        log_security_event(
            action="tenant.create",
            outcome="success",
            actor_user_id=request.session.get("user_id"),
            details={
                "tenant_id": tenant.id,
                "tenant_name": tenant.name,
            },
            session=session,
        )
        session.add(
            TenantUser(
                tenant_id=tenant.id,
                user_id=user.id,
                role=UserRole.user_admin,
                roles=UserRole.user_admin.value,
            )
        )
        log_audit(
            actor_user_id=user.id,
            action="tenant.create",
            entity_type="tenant",
            entity_id=tenant.id,
            details={"name": tenant.name},
            session=session,
        )
    if wants_json:
        return JSONResponse(
            {"status": "created", "tenant_id": tenant.id, "name": tenant.name}
        )
    return RedirectResponse(url="/admin/tenants", status_code=302)


@router.get("/admin/tenants/{tenant_id}", response_class=HTMLResponse)
def admin_tenant_edit(request: Request, tenant_id: int) -> WebResponse:
    user = require_superadmin(request)
    if not isinstance(user, User):
        return user

    def fetch() -> Iterable[Tenant]:
        with get_session() as session:
            return session.query(Tenant).filter(Tenant.id == tenant_id).all()

    tenants, error = _safe_query(fetch)
    tenant = tenants[0] if tenants else None
    if _wants_json(request):
        if not tenant:
            return JSONResponse({"error": "Tenant not found"}, status_code=404)
        return JSONResponse(
            {
                "tenant": {
                    "id": tenant.id,
                    "name": tenant.name,
                    "description": tenant.description,
                    "default_scanner": tenant.default_scanner,
                    "default_scan_interval_minutes": tenant.default_scan_interval_minutes,
                    "created_at": _format_dt(tenant.created_at),
                },
                "error": error,
            }
        )
    return templates.TemplateResponse(
        "admin_tenant_edit.html",
        {"request": request, "tenant": tenant, "error": error, "user": user},
    )


@router.post("/admin/tenants/{tenant_id}", response_model=None)
async def admin_tenant_update(
    request: Request,
    tenant_id: int,
    name: str | None = Form(None),
    description: str | None = Form(None),
    default_scanner: str | None = Form(None),
    default_scan_interval_minutes: str | None = Form(None),
) -> WebResponse:
    user = require_superadmin(request)
    if not isinstance(user, User):
        return user
    wants_json = "application/json" in request.headers.get("accept", "")
    if not name:
        try:
            payload = await request.json()
            name = payload.get("name") if payload else None
            description = payload.get("description") if payload else description
            default_scanner = (
                payload.get("default_scanner") if payload else default_scanner
            )
            default_scan_interval_minutes = (
                str(payload.get("default_scan_interval_minutes"))
                if payload and payload.get("default_scan_interval_minutes") is not None
                else default_scan_interval_minutes
            )
        except (JSONDecodeError, ValueError, TypeError):
            name = None
    if not name:
        if wants_json:
            return JSONResponse({"error": "Name is required"}, status_code=400)
        return RedirectResponse(
            url="/admin/tenants?message=Name%20is%20required", status_code=302
        )
    with get_session() as session:
        tenant = session.query(Tenant).filter(Tenant.id == tenant_id).one_or_none()
        if not tenant:
            if wants_json:
                return JSONResponse({"error": "Tenant not found"}, status_code=404)
            return HTMLResponse(content="Tenant not found", status_code=404)
        tenant.name = name.strip()
        tenant.description = (description or "").strip() or None
        tenant.default_scanner = (default_scanner or "").strip() or None
        tenant.default_scan_interval_minutes = (
            int(default_scan_interval_minutes)
            if default_scan_interval_minutes
            else None
        )
        log_security_event(
            action="tenant.update",
            outcome="success",
            actor_user_id=request.session.get("user_id"),
            details={
                "tenant_id": tenant.id,
                "tenant_name": tenant.name,
            },
            session=session,
        )
        log_audit(
            actor_user_id=user.id,
            action="tenant.update",
            entity_type="tenant",
            entity_id=tenant.id,
            details={"name": tenant.name},
            session=session,
        )
    if wants_json:
        return JSONResponse(
            {"status": "updated", "tenant_id": tenant.id, "name": tenant.name}
        )
    return RedirectResponse(url="/admin/tenants", status_code=302)


@router.post("/admin/tenants/{tenant_id}/delete", response_model=None)
async def admin_tenant_delete(
    request: Request,
    tenant_id: int,
    confirm_name: str | None = Form(None),
) -> WebResponse:
    user = require_superadmin(request)
    if not isinstance(user, User):
        return user
    if not confirm_name:
        try:
            payload = await request.json()
            confirm_name = (payload or {}).get("confirm_name")
        except (JSONDecodeError, ValueError, TypeError):
            confirm_name = None
    wants_json = "application/json" in request.headers.get("accept", "")
    with get_session() as session:
        tenant = session.query(Tenant).filter(Tenant.id == tenant_id).one_or_none()
        if not tenant:
            if wants_json:
                return JSONResponse({"error": "Tenant not found"}, status_code=404)
            return HTMLResponse(content="Tenant not found", status_code=404)
        if not confirm_name or confirm_name.strip() != tenant.name:
            log_security_event(
                action="tenant.delete",
                outcome="denied",
                actor_user_id=request.session.get("user_id"),
                details={
                    "tenant_id": tenant.id,
                    "tenant_name": tenant.name,
                    "reason": "confirm_name_mismatch",
                    "path": request.url.path,
                    "ip": request.client.host if request.client else None,
                },
                session=session,
            )
            if wants_json:
                return JSONResponse(
                    {"error": "Tenant name confirmation does not match"},
                    status_code=400,
                )
            return RedirectResponse(
                url="/admin/tenants?message=Tenant%20name%20confirmation%20does%20not%20match",
                status_code=302,
            )
        log_security_event(
            action="tenant.delete",
            outcome="success",
            actor_user_id=request.session.get("user_id"),
            details={
                "tenant_id": tenant.id,
                "tenant_name": tenant.name,
                "ip": request.client.host if request.client else None,
            },
            session=session,
        )
        membership_count = (
            session.query(TenantUser).filter(TenantUser.tenant_id == tenant_id).count()
        )
        collector_count = (
            session.query(Collector).filter(Collector.tenant_id == tenant_id).count()
        )
        if membership_count or collector_count:
            if wants_json:
                return JSONResponse(
                    {"error": "Delete blocked: tenant has memberships or collectors"},
                    status_code=409,
                )
            return RedirectResponse(
                url="/admin/tenants?message=Delete%20blocked%3A%20tenant%20has%20memberships%20or%20collectors",
                status_code=302,
            )
        session.delete(tenant)
        log_audit(
            actor_user_id=user.id,
            action="tenant.delete",
            entity_type="tenant",
            entity_id=tenant_id,
            details={"name": tenant.name},
            session=session,
        )
    if wants_json:
        return JSONResponse({"status": "deleted", "tenant_id": tenant_id})
    return RedirectResponse(url="/admin/tenants", status_code=302)


@router.post("/admin/tenants/{tenant_id}/add-me", response_model=None)
def admin_tenant_add_me(request: Request, tenant_id: int) -> WebResponse:
    user = require_superadmin(request)
    if not isinstance(user, User):
        return user
    wants_json = "application/json" in request.headers.get("accept", "")
    with get_session() as session:
        exists = (
            session.query(TenantUser)
            .filter(TenantUser.tenant_id == tenant_id, TenantUser.user_id == user.id)
            .one_or_none()
        )
        if not exists:
            session.add(
                TenantUser(
                    tenant_id=tenant_id,
                    user_id=user.id,
                    role=UserRole.user_admin,
                    roles=UserRole.user_admin.value,
                )
            )
            log_audit(
                actor_user_id=user.id,
                action="tenant.user.add",
                entity_type="tenant",
                entity_id=tenant_id,
                details={"user": user.email, "role": UserRole.user_admin.value},
                session=session,
            )
    if wants_json:
        return JSONResponse(
            {"status": "updated", "tenant_id": tenant_id, "user_id": user.id}
        )
    return RedirectResponse(url="/admin/tenants", status_code=302)
