from __future__ import annotations

from collections.abc import Iterable
from json import JSONDecodeError

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from central.core.audit import log_audit, log_security_event
from central.db.models import (
    Collector,
    CollectorAffinity,
    CollectorCertificate,
    CollectorEnrollmentToken,
    CredentialAssignment,
    CredentialSet,
    ExportSchedule,
    InventoryDevice,
    Network,
    NetworkRateLimit,
    Observation,
    ScanRun,
    ScanSchedule,
    ScanScheduleType,
    Site,
    Tenant,
    TenantUser,
    User,
    UserRole,
)
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

    # Additional authentication validation for critical tenant management function
    if not user.is_superadmin:
        return RedirectResponse(url="/login", status_code=302)

    def fetch() -> Iterable[Tenant]:
        with get_session() as session:
            query = session.query(Tenant)
            name_filter = request.query_params.get("name")
            if name_filter:
                # Sanitize name filter to prevent SQL injection
                name_filter = name_filter.replace("%", "\\%").replace("_", "\\_")
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
        dependency_counts = {
            "memberships": session.query(TenantUser)
            .filter(TenantUser.tenant_id == tenant_id)
            .count(),
            "collectors": session.query(Collector)
            .filter(Collector.tenant_id == tenant_id)
            .count(),
            "collector_affinities": session.query(CollectorAffinity)
            .filter(CollectorAffinity.tenant_id == tenant_id)
            .count(),
            "collector_certificates": session.query(CollectorCertificate)
            .join(Collector, Collector.id == CollectorCertificate.collector_id)
            .filter(Collector.tenant_id == tenant_id)
            .count(),
            "collector_enrollment_tokens": session.query(CollectorEnrollmentToken)
            .filter(CollectorEnrollmentToken.tenant_id == tenant_id)
            .count(),
            "sites": session.query(Site).filter(Site.tenant_id == tenant_id).count(),
            "networks": session.query(Network)
            .filter(Network.tenant_id == tenant_id)
            .count(),
            "network_rate_limits": session.query(NetworkRateLimit)
            .filter(NetworkRateLimit.tenant_id == tenant_id)
            .count(),
            "scan_schedules": session.query(ScanSchedule)
            .filter(ScanSchedule.tenant_id == tenant_id)
            .count(),
            "scan_schedule_types": session.query(ScanScheduleType)
            .join(ScanSchedule, ScanSchedule.id == ScanScheduleType.schedule_id)
            .filter(ScanSchedule.tenant_id == tenant_id)
            .count(),
            "scan_runs": session.query(ScanRun)
            .filter(ScanRun.tenant_id == tenant_id)
            .count(),
            "observations": session.query(Observation)
            .join(ScanRun, ScanRun.id == Observation.scan_run_id)
            .filter(ScanRun.tenant_id == tenant_id)
            .count(),
            "inventory_devices": session.query(InventoryDevice)
            .filter(InventoryDevice.tenant_id == tenant_id)
            .count(),
            "credential_sets": session.query(CredentialSet)
            .filter(CredentialSet.tenant_id == tenant_id)
            .count(),
            "credential_assignments": session.query(CredentialAssignment)
            .filter(CredentialAssignment.tenant_id == tenant_id)
            .count(),
            "export_schedules": session.query(ExportSchedule)
            .filter(ExportSchedule.tenant_id == tenant_id)
            .count(),
        }
        blocking = {key: count for key, count in dependency_counts.items() if count}
        if blocking:
            if wants_json:
                return JSONResponse(
                    {
                        "error": "Delete blocked: tenant has dependent records",
                        "dependencies": blocking,
                    },
                    status_code=409,
                )
            return RedirectResponse(
                url="/admin/tenants?message=Delete%20blocked%3A%20tenant%20has%20dependent%20records",
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
