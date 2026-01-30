from __future__ import annotations

from collections.abc import Iterable

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse

from central.db.models import ScanSchedule, Site, Tenant, User
from central.db.session import get_session
from central.web.auth import require_superadmin
from central.web.routes.common import (
    WebResponse,
    _format_dt,
    _paginate_query,
    _pagination_params,
    _parse_csv,
    _safe_query,
    _wants_json,
    templates,
)

router = APIRouter()


@router.get("/admin/schedules", response_class=HTMLResponse)
def admin_schedules(request: Request) -> WebResponse:
    user = require_superadmin(request)
    if not isinstance(user, User):
        return user

    def fetch_schedules() -> Iterable[ScanSchedule]:
        with get_session() as session:
            query = session.query(ScanSchedule)
            tenant_filter = request.query_params.get("tenant_id")
            scan_type_filter = request.query_params.get("scan_type")
            start_after = request.query_params.get("start_after")
            start_before = request.query_params.get("start_before")
            if tenant_filter:
                try:
                    query = query.filter(ScanSchedule.tenant_id == int(tenant_filter))
                except ValueError:
                    pass
            if scan_type_filter:
                query = query.filter(
                    ScanSchedule.scan_types.ilike(f"%{scan_type_filter}%")
                )
            if start_after:
                query = query.filter(ScanSchedule.scheduled_at_utc >= start_after)
            if start_before:
                query = query.filter(ScanSchedule.scheduled_at_utc <= start_before)
            query = query.order_by(ScanSchedule.scheduled_at_utc.asc())
            query, _, _ = _paginate_query(query, request)
            return query.all()

    def fetch_tenants() -> Iterable[Tenant]:
        with get_session() as session:
            return session.query(Tenant).order_by(Tenant.name).all()

    schedules, error = _safe_query(fetch_schedules)
    tenants, _ = _safe_query(fetch_tenants)
    tenant_map = {tenant.id: tenant.name for tenant in tenants}
    site_map: dict[int, Site] = {}
    site_ids = {schedule.site_id for schedule in schedules if schedule.site_id}
    if site_ids:
        with get_session() as session:
            sites = session.query(Site).filter(Site.id.in_(site_ids)).all()
            site_map = {site.id: site for site in sites}
    if _wants_json(request):
        limit, offset = _pagination_params(request)
        return JSONResponse(
            {
                "schedules": [
                    {
                        "id": schedule.id,
                        "tenant_id": schedule.tenant_id,
                        "tenant_name": tenant_map.get(schedule.tenant_id),
                        "site_id": schedule.site_id,
                        "site_name": (
                            site.name
                            if (site := site_map.get(schedule.site_id))
                            else None
                        ),
                        "site_timezone": (site.timezone if site else None),
                        "name": schedule.name,
                        "scheduled_at_utc": _format_dt(schedule.scheduled_at_utc),
                        "not_before_utc": _format_dt(schedule.not_before_utc),
                        "not_after_utc": _format_dt(schedule.not_after_utc),
                        "scan_types": _parse_csv(schedule.scan_types),
                    }
                    for schedule in schedules
                ],
                "tenants": [
                    {"id": tenant.id, "name": tenant.name} for tenant in tenants
                ],
                "error": error,
                "limit": limit,
                "offset": offset,
            }
        )
    return templates.TemplateResponse(
        "admin_schedules.html",
        {
            "request": request,
            "schedules": schedules,
            "tenants": tenants,
            "error": error,
            "user": user,
        },
    )
