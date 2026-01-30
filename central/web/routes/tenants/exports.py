from __future__ import annotations

import json
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from json import JSONDecodeError

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse

from central.core.audit import log_audit
from central.db.models import ExportSchedule, Site, Tenant, User, UserRole
from central.db.session import get_session
from central.web.auth import allow_api_key_scope, require_tenant_role
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


@router.get("/tenants/{tenant_id}/exports", response_class=HTMLResponse)
def tenant_exports(request: Request, tenant_id: int) -> WebResponse:
    user = require_tenant_role(request, tenant_id, UserRole.read_only)
    if not isinstance(user, User):
        return user

    def fetch_exports() -> Iterable[ExportSchedule]:
        with get_session() as session:
            query = session.query(ExportSchedule).filter(
                ExportSchedule.tenant_id == tenant_id
            )
            site_filter = request.query_params.get("site_id")
            start_after = request.query_params.get("start_after")
            start_before = request.query_params.get("start_before")
            if site_filter:
                try:
                    query = query.filter(ExportSchedule.site_id == int(site_filter))
                except ValueError:
                    pass
            if start_after:
                query = query.filter(ExportSchedule.scheduled_at_utc >= start_after)
            if start_before:
                query = query.filter(ExportSchedule.scheduled_at_utc <= start_before)
            query = query.order_by(ExportSchedule.scheduled_at_utc.asc())
            query, _, _ = _paginate_query(query, request)
            return query.all()

    def fetch_sites() -> Iterable[Site]:
        with get_session() as session:
            return (
                session.query(Site)
                .filter(Site.tenant_id == tenant_id)
                .order_by(Site.name)
                .all()
            )

    def fetch_tenant() -> Iterable[Tenant]:
        with get_session() as session:
            return session.query(Tenant).filter(Tenant.id == tenant_id).all()

    schedules, error = _safe_query(fetch_exports)
    sites, _ = _safe_query(fetch_sites)
    tenants, _ = _safe_query(fetch_tenant)
    tenant = tenants[0] if tenants else None
    site_map = {site.id: site.name for site in sites}
    site_tz_map = {site.id: site.timezone for site in sites}
    if _wants_json(request):
        limit, offset = _pagination_params(request)
        return JSONResponse(
            {
                "tenant_id": tenant_id,
                "tenant_name": tenant.name if tenant else None,
                "exports": [
                    {
                        "id": schedule.id,
                        "name": schedule.name,
                        "exporter": schedule.exporter,
                        "scheduled_at_utc": _format_dt(schedule.scheduled_at_utc),
                        "not_before_utc": _format_dt(schedule.not_before_utc),
                        "not_after_utc": _format_dt(schedule.not_after_utc),
                        "actual_start_at_utc": _format_dt(schedule.actual_start_at_utc),
                        "finished_at_utc": _format_dt(schedule.finished_at_utc),
                        "site_id": schedule.site_id,
                        "site_name": site_map.get(schedule.site_id),
                        "site_timezone": site_tz_map.get(schedule.site_id),
                        "settings_json": schedule.settings_json,
                        "created_at_utc": _format_dt(schedule.created_at),
                    }
                    for schedule in schedules
                ],
                "sites": [{"id": site.id, "name": site.name} for site in sites],
                "error": error,
                "limit": limit,
                "offset": offset,
            }
        )
    return templates.TemplateResponse(
        "tenant_exports.html",
        {
            "request": request,
            "tenant_id": tenant_id,
            "tenant_name": tenant.name if tenant else None,
            "schedules": schedules,
            "sites": sites,
            "site_map": site_map,
            "site_tz_map": site_tz_map,
            "error": error,
            "message": request.query_params.get("message"),
            "user": user,
        },
    )


@router.post("/tenants/{tenant_id}/exports", response_model=None)
async def tenant_export_schedule_create(
    request: Request,
    tenant_id: int,
    name: str | None = Form(None),
    start_date: str | None = Form(None),
    start_time: str | None = Form(None),
    site_id: str | None = Form(None),
    exporter: str | None = Form(None),
    settings_json: str | None = Form(None),
) -> WebResponse:
    user: User | None
    if not allow_api_key_scope(request, "export:schedule"):
        user_or_response = require_tenant_role(
            request, tenant_id, UserRole.scan_operator
        )
        if not isinstance(user_or_response, User):
            return user_or_response
        user = user_or_response
    else:
        user = None
    wants_json = _wants_json(request)
    payload = None
    if not start_date or not start_time:
        try:
            payload = await request.json()
        except (JSONDecodeError, ValueError, TypeError):
            payload = None
    if payload:
        name = payload.get("name") if payload else name
        start_at = payload.get("start_at")
        site_id = (
            str(payload.get("site_id"))
            if payload and payload.get("site_id") is not None
            else site_id
        )
        exporter = payload.get("exporter") if payload else exporter
        if isinstance(payload, dict) and payload.get("settings"):
            settings_json = json.dumps(payload.get("settings"))
        else:
            settings_json = payload.get("settings_json") if payload else settings_json
    else:
        start_at = None

    if start_at:
        try:
            start_at_dt = datetime.fromisoformat(start_at)
        except ValueError:
            start_at_dt = None
    else:
        if not start_date or not start_time:
            start_at_dt = None
        else:
            try:
                start_at_dt = datetime.fromisoformat(f"{start_date}T{start_time}")
            except ValueError:
                start_at_dt = None

    if start_at_dt is None:
        if wants_json:
            return JSONResponse(
                {"error": "Start date/time is required"}, status_code=400
            )
        return _redirect_with_message(
            f"/tenants/{tenant_id}/exports",
            "Start date/time is required",
        )
    if start_at_dt.tzinfo is None:
        start_at_dt = start_at_dt.replace(tzinfo=UTC)
    else:
        start_at_dt = start_at_dt.astimezone(UTC)

    exporter = (exporter or "").strip()
    if not exporter:
        if wants_json:
            return JSONResponse({"error": "Exporter is required"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/exports",
            "Exporter is required",
        )

    parsed_site_id = int(site_id) if site_id else None
    normalized_settings = None
    if settings_json:
        try:
            parsed_settings = json.loads(settings_json)
            normalized_settings = json.dumps(parsed_settings, sort_keys=True)
        except json.JSONDecodeError:
            if wants_json:
                return JSONResponse({"error": "Invalid settings JSON"}, status_code=400)
            return _redirect_with_message(
                f"/tenants/{tenant_id}/exports",
                "Invalid settings JSON",
            )

    window_minutes = 10
    not_before = start_at_dt
    not_after = start_at_dt + timedelta(minutes=window_minutes)
    with get_session() as session:
        schedule = ExportSchedule(
            tenant_id=tenant_id,
            site_id=parsed_site_id,
            name=(name or "").strip() or None,
            exporter=exporter,
            scheduled_at_utc=start_at_dt,
            not_before_utc=not_before,
            not_after_utc=not_after,
            settings_json=normalized_settings,
        )
        session.add(schedule)
        session.flush()
        log_audit(
            actor_user_id=user.id if user else None,
            action="tenant.export.schedule.create",
            entity_type="export_schedule",
            entity_id=schedule.id,
            details={
                "exporter": exporter,
                "scheduled_at_utc": _format_dt(schedule.scheduled_at_utc),
            },
            session=session,
        )

    if wants_json:
        return JSONResponse(
            {
                "status": "created",
                "export_schedule_id": schedule.id,
                "scheduled_at_utc": _format_dt(schedule.scheduled_at_utc),
                "not_before_utc": _format_dt(schedule.not_before_utc),
                "not_after_utc": _format_dt(schedule.not_after_utc),
            }
        )
    return _redirect_with_message(
        f"/tenants/{tenant_id}/exports",
        "Export scheduled",
    )


@router.post("/tenants/{tenant_id}/exports/run", response_model=None)
async def tenant_export_run(
    request: Request,
    tenant_id: int,
    exporter: str | None = Form(None),
    export_schedule_id: str | None = Form(None),
    site_id: str | None = Form(None),
    settings_json: str | None = Form(None),
) -> WebResponse:
    user: User | None
    if not allow_api_key_scope(request, "export:run"):
        user_or_response = require_tenant_role(
            request, tenant_id, UserRole.scan_operator
        )
        if not isinstance(user_or_response, User):
            return user_or_response
        user = user_or_response
    else:
        user = None
    wants_json = _wants_json(request)
    if not exporter:
        try:
            payload = await request.json()
            exporter = payload.get("exporter") if payload else None
            export_schedule_id = (
                payload.get("export_schedule_id") if payload else export_schedule_id
            )
            site_id = payload.get("site_id") if payload else site_id
            settings_json = payload.get("settings_json") if payload else settings_json
            if isinstance(payload, dict) and payload.get("settings"):
                settings_json = json.dumps(payload.get("settings"))
        except (JSONDecodeError, ValueError, TypeError):
            exporter = None
    exporter = (exporter or "netbox").strip()
    if not exporter:
        if wants_json:
            return JSONResponse({"error": "Exporter is required"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/schedules",
            "Exporter is required",
        )
    parsed_schedule_id = int(export_schedule_id) if export_schedule_id else None
    parsed_site_id = int(site_id) if site_id else None
    parsed_settings = None
    if settings_json:
        try:
            parsed_settings = json.loads(settings_json)
            settings_json = json.dumps(parsed_settings, sort_keys=True)
        except json.JSONDecodeError:
            if wants_json:
                return JSONResponse({"error": "Invalid settings JSON"}, status_code=400)
            return _redirect_with_message(
                f"/tenants/{tenant_id}/exports",
                "Invalid settings JSON",
            )
    payload = {
        "tenant_id": tenant_id,
        "site_id": parsed_site_id,
        "export_schedule_id": parsed_schedule_id,
        "requested_by_user_id": user.id if user else None,
    }
    from central.workers.exports import export_inventory_task

    export_inventory_task.delay(exporter, payload, parsed_settings, None)
    with get_session() as session:
        log_audit(
            actor_user_id=user.id if user else None,
            action="tenant.export.run",
            entity_type="tenant",
            entity_id=tenant_id,
            details={
                "exporter": exporter,
                "export_schedule_id": parsed_schedule_id,
                "site_id": parsed_site_id,
            },
            session=session,
        )
    if wants_json:
        return JSONResponse({"status": "queued", "exporter": exporter})
    redirect_target = f"/tenants/{tenant_id}/exports"
    return _redirect_with_message(
        redirect_target,
        f"Export queued: {exporter}",
    )
