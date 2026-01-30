from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from json import JSONDecodeError

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse

from central.core.audit import log_audit
from central.db.models import (
    Network,
    ScanSchedule,
    ScanScheduleType,
    Site,
    Tenant,
    User,
    UserRole,
)
from central.db.session import get_session
from central.web.auth import (
    allow_api_key_scope,
    allow_collector_token,
    require_tenant_role,
)
from central.web.routes.common import (
    WebResponse,
    _format_dt,
    _paginate_query,
    _pagination_params,
    _parse_csv,
    _redirect_with_message,
    _safe_query,
    _wants_json,
    templates,
)

router = APIRouter()


@router.get("/tenants/{tenant_id}/schedules", response_class=HTMLResponse)
def tenant_schedules(request: Request, tenant_id: int) -> WebResponse:
    user = require_tenant_role(request, tenant_id, UserRole.read_only)
    if not isinstance(user, User):
        return user

    def fetch_schedules() -> Iterable[ScanSchedule]:
        with get_session() as session:
            query = session.query(ScanSchedule).filter(
                ScanSchedule.tenant_id == tenant_id
            )
            site_filter = request.query_params.get("site_id")
            scan_type_filter = request.query_params.get("scan_type")
            start_after = request.query_params.get("start_after")
            start_before = request.query_params.get("start_before")
            if site_filter:
                try:
                    query = query.filter(ScanSchedule.site_id == int(site_filter))
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

    def fetch_sites() -> Iterable[Site]:
        with get_session() as session:
            return (
                session.query(Site)
                .filter(Site.tenant_id == tenant_id)
                .order_by(Site.name)
                .all()
            )

    def fetch_networks() -> Iterable[Network]:
        with get_session() as session:
            query = session.query(Network).filter(Network.tenant_id == tenant_id)
            site_filter = request.query_params.get("site_id")
            if site_filter:
                try:
                    query = query.filter(Network.site_id == int(site_filter))
                except ValueError:
                    pass
            return query.order_by(Network.name).all()

    def fetch_tenant() -> Iterable[Tenant]:
        with get_session() as session:
            return session.query(Tenant).filter(Tenant.id == tenant_id).all()

    schedules, error = _safe_query(fetch_schedules)
    sites, _ = _safe_query(fetch_sites)
    networks, _ = _safe_query(fetch_networks)
    tenants, _ = _safe_query(fetch_tenant)
    tenant = tenants[0] if tenants else None
    site_map = {site.id: site.name for site in sites}
    site_tz_map = {site.id: site.timezone for site in sites}
    network_map = {network.id: network.name for network in networks}
    if _wants_json(request):
        limit, offset = _pagination_params(request)
        return JSONResponse(
            {
                "tenant_id": tenant_id,
                "tenant_name": tenant.name if tenant else None,
                "schedules": [
                    {
                        "id": schedule.id,
                        "name": schedule.name,
                        "scheduled_at_utc": _format_dt(schedule.scheduled_at_utc),
                        "not_before_utc": _format_dt(schedule.not_before_utc),
                        "not_after_utc": _format_dt(schedule.not_after_utc),
                        "actual_start_at_utc": _format_dt(schedule.actual_start_at_utc),
                        "finished_at_utc": _format_dt(schedule.finished_at_utc),
                        "site_id": schedule.site_id,
                        "site_name": site_map.get(schedule.site_id),
                        "site_timezone": site_tz_map.get(schedule.site_id),
                        "network_ids": _parse_csv(schedule.network_ids),
                        "scan_types": _parse_csv(schedule.scan_types),
                        "created_at_utc": _format_dt(schedule.created_at),
                    }
                    for schedule in schedules
                ],
                "sites": [{"id": site.id, "name": site.name} for site in sites],
                "networks": [
                    {"id": network.id, "name": network.name, "site_id": network.site_id}
                    for network in networks
                ],
                "error": error,
                "limit": limit,
                "offset": offset,
            }
        )
    return templates.TemplateResponse(
        "tenant_schedules.html",
        {
            "request": request,
            "schedules": schedules,
            "sites": sites,
            "networks": networks,
            "tenant_id": tenant_id,
            "tenant_name": tenant.name if tenant else None,
            "error": error,
            "user": user,
            "message": request.query_params.get("message"),
            "site_filter": request.query_params.get("site_id"),
            "site_map": site_map,
            "site_tz_map": site_tz_map,
            "network_map": network_map,
        },
    )


@router.post("/tenants/{tenant_id}/schedules", response_model=None)
async def tenant_schedule_create(
    request: Request,
    tenant_id: int,
    name: str | None = Form(None),
    start_date: str | None = Form(None),
    start_time: str | None = Form(None),
    site_id: str | None = Form(None),
    network_ids: list[str] = Form(None),
    scan_types: list[str] = Form(None),
    priority: str | None = Form(None),
) -> WebResponse:
    user: User | None
    if not allow_api_key_scope(request, "schedule:write"):
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
        network_ids = payload.get("network_ids") if payload else network_ids
        scan_types = payload.get("scan_types") if payload else scan_types
        priority = (
            str(payload.get("priority"))
            if payload and payload.get("priority") is not None
            else priority
        )
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
            f"/tenants/{tenant_id}/schedules",
            "Start date/time is required",
        )
    if start_at_dt.tzinfo is None:
        start_at_dt = start_at_dt.replace(tzinfo=UTC)
    else:
        start_at_dt = start_at_dt.astimezone(UTC)

    if not scan_types:
        if wants_json:
            return JSONResponse(
                {"error": "Select at least one scan type"}, status_code=400
            )
        return _redirect_with_message(
            f"/tenants/{tenant_id}/schedules",
            "Select at least one scan type",
        )

    if not network_ids:
        if wants_json:
            return JSONResponse(
                {"error": "Select at least one network"}, status_code=400
            )
        return _redirect_with_message(
            f"/tenants/{tenant_id}/schedules",
            "Select at least one network",
        )

    parsed_site_id = int(site_id) if site_id else None
    try:
        parsed_priority = int(priority) if priority is not None else 0
    except ValueError:
        parsed_priority = 0
    network_csv = ",".join([str(item) for item in (network_ids or [])])
    scan_type_csv = ",".join([str(item) for item in scan_types])

    window_minutes = 10
    not_before = start_at_dt
    not_after = start_at_dt + timedelta(minutes=window_minutes)
    with get_session() as session:
        schedule = ScanSchedule(
            tenant_id=tenant_id,
            site_id=parsed_site_id,
            name=(name or "").strip() or None,
            scheduled_at_utc=start_at_dt,
            not_before_utc=not_before,
            not_after_utc=not_after,
            network_ids=network_csv,
            scan_types=scan_type_csv,
        )
        session.add(schedule)
        session.flush()
        for scan_type in scan_types:
            session.add(
                ScanScheduleType(
                    schedule_id=schedule.id,
                    scan_type=str(scan_type),
                    scheduled_at_utc=start_at_dt,
                    not_before_utc=not_before,
                    not_after_utc=not_after,
                    priority=parsed_priority,
                )
            )
        log_audit(
            actor_user_id=user.id if user else None,
            action="tenant.schedule.create",
            entity_type="scan_schedule",
            entity_id=schedule.id,
            details={
                "name": schedule.name,
                "scheduled_at_utc": _format_dt(schedule.scheduled_at_utc),
            },
            session=session,
        )

    if wants_json:
        return JSONResponse(
            {
                "status": "created",
                "schedule_id": schedule.id,
                "scheduled_at_utc": _format_dt(schedule.scheduled_at_utc),
                "not_before_utc": _format_dt(schedule.not_before_utc),
                "not_after_utc": _format_dt(schedule.not_after_utc),
            }
        )
    return _redirect_with_message(
        f"/tenants/{tenant_id}/schedules",
        "Schedule created",
    )


@router.get("/tenants/{tenant_id}/schedules/{schedule_id}", response_class=HTMLResponse)
def tenant_schedule_detail(
    request: Request, tenant_id: int, schedule_id: int
) -> WebResponse:
    user = require_tenant_role(request, tenant_id, UserRole.read_only)
    if not isinstance(user, User):
        return user

    def fetch_schedule() -> Iterable[ScanSchedule]:
        with get_session() as session:
            return (
                session.query(ScanSchedule)
                .filter(
                    ScanSchedule.id == schedule_id, ScanSchedule.tenant_id == tenant_id
                )
                .all()
            )

    def fetch_types() -> Iterable[ScanScheduleType]:
        with get_session() as session:
            return (
                session.query(ScanScheduleType)
                .filter(ScanScheduleType.schedule_id == schedule_id)
                .order_by(ScanScheduleType.scan_type)
                .all()
            )

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

    schedules, error = _safe_query(fetch_schedule)
    schedule = schedules[0] if schedules else None
    schedule_types, _ = _safe_query(fetch_types)
    sites, _ = _safe_query(fetch_sites)
    tenants, _ = _safe_query(fetch_tenant)
    tenant = tenants[0] if tenants else None
    site_map = {site.id: site.name for site in sites}
    site_tz_map = {site.id: site.timezone for site in sites}

    if _wants_json(request):
        if not schedule:
            return JSONResponse({"error": "Schedule not found"}, status_code=404)
        return JSONResponse(
            {
                "tenant_id": tenant_id,
                "tenant_name": tenant.name if tenant else None,
                "schedule": {
                    "id": schedule.id,
                    "name": schedule.name,
                    "scheduled_at_utc": _format_dt(schedule.scheduled_at_utc),
                    "not_before_utc": _format_dt(schedule.not_before_utc),
                    "not_after_utc": _format_dt(schedule.not_after_utc),
                    "actual_start_at_utc": _format_dt(schedule.actual_start_at_utc),
                    "finished_at_utc": _format_dt(schedule.finished_at_utc),
                    "site_id": schedule.site_id,
                    "site_name": site_map.get(schedule.site_id),
                    "site_timezone": site_tz_map.get(schedule.site_id),
                    "network_ids": _parse_csv(schedule.network_ids),
                    "scan_types": _parse_csv(schedule.scan_types),
                    "created_at_utc": _format_dt(schedule.created_at),
                },
                "scan_types": [
                    {
                        "id": entry.id,
                        "scan_type": entry.scan_type,
                        "scheduled_at_utc": _format_dt(entry.scheduled_at_utc),
                        "not_before_utc": _format_dt(entry.not_before_utc),
                        "not_after_utc": _format_dt(entry.not_after_utc),
                        "actual_start_at_utc": _format_dt(entry.actual_start_at_utc),
                        "finished_at_utc": _format_dt(entry.finished_at_utc),
                    }
                    for entry in schedule_types
                ],
                "error": error,
            }
        )

    return templates.TemplateResponse(
        "tenant_schedule_detail.html",
        {
            "request": request,
            "schedule": schedule,
            "schedule_types": schedule_types,
            "tenant_id": tenant_id,
            "tenant_name": tenant.name if tenant else None,
            "site_map": site_map,
            "site_tz_map": site_tz_map,
            "error": error,
            "user": user,
        },
    )


@router.post("/tenants/{tenant_id}/schedules/{schedule_id}/status", response_model=None)
async def tenant_schedule_update_status(
    request: Request,
    tenant_id: int,
    schedule_id: int,
    actual_start_at_utc: str | None = Form(None),
    finished_at_utc: str | None = Form(None),
) -> WebResponse:
    user: User | None
    if not allow_collector_token(request):
        user_or_response = require_tenant_role(request, tenant_id, UserRole.read_write)
        if not isinstance(user_or_response, User):
            return user_or_response
        user = user_or_response
    else:
        user = None
    wants_json = _wants_json(request)
    if not actual_start_at_utc and not finished_at_utc:
        try:
            payload = await request.json()
            actual_start_at_utc = (
                payload.get("actual_start_at_utc") if payload else None
            ) or (payload.get("actual_start_at") if payload else None)
            finished_at_utc = (payload.get("finished_at_utc") if payload else None) or (
                payload.get("finished_at") if payload else None
            )
        except (JSONDecodeError, ValueError, TypeError):
            actual_start_at_utc = None
            finished_at_utc = None

    def parse_dt(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)

    actual_dt = parse_dt(actual_start_at_utc)
    finished_dt = parse_dt(finished_at_utc)
    if actual_start_at_utc and actual_dt is None:
        if wants_json:
            return JSONResponse(
                {"error": "Invalid actual_start_at_utc"}, status_code=400
            )
        return _redirect_with_message(
            f"/tenants/{tenant_id}/schedules/{schedule_id}",
            "Invalid actual_start_at_utc",
        )
    if finished_at_utc and finished_dt is None:
        if wants_json:
            return JSONResponse({"error": "Invalid finished_at_utc"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/schedules/{schedule_id}",
            "Invalid finished_at_utc",
        )

    with get_session() as session:
        schedule = (
            session.query(ScanSchedule)
            .filter(ScanSchedule.id == schedule_id, ScanSchedule.tenant_id == tenant_id)
            .one_or_none()
        )
        if not schedule:
            if wants_json:
                return JSONResponse({"error": "Schedule not found"}, status_code=404)
            return _redirect_with_message(
                f"/tenants/{tenant_id}/schedules",
                "Schedule not found",
            )
        if actual_dt:
            schedule.actual_start_at_utc = actual_dt
        if finished_dt:
            schedule.finished_at_utc = finished_dt
        log_audit(
            actor_user_id=user.id if user else None,
            action="tenant.schedule.update",
            entity_type="scan_schedule",
            entity_id=schedule.id,
            details={
                "actual_start_at_utc": _format_dt(schedule.actual_start_at_utc),
                "finished_at_utc": _format_dt(schedule.finished_at_utc),
            },
            session=session,
        )

    if wants_json:
        return JSONResponse(
            {
                "status": "updated",
                "schedule_id": schedule_id,
                "actual_start_at_utc": _format_dt(
                    actual_dt or schedule.actual_start_at_utc
                ),
                "finished_at_utc": _format_dt(finished_dt or schedule.finished_at_utc),
            }
        )
    return _redirect_with_message(
        f"/tenants/{tenant_id}/schedules/{schedule_id}",
        "Schedule updated",
    )


@router.post(
    "/tenants/{tenant_id}/schedules/{schedule_id}/types/{type_id}/status",
    response_model=None,
)
async def tenant_schedule_type_update_status(
    request: Request,
    tenant_id: int,
    schedule_id: int,
    type_id: int,
    actual_start_at_utc: str | None = Form(None),
    finished_at_utc: str | None = Form(None),
) -> WebResponse:
    user: User | None
    if not allow_collector_token(request):
        user_or_response = require_tenant_role(request, tenant_id, UserRole.read_write)
        if not isinstance(user_or_response, User):
            return user_or_response
        user = user_or_response
    else:
        user = None
    wants_json = _wants_json(request)
    if not actual_start_at_utc and not finished_at_utc:
        try:
            payload = await request.json()
            actual_start_at_utc = (
                payload.get("actual_start_at_utc") if payload else None
            ) or (payload.get("actual_start_at") if payload else None)
            finished_at_utc = (payload.get("finished_at_utc") if payload else None) or (
                payload.get("finished_at") if payload else None
            )
        except (JSONDecodeError, ValueError, TypeError):
            actual_start_at_utc = None
            finished_at_utc = None

    def parse_dt(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)

    actual_dt = parse_dt(actual_start_at_utc)
    finished_dt = parse_dt(finished_at_utc)
    if actual_start_at_utc and actual_dt is None:
        if wants_json:
            return JSONResponse(
                {"error": "Invalid actual_start_at_utc"}, status_code=400
            )
        return _redirect_with_message(
            f"/tenants/{tenant_id}/schedules/{schedule_id}",
            "Invalid actual_start_at_utc",
        )
    if finished_at_utc and finished_dt is None:
        if wants_json:
            return JSONResponse({"error": "Invalid finished_at_utc"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/schedules/{schedule_id}",
            "Invalid finished_at_utc",
        )

    with get_session() as session:
        schedule = (
            session.query(ScanSchedule)
            .filter(ScanSchedule.id == schedule_id, ScanSchedule.tenant_id == tenant_id)
            .one_or_none()
        )
        if not schedule:
            if wants_json:
                return JSONResponse({"error": "Schedule not found"}, status_code=404)
            return _redirect_with_message(
                f"/tenants/{tenant_id}/schedules",
                "Schedule not found",
            )
        entry = (
            session.query(ScanScheduleType)
            .filter(
                ScanScheduleType.id == type_id,
                ScanScheduleType.schedule_id == schedule_id,
            )
            .one_or_none()
        )
        if not entry:
            if wants_json:
                return JSONResponse(
                    {"error": "Scan type entry not found"}, status_code=404
                )
            return _redirect_with_message(
                f"/tenants/{tenant_id}/schedules/{schedule_id}",
                "Scan type entry not found",
            )
        if actual_dt:
            entry.actual_start_at_utc = actual_dt
        if finished_dt:
            entry.finished_at_utc = finished_dt
        log_audit(
            actor_user_id=user.id if user else None,
            action="tenant.schedule_type.update",
            entity_type="scan_schedule_type",
            entity_id=entry.id,
            details={
                "scan_type": entry.scan_type,
                "actual_start_at_utc": _format_dt(entry.actual_start_at_utc),
                "finished_at_utc": _format_dt(entry.finished_at_utc),
            },
            session=session,
        )

    if wants_json:
        return JSONResponse(
            {
                "status": "updated",
                "type_id": type_id,
                "actual_start_at_utc": _format_dt(
                    actual_dt or entry.actual_start_at_utc
                ),
                "finished_at_utc": _format_dt(finished_dt or entry.finished_at_utc),
            }
        )
    return _redirect_with_message(
        f"/tenants/{tenant_id}/schedules/{schedule_id}",
        "Scan type updated",
    )
