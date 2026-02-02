from __future__ import annotations

import secrets
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from json import JSONDecodeError

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from central.core.audit import log_audit, log_security_event
from central.core.auth import hash_token
from central.db.models import (
    Collector,
    CollectorEnrollmentToken,
    Site,
    Tenant,
    User,
    UserRole,
)
from central.db.session import get_session
from central.web.auth import require_tenant_role
from central.web.routes.common import (
    WebResponse,
    _format_dt,
    _paginate_query,
    _pagination_params,
    _parse_capabilities_value,
    _parse_labels_value,
    _parse_scopes_value,
    _redirect_with_message,
    _safe_query,
    _wants_json,
    templates,
)

router = APIRouter()


@router.get("/tenants/{tenant_id}/collectors/enrollment", response_class=HTMLResponse)
def tenant_collector_enrollment(request: Request, tenant_id: int) -> WebResponse:
    user = require_tenant_role(request, tenant_id, UserRole.user_admin)
    if not isinstance(user, User):
        return user

    def fetch_tokens() -> Iterable[CollectorEnrollmentToken]:
        with get_session() as session:
            query = session.query(CollectorEnrollmentToken).filter(
                CollectorEnrollmentToken.tenant_id == tenant_id
            )
            site_filter = request.query_params.get("site_id")
            used_filter = request.query_params.get("used")
            if site_filter:
                try:
                    query = query.filter(
                        CollectorEnrollmentToken.site_id == int(site_filter)
                    )
                except ValueError:
                    pass
            if used_filter in {"true", "false"}:
                if used_filter == "true":
                    query = query.filter(CollectorEnrollmentToken.used_at.isnot(None))
                else:
                    query = query.filter(CollectorEnrollmentToken.used_at.is_(None))
            query = query.order_by(CollectorEnrollmentToken.created_at.desc())
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

    def fetch_users() -> Iterable[User]:
        with get_session() as session:
            return session.query(User).all()

    def fetch_tenant() -> Iterable[Tenant]:
        with get_session() as session:
            return session.query(Tenant).filter(Tenant.id == tenant_id).all()

    tokens, error = _safe_query(fetch_tokens)
    sites, _ = _safe_query(fetch_sites)
    users, _ = _safe_query(fetch_users)
    tenants, _ = _safe_query(fetch_tenant)
    tenant = tenants[0] if tenants else None
    user_map = {u.id: u.email for u in users}
    site_map = {site.id: site.name for site in sites}
    site_tz_map = {site.id: site.timezone for site in sites}
    if _wants_json(request):
        limit, offset = _pagination_params(request)
        return JSONResponse(
            {
                "tenant_id": tenant_id,
                "tenant_name": tenant.name if tenant else None,
                "tokens": [
                    {
                        "id": token.id,
                        "site_id": token.site_id,
                        "site_name": site_map.get(token.site_id),
                        "site_timezone": site_tz_map.get(token.site_id),
                        "expires_at": _format_dt(token.expires_at),
                        "used_at": _format_dt(token.used_at),
                        "created_by": user_map.get(token.created_by_user_id),
                        "created_at_utc": _format_dt(token.created_at),
                    }
                    for token in tokens
                ],
                "error": error,
                "limit": limit,
                "offset": offset,
            }
        )
    return templates.TemplateResponse(
        "tenant_collector_enrollment.html",
        {
            "request": request,
            "tenant_id": tenant_id,
            "tenant_name": tenant.name if tenant else None,
            "tokens": tokens,
            "sites": sites,
            "user_map": user_map,
            "site_map": site_map,
            "site_tz_map": site_tz_map,
            "error": error,
            "user": user,
            "message": request.query_params.get("message"),
            "issued_token": request.query_params.get("issued_token"),
        },
    )


@router.post("/tenants/{tenant_id}/collectors/enrollment", response_model=None)
async def tenant_collector_enrollment_create(
    request: Request,
    tenant_id: int,
    site_id: str | None = Form(None),
    ttl_minutes: str | None = Form(None),
) -> WebResponse:
    user = require_tenant_role(request, tenant_id, UserRole.user_admin)
    if not isinstance(user, User):
        return user
    wants_json = _wants_json(request)
    if ttl_minutes is None:
        try:
            payload = await request.json()
            site_id = (
                str(payload.get("site_id"))
                if payload and payload.get("site_id") is not None
                else site_id
            )
            ttl_minutes = (
                str(payload.get("ttl_minutes"))
                if payload and payload.get("ttl_minutes") is not None
                else ttl_minutes
            )
        except (JSONDecodeError, ValueError, TypeError):
            ttl_minutes = None
    try:
        ttl_value = int(ttl_minutes) if ttl_minutes else 30
    except ValueError:
        ttl_value = 30
    if ttl_value <= 0 or ttl_value > 1440:
        if wants_json:
            return JSONResponse(
                {"error": "ttl_minutes must be between 1 and 1440"}, status_code=400
            )
        return _redirect_with_message(
            f"/tenants/{tenant_id}/collectors/enrollment",
            "ttl_minutes must be between 1 and 1440",
        )
    token_value = secrets.token_urlsafe(32)
    token_hash = hash_token(token_value)
    parsed_site_id = int(site_id) if site_id else None
    expires_at = datetime.now(UTC) + timedelta(minutes=ttl_value)
    with get_session() as session:
        entry = CollectorEnrollmentToken(
            tenant_id=tenant_id,
            site_id=parsed_site_id,
            token_hash=token_hash,
            expires_at=expires_at,
            created_by_user_id=user.id,
        )
        session.add(entry)
        session.flush()
        log_security_event(
            action="collector.enrollment_token.create",
            outcome="success",
            actor_user_id=user.id,
            details={
                "tenant_id": tenant_id,
                "site_id": parsed_site_id,
                "ttl_minutes": ttl_value,
            },
            session=session,
        )
        log_audit(
            actor_user_id=user.id,
            action="collector.enrollment.create",
            entity_type="collector_enrollment_token",
            entity_id=entry.id,
            details={"site_id": parsed_site_id, "expires_at": _format_dt(expires_at)},
            session=session,
        )
    if wants_json:
        return JSONResponse(
            {
                "status": "created",
                "token": token_value,
                "expires_at": _format_dt(expires_at),
            }
        )
    return RedirectResponse(
        url=f"/tenants/{tenant_id}/collectors/enrollment?issued_token={token_value}",
        status_code=302,
    )


@router.get("/tenants/{tenant_id}/collectors", response_class=HTMLResponse)
def tenant_collectors(request: Request, tenant_id: int) -> WebResponse:
    user = require_tenant_role(request, tenant_id, UserRole.user_admin)
    if not isinstance(user, User):
        return user

    def fetch_collectors() -> Iterable[Collector]:
        with get_session() as session:
            query = session.query(Collector).filter(Collector.tenant_id == tenant_id)
            status_filter = request.query_params.get("status")
            site_filter = request.query_params.get("site_id")
            if status_filter:
                query = query.filter(Collector.status == status_filter)
            if site_filter:
                try:
                    query = query.filter(Collector.site_id == int(site_filter))
                except ValueError:
                    pass
            query = query.order_by(Collector.name)
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

    collectors, error = _safe_query(fetch_collectors)
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
                "collectors": [
                    {
                        "id": collector.id,
                        "uuid": collector.uuid,
                        "name": collector.name,
                        "status": collector.status,
                        "site_id": collector.site_id,
                        "site_name": site_map.get(collector.site_id),
                        "site_timezone": site_tz_map.get(collector.site_id),
                        "capabilities": collector.capabilities,
                        "labels": collector.labels,
                        "last_seen_utc": _format_dt(collector.last_seen_utc),
                        "clock_skew_seconds": collector.clock_skew_seconds,
                        "cert_serial": collector.cert_serial,
                        "cert_fingerprint": collector.cert_fingerprint,
                        "cert_valid_to": _format_dt(collector.cert_valid_to),
                    }
                    for collector in collectors
                ],
                "error": error,
                "limit": limit,
                "offset": offset,
            }
        )
    return templates.TemplateResponse(
        "tenant_collectors.html",
        {
            "request": request,
            "tenant_id": tenant_id,
            "tenant_name": tenant.name if tenant else None,
            "collectors": collectors,
            "sites": sites,
            "site_map": site_map,
            "site_tz_map": site_tz_map,
            "error": error,
            "user": user,
            "message": request.query_params.get("message"),
        },
    )


@router.get(
    "/tenants/{tenant_id}/collectors/{collector_id}", response_class=HTMLResponse
)
def tenant_collector_detail(
    request: Request, tenant_id: int, collector_id: int
) -> WebResponse:
    user = require_tenant_role(request, tenant_id, UserRole.user_admin)
    if not isinstance(user, User):
        return user

    def fetch_collector() -> Iterable[Collector]:
        with get_session() as session:
            return (
                session.query(Collector)
                .filter(Collector.id == collector_id, Collector.tenant_id == tenant_id)
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

    collectors, error = _safe_query(fetch_collector)
    collector = collectors[0] if collectors else None
    sites, _ = _safe_query(fetch_sites)
    tenants, _ = _safe_query(fetch_tenant)
    tenant = tenants[0] if tenants else None
    site_map = {site.id: site.name for site in sites}
    site_tz_map = {site.id: site.timezone for site in sites}
    if _wants_json(request):
        if not collector:
            return JSONResponse({"error": "Collector not found"}, status_code=404)
        return JSONResponse(
            {
                "tenant_id": tenant_id,
                "tenant_name": tenant.name if tenant else None,
                "collector": {
                    "id": collector.id,
                    "uuid": collector.uuid,
                    "name": collector.name,
                    "status": collector.status,
                    "site_id": collector.site_id,
                    "site_name": site_map.get(collector.site_id),
                    "site_timezone": site_tz_map.get(collector.site_id),
                    "capabilities": collector.capabilities,
                    "labels": collector.labels,
                    "allowed_scopes": collector.allowed_scopes,
                    "last_seen_utc": _format_dt(collector.last_seen_utc),
                    "clock_skew_seconds": collector.clock_skew_seconds,
                    "cert_serial": collector.cert_serial,
                    "cert_fingerprint": collector.cert_fingerprint,
                    "cert_valid_to": _format_dt(collector.cert_valid_to),
                },
                "error": error,
            }
        )
    return templates.TemplateResponse(
        "tenant_collector_detail.html",
        {
            "request": request,
            "tenant_id": tenant_id,
            "tenant_name": tenant.name if tenant else None,
            "collector": collector,
            "sites": sites,
            "site_map": site_map,
            "site_tz_map": site_tz_map,
            "error": error,
            "user": user,
        },
    )


@router.post("/tenants/{tenant_id}/collectors/{collector_id}", response_model=None)
async def tenant_collector_update(
    request: Request,
    tenant_id: int,
    collector_id: int,
    name: str | None = Form(None),
    status: str | None = Form(None),
    site_id: str | None = Form(None),
    labels: str | None = Form(None),
    capabilities: str | None = Form(None),
    allowed_scopes: str | None = Form(None),
) -> WebResponse:
    user = require_tenant_role(request, tenant_id, UserRole.user_admin)
    if not isinstance(user, User):
        return user
    wants_json = _wants_json(request)
    if (
        not name
        and not status
        and not site_id
        and not labels
        and not capabilities
        and not allowed_scopes
    ):
        try:
            payload = await request.json()
            name = payload.get("name") if payload else name
            status = payload.get("status") if payload else status
            site_id = (
                str(payload.get("site_id"))
                if payload and payload.get("site_id") is not None
                else site_id
            )
            labels = payload.get("labels") if payload else labels
            capabilities = payload.get("capabilities") if payload else capabilities
            allowed_scopes = (
                payload.get("allowed_scopes") if payload else allowed_scopes
            )
        except (JSONDecodeError, ValueError, TypeError):
            pass
    parsed_site_id = int(site_id) if site_id else None
    with get_session() as session:
        collector = (
            session.query(Collector)
            .filter(Collector.id == collector_id, Collector.tenant_id == tenant_id)
            .one_or_none()
        )
        if not collector:
            if wants_json:
                return JSONResponse({"error": "Collector not found"}, status_code=404)
            return _redirect_with_message(
                f"/tenants/{tenant_id}/collectors",
                "Collector not found",
            )
        if name:
            collector.name = name.strip()
        if status:
            collector.status = status.strip()
        if site_id is not None:
            collector.site_id = parsed_site_id
        if labels is not None:
            collector.labels = _parse_labels_value(labels)
        if capabilities is not None:
            collector.capabilities = _parse_capabilities_value(capabilities)
        if allowed_scopes is not None:
            collector.allowed_scopes = _parse_scopes_value(allowed_scopes)
        log_security_event(
            action="collector.update",
            outcome="success",
            actor_user_id=user.id,
            details={
                "collector_id": collector.id,
                "tenant_id": tenant_id,
                "status": collector.status,
            },
            session=session,
        )
        log_audit(
            actor_user_id=user.id,
            action="collector.update",
            entity_type="collector",
            entity_id=collector.id,
            details={"status": collector.status, "site_id": collector.site_id},
            session=session,
        )
    if wants_json:
        return JSONResponse({"status": "updated", "collector_id": collector_id})
    return _redirect_with_message(
        f"/tenants/{tenant_id}/collectors",
        "Collector updated",
    )
