from __future__ import annotations

from typing import Any, Callable, Iterable, Optional, Sequence
import json
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from urllib.parse import quote_plus

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import joinedload

from central.core.audit import log_audit
from central.core.auth import highest_role
from central.db.models import (
    AuditLog,
    Collector,
    CollectorEnrollmentToken,
    ExportSchedule,
    InventoryDevice,
    Network,
    ScanSchedule,
    ScanScheduleType,
    Site,
    Tenant,
    TenantUser,
    User,
)
from central.db.session import get_session
from central.core.config import settings
from central.web.auth import (
    allow_collector_token,
    authenticate,
    hash_password,
    login_user,
    logout_user,
    require_superadmin,
    require_tenant_role,
    require_user,
)
from central.web.oidc import get_oauth, oidc_enabled
from central.db.models import UserRole

templates = Jinja2Templates(directory="central/web/templates")
router = APIRouter()


def _safe_query(fetch: Callable[[], Iterable[Any]]) -> tuple[list[Any], Optional[str]]:
    try:
        return list(fetch()), None
    except Exception as exc:  # pragma: no cover - guard for missing migrations
        return [], str(exc)


def _wants_json(request: Request) -> bool:
    return "application/json" in request.headers.get("accept", "")


def _format_dt(value: Any) -> str | None:
    if not value:
        return None
    utc_value = value.astimezone(timezone.utc)
    return utc_value.isoformat().replace("+00:00", "Z")


def _parse_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]



def _is_valid_timezone(value: str) -> bool:
    banned = {"CET", "CEST", "EST", "EDT", "PST", "PDT", "CST", "CDT", "MST", "MDT", "GMT", "UTC"}
    if value.upper() in banned:
        return False
    try:
        ZoneInfo(value)
    except ZoneInfoNotFoundError:
        return False
    return True


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _pagination_params(request: Request) -> tuple[int, int]:
    limit_param = request.query_params.get("limit")
    offset_param = request.query_params.get("offset")
    try:
        limit = min(int(limit_param), 200) if limit_param else 50
    except ValueError:
        limit = 50
    try:
        offset = max(int(offset_param), 0) if offset_param else 0
    except ValueError:
        offset = 0
    return limit, offset


def _paginate_query(query, request: Request):
    limit, offset = _pagination_params(request)
    return query.limit(limit).offset(offset), limit, offset


def _paginate_list(items: Sequence[Any], request: Request) -> list[Any]:
    limit, offset = _pagination_params(request)
    return list(items[offset : offset + limit])


def _redirect_with_message(url: str, message: str) -> RedirectResponse:
    return RedirectResponse(url=f"{url}?message={quote_plus(message)}", status_code=302)


@router.get("/", response_class=HTMLResponse)
def home(request: Request) -> HTMLResponse:
    user = require_user(request)
    if isinstance(user, RedirectResponse):
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
    except Exception as exc:  # pragma: no cover - guard for missing migrations
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


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request) -> HTMLResponse:
    if oidc_enabled():
        oauth = get_oauth()
        return oauth.okta.authorize_redirect(request, settings.oidc_redirect_uri)
    return templates.TemplateResponse(
        "login.html", {"request": request, "auth_mode": settings.auth_mode}
    )


@router.post("/login", response_class=HTMLResponse)
def login_submit(request: Request, email: str = Form(...), password: str = Form(...)) -> HTMLResponse:
    if oidc_enabled():
        return HTMLResponse(content="OIDC login enabled", status_code=400)
    user = authenticate(email, password)
    if not user:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid credentials"},
            status_code=401,
        )
    login_user(request, user)
    return RedirectResponse(url="/", status_code=302)


@router.post("/logout")
def logout(request: Request) -> RedirectResponse:
    oidc_logout_url = settings.oidc_logout_url
    id_token = request.session.get("id_token")
    logout_user(request)
    if oidc_logout_url and id_token:
        redirect_url = f"{oidc_logout_url}?id_token_hint={id_token}&post_logout_redirect_uri={settings.oidc_redirect_uri}"
        return RedirectResponse(url=redirect_url, status_code=302)
    return RedirectResponse(url="/login", status_code=302)


@router.get("/tenants", response_class=HTMLResponse)
def tenant_list(request: Request) -> HTMLResponse:
    user = require_user(request)
    if isinstance(user, RedirectResponse):
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


@router.get("/tenants/{tenant_id}/users", response_class=HTMLResponse)
def tenant_users(request: Request, tenant_id: int) -> HTMLResponse:
    user = require_tenant_role(request, tenant_id, UserRole.user_admin)
    if not isinstance(user, User):
        return user

    def fetch() -> Iterable[TenantUser]:
        with get_session() as session:
            query = (
                session.query(TenantUser)
                .options(joinedload(TenantUser.user))
                .join(User)
                .filter(TenantUser.tenant_id == tenant_id)
            )
            email_filter = request.query_params.get("email")
            role_filter = request.query_params.get("role")
            if email_filter:
                query = query.filter(User.email.ilike(f"%{email_filter}%"))
            if role_filter:
                query = query.filter(
                    (TenantUser.roles.ilike(f"%{role_filter}%"))
                    | (TenantUser.role == role_filter)
                )
            query = query.order_by(User.email)
            query, _, _ = _paginate_query(query, request)
            return query.all()

    def fetch_tenant() -> Iterable[Tenant]:
        with get_session() as session:
            return session.query(Tenant).filter(Tenant.id == tenant_id).all()

    memberships, error = _safe_query(fetch)
    tenants, _ = _safe_query(fetch_tenant)
    tenant = tenants[0] if tenants else None
    if _wants_json(request):
        limit, offset = _pagination_params(request)
        return JSONResponse(
            {
                "tenant_id": tenant_id,
                "tenant_name": tenant.name if tenant else None,
                "memberships": [
                    {
                        "id": membership.id,
                        "user_id": membership.user_id,
                        "email": membership.user.email,
                        "full_name": membership.user.full_name,
                        "display_name": membership.user.full_name or membership.user.email,
                        "roles": membership.roles.split(",")
                        if membership.roles
                        else [membership.role.value],
                    }
                    for membership in memberships
                ],
                "error": error,
                "limit": limit,
                "offset": offset,
            }
        )
    return templates.TemplateResponse(
        "tenant_users.html",
        {
            "request": request,
            "memberships": memberships,
            "tenant_id": tenant_id,
            "tenant_name": tenant.name if tenant else None,
            "error": error,
            "user": user,
            "message": request.query_params.get("message"),
        },
    )


@router.get("/tenants/{tenant_id}/sites", response_class=HTMLResponse)
def tenant_sites(request: Request, tenant_id: int) -> HTMLResponse:
    user = require_tenant_role(request, tenant_id, UserRole.read_only)
    if not isinstance(user, User):
        return user

    def fetch() -> Iterable[Site]:
        with get_session() as session:
            query = session.query(Site).filter(Site.tenant_id == tenant_id)
            name_filter = request.query_params.get("name")
            code_filter = request.query_params.get("code")
            if name_filter:
                query = query.filter(Site.name.ilike(f"%{name_filter}%"))
            if code_filter:
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
):
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
        except Exception:
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
        return JSONResponse({"status": "created", "site_id": site.id, "name": site.name})
    return _redirect_with_message(
        f"/tenants/{tenant_id}/sites",
        f"Site {name} created",
    )


@router.get("/tenants/{tenant_id}/sites/{site_id}", response_class=HTMLResponse)
def tenant_site_edit(request: Request, tenant_id: int, site_id: int) -> HTMLResponse:
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
):
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
        except Exception:
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
        return JSONResponse({"status": "updated", "site_id": site.id, "name": site.name})
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
):
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


@router.get("/tenants/{tenant_id}/networks", response_class=HTMLResponse)
def tenant_networks(request: Request, tenant_id: int) -> HTMLResponse:
    user = require_tenant_role(request, tenant_id, UserRole.read_only)
    if not isinstance(user, User):
        return user

    def fetch() -> Iterable[Network]:
        with get_session() as session:
            query = session.query(Network).filter(Network.tenant_id == tenant_id)
            name_filter = request.query_params.get("name")
            cidr_filter = request.query_params.get("cidr")
            site_filter = request.query_params.get("site_id")
            if name_filter:
                query = query.filter(Network.name.ilike(f"%{name_filter}%"))
            if cidr_filter:
                query = query.filter(Network.cidr.ilike(f"%{cidr_filter}%"))
            if site_filter:
                try:
                    query = query.filter(Network.site_id == int(site_filter))
                except ValueError:
                    pass
            query = query.order_by(Network.name)
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

    networks, error = _safe_query(fetch)
    sites, _ = _safe_query(fetch_sites)
    site_map = {site.id: site.name for site in sites}
    def fetch_tenant() -> Iterable[Tenant]:
        with get_session() as session:
            return session.query(Tenant).filter(Tenant.id == tenant_id).all()
    tenants, _ = _safe_query(fetch_tenant)
    tenant = tenants[0] if tenants else None
    if _wants_json(request):
        limit, offset = _pagination_params(request)
        return JSONResponse(
            {
                "tenant_id": tenant_id,
                "tenant_name": tenant.name if tenant else None,
                "networks": [
                    {
                        "id": network.id,
                        "name": network.name,
                        "cidr": network.cidr,
                        "site_id": network.site_id,
                        "site_name": site_map.get(network.site_id),
                        "description": network.description,
                        "created_at": _format_dt(network.created_at),
                    }
                    for network in networks
                ],
                "sites": [
                    {"id": site.id, "name": site.name} for site in sites
                ],
                "error": error,
                "limit": limit,
                "offset": offset,
            }
        )
    return templates.TemplateResponse(
        "tenant_networks.html",
        {
            "request": request,
            "networks": networks,
            "sites": sites,
            "site_map": site_map,
            "tenant_id": tenant_id,
            "tenant_name": tenant.name if tenant else None,
            "error": error,
            "user": user,
            "message": request.query_params.get("message"),
        },
    )


@router.post("/tenants/{tenant_id}/networks", response_model=None)
async def tenant_network_create(
    request: Request,
    tenant_id: int,
    name: str | None = Form(None),
    cidr: str | None = Form(None),
    site_id: str | None = Form(None),
    description: str | None = Form(None),
):
    user = require_tenant_role(request, tenant_id, UserRole.read_write)
    if not isinstance(user, User):
        return user
    wants_json = "application/json" in request.headers.get("accept", "")
    if not name or not cidr:
        try:
            payload = await request.json()
            name = payload.get("name") if payload else name
            cidr = payload.get("cidr") if payload else cidr
            site_id = str(payload.get("site_id")) if payload and payload.get("site_id") is not None else site_id
            description = payload.get("description") if payload else description
        except Exception:
            name = name
    if not name or not cidr:
        if wants_json:
            return JSONResponse({"error": "Name and CIDR are required"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/networks",
            "Name and CIDR are required",
        )
    parsed_site_id = int(site_id) if site_id else None
    with get_session() as session:
        network = Network(
            tenant_id=tenant_id,
            site_id=parsed_site_id,
            name=name.strip(),
            cidr=cidr.strip(),
            description=(description or "").strip() or None,
        )
        session.add(network)
        session.flush()
        log_audit(
            actor_user_id=user.id,
            action="tenant.network.create",
            entity_type="network",
            entity_id=network.id,
            details={"name": network.name, "cidr": network.cidr},
            session=session,
        )
    if wants_json:
        return JSONResponse(
            {
                "status": "created",
                "network_id": network.id,
                "name": network.name,
            }
        )
    return _redirect_with_message(
        f"/tenants/{tenant_id}/networks",
        f"Network {name} created",
    )


@router.get("/tenants/{tenant_id}/networks/{network_id}", response_class=HTMLResponse)
def tenant_network_edit(
    request: Request, tenant_id: int, network_id: int
) -> HTMLResponse:
    user = require_tenant_role(request, tenant_id, UserRole.read_write)
    if not isinstance(user, User):
        return user

    def fetch() -> Iterable[Network]:
        with get_session() as session:
            return (
                session.query(Network)
                .filter(Network.id == network_id, Network.tenant_id == tenant_id)
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

    networks, error = _safe_query(fetch)
    sites, _ = _safe_query(fetch_sites)
    network = networks[0] if networks else None
    def fetch_tenant() -> Iterable[Tenant]:
        with get_session() as session:
            return session.query(Tenant).filter(Tenant.id == tenant_id).all()
    tenants, _ = _safe_query(fetch_tenant)
    tenant = tenants[0] if tenants else None
    if _wants_json(request):
        if not network:
            return JSONResponse({"error": "Network not found"}, status_code=404)
        return JSONResponse(
            {
                "tenant_id": tenant_id,
                "tenant_name": tenant.name if tenant else None,
                "network": {
                    "id": network.id,
                    "name": network.name,
                    "cidr": network.cidr,
                    "site_id": network.site_id,
                    "description": network.description,
                    "created_at": _format_dt(network.created_at),
                },
                "sites": [{"id": site.id, "name": site.name} for site in sites],
                "error": error,
            }
        )
    return templates.TemplateResponse(
        "tenant_network_edit.html",
        {
            "request": request,
            "network": network,
            "sites": sites,
            "tenant_id": tenant_id,
            "tenant_name": tenant.name if tenant else None,
            "error": error,
            "user": user,
        },
    )


@router.post("/tenants/{tenant_id}/networks/{network_id}", response_model=None)
async def tenant_network_update(
    request: Request,
    tenant_id: int,
    network_id: int,
    name: str | None = Form(None),
    cidr: str | None = Form(None),
    site_id: str | None = Form(None),
    description: str | None = Form(None),
):
    user = require_tenant_role(request, tenant_id, UserRole.read_write)
    if not isinstance(user, User):
        return user
    wants_json = "application/json" in request.headers.get("accept", "")
    if not name or not cidr:
        try:
            payload = await request.json()
            name = payload.get("name") if payload else name
            cidr = payload.get("cidr") if payload else cidr
            site_id = str(payload.get("site_id")) if payload and payload.get("site_id") is not None else site_id
            description = payload.get("description") if payload else description
        except Exception:
            name = name
    if not name or not cidr:
        if wants_json:
            return JSONResponse({"error": "Name and CIDR are required"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/networks",
            "Name and CIDR are required",
        )
    parsed_site_id = int(site_id) if site_id else None
    with get_session() as session:
        network = (
            session.query(Network)
            .filter(Network.id == network_id, Network.tenant_id == tenant_id)
            .one_or_none()
        )
        if not network:
            if wants_json:
                return JSONResponse({"error": "Network not found"}, status_code=404)
            return _redirect_with_message(
                f"/tenants/{tenant_id}/networks",
                "Network not found",
            )
        network.name = name.strip()
        network.cidr = cidr.strip()
        network.site_id = parsed_site_id
        network.description = (description or "").strip() or None
        log_audit(
            actor_user_id=user.id,
            action="tenant.network.update",
            entity_type="network",
            entity_id=network.id,
            details={"name": network.name, "cidr": network.cidr},
            session=session,
        )
    if wants_json:
        return JSONResponse(
            {
                "status": "updated",
                "network_id": network.id,
                "name": network.name,
            }
        )
    return _redirect_with_message(
        f"/tenants/{tenant_id}/networks",
        f"Network {name} updated",
    )


@router.post("/tenants/{tenant_id}/networks/{network_id}/delete", response_model=None)
def tenant_network_delete(
    request: Request,
    tenant_id: int,
    network_id: int,
    confirm_name: str = Form(...),
):
    user = require_tenant_role(request, tenant_id, UserRole.read_write)
    if not isinstance(user, User):
        return user
    wants_json = "application/json" in request.headers.get("accept", "")
    with get_session() as session:
        network = (
            session.query(Network)
            .filter(Network.id == network_id, Network.tenant_id == tenant_id)
            .one_or_none()
        )
        if not network:
            if wants_json:
                return JSONResponse({"error": "Network not found"}, status_code=404)
            return _redirect_with_message(
                f"/tenants/{tenant_id}/networks",
                "Network not found",
            )
        if confirm_name.strip() != network.name:
            if wants_json:
                return JSONResponse(
                    {"error": "Network name confirmation does not match"},
                    status_code=400,
                )
            return _redirect_with_message(
                f"/tenants/{tenant_id}/networks",
                "Network name confirmation does not match",
            )
        session.delete(network)
        log_audit(
            actor_user_id=user.id,
            action="tenant.network.delete",
            entity_type="network",
            entity_id=network_id,
            details={"name": network.name, "cidr": network.cidr},
            session=session,
        )
    if wants_json:
        return JSONResponse({"status": "deleted", "network_id": network_id})
    return _redirect_with_message(
        f"/tenants/{tenant_id}/networks",
        "Network deleted",
    )


@router.get("/tenants/{tenant_id}/schedules", response_class=HTMLResponse)
def tenant_schedules(request: Request, tenant_id: int) -> HTMLResponse:
    user = require_tenant_role(request, tenant_id, UserRole.read_only)
    if not isinstance(user, User):
        return user

    def fetch_schedules() -> Iterable[ScanSchedule]:
        with get_session() as session:
            query = session.query(ScanSchedule).filter(ScanSchedule.tenant_id == tenant_id)
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
                query = query.filter(ScanSchedule.scan_types.ilike(f"%{scan_type_filter}%"))
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


@router.get("/tenants/{tenant_id}/collectors/enrollment", response_class=HTMLResponse)
def tenant_collector_enrollment(request: Request, tenant_id: int) -> HTMLResponse:
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
                    query = query.filter(CollectorEnrollmentToken.site_id == int(site_filter))
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
):
    user = require_tenant_role(request, tenant_id, UserRole.user_admin)
    if not isinstance(user, User):
        return user
    wants_json = _wants_json(request)
    if ttl_minutes is None:
        try:
            payload = await request.json()
            site_id = str(payload.get("site_id")) if payload and payload.get("site_id") is not None else site_id
            ttl_minutes = str(payload.get("ttl_minutes")) if payload and payload.get("ttl_minutes") is not None else ttl_minutes
        except Exception:
            ttl_minutes = None
    try:
        ttl_value = int(ttl_minutes) if ttl_minutes else 30
    except ValueError:
        ttl_value = 30
    if ttl_value <= 0 or ttl_value > 1440:
        if wants_json:
            return JSONResponse({"error": "ttl_minutes must be between 1 and 1440"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/collectors/enrollment",
            "ttl_minutes must be between 1 and 1440",
        )
    token_value = secrets.token_urlsafe(32)
    token_hash = _hash_token(token_value)
    parsed_site_id = int(site_id) if site_id else None
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=ttl_value)
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
def tenant_collectors(request: Request, tenant_id: int) -> HTMLResponse:
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


@router.get("/tenants/{tenant_id}/collectors/{collector_id}", response_class=HTMLResponse)
def tenant_collector_detail(
    request: Request, tenant_id: int, collector_id: int
) -> HTMLResponse:
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
):
    user = require_tenant_role(request, tenant_id, UserRole.user_admin)
    if not isinstance(user, User):
        return user
    wants_json = _wants_json(request)
    if not name and not status and not site_id and not labels and not capabilities and not allowed_scopes:
        try:
            payload = await request.json()
            name = payload.get("name") if payload else name
            status = payload.get("status") if payload else status
            site_id = str(payload.get("site_id")) if payload and payload.get("site_id") is not None else site_id
            labels = payload.get("labels") if payload else labels
            capabilities = payload.get("capabilities") if payload else capabilities
            allowed_scopes = payload.get("allowed_scopes") if payload else allowed_scopes
        except Exception:
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
            collector.labels = labels.strip() or None
        if capabilities is not None:
            collector.capabilities = capabilities.strip() or None
        if allowed_scopes is not None:
            collector.allowed_scopes = allowed_scopes.strip() or None
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
):
    user = require_tenant_role(request, tenant_id, UserRole.read_write)
    if not isinstance(user, User):
        return user

    wants_json = _wants_json(request)
    payload = None
    if not start_date or not start_time:
        try:
            payload = await request.json()
        except Exception:
            payload = None
    if payload:
        name = payload.get("name") if payload else name
        start_at = payload.get("start_at")
        site_id = str(payload.get("site_id")) if payload and payload.get("site_id") is not None else site_id
        network_ids = payload.get("network_ids") if payload else network_ids
        scan_types = payload.get("scan_types") if payload else scan_types
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
            return JSONResponse({"error": "Start date/time is required"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/schedules",
            "Start date/time is required",
        )
    if start_at_dt.tzinfo is None:
        start_at_dt = start_at_dt.replace(tzinfo=timezone.utc)
    else:
        start_at_dt = start_at_dt.astimezone(timezone.utc)

    if not scan_types:
        if wants_json:
            return JSONResponse({"error": "Select at least one scan type"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/schedules",
            "Select at least one scan type",
        )

    if not network_ids:
        if wants_json:
            return JSONResponse({"error": "Select at least one network"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/schedules",
            "Select at least one network",
        )

    parsed_site_id = int(site_id) if site_id else None
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
                )
            )
        log_audit(
            actor_user_id=user.id,
            action="tenant.schedule.create",
            entity_type="scan_schedule",
            entity_id=schedule.id,
            details={"name": schedule.name, "scheduled_at_utc": _format_dt(schedule.scheduled_at_utc)},
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
) -> HTMLResponse:
    user = require_tenant_role(request, tenant_id, UserRole.read_only)
    if not isinstance(user, User):
        return user

    def fetch_schedule() -> Iterable[ScanSchedule]:
        with get_session() as session:
            return (
                session.query(ScanSchedule)
                .filter(ScanSchedule.id == schedule_id, ScanSchedule.tenant_id == tenant_id)
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


@router.get("/tenants/{tenant_id}/exports", response_class=HTMLResponse)
def tenant_exports(request: Request, tenant_id: int) -> HTMLResponse:
    user = require_tenant_role(request, tenant_id, UserRole.read_only)
    if not isinstance(user, User):
        return user

    def fetch_exports() -> Iterable[ExportSchedule]:
        with get_session() as session:
            query = session.query(ExportSchedule).filter(ExportSchedule.tenant_id == tenant_id)
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
):
    user = require_tenant_role(request, tenant_id, UserRole.read_write)
    if not isinstance(user, User):
        return user
    wants_json = _wants_json(request)
    payload = None
    if not start_date or not start_time:
        try:
            payload = await request.json()
        except Exception:
            payload = None
    if payload:
        name = payload.get("name") if payload else name
        start_at = payload.get("start_at")
        site_id = str(payload.get("site_id")) if payload and payload.get("site_id") is not None else site_id
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
            return JSONResponse({"error": "Start date/time is required"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/exports",
            "Start date/time is required",
        )
    if start_at_dt.tzinfo is None:
        start_at_dt = start_at_dt.replace(tzinfo=timezone.utc)
    else:
        start_at_dt = start_at_dt.astimezone(timezone.utc)

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
            actor_user_id=user.id,
            action="tenant.export.schedule.create",
            entity_type="export_schedule",
            entity_id=schedule.id,
            details={"exporter": exporter, "scheduled_at_utc": _format_dt(schedule.scheduled_at_utc)},
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
):
    user = require_tenant_role(request, tenant_id, UserRole.read_write)
    if not isinstance(user, User):
        return user
    wants_json = _wants_json(request)
    if not exporter:
        try:
            payload = await request.json()
            exporter = payload.get("exporter") if payload else None
            export_schedule_id = payload.get("export_schedule_id") if payload else export_schedule_id
            site_id = payload.get("site_id") if payload else site_id
            settings_json = payload.get("settings_json") if payload else settings_json
            if isinstance(payload, dict) and payload.get("settings"):
                settings_json = json.dumps(payload.get("settings"))
        except Exception:
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
        "requested_by_user_id": user.id,
    }
    from central.workers.exports import export_inventory_task

    export_inventory_task.delay(exporter, payload, parsed_settings, None)
    with get_session() as session:
        log_audit(
            actor_user_id=user.id,
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


@router.post("/tenants/{tenant_id}/schedules/{schedule_id}/status", response_model=None)
async def tenant_schedule_update_status(
    request: Request,
    tenant_id: int,
    schedule_id: int,
    actual_start_at_utc: str | None = Form(None),
    finished_at_utc: str | None = Form(None),
):
    user = None
    if not allow_collector_token(request):
        user = require_tenant_role(request, tenant_id, UserRole.read_write)
        if not isinstance(user, User):
            return user
    wants_json = _wants_json(request)
    if not actual_start_at_utc and not finished_at_utc:
        try:
            payload = await request.json()
            actual_start_at_utc = (
                payload.get("actual_start_at_utc") if payload else None
            ) or (payload.get("actual_start_at") if payload else None)
            finished_at_utc = (
                payload.get("finished_at_utc") if payload else None
            ) or (payload.get("finished_at") if payload else None)
        except Exception:
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
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    actual_dt = parse_dt(actual_start_at_utc)
    finished_dt = parse_dt(finished_at_utc)
    if actual_start_at_utc and actual_dt is None:
        if wants_json:
            return JSONResponse({"error": "Invalid actual_start_at_utc"}, status_code=400)
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
                "actual_start_at_utc": _format_dt(actual_dt or schedule.actual_start_at_utc),
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
):
    user = None
    if not allow_collector_token(request):
        user = require_tenant_role(request, tenant_id, UserRole.read_write)
        if not isinstance(user, User):
            return user
    wants_json = _wants_json(request)
    if not actual_start_at_utc and not finished_at_utc:
        try:
            payload = await request.json()
            actual_start_at_utc = (
                payload.get("actual_start_at_utc") if payload else None
            ) or (payload.get("actual_start_at") if payload else None)
            finished_at_utc = (
                payload.get("finished_at_utc") if payload else None
            ) or (payload.get("finished_at") if payload else None)
        except Exception:
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
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    actual_dt = parse_dt(actual_start_at_utc)
    finished_dt = parse_dt(finished_at_utc)
    if actual_start_at_utc and actual_dt is None:
        if wants_json:
            return JSONResponse({"error": "Invalid actual_start_at_utc"}, status_code=400)
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
                return JSONResponse({"error": "Scan type entry not found"}, status_code=404)
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
                "actual_start_at_utc": _format_dt(actual_dt or entry.actual_start_at_utc),
                "finished_at_utc": _format_dt(finished_dt or entry.finished_at_utc),
            }
        )
    return _redirect_with_message(
        f"/tenants/{tenant_id}/schedules/{schedule_id}",
        "Scan type updated",
    )

@router.post("/tenants/{tenant_id}/users", response_model=None)
async def tenant_user_add(
    request: Request,
    tenant_id: int,
    email: str | None = Form(None),
    full_name: str | None = Form(None),
    password: str | None = Form(None),
    roles: list[str] = Form(None),
):
    user = require_tenant_role(request, tenant_id, UserRole.user_admin)
    if not isinstance(user, User):
        return user

    wants_json = "application/json" in request.headers.get("accept", "")
    if not email:
        try:
            payload = await request.json()
            email = payload.get("email") if payload else None
            full_name = payload.get("full_name") if payload else full_name
            password = payload.get("password") if payload else password
            roles = payload.get("roles") if payload else roles
        except Exception:
            email = None
    if not email:
        if wants_json:
            return JSONResponse({"error": "Email is required"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/users",
            "Email is required",
        )
    if not roles:
        if wants_json:
            return JSONResponse({"error": "Select at least one role"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/users",
            "Select at least one role",
        )

    role_set = set()
    for item in roles:
        try:
            role_set.add(UserRole(item))
        except ValueError:
            continue
    if not role_set:
        if wants_json:
            return JSONResponse({"error": "Invalid role selection"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/users",
            "Invalid role selection",
        )

    with get_session() as session:
        account = session.query(User).filter(User.email == email).one_or_none()
        if not account:
            if not password and not oidc_enabled():
                if wants_json:
                    return JSONResponse(
                        {"error": "Password required for new users"}, status_code=400
                    )
                return _redirect_with_message(
                    f"/tenants/{tenant_id}/users",
                    "Password required for new users",
                )
            account = User(
                email=email,
                full_name=(full_name or "").strip() or None,
                password_hash=hash_password(password) if password else None,
            )
            session.add(account)
            session.flush()

        membership = (
            session.query(TenantUser)
            .filter(TenantUser.tenant_id == tenant_id, TenantUser.user_id == account.id)
            .one_or_none()
        )
        if membership:
            membership.roles = ",".join(sorted({r.value for r in role_set}))
            membership.role = highest_role(role_set)
        else:
            session.add(
                TenantUser(
                    tenant_id=tenant_id,
                    user_id=account.id,
                    role=highest_role(role_set),
                    roles=",".join(sorted({r.value for r in role_set})),
                )
            )
        log_audit(
            actor_user_id=user.id,
            action="tenant.user.add",
            entity_type="tenant",
            entity_id=tenant_id,
            details={"user": account.email, "roles": sorted([r.value for r in role_set])},
            session=session,
        )
    if wants_json:
        return JSONResponse(
            {
                "status": "updated",
                "email": account.email,
                "roles": sorted([r.value for r in role_set]),
            }
        )
    return _redirect_with_message(
        f"/tenants/{tenant_id}/users",
        f"User {email} added or updated",
    )


@router.post("/tenants/{tenant_id}/users/{membership_id}/role", response_model=None)
async def tenant_user_update_role(
    request: Request, tenant_id: int, membership_id: int, roles: list[str] = Form(None)
):
    user = require_tenant_role(request, tenant_id, UserRole.user_admin)
    if not isinstance(user, User):
        return user

    wants_json = "application/json" in request.headers.get("accept", "")
    if not roles:
        try:
            payload = await request.json()
            roles = payload.get("roles") if payload else roles
        except Exception:
            roles = None
    if not roles:
        if wants_json:
            return JSONResponse({"error": "Select at least one role"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/users",
            "Select at least one role",
        )

    role_set = set()
    for item in roles:
        try:
            role_set.add(UserRole(item))
        except ValueError:
            continue
    if not role_set:
        if wants_json:
            return JSONResponse({"error": "Invalid role selection"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/users",
            "Invalid role selection",
        )

    with get_session() as session:
        membership = (
            session.query(TenantUser)
            .filter(TenantUser.id == membership_id, TenantUser.tenant_id == tenant_id)
            .one_or_none()
        )
        if not membership:
            if wants_json:
                return JSONResponse({"error": "Membership not found"}, status_code=404)
            return _redirect_with_message(
                f"/tenants/{tenant_id}/users",
                "Membership not found",
            )
        membership.roles = ",".join(sorted({r.value for r in role_set}))
        membership.role = highest_role(role_set)
        session.flush()
        log_audit(
            actor_user_id=user.id,
            action="tenant.user.role",
            entity_type="tenant_user",
            entity_id=membership_id,
            details={"roles": sorted([r.value for r in role_set])},
            session=session,
        )
    if wants_json:
        return JSONResponse(
            {
                "status": "updated",
                "membership_id": membership_id,
                "roles": sorted([r.value for r in role_set]),
            }
        )
    return _redirect_with_message(
        f"/tenants/{tenant_id}/users",
        "Role updated",
    )


@router.post("/tenants/{tenant_id}/users/{membership_id}/delete", response_model=None)
def tenant_user_delete(
    request: Request, tenant_id: int, membership_id: int
):
    user = require_tenant_role(request, tenant_id, UserRole.user_admin)
    if not isinstance(user, User):
        return user

    wants_json = "application/json" in request.headers.get("accept", "")
    with get_session() as session:
        membership = (
            session.query(TenantUser)
            .filter(TenantUser.id == membership_id, TenantUser.tenant_id == tenant_id)
            .one_or_none()
        )
        if not membership:
            if wants_json:
                return JSONResponse({"error": "Membership not found"}, status_code=404)
            return _redirect_with_message(
                f"/tenants/{tenant_id}/users",
                "Membership not found",
            )
        session.delete(membership)
        log_audit(
            actor_user_id=user.id,
            action="tenant.user.remove",
            entity_type="tenant_user",
            entity_id=membership_id,
            details={"user_id": membership.user_id},
            session=session,
        )
    if wants_json:
        return JSONResponse({"status": "deleted", "membership_id": membership_id})
    return _redirect_with_message(
        f"/tenants/{tenant_id}/users",
        "User removed from tenant",
    )


@router.post("/tenants/{tenant_id}/users/{membership_id}/password", response_model=None)
async def tenant_user_reset_password(
    request: Request, tenant_id: int, membership_id: int, password: str | None = Form(None)
):
    user = require_tenant_role(request, tenant_id, UserRole.user_admin)
    if not isinstance(user, User):
        return user
    if oidc_enabled():
        return _redirect_with_message(
            f"/tenants/{tenant_id}/users",
            "Password resets are disabled when OIDC is enabled",
        )
    wants_json = "application/json" in request.headers.get("accept", "")
    if not password:
        try:
            payload = await request.json()
            password = payload.get("password") if payload else None
        except Exception:
            password = None
    if not password or not password.strip():
        if wants_json:
            return JSONResponse({"error": "Password cannot be empty"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/users",
            "Password cannot be empty",
        )
    with get_session() as session:
        membership = (
            session.query(TenantUser)
            .options(joinedload(TenantUser.user))
            .filter(TenantUser.id == membership_id, TenantUser.tenant_id == tenant_id)
            .one_or_none()
        )
        if not membership:
            if wants_json:
                return JSONResponse({"error": "Membership not found"}, status_code=404)
            return _redirect_with_message(
                f"/tenants/{tenant_id}/users",
                "Membership not found",
            )
        membership.user.password_hash = hash_password(password)
        log_audit(
            actor_user_id=user.id,
            action="tenant.user.password_reset",
            entity_type="tenant_user",
            entity_id=membership_id,
            details={"user": membership.user.email},
            session=session,
        )
    if wants_json:
        return JSONResponse({"status": "updated", "membership_id": membership_id})
    return _redirect_with_message(
        f"/tenants/{tenant_id}/users",
        "Password reset",
    )


@router.get("/oidc/callback", response_model=None)
async def oidc_callback(request: Request):
    if not oidc_enabled():
        return HTMLResponse(content="OIDC not configured", status_code=400)
    oauth = get_oauth()
    token = await oauth.okta.authorize_access_token(request)
    userinfo = await oauth.okta.userinfo(token=token)
    email = userinfo.get("email")
    if not email:
        return HTMLResponse(content="Email missing from OIDC provider", status_code=400)
    full_name = userinfo.get("name")
    with get_session() as session:
        user = session.query(User).filter(User.email == email).one_or_none()
        if not user:
            user = User(
                email=email,
                full_name=full_name,
                password_hash=None,
            )
            session.add(user)
            session.flush()
    login_user(request, user)
    request.session["id_token"] = token.get("id_token")
    return RedirectResponse(url="/", status_code=302)


@router.get("/admin/tenants", response_class=HTMLResponse)
def admin_tenants(request: Request) -> HTMLResponse:
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


@router.get("/admin/schedules", response_class=HTMLResponse)
def admin_schedules(request: Request) -> HTMLResponse:
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
                query = query.filter(ScanSchedule.scan_types.ilike(f"%{scan_type_filter}%"))
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
                        "site_name": site_map.get(schedule.site_id).name if schedule.site_id in site_map else None,
                        "site_timezone": site_map.get(schedule.site_id).timezone if schedule.site_id in site_map else None,
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


@router.post("/admin/tenants", response_model=None)
async def admin_tenant_create(
    request: Request,
    name: str | None = Form(None),
    description: str | None = Form(None),
    default_scanner: str | None = Form(None),
    default_scan_interval_minutes: str | None = Form(None),
):
    user = require_superadmin(request)
    if not isinstance(user, User):
        return user
    wants_json = "application/json" in request.headers.get("accept", "")
    if not name:
        try:
            payload = await request.json()
            name = payload.get("name") if payload else None
            description = payload.get("description") if payload else description
            default_scanner = payload.get("default_scanner") if payload else default_scanner
            default_scan_interval_minutes = (
                str(payload.get("default_scan_interval_minutes"))
                if payload and payload.get("default_scan_interval_minutes") is not None
                else default_scan_interval_minutes
            )
        except Exception:
            name = None
    if not name:
        if wants_json:
            return JSONResponse({"error": "Name is required"}, status_code=400)
        return RedirectResponse(url="/admin/tenants?message=Name%20is%20required", status_code=302)
    with get_session() as session:
        interval = int(default_scan_interval_minutes) if default_scan_interval_minutes else None
        tenant = Tenant(
            name=name.strip(),
            description=(description or "").strip() or None,
            default_scanner=(default_scanner or "").strip() or None,
            default_scan_interval_minutes=interval,
        )
        session.add(tenant)
        session.flush()
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
def admin_tenant_edit(request: Request, tenant_id: int) -> HTMLResponse:
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
):
    user = require_superadmin(request)
    if not isinstance(user, User):
        return user
    wants_json = "application/json" in request.headers.get("accept", "")
    if not name:
        try:
            payload = await request.json()
            name = payload.get("name") if payload else None
            description = payload.get("description") if payload else description
            default_scanner = payload.get("default_scanner") if payload else default_scanner
            default_scan_interval_minutes = (
                str(payload.get("default_scan_interval_minutes"))
                if payload and payload.get("default_scan_interval_minutes") is not None
                else default_scan_interval_minutes
            )
        except Exception:
            name = None
    if not name:
        if wants_json:
            return JSONResponse({"error": "Name is required"}, status_code=400)
        return RedirectResponse(url="/admin/tenants?message=Name%20is%20required", status_code=302)
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
            int(default_scan_interval_minutes) if default_scan_interval_minutes else None
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
):
    user = require_superadmin(request)
    if not isinstance(user, User):
        return user
    if not confirm_name:
        try:
            payload = await request.json()
            confirm_name = (payload or {}).get("confirm_name")
        except Exception:
            confirm_name = None
    wants_json = "application/json" in request.headers.get("accept", "")
    with get_session() as session:
        tenant = session.query(Tenant).filter(Tenant.id == tenant_id).one_or_none()
        if not tenant:
            if wants_json:
                return JSONResponse({"error": "Tenant not found"}, status_code=404)
            return HTMLResponse(content="Tenant not found", status_code=404)
        if not confirm_name or confirm_name.strip() != tenant.name:
            if wants_json:
                return JSONResponse(
                    {"error": "Tenant name confirmation does not match"},
                    status_code=400,
                )
            return RedirectResponse(
                url="/admin/tenants?message=Tenant%20name%20confirmation%20does%20not%20match",
                status_code=302,
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
def admin_tenant_add_me(request: Request, tenant_id: int):
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


@router.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request) -> HTMLResponse:
    user = require_superadmin(request)
    if not isinstance(user, User):
        return user

    def fetch() -> Iterable[User]:
        with get_session() as session:
            query = session.query(User)
            email_filter = request.query_params.get("email")
            superadmin_filter = request.query_params.get("superadmin")
            if email_filter:
                query = query.filter(User.email.ilike(f"%{email_filter}%"))
            if superadmin_filter in {"true", "false"}:
                query = query.filter(User.is_superadmin == (superadmin_filter == "true"))
            query = query.order_by(User.email)
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


@router.get("/admin/audit", response_class=HTMLResponse)
def admin_audit(request: Request) -> HTMLResponse:
    user = require_superadmin(request)
    if not isinstance(user, User):
        return user

    def fetch() -> Iterable[AuditLog]:
        with get_session() as session:
            query = session.query(AuditLog)
            action_filter = request.query_params.get("action")
            entity_type_filter = request.query_params.get("entity_type")
            actor_filter = request.query_params.get("actor_user_id")
            entity_id_filter = request.query_params.get("entity_id")
            if action_filter:
                query = query.filter(AuditLog.action.ilike(f"%{action_filter}%"))
            if entity_type_filter:
                query = query.filter(AuditLog.entity_type == entity_type_filter)
            if actor_filter:
                try:
                    query = query.filter(AuditLog.actor_user_id == int(actor_filter))
                except ValueError:
                    pass
            if entity_id_filter:
                try:
                    query = query.filter(AuditLog.entity_id == int(entity_id_filter))
                except ValueError:
                    pass
            query = query.order_by(AuditLog.created_at.desc())
            query, _, _ = _paginate_query(query, request)
            return query.all()

    def fetch_users() -> Iterable[User]:
        with get_session() as session:
            return session.query(User).all()

    entries, error = _safe_query(fetch)
    users, _ = _safe_query(fetch_users)
    user_map = {u.id: {"email": u.email, "full_name": u.full_name} for u in users}
    if _wants_json(request):
        limit, offset = _pagination_params(request)
        return JSONResponse(
            {
                "entries": [
                    {
                        "id": entry.id,
                        "actor_user_id": entry.actor_user_id,
                        "actor_email": (user_map.get(entry.actor_user_id) or {}).get("email"),
                        "actor_name": (user_map.get(entry.actor_user_id) or {}).get("full_name"),
                        "action": entry.action,
                        "entity_type": entry.entity_type,
                        "entity_id": entry.entity_id,
                        "details": entry.details,
                        "created_at": _format_dt(entry.created_at),
                    }
                    for entry in entries
                ],
                "error": error,
                "limit": limit,
                "offset": offset,
            }
        )
    return templates.TemplateResponse(
        "admin_audit.html",
        {
            "request": request,
            "entries": entries,
            "error": error,
            "user": user,
            "user_map": user_map,
        },
    )
