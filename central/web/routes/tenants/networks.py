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
    _paginate_query,
    _pagination_params,
    _redirect_with_message,
    _safe_query,
    _wants_json,
    templates,
)

router = APIRouter()


@router.get("/tenants/{tenant_id}/networks", response_class=HTMLResponse)
def tenant_networks(request: Request, tenant_id: int) -> WebResponse:
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
                "sites": [{"id": site.id, "name": site.name} for site in sites],
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
) -> WebResponse:
    user = require_tenant_role(request, tenant_id, UserRole.read_write)
    if not isinstance(user, User):
        return user
    wants_json = "application/json" in request.headers.get("accept", "")
    if not name or not cidr:
        try:
            payload = await request.json()
            name = payload.get("name") if payload else name
            cidr = payload.get("cidr") if payload else cidr
            site_id = (
                str(payload.get("site_id"))
                if payload and payload.get("site_id") is not None
                else site_id
            )
            description = payload.get("description") if payload else description
        except (JSONDecodeError, ValueError, TypeError):
            name = name
    if not name or not cidr:
        if wants_json:
            return JSONResponse(
                {"error": "Name and CIDR are required"}, status_code=400
            )
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
) -> WebResponse:
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
) -> WebResponse:
    user = require_tenant_role(request, tenant_id, UserRole.read_write)
    if not isinstance(user, User):
        return user
    wants_json = "application/json" in request.headers.get("accept", "")
    if not name or not cidr:
        try:
            payload = await request.json()
            name = payload.get("name") if payload else name
            cidr = payload.get("cidr") if payload else cidr
            site_id = (
                str(payload.get("site_id"))
                if payload and payload.get("site_id") is not None
                else site_id
            )
            description = payload.get("description") if payload else description
        except (JSONDecodeError, ValueError, TypeError):
            name = name
    if not name or not cidr:
        if wants_json:
            return JSONResponse(
                {"error": "Name and CIDR are required"}, status_code=400
            )
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
) -> WebResponse:
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
