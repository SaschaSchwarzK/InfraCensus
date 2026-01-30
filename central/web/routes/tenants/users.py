from __future__ import annotations

from collections.abc import Iterable
from json import JSONDecodeError

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import joinedload

from central.core.audit import log_audit, log_security_event
from central.core.auth import highest_role
from central.db.models import Tenant, TenantUser, User, UserRole
from central.db.session import get_session
from central.web.auth import hash_password, require_tenant_role
from central.web.oidc import oidc_enabled
from central.web.routes.common import (
    WebResponse,
    _paginate_query,
    _pagination_params,
    _redirect_with_message,
    _safe_query,
    _wants_json,
    templates,
)

router = APIRouter()


@router.get("/tenants/{tenant_id}/users", response_class=HTMLResponse)
def tenant_users(request: Request, tenant_id: int) -> WebResponse:
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
                        "display_name": membership.user.full_name
                        or membership.user.email,
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


@router.post("/tenants/{tenant_id}/users", response_model=None)
async def tenant_user_add(
    request: Request,
    tenant_id: int,
    email: str | None = Form(None),
    full_name: str | None = Form(None),
    password: str | None = Form(None),
    roles: list[str] = Form(None),
) -> WebResponse:
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
        except (JSONDecodeError, ValueError, TypeError):
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
        log_security_event(
            action="tenant.user.add_or_update",
            outcome="success",
            actor_user_id=user.id,
            details={
                "tenant_id": tenant_id,
                "user_id": account.id,
                "roles": sorted([r.value for r in role_set]),
            },
            session=session,
        )
        log_audit(
            actor_user_id=user.id,
            action="tenant.user.add",
            entity_type="tenant",
            entity_id=tenant_id,
            details={
                "user": account.email,
                "roles": sorted([r.value for r in role_set]),
            },
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
    request: Request,
    tenant_id: int,
    membership_id: int,
    roles: list[str] | None = Form(None),
) -> WebResponse:
    user = require_tenant_role(request, tenant_id, UserRole.user_admin)
    if not isinstance(user, User):
        return user

    wants_json = "application/json" in request.headers.get("accept", "")
    if not roles:
        try:
            payload = await request.json()
            roles = payload.get("roles") if payload else roles
        except (JSONDecodeError, ValueError, TypeError):
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
) -> WebResponse:
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
        log_security_event(
            action="tenant.user.remove",
            outcome="success",
            actor_user_id=user.id,
            details={
                "tenant_id": tenant_id,
                "membership_id": membership_id,
            },
            session=session,
        )
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
    request: Request,
    tenant_id: int,
    membership_id: int,
    password: str | None = Form(None),
) -> WebResponse:
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
        except (JSONDecodeError, ValueError, TypeError):
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
        log_security_event(
            action="user.password_reset",
            outcome="success",
            actor_user_id=request.session.get("user_id"),
            details={
                "target_user_id": membership.user.id,
                "tenant_id": tenant_id,
                "ip": request.client.host if request.client else None,
            },
            session=session,
        )
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
