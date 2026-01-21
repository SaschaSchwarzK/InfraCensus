from __future__ import annotations

from typing import Any, Callable, Iterable, Optional
from urllib.parse import quote_plus

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import joinedload

from central.core.audit import log_audit
from central.db.models import AuditLog, Collector, Tenant, TenantUser, User
from central.db.session import get_session
from central.core.config import settings
from central.web.auth import (
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


def _redirect_with_message(url: str, message: str) -> RedirectResponse:
    return RedirectResponse(url=f"{url}?message={quote_plus(message)}", status_code=302)


@router.get("/", response_class=HTMLResponse)
def home(request: Request) -> HTMLResponse:
    user = require_user(request)
    if isinstance(user, RedirectResponse):
        return user
    return templates.TemplateResponse("index.html", {"request": request, "user": user})


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
            return (
                session.query(Tenant)
                .join(TenantUser, TenantUser.tenant_id == Tenant.id)
                .filter(TenantUser.user_id == user.id)
                .order_by(Tenant.name)
                .all()
            )

    tenants, error = _safe_query(fetch)
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
            return (
                session.query(TenantUser)
                .options(joinedload(TenantUser.user))
                .filter(TenantUser.tenant_id == tenant_id)
                .all()
            )

    memberships, error = _safe_query(fetch)
    return templates.TemplateResponse(
        "tenant_users.html",
        {
            "request": request,
            "memberships": memberships,
            "tenant_id": tenant_id,
            "error": error,
            "user": user,
            "message": request.query_params.get("message"),
        },
    )


@router.post("/tenants/{tenant_id}/users", response_model=None)
def tenant_user_add(
    request: Request,
    tenant_id: int,
    email: str = Form(...),
    full_name: str | None = Form(None),
    password: str | None = Form(None),
    role: str = Form(...),
):
    user = require_tenant_role(request, tenant_id, UserRole.user_admin)
    if not isinstance(user, User):
        return user

    try:
        selected_role = UserRole(role)
    except ValueError:
        return _redirect_with_message(
            f"/tenants/{tenant_id}/users",
            "Invalid role selection",
        )

    with get_session() as session:
        account = session.query(User).filter(User.email == email).one_or_none()
        if not account:
            if not password and not oidc_enabled():
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
            membership.role = selected_role
        else:
            session.add(
                TenantUser(tenant_id=tenant_id, user_id=account.id, role=selected_role)
            )
        log_audit(
            actor_user_id=user.id,
            action="tenant.user.add",
            entity_type="tenant",
            entity_id=tenant_id,
            details={"user": account.email, "role": selected_role.value},
        )
    return _redirect_with_message(
        f"/tenants/{tenant_id}/users",
        f"User {email} added or updated",
    )


@router.post("/tenants/{tenant_id}/users/{membership_id}/role", response_model=None)
def tenant_user_update_role(
    request: Request, tenant_id: int, membership_id: int, role: str = Form(...)
):
    user = require_tenant_role(request, tenant_id, UserRole.user_admin)
    if not isinstance(user, User):
        return user

    try:
        selected_role = UserRole(role)
    except ValueError:
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
            return _redirect_with_message(
                f"/tenants/{tenant_id}/users",
                "Membership not found",
            )
        membership.role = selected_role
        session.flush()
        log_audit(
            actor_user_id=user.id,
            action="tenant.user.role",
            entity_type="tenant_user",
            entity_id=membership_id,
            details={"role": selected_role.value},
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

    with get_session() as session:
        membership = (
            session.query(TenantUser)
            .filter(TenantUser.id == membership_id, TenantUser.tenant_id == tenant_id)
            .one_or_none()
        )
        if not membership:
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
        )
    return _redirect_with_message(
        f"/tenants/{tenant_id}/users",
        "User removed from tenant",
    )


@router.post("/tenants/{tenant_id}/users/{membership_id}/password", response_model=None)
def tenant_user_reset_password(
    request: Request, tenant_id: int, membership_id: int, password: str = Form(...)
):
    user = require_tenant_role(request, tenant_id, UserRole.user_admin)
    if not isinstance(user, User):
        return user
    if oidc_enabled():
        return _redirect_with_message(
            f"/tenants/{tenant_id}/users",
            "Password resets are disabled when OIDC is enabled",
        )
    if not password.strip():
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
        )
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
            return session.query(Tenant).order_by(Tenant.name).all()

    tenants, error = _safe_query(fetch)
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
def admin_tenant_create(
    request: Request,
    name: str = Form(...),
    description: str | None = Form(None),
    default_scanner: str | None = Form(None),
    default_scan_interval_minutes: str | None = Form(None),
):
    user = require_superadmin(request)
    if not isinstance(user, User):
        return user
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
        log_audit(
            actor_user_id=user.id,
            action="tenant.create",
            entity_type="tenant",
            entity_id=tenant.id,
            details={"name": tenant.name},
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
    return templates.TemplateResponse(
        "admin_tenant_edit.html",
        {"request": request, "tenant": tenant, "error": error, "user": user},
    )


@router.post("/admin/tenants/{tenant_id}", response_model=None)
def admin_tenant_update(
    request: Request,
    tenant_id: int,
    name: str = Form(...),
    description: str | None = Form(None),
    default_scanner: str | None = Form(None),
    default_scan_interval_minutes: str | None = Form(None),
):
    user = require_superadmin(request)
    if not isinstance(user, User):
        return user
    with get_session() as session:
        tenant = session.query(Tenant).filter(Tenant.id == tenant_id).one_or_none()
        if not tenant:
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
        )
    return RedirectResponse(url="/admin/tenants", status_code=302)


@router.post("/admin/tenants/{tenant_id}/delete", response_model=None)
def admin_tenant_delete(request: Request, tenant_id: int):
    user = require_superadmin(request)
    if not isinstance(user, User):
        return user
    with get_session() as session:
        tenant = session.query(Tenant).filter(Tenant.id == tenant_id).one_or_none()
        if not tenant:
            return HTMLResponse(content="Tenant not found", status_code=404)
        membership_count = (
            session.query(TenantUser).filter(TenantUser.tenant_id == tenant_id).count()
        )
        collector_count = (
            session.query(Collector).filter(Collector.tenant_id == tenant_id).count()
        )
        if membership_count or collector_count:
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
        )
    return RedirectResponse(url="/admin/tenants", status_code=302)


@router.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request) -> HTMLResponse:
    user = require_superadmin(request)
    if not isinstance(user, User):
        return user

    def fetch() -> Iterable[User]:
        with get_session() as session:
            return session.query(User).order_by(User.email).all()

    users, error = _safe_query(fetch)
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
            return session.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(100).all()

    entries, error = _safe_query(fetch)
    return templates.TemplateResponse(
        "admin_audit.html",
        {"request": request, "entries": entries, "error": error, "user": user},
    )
