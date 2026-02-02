from __future__ import annotations

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse
from passlib.context import CryptContext

from central.core.audit import log_security_event, should_sample_security_event
from central.core.auth import get_api_key_scopes, has_tenant_access
from central.core.config import settings
from central.core.logging import set_log_context
from central.db.models import TenantUser, User, UserRole
from central.db.session import get_session

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    if not password_hash:
        return False
    return pwd_context.verify(password, password_hash)


def authenticate(email: str, password: str) -> User | None:
    with get_session() as session:
        user = session.query(User).filter(User.email == email).one_or_none()
        if not user:
            return None
        if not verify_password(password, user.password_hash):
            return None
        return user


def login_user(request: Request, user: User) -> None:
    session = request.scope.get("session")
    if isinstance(session, dict):
        session["user_id"] = user.id


def logout_user(request: Request) -> None:
    session = request.scope.get("session")
    if isinstance(session, dict):
        session.clear()


def get_current_user(request: Request) -> User | None:
    session = request.scope.get("session")
    if not isinstance(session, dict):
        return None
    user_id = session.get("user_id")
    if not user_id:
        return None
    with get_session() as session:
        return session.query(User).filter(User.id == user_id).one_or_none()


def require_user(request: Request) -> User | RedirectResponse:
    user = get_current_user(request)
    if user is None:
        log_security_event(
            action="web.access.denied",
            outcome="denied",
            details={
                "reason": "unauthenticated",
                "path": request.url.path,
                "ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
            },
        )
        return RedirectResponse(url="/login", status_code=302)
    return user


def require_superadmin(request: Request) -> User | HTMLResponse | RedirectResponse:
    user_or_response = require_user(request)
    if isinstance(user_or_response, User):
        if user_or_response.is_superadmin:
            return user_or_response
        log_security_event(
            action="web.access.denied",
            outcome="denied",
            actor_user_id=user_or_response.id,
            details={
                "reason": "superadmin_required",
                "path": request.url.path,
                "ip": request.client.host if request.client else None,
            },
        )
        return HTMLResponse(content="Forbidden", status_code=403)
    return user_or_response


def require_tenant_role(
    request: Request, tenant_id: int, role: UserRole
) -> User | HTMLResponse | RedirectResponse:
    user_or_response = require_user(request)
    if not isinstance(user_or_response, User):
        return user_or_response
    user = user_or_response
    if user.is_auditor and role == UserRole.read_only:
        return user
    with get_session() as session:
        memberships = (
            session.query(TenantUser).filter(TenantUser.user_id == user.id).all()
        )
    if has_tenant_access(memberships, tenant_id, role):
        set_log_context(user_id=str(user.id), tenant_id=str(tenant_id))
        return user
    log_security_event(
        action="web.access.denied",
        outcome="denied",
        actor_user_id=user.id,
        details={
            "reason": "tenant_role_required",
            "tenant_id": tenant_id,
            "role": role.value,
            "path": request.url.path,
            "ip": request.client.host if request.client else None,
        },
    )
    return HTMLResponse(content="Forbidden", status_code=403)


def allow_collector_token(request: Request) -> bool:
    if not settings.collector_tokens:
        return False
    header = request.headers.get("authorization") or ""
    token = ""  # nosec
    if header.lower().startswith("bearer "):
        token = header.split(" ", 1)[1].strip()
    if not token:
        token = request.headers.get("x-collector-token", "").strip()
    valid_tokens = {
        item.strip() for item in settings.collector_tokens.split(",") if item.strip()
    }
    return token in valid_tokens


def allow_api_key_scope(request: Request, scope: str) -> bool:
    if not settings.api_keys:
        return False
    header = request.headers.get("authorization") or ""
    key = ""
    if header.lower().startswith("bearer "):
        key = header.split(" ", 1)[1].strip()
    if not key:
        key = request.headers.get("x-api-key", "").strip()
    if not key:
        return False
    scopes = get_api_key_scopes(settings.api_keys, key, settings.api_key_pepper)
    allowed = scope in scopes or "*" in scopes
    if not allowed:
        log_security_event(
            action="api_key.denied",
            outcome="denied",
            details={
                "scope": scope,
                "ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
            },
        )
    elif should_sample_security_event(settings.security_audit_sample_rate):
        log_security_event(
            action="api_key.allowed",
            outcome="success",
            details={
                "scope": scope,
                "ip": request.client.host if request.client else None,
            },
        )
    return allowed
