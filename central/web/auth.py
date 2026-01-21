from __future__ import annotations

from typing import Optional

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse
from passlib.context import CryptContext

from central.core.auth import has_tenant_access
from central.db.models import TenantUser, User, UserRole
from central.db.session import get_session

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    if not password_hash:
        return False
    return pwd_context.verify(password, password_hash)


def authenticate(email: str, password: str) -> Optional[User]:
    with get_session() as session:
        user = session.query(User).filter(User.email == email).one_or_none()
        if not user:
            return None
        if not verify_password(password, user.password_hash):
            return None
        return user


def login_user(request: Request, user: User) -> None:
    request.session["user_id"] = user.id


def logout_user(request: Request) -> None:
    request.session.clear()


def get_current_user(request: Request) -> Optional[User]:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    with get_session() as session:
        return session.query(User).filter(User.id == user_id).one_or_none()


def require_user(request: Request) -> User | RedirectResponse:
    user = get_current_user(request)
    if user is None:
        return RedirectResponse(url="/login", status_code=302)
    return user


def require_superadmin(request: Request) -> User | HTMLResponse | RedirectResponse:
    user_or_response = require_user(request)
    if isinstance(user_or_response, User):
        if user_or_response.is_superadmin:
            return user_or_response
        return HTMLResponse(content="Forbidden", status_code=403)
    return user_or_response


def require_tenant_role(
    request: Request, tenant_id: int, role: UserRole
) -> User | HTMLResponse | RedirectResponse:
    user_or_response = require_user(request)
    if not isinstance(user_or_response, User):
        return user_or_response
    user = user_or_response
    with get_session() as session:
        memberships = (
            session.query(TenantUser)
            .filter(TenantUser.user_id == user.id)
            .all()
        )
    if has_tenant_access(memberships, tenant_id, role):
        return user
    return HTMLResponse(content="Forbidden", status_code=403)
