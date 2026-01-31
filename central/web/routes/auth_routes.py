from __future__ import annotations

import html

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from central.core.audit import log_security_event
from central.core.config import settings
from central.db.models import User
from central.db.session import get_session
from central.web.auth import authenticate, login_user, logout_user
from central.web.oidc import get_oauth, oidc_enabled
from central.web.routes.common import WebResponse, templates

router = APIRouter()


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request) -> WebResponse:
    if oidc_enabled():
        oauth = get_oauth()
        return oauth.okta.authorize_redirect(request, settings.oidc_redirect_uri)
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "auth_mode": html.escape(str(settings.auth_mode))},
    )


@router.post("/login", response_class=HTMLResponse)
def login_submit(
    request: Request, email: str = Form(...), password: str = Form(...)
) -> WebResponse:
    if oidc_enabled():
        log_security_event(
            action="login.oidc_blocked",
            outcome="denied",
            details={
                "email": email,
                "ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
            },
        )
        return HTMLResponse(content="OIDC login enabled", status_code=400)
    user = authenticate(email, password)
    if not user:
        log_security_event(
            action="login.failed",
            outcome="denied",
            details={
                "email": email,
                "ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
            },
        )
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid credentials"},
            status_code=401,
        )
    login_user(request, user)
    log_security_event(
        action="login.success",
        outcome="success",
        actor_user_id=user.id,
        details={
            "email": user.email,
            "ip": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
        },
    )
    return RedirectResponse(url="/", status_code=302)


@router.post("/logout")
def logout(request: Request) -> RedirectResponse:
    oidc_logout_url = settings.oidc_logout_url
    id_token = request.session.get("id_token")
    user_id = request.session.get("user_id")
    log_security_event(
        action="logout",
        outcome="success",
        actor_user_id=user_id,
        details={
            "ip": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
        },
    )
    logout_user(request)
    if oidc_logout_url and id_token:
        redirect_url = f"{oidc_logout_url}?id_token_hint={id_token}&post_logout_redirect_uri={settings.oidc_redirect_uri}"
        return RedirectResponse(url=redirect_url, status_code=302)
    return RedirectResponse(url="/login", status_code=302)


@router.get("/oidc/callback", response_model=None)
async def oidc_callback(request: Request) -> WebResponse:
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
