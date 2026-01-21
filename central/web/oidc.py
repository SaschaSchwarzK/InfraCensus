from __future__ import annotations

from functools import lru_cache

from authlib.integrations.starlette_client import OAuth

from central.core.config import settings


def oidc_enabled() -> bool:
    return settings.auth_mode == "oidc" and bool(
        settings.oidc_issuer_url and settings.oidc_client_id
    )


@lru_cache
def get_oauth() -> OAuth:
    oauth = OAuth()
    if not oidc_enabled():
        return oauth
    oauth.register(
        name="okta",
        client_id=settings.oidc_client_id,
        client_secret=settings.oidc_client_secret,
        server_metadata_url=f"{settings.oidc_issuer_url}/.well-known/openid-configuration",
        client_kwargs={"scope": settings.oidc_scopes},
    )
    return oauth
