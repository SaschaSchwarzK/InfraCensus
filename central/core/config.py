from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    database_url: str = "sqlite:///./infracensus.db"
    session_secret: str = "dev-session-secret"
    auth_mode: str = "local"
    oidc_issuer_url: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_scopes: str = "openid email profile"
    oidc_redirect_uri: str = "http://localhost:8000/oidc/callback"
    oidc_logout_url: str | None = None
    collector_tokens: str = ""


settings = Settings()
