from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, field_validator


class CentralConfigSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    environment: str = "dev"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    database_url: str = (
        "postgresql+psycopg://infracensus:infracensus@localhost:5432/infracensus"
    )
    db_pool_size: int = 5
    db_max_overflow: int = 10
    db_pool_timeout: int = 30
    db_pool_recycle: int = 1800
    db_pool_pre_ping: bool = True
    session_secret: str = "dev-session-secret"
    auth_mode: str = "local"
    oidc_issuer_url: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_scopes: str = "openid email profile"
    oidc_redirect_uri: str = "http://localhost:8000/oidc/callback"
    oidc_logout_url: str | None = None
    collector_tokens: str = ""
    api_keys: str = ""
    api_key_pepper: str = ""
    vault_addr: str | None = None
    vault_token: str | None = None
    vault_kv_mount: str = "secret"
    vault_namespace: str | None = None
    require_vault: bool = False
    collector_rate_limit_per_hour: int = 1000
    collector_quarantine_seconds: int = 3600
    scheduler_max_jobs_per_poll: int = 5
    scheduler_default_capacity: int = 2
    scheduler_job_assignment_ttl_seconds: int = 1800
    scheduler_network_rate_limit_per_minute: int = 6
    scheduler_network_rate_limit_window_seconds: int = 60
    vault_rotation_targets: str = ""
    collector_clock_skew_max_seconds: int = 300
    security_headers_enabled: bool = True
    security_csp: str = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; connect-src 'self'"
    )
    security_frame_options: str = "DENY"
    security_referrer_policy: str = "no-referrer"
    security_hsts_seconds: int = 31536000
    security_hsts_include_subdomains: bool = True
    security_hsts_preload: bool = False
    security_audit_sample_rate: float = 0.1
    ca_key_path: str = "./ca/ca.key"
    ca_cert_path: str = "./ca/ca.crt"
    ca_cert_valid_days: int = 3650
    collector_cert_valid_days: int = 365

    @field_validator("api_port")
    @classmethod
    def _validate_api_port(cls, value: int) -> int:
        if not 1 <= value <= 65535:
            raise ValueError("api_port must be between 1 and 65535")
        return value

    @field_validator("api_keys")
    @classmethod
    def _validate_api_keys(cls, value: str) -> str:
        if not value:
            return value
        for entry in value.split(","):
            entry = entry.strip()
            if not entry:
                continue
            key_hash, _, _scopes = entry.partition(":")
            key_hash = key_hash.strip()
            if not re.fullmatch(r"[0-9a-f]{64}", key_hash):
                raise ValueError("api_keys must use sha256 hex hashes")
        return value

    @field_validator(
        "db_pool_size",
        "db_max_overflow",
        "db_pool_timeout",
        "db_pool_recycle",
        "collector_rate_limit_per_hour",
        "collector_quarantine_seconds",
        "scheduler_max_jobs_per_poll",
        "scheduler_default_capacity",
        "scheduler_job_assignment_ttl_seconds",
        "scheduler_network_rate_limit_per_minute",
        "scheduler_network_rate_limit_window_seconds",
        "collector_clock_skew_max_seconds",
        "security_hsts_seconds",
        "ca_cert_valid_days",
        "collector_cert_valid_days",
    )
    @classmethod
    def _validate_non_negative(cls, value: int) -> int:
        if value < 0:
            raise ValueError("value must be >= 0")
        return value

    @field_validator("security_audit_sample_rate")
    @classmethod
    def _validate_audit_sample_rate(cls, value: float) -> float:
        if not 0 <= value <= 1:
            raise ValueError("security_audit_sample_rate must be between 0 and 1")
        return value
