from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Settings:
    api_host: str
    api_port: int
    database_url: str
    db_pool_size: int
    db_max_overflow: int
    db_pool_timeout: int
    db_pool_recycle: int
    db_pool_pre_ping: bool
    session_secret: str
    auth_mode: str
    oidc_issuer_url: str | None
    oidc_client_id: str | None
    oidc_client_secret: str | None
    oidc_scopes: str
    oidc_redirect_uri: str
    oidc_logout_url: str | None
    collector_tokens: str
    api_keys: str
    vault_addr: str | None
    vault_token: str | None
    vault_kv_mount: str
    vault_namespace: str | None
    collector_rate_limit_per_hour: int
    collector_quarantine_seconds: int
    scheduler_max_jobs_per_poll: int
    scheduler_default_capacity: int
    scheduler_job_assignment_ttl_seconds: int
    scheduler_network_rate_limit_per_minute: int
    scheduler_network_rate_limit_window_seconds: int
    vault_rotation_targets: str
    ca_key_path: str
    ca_cert_path: str
    ca_cert_valid_days: int
    collector_cert_valid_days: int

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            api_host=os.getenv("API_HOST", "0.0.0.0"),
            api_port=int(os.getenv("API_PORT", "8000")),
            database_url=os.getenv(
                "DATABASE_URL",
                "postgresql+psycopg://infracensus:infracensus@localhost:5432/infracensus",
            ),
            db_pool_size=int(os.getenv("DB_POOL_SIZE", "5")),
            db_max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "10")),
            db_pool_timeout=int(os.getenv("DB_POOL_TIMEOUT", "30")),
            db_pool_recycle=int(os.getenv("DB_POOL_RECYCLE", "1800")),
            db_pool_pre_ping=os.getenv("DB_POOL_PRE_PING", "true").lower() in {"1", "true", "yes", "on"},
            session_secret=os.getenv("SESSION_SECRET", "dev-session-secret"),
            auth_mode=os.getenv("AUTH_MODE", "local"),
            oidc_issuer_url=os.getenv("OIDC_ISSUER_URL"),
            oidc_client_id=os.getenv("OIDC_CLIENT_ID"),
            oidc_client_secret=os.getenv("OIDC_CLIENT_SECRET"),
            oidc_scopes=os.getenv("OIDC_SCOPES", "openid email profile"),
            oidc_redirect_uri=os.getenv("OIDC_REDIRECT_URI", "http://localhost:8000/oidc/callback"),
            oidc_logout_url=os.getenv("OIDC_LOGOUT_URL"),
            collector_tokens=os.getenv("COLLECTOR_TOKENS", ""),
            api_keys=os.getenv("API_KEYS", ""),
            vault_addr=os.getenv("VAULT_ADDR"),
            vault_token=os.getenv("VAULT_TOKEN"),
            vault_kv_mount=os.getenv("VAULT_KV_MOUNT", "secret"),
            vault_namespace=os.getenv("VAULT_NAMESPACE"),
            collector_rate_limit_per_hour=int(os.getenv("COLLECTOR_RATE_LIMIT_PER_HOUR", "1000")),
            collector_quarantine_seconds=int(os.getenv("COLLECTOR_QUARANTINE_SECONDS", "3600")),
            scheduler_max_jobs_per_poll=int(os.getenv("SCHEDULER_MAX_JOBS_PER_POLL", "5")),
            scheduler_default_capacity=int(os.getenv("SCHEDULER_DEFAULT_CAPACITY", "2")),
            scheduler_job_assignment_ttl_seconds=int(
                os.getenv("SCHEDULER_JOB_ASSIGNMENT_TTL_SECONDS", "1800")
            ),
            scheduler_network_rate_limit_per_minute=int(
                os.getenv("SCHEDULER_NETWORK_RATE_LIMIT_PER_MINUTE", "6")
            ),
            scheduler_network_rate_limit_window_seconds=int(
                os.getenv("SCHEDULER_NETWORK_RATE_LIMIT_WINDOW_SECONDS", "60")
            ),
            vault_rotation_targets=os.getenv("VAULT_ROTATION_TARGETS", ""),
            ca_key_path=os.getenv("CA_KEY_PATH", "./ca/ca.key"),
            ca_cert_path=os.getenv("CA_CERT_PATH", "./ca/ca.crt"),
            ca_cert_valid_days=int(os.getenv("CA_CERT_VALID_DAYS", "3650")),
            collector_cert_valid_days=int(os.getenv("COLLECTOR_CERT_VALID_DAYS", "365")),
        )


settings = Settings.from_env()
