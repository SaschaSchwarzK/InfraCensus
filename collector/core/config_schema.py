from __future__ import annotations

from pydantic import BaseModel, ConfigDict, field_validator


class CollectorConfigSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    central_url: str = "https://central.infracensus.local"
    central_service_host: str | None = None
    central_service_scheme: str = "https"
    central_service_port: str | None = None
    enrollment_token: str | None = None
    collector_name: str = "collector"
    collector_labels: dict[str, str] | str = ""
    capabilities: list[str] | str = ""
    poll_interval_seconds: int = 30
    backoff_multiplier: float = 2.0
    max_backoff_seconds: int = 300
    storage_path: str = "/collector/data"
    certs_path: str = "/collector/certs"
    verify_ssl: bool = True
    timeout_seconds: int = 30
    log_level: str = "INFO"
    cert_renewal_days: int = 7
    max_concurrent_jobs: int = 5
    max_job_queue: int = 100
    health_host: str = "127.0.0.1"
    health_port: int = 8080
    api_max_retries: int = 3
    api_backoff_seconds: float = 0.5
    api_circuit_breaker_threshold: int = 5
    api_circuit_breaker_cooldown: int = 30
    collector_version: str = "unknown"
    collector_build: str = "unknown"
    clock_skew_warn_seconds: int = 60
    vault_addr: str | None = None
    vault_token: str | None = None
    vault_kv_mount: str = "secret"
    vault_namespace: str | None = None
    vault_cache_ttl_seconds: int = 300
    job_state_cleanup_interval_seconds: int = 3600
    job_queue_join_timeout_seconds: int = 10
    health_request_timeout_seconds: int = 5
    backends: dict[str, dict] | None = None

    @field_validator("health_port")
    @classmethod
    def _validate_health_port(cls, value: int) -> int:
        if not 1 <= value <= 65535:
            raise ValueError("health_port must be between 1 and 65535")
        return value

    @field_validator(
        "poll_interval_seconds",
        "max_backoff_seconds",
        "timeout_seconds",
        "cert_renewal_days",
        "max_concurrent_jobs",
        "max_job_queue",
        "api_max_retries",
        "api_circuit_breaker_threshold",
        "api_circuit_breaker_cooldown",
        "clock_skew_warn_seconds",
        "vault_cache_ttl_seconds",
        "job_state_cleanup_interval_seconds",
        "job_queue_join_timeout_seconds",
        "health_request_timeout_seconds",
    )
    @classmethod
    def _validate_non_negative(cls, value: int) -> int:
        if value < 0:
            raise ValueError("value must be >= 0")
        return value
