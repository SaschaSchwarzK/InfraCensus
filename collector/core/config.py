from __future__ import annotations

from dataclasses import dataclass
import os


def _parse_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_labels(value: str | None) -> dict[str, str]:
    labels: dict[str, str] = {}
    if not value:
        return labels
    for entry in value.split(","):
        if not entry.strip():
            continue
        key, _, raw_value = entry.partition("=")
        if not key:
            continue
        labels[key.strip()] = raw_value.strip()
    return labels


def _parse_list(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class CollectorConfig:
    central_url: str
    enrollment_token: str | None
    collector_name: str
    collector_labels: dict[str, str]
    capabilities: list[str]
    poll_interval_seconds: int
    backoff_multiplier: float
    max_backoff_seconds: int
    storage_path: str
    certs_path: str
    verify_ssl: bool
    timeout_seconds: int
    log_level: str
    cert_renewal_days: int
    max_concurrent_jobs: int
    max_job_queue: int
    health_host: str
    health_port: int
    api_max_retries: int
    api_backoff_seconds: float
    api_circuit_breaker_threshold: int
    api_circuit_breaker_cooldown: int
    collector_version: str
    collector_build: str
    clock_skew_warn_seconds: int
    vault_addr: str | None
    vault_token: str | None
    vault_kv_mount: str
    vault_namespace: str | None
    vault_cache_ttl_seconds: int

    @classmethod
    def from_env(cls) -> "CollectorConfig":
        central_url = _resolve_central_url()
        if not central_url.startswith(("http://", "https://")):
            raise ValueError("CENTRAL_URL must start with http:// or https://")
        enrollment_token = os.getenv("ENROLLMENT_TOKEN")
        collector_name = os.getenv("COLLECTOR_NAME", "collector")
        labels = _parse_labels(os.getenv("COLLECTOR_LABELS"))
        capabilities = _parse_list(os.getenv("COLLECTOR_CAPABILITIES"))
        poll_interval = int(os.getenv("POLL_INTERVAL", "30"))
        backoff_multiplier = float(os.getenv("POLL_BACKOFF_MULTIPLIER", "2"))
        max_backoff = int(os.getenv("POLL_MAX_BACKOFF", "300"))
        storage_path = os.getenv("STORAGE_PATH", "/collector/data")
        certs_path = os.getenv("CERTS_PATH", "/collector/certs")
        verify_ssl = _parse_bool(os.getenv("VERIFY_SSL"), True)
        timeout_seconds = int(os.getenv("HTTP_TIMEOUT", "30"))
        log_level = os.getenv("LOG_LEVEL", "INFO")
        cert_renewal_days = int(os.getenv("CERT_RENEWAL_DAYS", "7"))
        max_concurrent_jobs = int(os.getenv("MAX_CONCURRENT_JOBS", "5"))
        max_job_queue = int(os.getenv("MAX_JOB_QUEUE", "100"))
        health_host = os.getenv("HEALTH_HOST", "0.0.0.0")
        health_port = int(os.getenv("HEALTH_PORT", "8080"))
        api_max_retries = int(os.getenv("API_MAX_RETRIES", "3"))
        api_backoff_seconds = float(os.getenv("API_BACKOFF_SECONDS", "0.5"))
        api_circuit_breaker_threshold = int(os.getenv("API_CIRCUIT_BREAKER_THRESHOLD", "5"))
        api_circuit_breaker_cooldown = int(os.getenv("API_CIRCUIT_BREAKER_COOLDOWN", "30"))
        collector_version = os.getenv("COLLECTOR_VERSION", "unknown")
        collector_build = os.getenv("COLLECTOR_BUILD", "unknown")
        clock_skew_warn_seconds = int(os.getenv("CLOCK_SKEW_WARN_SECONDS", "60"))
        vault_addr = os.getenv("VAULT_ADDR")
        vault_token = os.getenv("VAULT_TOKEN")
        vault_kv_mount = os.getenv("VAULT_KV_MOUNT", "secret")
        vault_namespace = os.getenv("VAULT_NAMESPACE")
        vault_cache_ttl_seconds = int(os.getenv("VAULT_CACHE_TTL_SECONDS", "300"))
        return cls(
            central_url=central_url,
            enrollment_token=enrollment_token,
            collector_name=collector_name,
            collector_labels=labels,
            capabilities=capabilities,
            poll_interval_seconds=poll_interval,
            backoff_multiplier=backoff_multiplier,
            max_backoff_seconds=max_backoff,
            storage_path=storage_path,
            certs_path=certs_path,
            verify_ssl=verify_ssl,
            timeout_seconds=timeout_seconds,
            log_level=log_level,
            cert_renewal_days=cert_renewal_days,
            max_concurrent_jobs=max_concurrent_jobs,
            max_job_queue=max_job_queue,
            health_host=health_host,
            health_port=health_port,
            api_max_retries=api_max_retries,
            api_backoff_seconds=api_backoff_seconds,
            api_circuit_breaker_threshold=api_circuit_breaker_threshold,
            api_circuit_breaker_cooldown=api_circuit_breaker_cooldown,
            collector_version=collector_version,
            collector_build=collector_build,
            clock_skew_warn_seconds=clock_skew_warn_seconds,
            vault_addr=vault_addr,
            vault_token=vault_token,
            vault_kv_mount=vault_kv_mount,
            vault_namespace=vault_namespace,
            vault_cache_ttl_seconds=vault_cache_ttl_seconds,
        )


def _resolve_central_url() -> str:
    explicit = os.getenv("CENTRAL_URL")
    if explicit:
        return explicit
    host = os.getenv("CENTRAL_SERVICE_HOST")
    if not host:
        return "https://central.infracensus.local"
    scheme = os.getenv("CENTRAL_SERVICE_SCHEME", "https")
    port = os.getenv("CENTRAL_SERVICE_PORT")
    if port:
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"
