from __future__ import annotations

import asyncio
import html
import os
import re
from dataclasses import dataclass
from typing import Any

from collector.core.config_schema import CollectorConfigSchema
from collector.core.config_source import ConfigSource


def _parse_bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_labels(value: str | None) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(key): str(val) for key, val in value.items()}
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
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
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
    job_state_cleanup_interval_seconds: int
    job_queue_join_timeout_seconds: int
    health_request_timeout_seconds: int
    backends: dict[str, dict[str, object]]

    @classmethod
    def from_env(cls) -> CollectorConfig:
        return load_config()

    @classmethod
    def from_sources(cls, config: dict[str, Any]) -> CollectorConfig:
        central_url = _resolve_central_url(config)
        if not central_url.startswith(("http://", "https://")):
            raise ValueError("CENTRAL_URL must start with http:// or https://")
        settings = cls(
            central_url=central_url,
            enrollment_token=_value(
                "ENROLLMENT_TOKEN", config, "enrollment_token", None
            ),
            collector_name=_value(
                "COLLECTOR_NAME", config, "collector_name", "collector"
            ),
            collector_labels=_parse_labels(
                _value("COLLECTOR_LABELS", config, "collector_labels", "")
            ),
            capabilities=_parse_list(
                _value("COLLECTOR_CAPABILITIES", config, "capabilities", "")
            ),
            poll_interval_seconds=_int_value(
                "POLL_INTERVAL", config, "poll_interval_seconds", 30
            ),
            backoff_multiplier=float(
                _value("POLL_BACKOFF_MULTIPLIER", config, "backoff_multiplier", 2.0)
            ),
            max_backoff_seconds=_int_value(
                "POLL_MAX_BACKOFF", config, "max_backoff_seconds", 300
            ),
            storage_path=_value(
                "STORAGE_PATH", config, "storage_path", "/collector/data"
            ),
            certs_path=_value("CERTS_PATH", config, "certs_path", "/collector/certs"),
            verify_ssl=_parse_bool(
                _value("VERIFY_SSL", config, "verify_ssl", True), True
            ),
            timeout_seconds=_int_value("HTTP_TIMEOUT", config, "timeout_seconds", 30),
            log_level=_value("LOG_LEVEL", config, "log_level", "INFO"),
            cert_renewal_days=_int_value(
                "CERT_RENEWAL_DAYS", config, "cert_renewal_days", 7
            ),
            max_concurrent_jobs=_int_value(
                "MAX_CONCURRENT_JOBS", config, "max_concurrent_jobs", 5
            ),
            max_job_queue=_int_value("MAX_JOB_QUEUE", config, "max_job_queue", 100),
            health_host=_value("HEALTH_HOST", config, "health_host", "127.0.0.1"),
            health_port=_int_value("HEALTH_PORT", config, "health_port", 8080),
            api_max_retries=_int_value("API_MAX_RETRIES", config, "api_max_retries", 3),
            api_backoff_seconds=float(
                _value("API_BACKOFF_SECONDS", config, "api_backoff_seconds", 0.5)
            ),
            api_circuit_breaker_threshold=_int_value(
                "API_CIRCUIT_BREAKER_THRESHOLD",
                config,
                "api_circuit_breaker_threshold",
                5,
            ),
            api_circuit_breaker_cooldown=_int_value(
                "API_CIRCUIT_BREAKER_COOLDOWN",
                config,
                "api_circuit_breaker_cooldown",
                30,
            ),
            collector_version=_value(
                "COLLECTOR_VERSION", config, "collector_version", "unknown"
            ),
            collector_build=_value(
                "COLLECTOR_BUILD", config, "collector_build", "unknown"
            ),
            clock_skew_warn_seconds=_int_value(
                "CLOCK_SKEW_WARN_SECONDS", config, "clock_skew_warn_seconds", 60
            ),
            vault_addr=_value("VAULT_ADDR", config, "vault_addr", None),
            vault_token=_value("VAULT_TOKEN", config, "vault_token", None),
            vault_kv_mount=_value("VAULT_KV_MOUNT", config, "vault_kv_mount", "secret"),
            vault_namespace=_value("VAULT_NAMESPACE", config, "vault_namespace", None),
            vault_cache_ttl_seconds=_int_value(
                "VAULT_CACHE_TTL_SECONDS", config, "vault_cache_ttl_seconds", 300
            ),
            job_state_cleanup_interval_seconds=_int_value(
                "JOB_STATE_CLEANUP_INTERVAL_SECONDS",
                config,
                "job_state_cleanup_interval_seconds",
                3600,
            ),
            job_queue_join_timeout_seconds=_int_value(
                "JOB_QUEUE_JOIN_TIMEOUT_SECONDS",
                config,
                "job_queue_join_timeout_seconds",
                10,
            ),
            health_request_timeout_seconds=_int_value(
                "HEALTH_REQUEST_TIMEOUT_SECONDS",
                config,
                "health_request_timeout_seconds",
                5,
            ),
            backends=_parse_backends(config.get("backends")),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        if not self.central_url:
            raise ValueError("CENTRAL_URL must be set")
        if self.poll_interval_seconds < 1:
            raise ValueError("POLL_INTERVAL must be >= 1")
        if self.max_concurrent_jobs < 1:
            raise ValueError("MAX_CONCURRENT_JOBS must be >= 1")
        if self.max_job_queue < 1:
            raise ValueError("MAX_JOB_QUEUE must be >= 1")
        if not (0 < self.health_port < 65536):
            raise ValueError("HEALTH_PORT must be between 1 and 65535")


def load_config() -> CollectorConfig:
    source = ConfigSource.from_env()
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        config, _ = asyncio.run(source.load())
    else:
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(lambda: asyncio.run(source.load()))
            config, _ = future.result()
    config = CollectorConfigSchema.model_validate(config).model_dump()
    return CollectorConfig.from_sources(config)


def _resolve_central_url(config: dict[str, Any]) -> str:
    explicit = _value("CENTRAL_URL", config, "central_url", None)
    if explicit:
        # Sanitize explicit URL to prevent XSS
        return _sanitize_url(str(explicit))
    host = _value("CENTRAL_SERVICE_HOST", config, "central_service_host", None)
    if not host:
        return "https://central.infracensus.local"

    # Sanitize host to prevent XSS
    host = _sanitize_host(str(host))

    scheme = _value("CENTRAL_SERVICE_SCHEME", config, "central_service_scheme", "https")
    # Validate scheme
    if scheme not in ["http", "https"]:
        scheme = "https"

    port = _value("CENTRAL_SERVICE_PORT", config, "central_service_port", None)
    if port:
        # Validate port is numeric
        try:
            port_num = int(port)
            if not (1 <= port_num <= 65535):
                raise ValueError("Invalid port")
            return f"{scheme}://{host}:{port_num}"
        except (ValueError, TypeError):
            return f"{scheme}://{host}"
    return f"{scheme}://{host}"


def _sanitize_url(url: str) -> str:
    """Sanitize URL to prevent XSS attacks."""
    # HTML escape the URL
    sanitized = html.escape(url, quote=True)
    # Validate URL format
    if not re.match(r"^https?://[a-zA-Z0-9.-]+(?::[0-9]+)?(?:/.*)?$", sanitized):
        raise ValueError(f"Invalid URL format: {url}")
    return sanitized


def _sanitize_host(host: str) -> str:
    """Sanitize hostname to prevent XSS attacks."""
    # HTML escape the host
    sanitized = html.escape(host, quote=True)
    # Validate hostname format
    if not re.match(r"^[a-zA-Z0-9.-]+$", sanitized):
        raise ValueError(f"Invalid hostname format: {host}")
    return sanitized


def _value(env_key: str, config: dict[str, Any], key: str, default: Any) -> Any:
    if env_key in os.environ:
        return os.environ[env_key]
    if key in config:
        return config[key]
    return default


def _int_value(env_key: str, config: dict[str, Any], key: str, default: int) -> int:
    return int(_value(env_key, config, key, default))


def _parse_backends(value: object) -> dict[str, dict[str, object]]:
    if isinstance(value, dict):
        return {str(name): dict(cfg) for name, cfg in value.items()}
    return {}
