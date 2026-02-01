from __future__ import annotations

import asyncio
import logging
import os
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from central.core.config_schema import CentralConfigSchema
from central.core.config_source import ConfigSource

logger = logging.getLogger(__name__)


def _validate_session_secret(secret: str, environment: str) -> None:
    if len(secret) < 32:
        raise ValueError("SESSION_SECRET must be at least 32 characters")
    weak_defaults = {
        "dev-session-secret",
        "test-secret",
        "change-me",
        "secret",
        "password",
    }
    if secret.lower() in weak_defaults:
        raise ValueError(
            "SESSION_SECRET cannot be a default value. "
            "Generate one with: python -c 'import secrets; "
            "print(secrets.token_urlsafe(32))'"
        )
    if len(set(secret)) < 8:
        logger.warning(
            "SESSION_SECRET has low entropy. Consider using a random value."
        )
    if environment == "dev" and len(secret) < 64:
        logger.warning(
            "Using short SESSION_SECRET in dev. "
            "Consider: python -c 'import secrets; "
            "print(secrets.token_urlsafe(64))'"
        )


@dataclass(frozen=True)
class Settings:
    environment: str
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
    api_key_pepper: str
    vault_addr: str | None
    vault_token: str | None
    vault_kv_mount: str
    vault_namespace: str | None
    require_vault: bool
    collector_rate_limit_per_hour: int
    collector_quarantine_seconds: int
    scheduler_max_jobs_per_poll: int
    scheduler_default_capacity: int
    scheduler_job_assignment_ttl_seconds: int
    scheduler_network_rate_limit_per_minute: int
    scheduler_network_rate_limit_window_seconds: int
    vault_rotation_targets: str
    collector_clock_skew_max_seconds: int
    security_headers_enabled: bool
    security_csp: str
    security_frame_options: str
    security_referrer_policy: str
    security_hsts_seconds: int
    security_hsts_include_subdomains: bool
    security_hsts_preload: bool
    security_audit_sample_rate: float
    ca_key_path: str
    ca_cert_path: str
    ca_cert_valid_days: int
    collector_cert_valid_days: int

    @classmethod
    def from_sources(cls, config: dict[str, Any]) -> Settings:
        validated = CentralConfigSchema.model_validate(config)
        environment = validated.environment.lower()
        session_secret = validated.session_secret
        _validate_session_secret(session_secret, environment)
        settings = cls(
            environment=environment,
            api_host=validated.api_host,
            api_port=validated.api_port,
            database_url=validated.database_url,
            db_pool_size=validated.db_pool_size,
            db_max_overflow=validated.db_max_overflow,
            db_pool_timeout=validated.db_pool_timeout,
            db_pool_recycle=validated.db_pool_recycle,
            db_pool_pre_ping=validated.db_pool_pre_ping,
            session_secret=session_secret,
            auth_mode=validated.auth_mode,
            oidc_issuer_url=validated.oidc_issuer_url,
            oidc_client_id=validated.oidc_client_id,
            oidc_client_secret=validated.oidc_client_secret,
            oidc_scopes=validated.oidc_scopes,
            oidc_redirect_uri=validated.oidc_redirect_uri,
            oidc_logout_url=validated.oidc_logout_url,
            collector_tokens=validated.collector_tokens,
            api_keys=validated.api_keys,
            api_key_pepper=validated.api_key_pepper,
            vault_addr=validated.vault_addr,
            vault_token=validated.vault_token,
            vault_kv_mount=validated.vault_kv_mount,
            vault_namespace=validated.vault_namespace,
            require_vault=validated.require_vault,
            collector_rate_limit_per_hour=validated.collector_rate_limit_per_hour,
            collector_quarantine_seconds=validated.collector_quarantine_seconds,
            scheduler_max_jobs_per_poll=validated.scheduler_max_jobs_per_poll,
            scheduler_default_capacity=validated.scheduler_default_capacity,
            scheduler_job_assignment_ttl_seconds=validated.scheduler_job_assignment_ttl_seconds,
            scheduler_network_rate_limit_per_minute=validated.scheduler_network_rate_limit_per_minute,
            scheduler_network_rate_limit_window_seconds=validated.scheduler_network_rate_limit_window_seconds,
            vault_rotation_targets=validated.vault_rotation_targets,
            collector_clock_skew_max_seconds=validated.collector_clock_skew_max_seconds,
            security_headers_enabled=validated.security_headers_enabled,
            security_csp=validated.security_csp,
            security_frame_options=validated.security_frame_options,
            security_referrer_policy=validated.security_referrer_policy,
            security_hsts_seconds=validated.security_hsts_seconds,
            security_hsts_include_subdomains=validated.security_hsts_include_subdomains,
            security_hsts_preload=validated.security_hsts_preload,
            security_audit_sample_rate=validated.security_audit_sample_rate,
            ca_key_path=validated.ca_key_path,
            ca_cert_path=validated.ca_cert_path,
            ca_cert_valid_days=validated.ca_cert_valid_days,
            collector_cert_valid_days=validated.collector_cert_valid_days,
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        if not (0 < self.api_port < 65536):
            raise ValueError("API_PORT must be between 1 and 65535")
        if self.db_pool_size < 1:
            raise ValueError("DB_POOL_SIZE must be >= 1")
        if self.db_pool_timeout < 1:
            raise ValueError("DB_POOL_TIMEOUT must be >= 1")
        if self.collector_clock_skew_max_seconds < 0:
            raise ValueError("COLLECTOR_CLOCK_SKEW_MAX_SECONDS must be >= 0")
        if self.require_vault and (not self.vault_addr or not self.vault_token):
            raise ValueError(
                "Vault configuration is required when REQUIRE_VAULT is true."
            )
        if self.security_hsts_seconds < 0:
            raise ValueError("SECURITY_HSTS_SECONDS must be >= 0")
        if not 0 <= self.security_audit_sample_rate <= 1:
            raise ValueError("SECURITY_AUDIT_SAMPLE_RATE must be between 0 and 1")


class SettingsProxy:
    def __init__(self, state: SettingsState) -> None:
        self._state = state

    def __getattr__(self, name: str) -> Any:
        return getattr(self._state.settings, name)


class SettingsState:
    def __init__(self, source: ConfigSource) -> None:
        self._source = source
        self._lock = threading.Lock()
        self._settings: Settings | None = None
        self._config_hash: str | None = None
        self._listeners: list[Callable[[Settings], None]] = []

    @property
    def settings(self) -> Settings:
        if self._settings is None:
            self.reload_sync(force=True)
        return self._settings  # type: ignore[return-value]

    async def reload(self, force: bool = False) -> None:
        config, digest = await self._source.load()
        if not force and digest and digest == self._config_hash:
            return
        new_settings = Settings.from_sources(config)
        with self._lock:
            self._settings = new_settings
            self._config_hash = digest
            listeners = list(self._listeners)
        for listener in listeners:
            try:
                listener(new_settings)
            except (RuntimeError, ValueError, TypeError) as exc:
                logger.warning(
                    "config.reload_listener_failed",
                    extra={"error": str(exc)},
                )

    def reload_sync(self, force: bool = False) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(self.reload(force=force))
            return
        loop.create_task(self.reload(force=force))

    def add_listener(self, listener: Callable[[Settings], None]) -> None:
        self._listeners.append(listener)


_config_source = ConfigSource.from_env()
_settings_state = SettingsState(_config_source)
settings = SettingsProxy(_settings_state)


def register_settings_listener(listener: Callable[[Settings], None]) -> None:
    _settings_state.add_listener(listener)


def get_config_poll_seconds() -> int:
    if os.getenv("CONFIG_POLL_SECONDS"):
        try:
            value = os.getenv("CONFIG_POLL_SECONDS", "0")
            # Validate that the value is a safe integer to prevent OS command injection
            if not value or not isinstance(value, str):
                raise ValueError(f"Invalid CONFIG_POLL_SECONDS type: {type(value)}")
            # Remove any non-digit characters to prevent injection
            clean_value = "".join(c for c in value if c.isdigit())
            if not clean_value or clean_value != value:
                raise ValueError(
                    f"Invalid CONFIG_POLL_SECONDS value contains non-digits: {value}"
                )
            poll_seconds = int(clean_value)
            # Ensure reasonable bounds to prevent resource exhaustion
            if poll_seconds < 0 or poll_seconds > 86400:  # Max 24 hours
                raise ValueError(
                    f"CONFIG_POLL_SECONDS must be between 0 and 86400, got: {poll_seconds}"
                )
            return poll_seconds
        except (ValueError, TypeError) as exc:
            logger.warning(f"Invalid CONFIG_POLL_SECONDS value, using default: {exc}")
            return 60 if _config_source.git_url else 0
    return 60 if _config_source.git_url else 0


async def start_config_polling() -> None:
    interval = get_config_poll_seconds()
    if interval <= 0:
        return

    async def _poll() -> None:
        while True:
            await asyncio.sleep(interval)
            try:
                await _settings_state.reload()
            except (RuntimeError, ValueError, TypeError) as exc:
                logger.warning(
                    "config.reload_failed",
                    extra={"error": str(exc)},
                )

    asyncio.create_task(_poll())


def _value(env_key: str, config: dict[str, Any], key: str, default: Any) -> Any:
    if env_key in os.environ:
        return os.environ[env_key]
    if key in config:
        return config[key]
    return default


def _int_value(env_key: str, config: dict[str, Any], key: str, default: int) -> int:
    return int(_value(env_key, config, key, default))


def _bool_value(env_key: str, config: dict[str, Any], key: str, default: bool) -> bool:
    value = _value(env_key, config, key, default)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}
