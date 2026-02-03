from __future__ import annotations

from dataclasses import asdict

import pytest

from central.core import config
from central.core.config_schema import CentralConfigSchema


def test_validate_session_secret_rejects_weak_default() -> None:
    weak = "dev-session-secret-please-change-0123456789ABCDEF"
    with pytest.raises(ValueError, match="SESSION_SECRET cannot be a default value"):
        config._validate_session_secret(weak, "dev")


def test_validate_session_secret_requires_length() -> None:
    with pytest.raises(ValueError, match="SESSION_SECRET must be at least 32"):
        config._validate_session_secret("short-secret", "dev")


def test_env_overrides_prefers_unprefixed(monkeypatch) -> None:
    monkeypatch.setenv("API_HOST", "0.0.0.0")
    monkeypatch.setenv("CENTRAL_API_HOST", "127.0.0.1")
    overrides = config._env_overrides()
    assert overrides["api_host"] == "0.0.0.0"


def test_settings_validate_rejects_bad_values() -> None:
    settings = config.Settings.from_sources(
        {
            "environment": "dev",
            "session_secret": "test-session-secret-0123456789abcdef",
        }
    )
    settings = settings.__class__(**{**asdict(settings), "api_port": 70000})
    with pytest.raises(ValueError, match="API_PORT"):
        settings.validate()


def test_config_schema_rejects_invalid_api_keys() -> None:
    with pytest.raises(ValueError, match="entries must include a hash"):
        CentralConfigSchema(api_keys=":read")


def test_config_schema_accepts_defaults() -> None:
    schema = CentralConfigSchema()
    assert schema.api_port == 8000


def test_config_schema_allows_argon2_hashes() -> None:
    sample = "$argon2id$v=19$m=65536,t=3,p=4$YWJj$Zm9v"
    CentralConfigSchema(api_keys=f"{sample}:read|write")


def test_config_schema_rejects_negative_values() -> None:
    with pytest.raises(ValueError):
        CentralConfigSchema(db_pool_size=-1)


def test_config_schema_rejects_bad_audit_rate() -> None:
    with pytest.raises(ValueError):
        CentralConfigSchema(security_audit_sample_rate=1.5)


def test_settings_from_sources_uses_env_override(monkeypatch) -> None:
    monkeypatch.setenv("API_HOST", "0.0.0.0")
    settings = config.Settings.from_sources(
        {
            "environment": "dev",
            "session_secret": "test-session-secret-0123456789abcdef",
        }
    )
    assert settings.api_host == "0.0.0.0"


def test_settings_validate_requires_vault_config() -> None:
    settings = config.Settings.from_sources(
        {
            "environment": "dev",
            "session_secret": "test-session-secret-0123456789abcdef",
        }
    )
    settings = settings.__class__(**{**asdict(settings), "require_vault": True})
    with pytest.raises(ValueError, match="Vault configuration is required"):
        settings.validate()
