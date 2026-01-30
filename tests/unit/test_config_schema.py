import pytest
from pydantic import ValidationError

from central.core.config_schema import CentralConfigSchema


def test_schema_validates_port():
    with pytest.raises(ValidationError):
        CentralConfigSchema(api_port=99999)


def test_schema_allows_valid_config():
    config = CentralConfigSchema(
        environment="dev",
        api_port=8000,
        session_secret="test-secret-12345678901234567890",
    )
    assert config.api_port == 8000


def test_schema_rejects_plain_api_keys():
    with pytest.raises(ValidationError):
        CentralConfigSchema(api_keys="plain-key:read_only")


def test_schema_allows_hashed_api_keys():
    key_hash = "a" * 64
    config = CentralConfigSchema(api_keys=f"{key_hash}:read_only|scan_operator")
    assert config.api_keys == f"{key_hash}:read_only|scan_operator"
