from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from central.core import credentials


@pytest.mark.asyncio
async def test_resolve_credentials_invalid_protocol():
    with pytest.raises(ValueError):
        await credentials.resolve_credentials(1, "../bad", ["10.0.0.1"])


@pytest.mark.asyncio
async def test_resolve_credentials_no_assignments_returns_empty(monkeypatch):
    monkeypatch.setattr(credentials, "_load_assignments", lambda *_: [])
    result = await credentials.resolve_credentials(1, "ssh", ["10.0.0.1", "bad"])
    assert result == {"10.0.0.1": [], "bad": []}


@pytest.mark.asyncio
async def test_resolve_credentials_returns_sorted_secrets(monkeypatch):
    assignment_low = SimpleNamespace(
        subnet_cidr="10.0.0.0/24",
        priority=1,
        credential_set=SimpleNamespace(vault_index=0),
    )
    assignment_high = SimpleNamespace(
        subnet_cidr="10.0.0.0/24",
        priority=10,
        credential_set=SimpleNamespace(vault_index=1),
    )
    monkeypatch.setattr(
        credentials, "_load_assignments", lambda *_: [assignment_low, assignment_high]
    )

    async def fake_fetch(_vault, tenant_id, protocol, credential_set):
        return {
            "tenant": tenant_id,
            "protocol": protocol,
            "idx": credential_set.vault_index,
        }

    monkeypatch.setattr(credentials, "_fetch_secret", fake_fetch)

    result = await credentials.resolve_credentials(7, "ssh", ["10.0.0.5"])
    assert result["10.0.0.5"][0]["idx"] == 1
    assert result["10.0.0.5"][1]["idx"] == 0


@pytest.mark.asyncio
async def test_fetch_secret_builds_vault_path(monkeypatch):
    vault = MagicMock()
    vault.read_secret = AsyncMock(return_value={"username": "u"})
    credential_set = SimpleNamespace(vault_index=3)
    result = await credentials._fetch_secret(vault, 12, "ssh", credential_set)
    assert result == {"username": "u"}
    vault.read_secret.assert_awaited_once_with("12/ssh/3")


def test_normalize_protocol_rejects_unknown():
    assert credentials._normalize_protocol("ftp") is None
    assert credentials._normalize_protocol("ssh") == "ssh"


def test_parse_ip_and_subnet():
    ip = credentials._parse_ip("10.0.0.1")
    assert ip is not None
    assert credentials._ip_in_subnet(ip, "10.0.0.0/24") is True
    assert credentials._ip_in_subnet(ip, "10.0.1.0/24") is False
