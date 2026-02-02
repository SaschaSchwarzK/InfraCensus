from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from central.core.vault import VaultClient, VaultSettings


@pytest.mark.asyncio
async def test_vault_read_secret():
    settings = VaultSettings(
        addr="http://vault:8200",
        token="test-token",
        kv_mount="secret",
        namespace=None,
    )

    with patch("httpx.AsyncClient") as mock_client:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json = MagicMock(
            return_value={"data": {"data": {"password": "secret123"}}}
        )
        mock_instance = mock_client.return_value
        mock_instance.get = AsyncMock(return_value=mock_response)
        mock_instance.aclose = AsyncMock()

        async with VaultClient(settings) as client:
            result = await client.read_secret("path/to/secret")
            assert result == {"password": "secret123"}
