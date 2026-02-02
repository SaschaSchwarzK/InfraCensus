from __future__ import annotations

from central.core import auth


def test_hash_and_verify_token() -> None:
    token = "test-token-123"
    stored = auth.hash_token(token)
    assert len(stored) >= 128
    assert auth.verify_token(token, stored) is True
    assert auth.verify_token("wrong", stored) is False


def test_parse_api_keys_and_scopes() -> None:
    api_key = "my-key"
    stored_hash = "fake-hash"
    raw = f"{stored_hash}:read|write"
    auth.pwd_context.verify = lambda *_args, **_kwargs: True
    scopes = auth.get_api_key_scopes(raw, api_key)
    assert scopes == {"read", "write"}
