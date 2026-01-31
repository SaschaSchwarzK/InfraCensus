from __future__ import annotations

import hashlib
import hmac

from central.db.models import TenantUser, UserRole

ROLE_ORDER = {
    UserRole.read_only: 1,
    UserRole.scan_operator: 2,
    UserRole.read_write: 3,
    UserRole.user_admin: 4,
}


def parse_roles(
    roles_value: str | None, fallback: UserRole | None = None
) -> set[UserRole]:
    roles: set[UserRole] = set()
    if roles_value:
        for item in roles_value.split(","):
            item = item.strip()
            if not item:
                continue
            try:
                roles.add(UserRole(item))
            except ValueError:
                continue
    if not roles and fallback is not None:
        roles.add(fallback)
    return roles


def highest_role(roles: set[UserRole]) -> UserRole:
    if not roles:
        return UserRole.read_only
    return max(roles, key=lambda role: ROLE_ORDER[role])


def has_tenant_access(
    memberships: list[TenantUser], tenant_id: int, required: UserRole
) -> bool:
    for membership in memberships:
        if membership.tenant_id != tenant_id:
            continue
        roles = parse_roles(membership.roles, membership.role)
        effective = highest_role(roles)
        try:
            return ROLE_ORDER[effective] >= ROLE_ORDER[required]
        except KeyError:
            # Handle unknown roles by denying access
            return False
    return False


def parse_api_keys(value: str | None) -> dict[str, set[str]]:
    keys: dict[str, set[str]] = {}
    if not value:
        return keys
    for entry in value.split(","):
        entry = entry.strip()
        if not entry:
            continue
        key_hash, _, scopes_raw = entry.partition(":")
        scopes = {item.strip() for item in scopes_raw.split("|") if item.strip()}
        if key_hash:
            keys[key_hash.strip()] = scopes
    return keys


def _hash_api_key(api_key: str, pepper: str | None = None) -> str:
    if pepper:
        return hmac.new(
            pepper.encode("utf-8"), api_key.encode("utf-8"), hashlib.sha256
        ).hexdigest()
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def get_api_key_scopes(
    value: str | None, api_key: str, pepper: str | None = None
) -> set[str]:
    if not value or not api_key:
        return set()
    key_hash = _hash_api_key(api_key, pepper)
    for stored_hash, scopes in parse_api_keys(value).items():
        if hmac.compare_digest(stored_hash, key_hash):
            return scopes
    return set()
