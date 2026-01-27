from __future__ import annotations

from central.db.models import TenantUser, UserRole


ROLE_ORDER = {
    UserRole.read_only: 1,
    UserRole.scan_operator: 2,
    UserRole.read_write: 3,
    UserRole.user_admin: 4,
}


def parse_roles(roles_value: str | None, fallback: UserRole | None = None) -> set[UserRole]:
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
        return ROLE_ORDER[effective] >= ROLE_ORDER[required]
    return False


def parse_api_keys(value: str | None) -> dict[str, set[str]]:
    keys: dict[str, set[str]] = {}
    if not value:
        return keys
    for entry in value.split(","):
        entry = entry.strip()
        if not entry:
            continue
        key, _, scopes_raw = entry.partition(":")
        scopes = {item.strip() for item in scopes_raw.split("|") if item.strip()}
        keys[key.strip()] = scopes
    return keys
