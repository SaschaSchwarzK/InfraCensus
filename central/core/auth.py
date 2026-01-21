from __future__ import annotations

from central.db.models import TenantUser, UserRole


ROLE_ORDER = {
    UserRole.read_only: 1,
    UserRole.read_write: 2,
    UserRole.user_admin: 3,
}


def has_tenant_access(
    memberships: list[TenantUser], tenant_id: int, required: UserRole
) -> bool:
    for membership in memberships:
        if membership.tenant_id != tenant_id:
            continue
        return ROLE_ORDER[membership.role] >= ROLE_ORDER[required]
    return False
