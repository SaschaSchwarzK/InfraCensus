from central.core.auth import has_tenant_access, highest_role, parse_roles
from central.db.models import TenantUser, UserRole


def test_parse_roles():
    roles = parse_roles("read_only,scan_operator")
    assert UserRole.read_only in roles
    assert UserRole.scan_operator in roles


def test_highest_role():
    roles = {UserRole.read_only, UserRole.user_admin}
    assert highest_role(roles) == UserRole.user_admin


def test_has_tenant_access():
    membership = TenantUser(
        tenant_id=1,
        user_id=1,
        roles="read_write",
    )
    assert has_tenant_access([membership], 1, UserRole.read_only)
    assert not has_tenant_access([membership], 2, UserRole.read_only)
