from __future__ import annotations

import hashlib
import hmac
import secrets

from passlib.context import CryptContext

from central.db.models import TenantUser, UserRole

# Secure password hashing context using Argon2
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


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
    aliases = {
        "read_only": UserRole.read_only,
        "ro": UserRole.read_only,
        "scan_operator": UserRole.scan_operator,
        "read_write": UserRole.read_write,
        "rw": UserRole.read_write,
        "user_admin": UserRole.user_admin,
    }
    if roles_value:
        for item in roles_value.split(","):
            item = item.strip()
            if not item:
                continue
            key = item.lower()
            if key in aliases:
                roles.add(aliases[key])
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
    """Hash API key using secure Argon2 algorithm."""
    if pepper:
        # Use HMAC with pepper for additional security
        salted_key = hmac.new(
            pepper.encode("utf-8"), api_key.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return pwd_context.hash(salted_key)
    return pwd_context.hash(api_key)


def get_api_key_scopes(
    value: str | None, api_key: str, pepper: str | None = None
) -> set[str]:
    if not value or not api_key:
        return set()
    for stored_hash, scopes in parse_api_keys(value).items():
        # Use secure verification for Argon2 hashes
        try:
            if pepper:
                salted_key = hmac.new(
                    pepper.encode("utf-8"), api_key.encode("utf-8"), hashlib.sha256
                ).hexdigest()
                if pwd_context.verify(salted_key, stored_hash):
                    return scopes
            else:
                if pwd_context.verify(api_key, stored_hash):
                    return scopes
        except ValueError:
            # Handle invalid hash format, continue to next
            continue
    return set()


def hash_token(token: str) -> str:
    salt = secrets.token_bytes(32)
    key = hashlib.pbkdf2_hmac("sha256", token.encode("utf-8"), salt, 100000)
    return salt.hex() + key.hex()


def verify_token(token: str, stored_hash: str) -> bool:
    if not stored_hash:
        return False
    try:
        if len(stored_hash) < 128:
            return False
        salt = bytes.fromhex(stored_hash[:64])
        expected = bytes.fromhex(stored_hash[64:])
    except ValueError:
        return False
    derived = hashlib.pbkdf2_hmac("sha256", token.encode("utf-8"), salt, 100000)
    return secrets.compare_digest(derived, expected)
