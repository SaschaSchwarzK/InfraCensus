from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Protocol

from central.core.config import settings
from central.core.vault import VaultClient, VaultSettings
from central.db.models import CredentialAssignment
from central.db.session import get_session


@dataclass
class ResolvedCredentials:
    target: str
    credentials: list[dict[str, Any]]


async def resolve_credentials(
    tenant_id: int, protocol: str, targets: list[str]
) -> dict[str, list[dict[str, Any]]]:
    normalized_protocol = _normalize_protocol(protocol)
    if normalized_protocol is None:
        raise ValueError("Invalid protocol")
    assignments = _load_assignments(tenant_id, normalized_protocol)
    if not assignments:
        return {target: [] for target in targets}
    resolved: dict[str, list[dict[str, Any]]] = {}
    try:
        async with VaultClient(
            VaultSettings(
                addr=settings.vault_addr,
                token=settings.vault_token,
                kv_mount=settings.vault_kv_mount,
                namespace=settings.vault_namespace,
            )
        ) as vault:
            for target in targets:
                ip = _parse_ip(target)
                if ip is None:
                    resolved[target] = []
                    continue
                matched = [
                    assignment
                    for assignment in assignments
                    if _ip_in_subnet(ip, assignment.subnet_cidr)
                ]
                matched.sort(key=lambda entry: entry.priority, reverse=True)
                secrets: list[dict[str, Any]] = []
                for assignment in matched:
                    secret = await _fetch_secret(
                        vault, tenant_id, normalized_protocol, assignment.credential_set
                    )
                    if secret:
                        secrets.append(secret)
                resolved[target] = secrets
    except (RuntimeError, ValueError, OSError, TypeError) as exc:
        # Handle vault connection or configuration errors
        # Return empty credentials for all targets as fallback
        return {target: [] for target in targets}
    return resolved


def _load_assignments(tenant_id: int, protocol: str) -> list[CredentialAssignment]:
    with get_session() as session:
        return (
            session.query(CredentialAssignment)
            .filter(
                CredentialAssignment.tenant_id == tenant_id,
                CredentialAssignment.protocol == protocol,
            )
            .all()
        )


class _CredentialSetLike(Protocol):
    vault_index: int


async def _fetch_secret(
    vault: VaultClient,
    tenant_id: int,
    protocol: str,
    credential_set: _CredentialSetLike,
) -> dict[str, Any] | None:
    try:
        path = f"{tenant_id}/{protocol}/{credential_set.vault_index}"
        return await vault.read_secret(path)
    except (ValueError, TypeError, AttributeError) as exc:
        # Log the error but don't expose sensitive vault details
        return None
    except (ValueError, TypeError, AttributeError, KeyError, ImportError) as exc:
        # Log the error but don't expose sensitive vault details
        return None


_ALLOWED_PROTOCOLS = {"snmp", "ssh", "http", "https", "netconf"}
_PROTOCOL_RE = re.compile(r"^[a-z0-9_-]+$")


def _normalize_protocol(protocol: str) -> str | None:
    value = (protocol or "").strip().lower()
    if not value or not _PROTOCOL_RE.fullmatch(value):
        return None
    if value not in _ALLOWED_PROTOCOLS:
        return None
    return value


def _parse_ip(target: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(target)
    except ValueError:
        return None


def _ip_in_subnet(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, cidr: str) -> bool:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return ip in network
