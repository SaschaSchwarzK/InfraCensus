from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any

from central.core.vault import VaultClient, VaultSettings
from central.db.models import CredentialAssignment, CredentialSet
from central.db.session import get_session
from central.core.config import settings


@dataclass
class ResolvedCredentials:
    target: str
    credentials: list[dict[str, Any]]


def resolve_credentials(tenant_id: int, protocol: str, targets: list[str]) -> dict[str, list[dict[str, Any]]]:
    assignments = _load_assignments(tenant_id, protocol)
    if not assignments:
        return {target: [] for target in targets}
    vault = VaultClient(
        VaultSettings(
            addr=settings.vault_addr,
            token=settings.vault_token,
            kv_mount=settings.vault_kv_mount,
            namespace=settings.vault_namespace,
        )
    )
    resolved: dict[str, list[dict[str, Any]]] = {}
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
            secret = _fetch_secret(vault, tenant_id, protocol, assignment.credential_set)
            if secret:
                secrets.append(secret)
        resolved[target] = secrets
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


def _fetch_secret(
    vault: VaultClient,
    tenant_id: int,
    protocol: str,
    credential_set: CredentialSet,
) -> dict[str, Any] | None:
    path = f"{tenant_id}/{protocol}/{credential_set.vault_index}"
    return vault.read_secret(path)


def _parse_ip(target: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(target)
    except ValueError:
        return None


def _ip_in_subnet(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address, cidr: str
) -> bool:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return ip in network
