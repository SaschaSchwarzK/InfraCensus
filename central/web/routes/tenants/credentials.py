from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from json import JSONDecodeError

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse

from central.core.audit import log_audit
from central.db.models import (
    CredentialAssignment,
    CredentialSet,
    Tenant,
    User,
    UserRole,
)
from central.db.session import get_session
from central.web.auth import require_tenant_role
from central.web.routes.common import (
    _ALLOWED_CREDENTIAL_PROTOCOLS,
    WebResponse,
    _format_dt,
    _redirect_with_message,
    _safe_query,
    _wants_json,
    templates,
)

router = APIRouter()


@router.get("/tenants/{tenant_id}/credentials", response_class=HTMLResponse)
def tenant_credentials(request: Request, tenant_id: int) -> WebResponse:
    user = require_tenant_role(request, tenant_id, UserRole.user_admin)
    if not isinstance(user, User):
        return user

    def fetch_sets() -> Iterable[CredentialSet]:
        with get_session() as session:
            return (
                session.query(CredentialSet)
                .filter(CredentialSet.tenant_id == tenant_id)
                .order_by(CredentialSet.created_at.desc())
                .all()
            )

    def fetch_assignments() -> Iterable[CredentialAssignment]:
        with get_session() as session:
            return (
                session.query(CredentialAssignment)
                .filter(CredentialAssignment.tenant_id == tenant_id)
                .order_by(CredentialAssignment.priority.desc())
                .all()
            )

    def fetch_tenant() -> Iterable[Tenant]:
        with get_session() as session:
            return session.query(Tenant).filter(Tenant.id == tenant_id).all()

    sets, error = _safe_query(fetch_sets)
    assignments, _ = _safe_query(fetch_assignments)
    tenants, _ = _safe_query(fetch_tenant)
    tenant = tenants[0] if tenants else None
    set_map = {entry.id: entry.name or f"set-{entry.id}" for entry in sets}
    if _wants_json(request):
        return JSONResponse(
            {
                "tenant_id": tenant_id,
                "credential_sets": [
                    {
                        "id": entry.id,
                        "name": entry.name,
                        "protocol": entry.protocol,
                        "vault_index": entry.vault_index,
                        "created_at_utc": _format_dt(entry.created_at),
                    }
                    for entry in sets
                ],
                "assignments": [
                    {
                        "id": entry.id,
                        "subnet_cidr": entry.subnet_cidr,
                        "protocol": entry.protocol,
                        "credential_set_id": entry.credential_set_id,
                        "priority": entry.priority,
                        "created_at_utc": _format_dt(entry.created_at),
                    }
                    for entry in assignments
                ],
                "error": error,
            }
        )
    return templates.TemplateResponse(
        "tenant_credentials.html",
        {
            "request": request,
            "tenant_id": tenant_id,
            "tenant_name": tenant.name if tenant else None,
            "credential_sets": sets,
            "credential_assignments": assignments,
            "credential_set_map": set_map,
            "error": error,
            "message": request.query_params.get("message"),
            "user": user,
        },
    )


@router.post("/tenants/{tenant_id}/credentials/sets", response_model=None)
async def tenant_credential_set_create(
    request: Request,
    tenant_id: int,
    name: str | None = Form(None),
    protocol: str | None = Form(None),
    vault_index: str | None = Form(None),
) -> WebResponse:
    user = require_tenant_role(request, tenant_id, UserRole.user_admin)
    if not isinstance(user, User):
        return user
    wants_json = _wants_json(request)
    if not protocol:
        try:
            payload = await request.json()
            name = payload.get("name") if payload else name
            protocol = payload.get("protocol") if payload else protocol
            vault_index = str(payload.get("vault_index")) if payload else vault_index
        except (JSONDecodeError, ValueError, TypeError):
            protocol = None
    if not protocol:
        if wants_json:
            return JSONResponse({"error": "Protocol is required"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/credentials",
            "Protocol is required",
        )
    try:
        parsed_index = int(vault_index) if vault_index is not None else 0
    except ValueError:
        if wants_json:
            return JSONResponse({"error": "Invalid vault_index"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/credentials",
            "Invalid vault index",
        )
    with get_session() as session:
        entry = CredentialSet(
            tenant_id=tenant_id,
            name=(name or "").strip() or None,
            protocol=protocol.strip().lower(),
            vault_index=parsed_index,
        )
        session.add(entry)
        session.flush()
        log_audit(
            actor_user_id=user.id,
            action="tenant.credential_set.create",
            entity_type="credential_set",
            entity_id=entry.id,
            details={"protocol": entry.protocol, "vault_index": entry.vault_index},
            session=session,
        )
    if wants_json:
        return JSONResponse({"status": "created", "credential_set_id": entry.id})
    return _redirect_with_message(
        f"/tenants/{tenant_id}/credentials",
        "Credential set created",
    )


@router.post("/tenants/{tenant_id}/credentials/assignments", response_model=None)
async def tenant_credential_assignment_create(
    request: Request,
    tenant_id: int,
    subnet_cidr: str | None = Form(None),
    protocol: str | None = Form(None),
    credential_set_id: str | None = Form(None),
    priority: str | None = Form(None),
) -> WebResponse:
    user = require_tenant_role(request, tenant_id, UserRole.user_admin)
    if not isinstance(user, User):
        return user
    wants_json = _wants_json(request)
    if not subnet_cidr or not protocol or not credential_set_id:
        try:
            payload = await request.json()
            subnet_cidr = payload.get("subnet_cidr") if payload else subnet_cidr
            protocol = payload.get("protocol") if payload else protocol
            credential_set_id = (
                str(payload.get("credential_set_id")) if payload else credential_set_id
            )
            priority = str(payload.get("priority")) if payload else priority
        except (JSONDecodeError, ValueError, TypeError):
            subnet_cidr = subnet_cidr
    if not subnet_cidr or not protocol or not credential_set_id:
        if wants_json:
            return JSONResponse(
                {"error": "Subnet, protocol, and credential set are required"},
                status_code=400,
            )
        return _redirect_with_message(
            f"/tenants/{tenant_id}/credentials",
            "Subnet, protocol, and credential set are required",
        )
    if protocol.strip().lower() not in _ALLOWED_CREDENTIAL_PROTOCOLS:
        if wants_json:
            return JSONResponse({"error": "Invalid protocol"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/credentials",
            "Invalid protocol",
        )
    try:
        ipaddress.ip_network(subnet_cidr.strip(), strict=False)
    except ValueError:
        if wants_json:
            return JSONResponse({"error": "Invalid subnet CIDR"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/credentials",
            "Invalid subnet CIDR",
        )
    try:
        parsed_set = int(credential_set_id)
        parsed_priority = int(priority) if priority is not None else 0
    except ValueError:
        if wants_json:
            return JSONResponse(
                {"error": "Invalid credential_set_id or priority"}, status_code=400
            )
        return _redirect_with_message(
            f"/tenants/{tenant_id}/credentials",
            "Invalid credential set or priority",
        )
    with get_session() as session:
        entry = CredentialAssignment(
            tenant_id=tenant_id,
            subnet_cidr=subnet_cidr.strip(),
            protocol=protocol.strip().lower(),
            credential_set_id=parsed_set,
            priority=parsed_priority,
        )
        session.add(entry)
        session.flush()
        log_audit(
            actor_user_id=user.id,
            action="tenant.credential_assignment.create",
            entity_type="credential_assignment",
            entity_id=entry.id,
            details={
                "subnet_cidr": entry.subnet_cidr,
                "protocol": entry.protocol,
                "credential_set_id": entry.credential_set_id,
                "priority": entry.priority,
            },
            session=session,
        )
    if wants_json:
        return JSONResponse({"status": "created", "assignment_id": entry.id})
    return _redirect_with_message(
        f"/tenants/{tenant_id}/credentials",
        "Credential assignment created",
    )


@router.post(
    "/tenants/{tenant_id}/credentials/sets/{set_id}/update", response_model=None
)
async def tenant_credential_set_update(
    request: Request,
    tenant_id: int,
    set_id: int,
    name: str | None = Form(None),
    vault_index: str | None = Form(None),
) -> WebResponse:
    user = require_tenant_role(request, tenant_id, UserRole.user_admin)
    if not isinstance(user, User):
        return user
    wants_json = _wants_json(request)
    if name is None and vault_index is None:
        try:
            payload = await request.json()
            name = payload.get("name") if payload else name
            vault_index = str(payload.get("vault_index")) if payload else vault_index
        except (JSONDecodeError, ValueError, TypeError):
            name = None
    try:
        parsed_index = int(vault_index) if vault_index is not None else None
    except ValueError:
        if wants_json:
            return JSONResponse({"error": "Invalid vault_index"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/credentials",
            "Invalid vault index",
        )
    with get_session() as session:
        entry = (
            session.query(CredentialSet)
            .filter(CredentialSet.id == set_id, CredentialSet.tenant_id == tenant_id)
            .one_or_none()
        )
        if not entry:
            if wants_json:
                return JSONResponse(
                    {"error": "Credential set not found"}, status_code=404
                )
            return _redirect_with_message(
                f"/tenants/{tenant_id}/credentials",
                "Credential set not found",
            )
        if name is not None:
            entry.name = name.strip() or None
        if parsed_index is not None:
            entry.vault_index = parsed_index
        log_audit(
            actor_user_id=user.id,
            action="tenant.credential_set.update",
            entity_type="credential_set",
            entity_id=entry.id,
            details={"name": entry.name, "vault_index": entry.vault_index},
            session=session,
        )
    if wants_json:
        return JSONResponse({"status": "updated", "credential_set_id": set_id})
    return _redirect_with_message(
        f"/tenants/{tenant_id}/credentials",
        "Credential set updated",
    )


@router.post(
    "/tenants/{tenant_id}/credentials/sets/{set_id}/delete", response_model=None
)
async def tenant_credential_set_delete(
    request: Request,
    tenant_id: int,
    set_id: int,
) -> WebResponse:
    user = require_tenant_role(request, tenant_id, UserRole.user_admin)
    if not isinstance(user, User):
        return user
    wants_json = _wants_json(request)
    with get_session() as session:
        entry = (
            session.query(CredentialSet)
            .filter(CredentialSet.id == set_id, CredentialSet.tenant_id == tenant_id)
            .one_or_none()
        )
        if not entry:
            if wants_json:
                return JSONResponse(
                    {"error": "Credential set not found"}, status_code=404
                )
            return _redirect_with_message(
                f"/tenants/{tenant_id}/credentials",
                "Credential set not found",
            )
        assignment_count = (
            session.query(CredentialAssignment)
            .filter(CredentialAssignment.credential_set_id == entry.id)
            .count()
        )
        if assignment_count:
            if wants_json:
                return JSONResponse(
                    {"error": "Credential set is in use"}, status_code=409
                )
            return _redirect_with_message(
                f"/tenants/{tenant_id}/credentials",
                "Credential set is in use",
            )
        session.delete(entry)
        log_audit(
            actor_user_id=user.id,
            action="tenant.credential_set.delete",
            entity_type="credential_set",
            entity_id=entry.id,
            details={"name": entry.name},
            session=session,
        )
    if wants_json:
        return JSONResponse({"status": "deleted", "credential_set_id": set_id})
    return _redirect_with_message(
        f"/tenants/{tenant_id}/credentials",
        "Credential set deleted",
    )


@router.post(
    "/tenants/{tenant_id}/credentials/assignments/{assignment_id}/update",
    response_model=None,
)
async def tenant_credential_assignment_update(
    request: Request,
    tenant_id: int,
    assignment_id: int,
    subnet_cidr: str | None = Form(None),
    protocol: str | None = Form(None),
    credential_set_id: str | None = Form(None),
    priority: str | None = Form(None),
) -> WebResponse:
    user = require_tenant_role(request, tenant_id, UserRole.user_admin)
    if not isinstance(user, User):
        return user
    wants_json = _wants_json(request)
    if (
        subnet_cidr is None
        and protocol is None
        and credential_set_id is None
        and priority is None
    ):
        try:
            payload = await request.json()
            subnet_cidr = payload.get("subnet_cidr") if payload else subnet_cidr
            protocol = payload.get("protocol") if payload else protocol
            credential_set_id = (
                str(payload.get("credential_set_id")) if payload else credential_set_id
            )
            priority = str(payload.get("priority")) if payload else priority
        except (JSONDecodeError, ValueError, TypeError):
            priority = None
    if (
        protocol is not None
        and protocol.strip().lower() not in _ALLOWED_CREDENTIAL_PROTOCOLS
    ):
        if wants_json:
            return JSONResponse({"error": "Invalid protocol"}, status_code=400)
        return _redirect_with_message(
            f"/tenants/{tenant_id}/credentials",
            "Invalid protocol",
        )
    if subnet_cidr is not None:
        try:
            ipaddress.ip_network(subnet_cidr.strip(), strict=False)
        except ValueError:
            if wants_json:
                return JSONResponse({"error": "Invalid subnet CIDR"}, status_code=400)
            return _redirect_with_message(
                f"/tenants/{tenant_id}/credentials",
                "Invalid subnet CIDR",
            )
    try:
        parsed_set_id = (
            int(credential_set_id) if credential_set_id is not None else None
        )
        parsed_priority = int(priority) if priority is not None else None
    except ValueError:
        if wants_json:
            return JSONResponse(
                {"error": "Invalid credential_set_id or priority"}, status_code=400
            )
        return _redirect_with_message(
            f"/tenants/{tenant_id}/credentials",
            "Invalid credential set or priority",
        )
    with get_session() as session:
        entry = (
            session.query(CredentialAssignment)
            .filter(
                CredentialAssignment.id == assignment_id,
                CredentialAssignment.tenant_id == tenant_id,
            )
            .one_or_none()
        )
        if not entry:
            if wants_json:
                return JSONResponse({"error": "Assignment not found"}, status_code=404)
            return _redirect_with_message(
                f"/tenants/{tenant_id}/credentials",
                "Assignment not found",
            )
        if subnet_cidr is not None:
            entry.subnet_cidr = subnet_cidr.strip()
        if protocol is not None:
            entry.protocol = protocol.strip().lower()
        if parsed_set_id is not None:
            entry.credential_set_id = parsed_set_id
        if parsed_priority is not None:
            entry.priority = parsed_priority
        log_audit(
            actor_user_id=user.id,
            action="tenant.credential_assignment.update",
            entity_type="credential_assignment",
            entity_id=entry.id,
            details={
                "subnet_cidr": entry.subnet_cidr,
                "protocol": entry.protocol,
                "credential_set_id": entry.credential_set_id,
                "priority": entry.priority,
            },
            session=session,
        )
    if wants_json:
        return JSONResponse({"status": "updated", "assignment_id": assignment_id})
    return _redirect_with_message(
        f"/tenants/{tenant_id}/credentials",
        "Assignment updated",
    )


@router.post(
    "/tenants/{tenant_id}/credentials/assignments/{assignment_id}/delete",
    response_model=None,
)
async def tenant_credential_assignment_delete(
    request: Request,
    tenant_id: int,
    assignment_id: int,
) -> WebResponse:
    user = require_tenant_role(request, tenant_id, UserRole.user_admin)
    if not isinstance(user, User):
        return user
    wants_json = _wants_json(request)
    with get_session() as session:
        entry = (
            session.query(CredentialAssignment)
            .filter(
                CredentialAssignment.id == assignment_id,
                CredentialAssignment.tenant_id == tenant_id,
            )
            .one_or_none()
        )
        if not entry:
            if wants_json:
                return JSONResponse({"error": "Assignment not found"}, status_code=404)
            return _redirect_with_message(
                f"/tenants/{tenant_id}/credentials",
                "Assignment not found",
            )
        session.delete(entry)
        log_audit(
            actor_user_id=user.id,
            action="tenant.credential_assignment.delete",
            entity_type="credential_assignment",
            entity_id=entry.id,
            details={"subnet_cidr": entry.subnet_cidr},
            session=session,
        )
    if wants_json:
        return JSONResponse({"status": "deleted", "assignment_id": assignment_id})
    return _redirect_with_message(
        f"/tenants/{tenant_id}/credentials",
        "Assignment deleted",
    )
