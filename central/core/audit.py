from __future__ import annotations

import json
import os
import random
from typing import Any

from sqlalchemy.orm import Session

from central.db.models import AuditLog
from central.db.session import get_session


def log_audit(
    actor_user_id: int | None,
    action: str,
    entity_type: str,
    entity_id: int | None,
    details: dict[str, Any] | None = None,
    session: Session | None = None,
) -> None:
    payload = json.dumps(details or {}, sort_keys=True)
    if session is None:
        raise ValueError("log_audit requires an active session")
    session.add(
        AuditLog(
            actor_user_id=actor_user_id,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            details=payload,
        )
    )


def log_security_event(
    action: str,
    outcome: str,
    actor_user_id: int | None = None,
    details: dict[str, Any] | None = None,
    session: Session | None = None,
) -> None:
    payload = {
        "outcome": outcome,
        **(details or {}),
    }
    if session is None:
        with get_session() as new_session:
            log_security_event(
                action=action,
                outcome=outcome,
                actor_user_id=actor_user_id,
                details=details,
                session=new_session,
            )
        return
    session.add(
        AuditLog(
            actor_user_id=actor_user_id,
            action=action,
            entity_type="security_event",
            entity_id=None,
            details=json.dumps(payload, sort_keys=True),
        )
    )


def should_sample_security_event(default_rate: float = 0.1) -> bool:
    try:
        rate = float(os.getenv("SECURITY_AUDIT_SAMPLE_RATE", str(default_rate)))
    except ValueError:
        rate = default_rate
    if rate <= 0:
        return False
    if rate >= 1:
        return True
    return random.random() < rate
