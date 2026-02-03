from __future__ import annotations

import json
import os
import secrets
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
    if session is None:
        raise ValueError("log_audit requires an active session")
    try:
        payload = json.dumps(details or {}, sort_keys=True)
        session.add(
            AuditLog(
                actor_user_id=actor_user_id,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                details=payload,
            )
        )
    except (ValueError, TypeError) as exc:
        # Handle JSON serialization errors or database constraint violations
        import sys

        print(f"Failed to log audit event: {exc}", file=sys.stderr)


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
        try:
            with get_session() as new_session:
                log_security_event(
                    action=action,
                    outcome=outcome,
                    actor_user_id=actor_user_id,
                    details=details,
                    session=new_session,
                )
        except (ValueError, TypeError, RuntimeError) as exc:
            # Handle database connection or session errors
            import sys

            print(
                f"Failed to create session for security event: {exc}", file=sys.stderr
            )
        return
    try:
        session.add(
            AuditLog(
                actor_user_id=actor_user_id,
                action=action,
                entity_type="security_event",
                entity_id=None,
                details=json.dumps(payload, sort_keys=True),
            )
        )
    except (ValueError, TypeError) as exc:
        # Handle JSON serialization errors or database constraint violations
        # Log to stderr as fallback since audit logging failed
        import sys

        print(f"Failed to log security event: {exc}", file=sys.stderr)


def should_sample_security_event(default_rate: float = 0.1) -> bool:
    try:
        rate = float(os.getenv("SECURITY_AUDIT_SAMPLE_RATE", str(default_rate)))
    except ValueError:
        rate = default_rate
    if rate <= 0:
        return False
    if rate >= 1:
        return True
    threshold = int(rate * 1_000_000)
    if threshold <= 0:
        return False
    return secrets.randbelow(1_000_000) < threshold
