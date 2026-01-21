from __future__ import annotations

import json
from typing import Any

from central.db.models import AuditLog
from central.db.session import get_session


def log_audit(
    actor_user_id: int | None,
    action: str,
    entity_type: str,
    entity_id: int | None,
    details: dict[str, Any] | None = None,
) -> None:
    payload = json.dumps(details or {}, sort_keys=True)
    with get_session() as session:
        session.add(
            AuditLog(
                actor_user_id=actor_user_id,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                details=payload,
            )
        )
