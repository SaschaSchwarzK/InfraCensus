from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

from central.core.celery_config import celery_app
from central.core.logging import log_error
from central.db.session import get_session

try:
    from central.db.models import PermanentFailure
except (ImportError, ModuleNotFoundError):  # pragma: no cover - optional model
    PermanentFailure = None

logger = logging.getLogger(__name__)


@celery_app.task(name="workers.handle_dead_letter")
def handle_dead_letter_task(task_data: dict) -> dict:
    """
    Process tasks that failed after all retries.
    """
    log_error(
        logger,
        "task.dead_letter",
        task_name=task_data.get("task_name"),
        task_id=task_data.get("task_id"),
        error=task_data.get("error"),
        args=task_data.get("args"),
    )
    if PermanentFailure is not None:
        with get_session() as session:
            failure = PermanentFailure(
                task_name=task_data.get("task_name"),
                task_id=task_data.get("task_id"),
                error=task_data.get("error"),
                args=json.dumps(task_data.get("args"), default=str),
                kwargs=json.dumps(task_data.get("kwargs"), default=str),
                created_at=datetime.now(UTC),
            )
            session.add(failure)
            session.commit()
    return {"handled": True}
