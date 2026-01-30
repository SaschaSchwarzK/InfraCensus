from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from central.core.celery_config import celery_app
from central.core.logging import log_info
from central.db.models import Observation
from central.db.session import get_session


@celery_app.task(name="workers.cleanup_old_observations")
def cleanup_old_observations_task(days_old: int = 90) -> dict:
    cutoff_date = datetime.now(UTC) - timedelta(days=days_old)
    with get_session() as session:
        deleted = (
            session.query(Observation)
            .filter(
                Observation.created_at < cutoff_date,
                Observation.device_id.isnot(None),
            )
            .delete(synchronize_session=False)
        )
        session.commit()
    log_info(
        logging.getLogger(__name__),
        "maintenance.cleanup_observations",
        deleted=deleted,
        days_old=days_old,
    )
    return {"deleted": deleted, "cutoff_date": cutoff_date.isoformat()}
