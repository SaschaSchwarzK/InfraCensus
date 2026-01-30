from __future__ import annotations

import logging
from datetime import UTC, datetime

from central.core.celery_config import celery_app
from central.core.logging import log_info, log_warning
from central.db.models import ExportSchedule
from central.db.session import get_session
from central.workers.exports import export_inventory_task


@celery_app.task(name="workers.dispatch_export_schedules")
def dispatch_export_schedules_task(limit: int = 100) -> dict[str, int]:
    now = datetime.now(UTC)
    triggered = 0
    skipped = 0
    with get_session() as session:
        entries = (
            session.query(ExportSchedule)
            .filter(ExportSchedule.actual_start_at_utc.is_(None))
            .filter(ExportSchedule.scheduled_at_utc <= now)
            .filter(
                (ExportSchedule.not_before_utc.is_(None))
                | (ExportSchedule.not_before_utc <= now)
            )
            .filter(
                (ExportSchedule.not_after_utc.is_(None))
                | (ExportSchedule.not_after_utc >= now)
            )
            .order_by(ExportSchedule.scheduled_at_utc.asc())
            .limit(limit)
            .all()
        )
        for entry in entries:
            exporter = (entry.exporter or "").strip()
            if not exporter:
                skipped += 1
                log_warning(
                    logging.getLogger(__name__),
                    "scheduler.exporter_missing",
                    export_schedule_id=entry.id,
                )
                continue
            entry.actual_start_at_utc = now
            payload = {
                "tenant_id": entry.tenant_id,
                "site_id": entry.site_id,
                "export_schedule_id": entry.id,
            }
            export_inventory_task.delay(exporter, payload, None, entry.id)
            triggered += 1
        session.commit()
    log_info(
        logging.getLogger(__name__),
        "scheduler.dispatch_complete",
        triggered=triggered,
        skipped=skipped,
    )
    return {"triggered": triggered, "skipped": skipped}
