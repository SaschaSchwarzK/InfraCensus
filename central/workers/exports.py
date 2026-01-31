from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from central.core.celery_config import celery_app
from central.core.logging import log_info, log_warning
from central.core.plugins import PluginSettings
from central.db.models import ExportSchedule
from central.db.session import get_session
from central.plugins import load_plugins, registry


@celery_app.task(name="workers.export_inventory")
def export_inventory_task(
    exporter: str,
    payload: dict[str, Any],
    settings: dict[str, Any] | None = None,
    export_schedule_id: int | None = None,
) -> dict[str, Any]:
    plugin_settings = PluginSettings()
    load_plugins(plugin_settings.modules)
    try:
        plugin = registry.create(exporter, settings or {})
    except KeyError:
        log_warning(logging.getLogger(__name__), "exporter.unknown", exporter=exporter)
        return {"status": "error", "error": "unknown_exporter"}
    log_info(logging.getLogger(__name__), "exporter.run", exporter=exporter)
    try:
        result = plugin.run(payload)
        _mark_schedule_finished(export_schedule_id)
        return {"status": "ok", "exporter": exporter, "result": result}
    except (RuntimeError, ValueError, OSError, TypeError, AttributeError, KeyError, ImportError) as exc:
        log_warning(
            logging.getLogger(__name__),
            "exporter.failed",
            exporter=exporter,
            error=str(exc),
        )
        _mark_schedule_finished(export_schedule_id)
        return {"status": "error", "error": str(exc)}


def _mark_schedule_finished(export_schedule_id: int | None) -> None:
    if export_schedule_id is None:
        return
    now = datetime.now(UTC)
    with get_session() as session:
        entry = (
            session.query(ExportSchedule)
            .filter(ExportSchedule.id == export_schedule_id)
            .one_or_none()
        )
        if not entry:
            return
        entry.finished_at_utc = now
        session.commit()
