from __future__ import annotations

import logging
from datetime import UTC, datetime

from celery.exceptions import (
    OperationalError as CeleryOperationalError,
)
from celery.exceptions import (
    TimeoutError as CeleryTimeoutError,
)

from central.core.celery_config import celery_app
from central.core.logging import log_info


@celery_app.task(name="workers.health_check")
def health_check_task() -> dict:
    log_info(logging.getLogger(__name__), "worker.health_check")
    return {
        "status": "healthy",
        "timestamp": datetime.now(UTC).isoformat(),
    }


def check_all_queues() -> dict:
    queues = ["ingestion", "parsing", "reconciliation", "snapshots", "changes"]
    results = {}
    for queue in queues:
        try:
            result = health_check_task.apply_async(queue=queue, expires=10).get(
                timeout=15
            )
            results[queue] = result.get("status", "unknown")
        except (CeleryTimeoutError, CeleryOperationalError, RuntimeError) as exc:
            results[queue] = f"unhealthy: {exc}"
    log_info(logging.getLogger(__name__), "worker.health_check_all", results=results)
    return results
