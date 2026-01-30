import os

from celery import Celery
from celery.schedules import crontab
from kombu import Exchange, Queue

celery_app = Celery("infracensus")

celery_app.conf.update(
    broker_url=os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0"),
    result_backend=os.getenv("CELERY_RESULT_BACKEND", "redis://redis:6379/0"),
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    # Task routing
    task_routes={
        "workers.ingest_scan_result": {"queue": "ingestion"},
        "workers.parse_observation": {"queue": "parsing"},
        "workers.reconcile_device": {"queue": "reconciliation"},
        "workers.create_snapshot": {"queue": "snapshots"},
        "workers.detect_changes": {"queue": "changes"},
        "workers.export_inventory": {"queue": "exports"},
    },
    # Worker configuration
    worker_prefetch_multiplier=4,
    worker_max_tasks_per_child=1000,
    # Retry configuration
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    # Result expiration
    result_expires=3600,
    imports=(
        "central.workers.ingestion",
        "central.workers.parsers",
        "central.workers.reconciliation",
        "central.workers.snapshots",
        "central.workers.change_detection",
        "central.workers.maintenance",
        "central.workers.exports",
        "central.workers.scheduler",
        "central.workers.rotation",
    ),
)

# Queue definitions
celery_app.conf.task_queues = (
    Queue(
        "ingestion", Exchange("ingestion"), routing_key="ingestion", priority=10
    ),  # Highest priority
    Queue("parsing", Exchange("parsing"), routing_key="parsing", priority=8),
    Queue(
        "reconciliation",
        Exchange("reconciliation"),
        routing_key="reconciliation",
        priority=6,
    ),
    Queue("snapshots", Exchange("snapshots"), routing_key="snapshots", priority=4),
    Queue("changes", Exchange("changes"), routing_key="changes", priority=2),
    Queue("exports", Exchange("exports"), routing_key="exports", priority=1),
)

celery_app.conf.beat_schedule = {
    "cleanup-old-observations": {
        "task": "workers.cleanup_old_observations",
        "schedule": crontab(hour=2, minute=0),
        "args": (90,),
    },
    "dispatch-export-schedules": {
        "task": "workers.dispatch_export_schedules",
        "schedule": crontab(minute="*"),
        "args": (100,),
    },
    "rotate-credentials": {
        "task": "workers.rotate_credentials",
        "schedule": crontab(hour=3, minute=0),
        "args": (),
    },
}
