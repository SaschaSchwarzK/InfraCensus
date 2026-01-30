from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal

from celery import Task

from central.core.logging import (
    configure_logging,
    log_error,
    log_info,
    log_warning,
    set_trace_id,
)
from central.db.session import get_session

if TYPE_CHECKING:  # pragma: no cover
    from central.db.models import PermanentFailure, TaskFailureLog
else:
    PermanentFailure: Any = None
    TaskFailureLog: Any = None

_structlog: Any = None
try:
    import structlog as _structlog
except (ImportError, ModuleNotFoundError):  # pragma: no cover - optional dependency
    _structlog = None

PromCounter: Any = None
PromHistogram: Any = None
try:
    from prometheus_client import Counter as PromCounter
    from prometheus_client import Histogram as PromHistogram
except (ImportError, ModuleNotFoundError):  # pragma: no cover - optional dependency
    PromCounter = None
    PromHistogram = None

_redis: Any = None
try:
    import redis as _redis
except (ImportError, ModuleNotFoundError):  # pragma: no cover - optional dependency
    _redis = None

logger = logging.getLogger(__name__)

configure_logging()


def _noop_counter(*args: Any, **kwargs: Any) -> Any:
    class _Counter:
        def labels(self, **_kwargs: Any) -> _Counter:
            return self

        def inc(self, *_args: Any, **_kwargs: Any) -> None:
            return None

    return _Counter()


def _noop_histogram(*args: Any, **kwargs: Any) -> Any:
    class _Histogram:
        def labels(self, **_kwargs: Any) -> _Histogram:
            return self

        def time(self) -> Any:
            class _Timer:
                def __enter__(self) -> None:
                    return None

                def __exit__(self, *_exc: Any) -> Literal[False]:
                    return False

            return _Timer()

    return _Histogram()


task_counter = (
    PromCounter("worker_tasks_total", "Total tasks processed", ["task_name", "status"])
    if PromCounter is not None
    else _noop_counter()
)
task_duration = (
    PromHistogram("worker_task_duration_seconds", "Task duration", ["task_name"])
    if PromHistogram is not None
    else _noop_histogram()
)

_redis_client = None
_REDIS_ERRORS: tuple[type[BaseException], ...] = (ConnectionError, OSError, ValueError)
if _redis is not None and hasattr(_redis, "RedisError"):
    _REDIS_ERRORS = (_redis.RedisError, ConnectionError, OSError, ValueError)


def _get_redis_client() -> Any:
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    if _redis is None:
        return None
    url = (
        os.getenv("REDIS_URL")
        or os.getenv("CELERY_BROKER_URL")
        or os.getenv("BROKER_URL")
        or "redis://redis:6379/0"
    )
    try:
        _redis_client = _redis.from_url(url)
    except _REDIS_ERRORS as exc:
        log_warning(logger, "redis.client_init_failed", error=str(exc))
        _redis_client = None
    return _redis_client


class ResilientTask(Task):
    autoretry_for = (Exception,)
    retry_kwargs = {"max_retries": 3}
    retry_backoff = True
    retry_backoff_max = 600  # 10 minutes
    retry_jitter = True

    @property
    def logger(self) -> logging.Logger:
        return logging.getLogger(self.name)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        set_trace_id(self.request.id if self.request else None)
        start = time.perf_counter()
        with task_duration.labels(task_name=self.name).time():
            result = super().__call__(*args, **kwargs)
        if self.request is not None:
            self.request._duration_ms = int((time.perf_counter() - start) * 1000)
        return result

    def apply_async(self, *args: Any, **kwargs: Any) -> Any:
        result = super().apply_async(*args, **kwargs)
        task_counter.labels(task_name=self.name, status="queued").inc()
        return result

    def on_success(self, retval, task_id, args, kwargs) -> None:
        task_counter.labels(task_name=self.name, status="success").inc()
        duration_ms = (
            getattr(self.request, "_duration_ms", None) if self.request else None
        )
        log_info(
            logger,
            "task.completed",
            task_id=task_id,
            task_name=self.name,
            duration_ms=duration_ms,
        )

    def on_failure(self, exc, task_id, args, kwargs, einfo) -> None:
        """Log failures to database and monitoring system"""
        task_counter.labels(task_name=self.name, status="failure").inc()
        log_error(
            logger,
            "task.failed",
            task_id=task_id,
            task_name=self.name,
            error=str(exc),
            retries=self.request.retries,
            max_retries=self.max_retries,
            duration_ms=getattr(self.request, "_duration_ms", None)
            if self.request
            else None,
        )
        if TaskFailureLog is not None:
            with get_session() as session:
                log = TaskFailureLog(
                    task_id=task_id,
                    task_name=self.name,
                    exception=str(exc),
                    traceback=str(einfo),
                    args=json.dumps(args, default=str),
                    kwargs=json.dumps(kwargs, default=str),
                    created_at=datetime.now(UTC),
                )
                session.add(log)
                session.commit()
        if self.request.retries >= self.max_retries:
            from central.workers.dlq import handle_dead_letter_task

            handle_dead_letter_task.delay(
                {
                    "task_id": task_id,
                    "task_name": self.name,
                    "error": str(exc),
                    "args": args,
                    "kwargs": kwargs,
                }
            )


class DeduplicatedTask(ResilientTask):
    dedup_ttl_seconds = 300

    def apply_async(self, args=None, kwargs=None, **options) -> Any:
        client = _get_redis_client()
        if client is not None:
            task_hash = self._compute_task_hash(args, kwargs)
            cache_key = f"task_dedup:{self.name}:{task_hash}"
            try:
                if client.exists(cache_key):
                    log_info(
                        logger,
                        "task.deduplicated",
                        task_name=self.name,
                        task_hash=task_hash,
                    )
                    return None
                client.setex(cache_key, self.dedup_ttl_seconds, "1")
            except _REDIS_ERRORS as exc:
                log_warning(
                    logger, "task.dedup_failed", task_name=self.name, error=str(exc)
                )
        return super().apply_async(args=args, kwargs=kwargs, **options)

    def _compute_task_hash(self, args, kwargs) -> str:
        data = json.dumps(
            {"args": args or [], "kwargs": kwargs or {}}, sort_keys=True, default=str
        )
        return hashlib.md5(data.encode("utf-8")).hexdigest()
