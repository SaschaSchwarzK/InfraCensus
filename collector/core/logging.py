from __future__ import annotations

import json
import logging
import os
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

SERVICE_NAME = os.getenv("SERVICE_NAME", "infracensus-collector")
ENVIRONMENT = os.getenv("ENVIRONMENT", "dev")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_PRETTY = os.getenv("LOG_PRETTY", "false").lower() in {"1", "true", "yes"}

_trace_id: ContextVar[str | None] = ContextVar("trace_id", default=None)
_collector_id: ContextVar[str | None] = ContextVar("collector_id", default=None)
_job_id: ContextVar[str | None] = ContextVar("job_id", default=None)


def set_trace_id(value: str | None) -> None:
    _trace_id.set(value)


def get_trace_id() -> str | None:
    return _trace_id.get()


def set_log_context(
    *, collector_id: str | None = None, job_id: str | None = None
) -> None:
    if collector_id is not None:
        _collector_id.set(collector_id)
    if job_id is not None:
        _job_id.set(job_id)


def get_log_context() -> dict[str, str]:
    context: dict[str, str] = {}
    collector_id = _collector_id.get()
    if collector_id:
        context["collector_id"] = collector_id
    job_id = _job_id.get()
    if job_id:
        context["job_id"] = job_id
    return context


def configure_logging(level: str | None = None) -> None:
    logging.basicConfig(level=level or LOG_LEVEL, format="%(message)s")


def log_event(logger: logging.Logger, level: int, event: str, **fields: Any) -> None:
    payload: dict[str, Any] = {
        "ts": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "level": logging.getLevelName(level).lower(),
        "event": event,
        "service": SERVICE_NAME,
        "env": ENVIRONMENT,
        "component": logger.name,
    }
    trace_id = get_trace_id()
    if trace_id:
        payload["trace_id"] = trace_id
    for key, value in get_log_context().items():
        payload.setdefault(key, value)
    payload.update(fields)
    indent = 2 if LOG_PRETTY and ENVIRONMENT == "dev" else None
    logger.log(level, json.dumps(payload, default=str, indent=indent))


def log_info(logger: logging.Logger, event: str, **fields: Any) -> None:
    log_event(logger, logging.INFO, event, **fields)


def log_warning(logger: logging.Logger, event: str, **fields: Any) -> None:
    log_event(logger, logging.WARNING, event, **fields)


def log_error(logger: logging.Logger, event: str, **fields: Any) -> None:
    log_event(logger, logging.ERROR, event, **fields)
