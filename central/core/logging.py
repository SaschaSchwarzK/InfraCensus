from __future__ import annotations

import json
import logging
import os
import random
import time
import traceback
from collections.abc import Callable
from contextvars import ContextVar
from datetime import UTC, datetime
from functools import wraps
from typing import Any

SERVICE_NAME = os.getenv("SERVICE_NAME", "infracensus")
ENVIRONMENT = os.getenv("ENVIRONMENT", "dev")
SCHEMA_VERSION = "1.0"
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_PRETTY = os.getenv("LOG_PRETTY", "false").lower() in {"1", "true", "yes"}
LOG_SAMPLE_DEFAULT = float(os.getenv("LOG_SAMPLE_DEFAULT", "1.0"))
LOG_SAMPLE_RATES = os.getenv("LOG_SAMPLE_RATES", "")
_LOG_SAMPLE_RATE_MAP: dict[str, float] = {}
if LOG_SAMPLE_RATES:
    for pair in LOG_SAMPLE_RATES.split(","):
        if not pair.strip():
            continue
        key, _, value = pair.partition("=")
        try:
            _LOG_SAMPLE_RATE_MAP[key.strip()] = float(value)
        except ValueError:
            continue

_trace_id: ContextVar[str | None] = ContextVar("trace_id", default=None)
_tenant_id: ContextVar[str | None] = ContextVar("tenant_id", default=None)
_collector_id: ContextVar[str | None] = ContextVar("collector_id", default=None)
_job_id: ContextVar[str | None] = ContextVar("job_id", default=None)
_user_id: ContextVar[str | None] = ContextVar("user_id", default=None)


def set_trace_id(value: str | None) -> None:
    _trace_id.set(value)


def get_trace_id() -> str | None:
    return _trace_id.get()


def set_log_context(
    *,
    tenant_id: str | None = None,
    collector_id: str | None = None,
    job_id: str | None = None,
    user_id: str | None = None,
) -> None:
    if tenant_id is not None:
        _tenant_id.set(tenant_id)
    if collector_id is not None:
        _collector_id.set(collector_id)
    if job_id is not None:
        _job_id.set(job_id)
    if user_id is not None:
        _user_id.set(user_id)


def get_log_context() -> dict[str, str]:
    context: dict[str, str] = {}
    for key, var in (
        ("tenant_id", _tenant_id),
        ("collector_id", _collector_id),
        ("job_id", _job_id),
        ("user_id", _user_id),
    ):
        value = var.get()
        if value:
            context[key] = value
    return context


def configure_logging() -> None:
    logging.basicConfig(level=LOG_LEVEL, format="%(message)s")


def _sample_rate_for_event(event: str) -> float:
    if not _LOG_SAMPLE_RATE_MAP:
        return LOG_SAMPLE_DEFAULT
    return _LOG_SAMPLE_RATE_MAP.get(event, LOG_SAMPLE_DEFAULT)


def log_event(
    logger: logging.Logger,
    level: int,
    event: str,
    message: str | None = None,
    **fields: Any,
) -> None:
    rate = _sample_rate_for_event(event)
    if rate < 1.0 and random.random() > rate:
        return
    
    # Cache timestamp and context for performance
    timestamp = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    context = get_log_context()
    
    payload: dict[str, Any] = {
        "ts": timestamp,
        "level": logging.getLevelName(level).lower(),
        "event": event,
        "service": SERVICE_NAME,
        "env": ENVIRONMENT,
        "schema_version": SCHEMA_VERSION,
        "component": logger.name,
    }
    trace_id = get_trace_id()
    if trace_id:
        payload["trace_id"] = trace_id
    payload.update(context)
    if message:
        payload["message"] = message
    for key, value in fields.items():
        if key == "exc" and isinstance(value, BaseException):
            payload["exception_type"] = type(value).__name__
            payload["exception_message"] = str(value)
            payload["stacktrace"] = "".join(
                traceback.format_exception(type(value), value, value.__traceback__)
            )
            continue
        if isinstance(value, Exception):
            payload[key] = str(value)
        else:
            payload[key] = value
    indent = 2 if LOG_PRETTY and ENVIRONMENT == "dev" else None
    logger.log(level, json.dumps(payload, default=str, indent=indent))


def log_info(
    logger: logging.Logger, event: str, message: str | None = None, **fields: Any
) -> None:
    log_event(logger, logging.INFO, event, message, **fields)


def log_warning(
    logger: logging.Logger, event: str, message: str | None = None, **fields: Any
) -> None:
    log_event(logger, logging.WARNING, event, message, **fields)


def log_error(
    logger: logging.Logger, event: str, message: str | None = None, **fields: Any
) -> None:
    log_event(logger, logging.ERROR, event, message, **fields)


def log_exception(
    logger: logging.Logger,
    event: str,
    exc: BaseException,
    message: str | None = None,
    **fields: Any,
) -> None:
    fields["exc"] = exc
    log_event(logger, logging.ERROR, event, message, **fields)


def log_duration(
    event: str,
    logger: logging.Logger | None = None,
    level: int = logging.INFO,
    **fields: Any,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            start = time.perf_counter()
            try:
                return func(*args, **kwargs)
            finally:
                duration_ms = int((time.perf_counter() - start) * 1000)
                target_logger = logger or logging.getLogger(func.__module__)
                log_event(
                    target_logger, level, event, duration_ms=duration_ms, **fields
                )

        return wrapper

    return decorator
