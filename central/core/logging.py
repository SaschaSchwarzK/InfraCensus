from __future__ import annotations

import json
import logging
import os
import random
import time
import traceback
from contextvars import ContextVar
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable

SERVICE_NAME = os.getenv("SERVICE_NAME", "infracensus")
ENVIRONMENT = os.getenv("ENVIRONMENT", "dev")
SCHEMA_VERSION = "1.0"
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_PRETTY = os.getenv("LOG_PRETTY", "false").lower() in {"1", "true", "yes"}
LOG_SAMPLE_DEFAULT = float(os.getenv("LOG_SAMPLE_DEFAULT", "1.0"))
LOG_SAMPLE_RATES = os.getenv("LOG_SAMPLE_RATES", "")

_trace_id: ContextVar[str | None] = ContextVar("trace_id", default=None)


def set_trace_id(value: str | None) -> None:
    _trace_id.set(value)


def get_trace_id() -> str | None:
    return _trace_id.get()


def configure_logging() -> None:
    logging.basicConfig(level=LOG_LEVEL, format="%(message)s")


def _sample_rate_for_event(event: str) -> float:
    if not LOG_SAMPLE_RATES:
        return LOG_SAMPLE_DEFAULT
    rates: dict[str, float] = {}
    for pair in LOG_SAMPLE_RATES.split(","):
        if not pair.strip():
            continue
        key, _, value = pair.partition("=")
        try:
            rates[key.strip()] = float(value)
        except ValueError:
            continue
    return rates.get(event, LOG_SAMPLE_DEFAULT)


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
    payload: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
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


def log_info(logger: logging.Logger, event: str, message: str | None = None, **fields: Any) -> None:
    log_event(logger, logging.INFO, event, message, **fields)


def log_warning(logger: logging.Logger, event: str, message: str | None = None, **fields: Any) -> None:
    log_event(logger, logging.WARNING, event, message, **fields)


def log_error(logger: logging.Logger, event: str, message: str | None = None, **fields: Any) -> None:
    log_event(logger, logging.ERROR, event, message, **fields)


def log_exception(logger: logging.Logger, event: str, exc: BaseException, message: str | None = None, **fields: Any) -> None:
    fields["exc"] = exc
    log_event(logger, logging.ERROR, event, message, **fields)


def log_duration(event: str, logger: logging.Logger | None = None, level: int = logging.INFO, **fields: Any) -> Callable:
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any):
            start = time.perf_counter()
            try:
                return func(*args, **kwargs)
            finally:
                duration_ms = int((time.perf_counter() - start) * 1000)
                target_logger = logger or logging.getLogger(func.__module__)
                log_event(target_logger, level, event, duration_ms=duration_ms, **fields)

        return wrapper

    return decorator
