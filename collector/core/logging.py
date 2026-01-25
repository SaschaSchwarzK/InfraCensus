from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

SERVICE_NAME = os.getenv("SERVICE_NAME", "infracensus-collector")
ENVIRONMENT = os.getenv("ENVIRONMENT", "dev")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_PRETTY = os.getenv("LOG_PRETTY", "false").lower() in {"1", "true", "yes"}


def configure_logging(level: str | None = None) -> None:
    logging.basicConfig(level=level or LOG_LEVEL, format="%(message)s")


def log_event(logger: logging.Logger, level: int, event: str, **fields: Any) -> None:
    payload: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "level": logging.getLevelName(level).lower(),
        "event": event,
        "service": SERVICE_NAME,
        "env": ENVIRONMENT,
        "component": logger.name,
    }
    payload.update(fields)
    indent = 2 if LOG_PRETTY and ENVIRONMENT == "dev" else None
    logger.log(level, json.dumps(payload, default=str, indent=indent))


def log_info(logger: logging.Logger, event: str, **fields: Any) -> None:
    log_event(logger, logging.INFO, event, **fields)


def log_warning(logger: logging.Logger, event: str, **fields: Any) -> None:
    log_event(logger, logging.WARNING, event, **fields)


def log_error(logger: logging.Logger, event: str, **fields: Any) -> None:
    log_event(logger, logging.ERROR, event, **fields)
