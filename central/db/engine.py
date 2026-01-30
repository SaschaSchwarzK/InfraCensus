from __future__ import annotations

import logging
import threading
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from central.core.config import (
    Settings,
    SettingsProxy,
    register_settings_listener,
    settings,
)

_engine_lock = threading.Lock()
logger = logging.getLogger(__name__)


def _build_engine(current: Settings | SettingsProxy) -> tuple[Engine, sessionmaker]:
    engine_kwargs: dict[str, Any] = {"future": True}
    if current.database_url.startswith("sqlite"):
        engine_kwargs["connect_args"] = {"check_same_thread": False}
        engine_kwargs["poolclass"] = NullPool
    else:
        engine_kwargs["pool_size"] = current.db_pool_size
        engine_kwargs["max_overflow"] = current.db_max_overflow
        engine_kwargs["pool_timeout"] = current.db_pool_timeout
        engine_kwargs["pool_recycle"] = current.db_pool_recycle
        engine_kwargs["pool_pre_ping"] = current.db_pool_pre_ping
    new_engine = create_engine(current.database_url, **engine_kwargs)
    new_session = sessionmaker(
        bind=new_engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
        future=True,
    )
    return new_engine, new_session


engine, SessionLocal = _build_engine(settings)


def _apply_settings(new_settings: Settings) -> None:
    global engine, SessionLocal
    new_engine, new_session = _build_engine(new_settings)
    with _engine_lock:
        old_engine = engine
        engine = new_engine
        SessionLocal = new_session
    try:
        old_engine.dispose()
    except (SQLAlchemyError, OSError) as exc:
        logger.warning("db.engine_dispose_failed", extra={"error": str(exc)})


register_settings_listener(_apply_settings)
