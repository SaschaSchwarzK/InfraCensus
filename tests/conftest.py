from __future__ import annotations

import os
import tempfile
import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import ProgrammingError

_CONTAINER = None
_TEST_DATABASES: set[str] = set()


def _normalize_db_url(database_url: str) -> str:
    if database_url.startswith("postgresql+psycopg2://"):
        return database_url.replace(
            "postgresql+psycopg2://", "postgresql+psycopg://", 1
        )
    if database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+psycopg://", 1)
    if database_url.startswith("postgres://"):
        return database_url.replace("postgres://", "postgresql+psycopg://", 1)
    return database_url


def pytest_configure() -> None:
    global _CONTAINER
    os.environ.setdefault("SESSION_SECRET", "test-session-secret-0123456789abcdef")
    os.environ.setdefault(
        "CENTRAL_SESSION_SECRET", "test-session-secret-0123456789abcdef"
    )
    os.environ.setdefault("CA_BASE_DIR", tempfile.mkdtemp(prefix="infracensus-ca-"))
    os.environ.setdefault("CA_ALLOW_ABSOLUTE_PATHS", "1")
    if os.getenv("DATABASE_URL"):
        return

    try:
        from testcontainers.postgres import PostgresContainer
    except Exception as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "DATABASE_URL not set and testcontainers is unavailable. "
            "Install testcontainers or set DATABASE_URL to run tests."
        ) from exc

    _CONTAINER = PostgresContainer("postgres:15")
    _CONTAINER.start()
    database_url = _normalize_db_url(_CONTAINER.get_connection_url())
    os.environ["TEST_DATABASE_URL"] = database_url


def pytest_sessionfinish(session, exitstatus) -> None:
    if _CONTAINER is not None:
        db_url = os.getenv("TEST_DATABASE_URL") or os.getenv("DATABASE_URL")
        if db_url and "psycopg" in db_url and _TEST_DATABASES:
            admin_url = db_url.rsplit("/", 1)[0] + "/postgres"
            engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
            try:
                with engine.connect() as conn:
                    for db_name in _TEST_DATABASES:
                        conn.execute(
                            text(
                                "SELECT pg_terminate_backend(pid) "
                                "FROM pg_stat_activity "
                                "WHERE datname = :db_name AND pid <> pg_backend_pid()"
                            ),
                            {"db_name": db_name},
                        )
                        conn.execute(text(f'DROP DATABASE IF EXISTS "{db_name}"'))
            finally:
                engine.dispose()
        try:
            _CONTAINER.stop()
        except Exception:
            pass


@pytest.fixture(autouse=True)
def _isolate_test_db(monkeypatch):
    db_url = os.getenv("DATABASE_URL") or os.getenv("TEST_DATABASE_URL")
    if db_url and db_url.startswith("sqlite"):
        yield
        try:
            import central.db.engine as engine_module

            engine_module.engine.dispose()
        except Exception:
            pass
        return
    if db_url and "psycopg" in db_url:
        if "SESSION_SECRET" not in os.environ:
            os.environ["SESSION_SECRET"] = "test-session-secret-0123456789abcdef"
        db_url = f"{db_url.rstrip('/')}_{uuid.uuid4().hex}"
        monkeypatch.setenv("DATABASE_URL", db_url)
        monkeypatch.setenv("CENTRAL_DATABASE_URL", db_url)
        monkeypatch.setenv("SQLALCHEMY_DATABASE_URL", db_url)
        monkeypatch.setenv("DATABASE_URI", db_url)
        db_name = db_url.rsplit("/", 1)[1]
        _TEST_DATABASES.add(db_name)
        admin_url = db_url.rsplit("/", 1)[0] + "/postgres"
        engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
        try:
            with engine.connect() as conn:
                conn.execute(text(f'CREATE DATABASE "{db_name}"'))
        except ProgrammingError:
            pass
        finally:
            engine.dispose()

        import central.db.engine as engine_module
        from central.core.config import Settings
        from central.db.base import Base
        from central.db.engine import _build_engine

        config = {
            "environment": "test",
            "database_url": db_url,
            "session_secret": os.environ.get(
                "SESSION_SECRET", "test-session-secret-0123456789abcdef"
            ),
        }
        settings = Settings.from_sources(config)
        engine, session_local = _build_engine(settings)
        Base.metadata.create_all(engine)
        engine_module.engine = engine
        engine_module.SessionLocal = session_local
        engine.dispose()
        yield
        try:
            engine_module.engine.dispose()
        except Exception:
            pass
        return
    yield


@pytest.fixture(autouse=True)
def _cleanup_sqlite_connections():
    yield
    db_url = os.getenv("DATABASE_URL")
    if not db_url or not db_url.startswith("sqlite"):
        return
    try:
        import central.db.engine as engine_module

        engine_module.engine.dispose()
    except Exception:
        pass
    try:
        from sqlalchemy.engine import make_url

        url = make_url(db_url)
        if url.database:
            try:
                os.remove(url.database)
            except OSError:
                pass
    except Exception:
        pass
