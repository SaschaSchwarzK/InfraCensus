from collections.abc import Iterator
from contextlib import contextmanager

from central.db.engine import SessionLocal


@contextmanager
def get_session() -> Iterator:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
