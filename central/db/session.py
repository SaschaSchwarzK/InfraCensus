from collections.abc import Iterator
from contextlib import contextmanager

import central.db.engine as engine_module


@contextmanager
def get_session() -> Iterator:
    session = engine_module.SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
