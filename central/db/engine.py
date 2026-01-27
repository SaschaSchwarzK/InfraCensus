from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool
from sqlalchemy.orm import sessionmaker

from central.core.config import settings


engine_kwargs = {"future": True}
if settings.database_url.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
    engine_kwargs["poolclass"] = NullPool
else:
    engine_kwargs["pool_size"] = settings.db_pool_size
    engine_kwargs["max_overflow"] = settings.db_max_overflow
    engine_kwargs["pool_timeout"] = settings.db_pool_timeout
    engine_kwargs["pool_recycle"] = settings.db_pool_recycle
    engine_kwargs["pool_pre_ping"] = settings.db_pool_pre_ping

engine = create_engine(settings.database_url, **engine_kwargs)
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    future=True,
)
