from collections.abc import Generator

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


_engine: Engine | None = None
_session_local: sessionmaker[Session] | None = None


def normalize_database_url(database_url: str) -> str:
    if database_url.startswith("postgres://"):
        return database_url.replace("postgres://", "postgresql+psycopg://", 1)
    if database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+psycopg://", 1)
    return database_url


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        database_url = normalize_database_url(get_settings().database_url)
        _engine = create_engine(
            database_url,
            connect_args={"check_same_thread": False}
            if database_url.startswith("sqlite")
            else {},
            pool_pre_ping=True,
        )
    return _engine


def get_session_local() -> sessionmaker[Session]:
    global _session_local
    if _session_local is None:
        _session_local = sessionmaker(
            bind=get_engine(), autocommit=False, autoflush=False
        )
    return _session_local


def reset_database_state() -> None:
    global _engine, _session_local
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _session_local = None


def get_db() -> Generator[Session, None, None]:
    db = get_session_local()()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from app import models  # noqa: F401

    Base.metadata.create_all(bind=get_engine())
