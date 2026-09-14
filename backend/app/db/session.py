"""Database engine / session management for PostgreSQL."""

from __future__ import annotations

from collections.abc import Generator
from functools import lru_cache

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


@lru_cache
def get_engine() -> Engine:
    settings = get_settings()
    return create_engine(settings.database_url, pool_pre_ping=True, future=True)


@lru_cache
def get_session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False, future=True)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a request-scoped session."""
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()


def check_database() -> tuple[bool, str]:
    """Return (ok, detail) for the health endpoint."""
    try:
        with get_engine().connect() as conn:
            version = conn.execute(text("select version()")).scalar_one()
        return True, str(version).split(",")[0]
    except Exception as exc:  # noqa: BLE001 - health check must never raise
        return False, str(exc).splitlines()[0][:200]
