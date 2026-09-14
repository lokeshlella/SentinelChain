"""SQLAlchemy declarative base shared by all models."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import DeclarativeBase


def utcnow() -> datetime:
    """Timezone-aware UTC timestamp used for all created_at/updated_at columns."""
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass
