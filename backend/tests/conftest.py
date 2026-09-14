"""Shared pytest fixtures.

Unit tests never talk to PostgreSQL, Neo4j, Ollama, Docker or the network. They
use an in-memory SQLite database and mocked providers. Tests that need real
services are marked ``integration`` and skipped unless SENTINEL_INTEGRATION=1.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base

os.environ.setdefault("APP_ENV", "test")


def pytest_collection_modifyitems(config, items):
    if os.environ.get("SENTINEL_INTEGRATION") == "1":
        return
    skip = pytest.mark.skip(reason="integration test (set SENTINEL_INTEGRATION=1 to run)")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip)


@pytest.fixture
def engine():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db(engine) -> Session:
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)
    session = factory()
    try:
        yield session
    finally:
        session.close()
