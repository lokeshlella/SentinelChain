"""Neo4j driver management (official neo4j Python driver)."""

from __future__ import annotations

from functools import lru_cache

from neo4j import Driver, GraphDatabase

from app.core.config import get_settings


@lru_cache
def get_neo4j_driver() -> Driver:
    settings = get_settings()
    return GraphDatabase.driver(
        settings.neo4j_uri,
        auth=(settings.neo4j_username, settings.neo4j_password),
        connection_timeout=5,
        max_connection_lifetime=300,
    )


def check_neo4j() -> tuple[bool, str]:
    """Return (ok, detail) for the health endpoint."""
    try:
        driver = get_neo4j_driver()
        settings = get_settings()
        with driver.session(database=settings.neo4j_database) as session:
            record = session.run(
                "CALL dbms.components() YIELD name, versions RETURN name, versions[0] AS version"
            ).single()
        return True, f"{record['name']} {record['version']}" if record else "connected"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc).splitlines()[0][:200]
