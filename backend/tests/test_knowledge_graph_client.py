"""Unit tests for Neo4jClient using a scripted in-memory driver (no Neo4j)."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import pytest
from neo4j.exceptions import (
    AuthError,
    ClientError,
    CypherSyntaxError,
    DatabaseUnavailable,
    ServiceUnavailable,
    SessionExpired,
)

from app.services.knowledge_graph.client import CONNECTIVITY_ERRORS, GraphClient, GraphQueryError, Neo4jClient


# ----------------------------------------------------------------- scripted driver


class FakeRecord:
    def __init__(self, payload: dict[str, Any]):
        self._payload = payload

    def data(self) -> dict[str, Any]:
        return dict(self._payload)


@dataclass
class FakeTx:
    rows: list[dict[str, Any]]
    error: Exception | None
    executed: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def run(self, cypher: str, params: dict[str, Any]):
        self.executed.append((cypher, dict(params)))
        if self.error is not None:
            raise self.error
        return [FakeRecord(row) for row in self.rows]


class FakeResult:
    def consume(self):
        return None


@dataclass
class FakeSession:
    driver: "FakeDriver"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, cypher: str, *args, **kwargs):
        self.driver.session_runs.append(cypher)
        if self.driver.session_run_error is not None:
            raise self.driver.session_run_error
        return FakeResult()

    def execute_read(self, fn):
        return self._execute("read", fn)

    def execute_write(self, fn):
        return self._execute("write", fn)

    def _execute(self, mode: str, fn):
        self.driver.executions.append(mode)
        if self.driver.execute_error is not None:
            raise self.driver.execute_error
        tx = FakeTx(rows=self.driver.rows, error=self.driver.tx_error)
        self.driver.transactions.append(tx)
        return fn(tx)


@dataclass
class FakeDriver:
    """Just enough of ``neo4j.Driver`` for the client: verify_connectivity() + session()."""

    verify_error: Exception | None = None
    session_run_error: Exception | None = None
    execute_error: Exception | None = None
    tx_error: Exception | None = None
    rows: list[dict[str, Any]] = field(default_factory=lambda: [{"ok": 1}])
    verify_calls: int = 0
    session_kwargs: list[dict[str, Any]] = field(default_factory=list)
    session_runs: list[str] = field(default_factory=list)
    executions: list[str] = field(default_factory=list)
    transactions: list[FakeTx] = field(default_factory=list)

    def verify_connectivity(self):
        self.verify_calls += 1
        if self.verify_error is not None:
            raise self.verify_error

    def session(self, **kwargs):
        self.session_kwargs.append(kwargs)
        return FakeSession(self)


@pytest.fixture
def clock(monkeypatch):
    """Controllable monotonic clock for the availability cache."""
    state = {"now": 1000.0}
    monkeypatch.setattr("app.services.knowledge_graph.client.time.monotonic", lambda: state["now"])
    return state


def _warnings(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING and "[KnowledgeGraph]" in r.getMessage()]


# ------------------------------------------------------------------------ tests


def test_client_satisfies_graph_client_protocol():
    assert isinstance(Neo4jClient(FakeDriver(), "neo4j"), GraphClient)


def test_available_is_cached_for_ttl(clock):
    driver = FakeDriver()
    client = Neo4jClient(driver, "neo4j", cache_ttl=30)
    assert client.available() is True
    assert client.available() is True
    assert driver.verify_calls == 1
    clock["now"] += 29
    client.available()
    assert driver.verify_calls == 1
    clock["now"] += 2  # TTL expired -> re-check
    assert client.available() is True
    assert driver.verify_calls == 2
    assert driver.session_kwargs[0]["database"] == "neo4j"


def test_unavailable_logs_one_warning_and_returns_empty(clock, caplog):
    caplog.set_level(logging.DEBUG)
    driver = FakeDriver(verify_error=ServiceUnavailable("Couldn't connect to localhost:7687"))
    client = Neo4jClient(driver, "neo4j", cache_ttl=30)

    assert client.available() is False
    assert client.run("MATCH (n) RETURN n") == []
    assert client.run_write("CREATE (n)") == []
    assert client.run_write_batch([("CREATE (n)", {})]) == []
    assert client.available() is False
    assert driver.verify_calls == 1  # cached: the dead server is not hammered
    assert driver.executions == []  # nothing is even attempted while unavailable
    warnings = _warnings(caplog)
    assert len(warnings) == 1
    assert "Couldn't connect" in warnings[0] and "disabled" in warnings[0]
    assert "unavailable" in client.last_error.lower()

    clock["now"] += 31  # still down after the TTL -> re-checked, but no second warning
    assert client.available() is False
    assert driver.verify_calls == 2
    assert len(_warnings(caplog)) == 1


def test_warning_is_repeated_after_a_recovery(clock, caplog):
    caplog.set_level(logging.INFO)
    driver = FakeDriver(verify_error=ServiceUnavailable("down"))
    client = Neo4jClient(driver, "neo4j", cache_ttl=30)
    assert client.available() is False

    driver.verify_error = None
    clock["now"] += 31
    assert client.available() is True
    assert client.last_error is None
    assert any("restored" in r.getMessage() for r in caplog.records if r.levelno == logging.INFO)

    driver.verify_error = ServiceUnavailable("down again")
    clock["now"] += 31
    assert client.available() is False
    assert len(_warnings(caplog)) == 2


@pytest.mark.parametrize(
    "error",
    [
        AuthError("The client is unauthorized due to authentication failure."),
        OSError("connection reset"),
        TimeoutError("timed out"),
        ClientError("Graph not found: nope"),  # e.g. database does not exist
    ],
)
def test_any_failure_during_the_check_means_unavailable(error, caplog):
    caplog.set_level(logging.WARNING)
    client = Neo4jClient(FakeDriver(verify_error=error), "neo4j")
    assert client.available() is False
    assert len(_warnings(caplog)) == 1


def test_database_check_failure_marks_unavailable(caplog):
    caplog.set_level(logging.WARNING)
    driver = FakeDriver(session_run_error=ClientError("Database does not exist"))
    client = Neo4jClient(driver, "missing")
    assert client.available() is False
    assert driver.verify_calls == 1 and driver.session_runs == ["RETURN 1 AS ok"]


def test_run_executes_read_transaction_and_returns_dicts():
    driver = FakeDriver(rows=[{"name": "requests", "version": "2.28.2"}, {"name": "urllib3", "version": ""}])
    client = Neo4jClient(driver, "neo4j")
    rows = client.run("MATCH (d:Dependency {name: $name}) RETURN d.name AS name", name="requests")
    assert rows == [{"name": "requests", "version": "2.28.2"}, {"name": "urllib3", "version": ""}]
    assert driver.executions == ["read"]
    assert driver.transactions[0].executed == [
        ("MATCH (d:Dependency {name: $name}) RETURN d.name AS name", {"name": "requests"})
    ]


def test_run_write_uses_write_transaction():
    driver = FakeDriver(rows=[{"n": 3}])
    client = Neo4jClient(driver, "neo4j")
    assert client.run_write("UNWIND $rows AS row MERGE (:X {k: row}) RETURN count(*) AS n", rows=[1, 2, 3]) == [{"n": 3}]
    assert driver.executions == ["write"]


def test_run_write_batch_runs_all_statements_in_one_transaction():
    driver = FakeDriver(rows=[{"n": 1}])
    client = Neo4jClient(driver, "neo4j")
    results = client.run_write_batch([("MERGE (a)", {"x": 1}), ("MERGE (b)", {"y": 2}), ("MERGE (c)", {})])
    assert results == [[{"n": 1}], [{"n": 1}], [{"n": 1}]]
    assert driver.executions == ["write"]  # exactly one managed transaction
    assert len(driver.transactions) == 1
    assert [c for c, _ in driver.transactions[0].executed] == ["MERGE (a)", "MERGE (b)", "MERGE (c)"]
    assert driver.transactions[0].executed[1][1] == {"y": 2}


def test_run_write_batch_with_no_statements_does_nothing():
    driver = FakeDriver()
    assert Neo4jClient(driver, "neo4j").run_write_batch([]) == []
    assert driver.verify_calls == 0 and driver.executions == []


def test_sessions_mute_unrecognized_property_warnings():
    driver = FakeDriver()
    Neo4jClient(driver, "neo4j").run("RETURN 1")
    for kwargs in driver.session_kwargs:
        assert kwargs["notifications_disabled_classifications"] == ["UNRECOGNIZED"]


def test_query_errors_raise_graph_query_error_but_keep_availability(caplog):
    caplog.set_level(logging.ERROR)
    driver = FakeDriver(tx_error=CypherSyntaxError("Invalid input 'RETRUN'"))
    client = Neo4jClient(driver, "neo4j")
    with pytest.raises(GraphQueryError) as excinfo:
        client.run("RETRUN 1")
    assert "Invalid input" in str(excinfo.value)
    assert excinfo.value.status_code == 502
    assert client.available() is True  # a bad statement is not an outage
    assert any("rejected a statement" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize(
    "error",
    [
        ServiceUnavailable("connection lost"),
        SessionExpired("session expired"),
        DatabaseUnavailable("database is unavailable"),
        AuthError("token expired"),
    ],
)
def test_connectivity_errors_during_execution_mark_unavailable(error, caplog):
    caplog.set_level(logging.WARNING)
    driver = FakeDriver(execute_error=error)
    client = Neo4jClient(driver, "neo4j", cache_ttl=30)
    assert client.available() is True
    assert client.run_write("CREATE (n)") == []
    assert client.available() is False  # remembered without another connectivity check
    assert driver.verify_calls == 1
    assert len(_warnings(caplog)) == 1


def test_connectivity_error_classes_cover_driver_and_auth_failures():
    for error in (ServiceUnavailable("x"), SessionExpired("x"), AuthError("x"), DatabaseUnavailable("x"), OSError()):
        assert isinstance(error, CONNECTIVITY_ERRORS)
    assert not isinstance(CypherSyntaxError("x"), CONNECTIVITY_ERRORS)


def test_edition_is_read_once_and_cached():
    driver = FakeDriver(rows=[{"name": "Neo4j Kernel", "edition": "Community"}])
    client = Neo4jClient(driver, "neo4j")
    assert client.edition() == "community"
    assert client.edition() == "community"
    assert driver.executions == ["read"]


def test_edition_unknown_when_unavailable():
    client = Neo4jClient(FakeDriver(verify_error=ServiceUnavailable("down")), "neo4j")
    assert client.edition() is None


def test_invalidate_forces_a_fresh_check(clock):
    driver = FakeDriver()
    client = Neo4jClient(driver, "neo4j")
    client.available()
    client.invalidate()
    client.available()
    assert driver.verify_calls == 2


def test_default_driver_and_database_are_resolved_lazily(monkeypatch):
    client = Neo4jClient()
    assert client._driver is None
    monkeypatch.setattr("app.db.neo4j.get_neo4j_driver", lambda: FakeDriver())
    assert isinstance(client.driver, FakeDriver)
    assert client.database == "neo4j"  # settings.neo4j_database default
