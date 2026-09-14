"""Thin, failure-tolerant wrapper around the official Neo4j driver.

The knowledge graph is an *optional* service: when Neo4j is down, misconfigured
or unreachable the rest of the analysis pipeline must keep working. This client
therefore never raises on connectivity problems - it logs ONE warning through
the ``KnowledgeGraph`` stage logger, remembers that the graph is unavailable for
``cache_ttl`` seconds (30 s by default, so a dead server is not hammered on every
call) and returns empty results / ``False``.

Errors that are *not* connectivity related (a Cypher syntax error, a constraint
violation, ...) indicate a programming or data problem. They are logged and
re-raised as :class:`GraphQueryError` so the service layer can report them in a
``GraphSyncResult`` instead of silently producing an empty graph.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from typing import Any, Protocol, runtime_checkable

from neo4j import Driver, unit_of_work
from neo4j.exceptions import (
    AuthError,
    ConfigurationError,
    DriverError,
    Neo4jError,
    ServiceUnavailable,
    SessionExpired,
    TokenExpired,
    TransientError,
)

from app.core.exceptions import ExternalServiceError
from app.core.logging import get_stage_logger

log = get_stage_logger("KnowledgeGraph")

#: Errors that mean "Neo4j cannot be reached / used right now" (not a query bug).
CONNECTIVITY_ERRORS: tuple[type[BaseException], ...] = (
    ServiceUnavailable,
    SessionExpired,
    DriverError,  # pool / connection acquisition timeouts, incomplete commits, ...
    AuthError,
    TokenExpired,
    ConfigurationError,
    TransientError,  # e.g. DatabaseUnavailable after the driver gave up retrying
    OSError,  # raw socket errors / timeouts surfacing from the transport
    TimeoutError,
)

Statement = tuple[str, dict[str, Any]]

#: Code the driver assigns to errors that were not hydrated from a server response.
_UNKNOWN_NEO4J_CODE = "Neo.DatabaseError.General.UnknownError"


class GraphQueryError(ExternalServiceError):
    """A Cypher statement was rejected by Neo4j (syntax, constraint, type error)."""


@runtime_checkable
class GraphClient(Protocol):
    """What :class:`~app.services.knowledge_graph.service.KnowledgeGraphService` needs from a client.

    Tests inject a fake implementing this protocol; production uses :class:`Neo4jClient`.
    """

    def available(self) -> bool: ...

    def run(self, cypher: str, **params: Any) -> list[dict]: ...

    def run_write(self, cypher: str, **params: Any) -> list[dict]: ...

    def run_write_batch(self, statements: Sequence[Statement]) -> list[list[dict]]: ...

    def edition(self) -> str | None: ...


def _first_line(exc: BaseException) -> str:
    """Compact, single-line description of a driver / server error."""
    message = getattr(exc, "message", None)
    code = getattr(exc, "code", None)
    if isinstance(exc, Neo4jError) and isinstance(message, str) and message and code != _UNKNOWN_NEO4J_CODE:
        # Server-hydrated error: use its message + code instead of the verbose repr.
        text = f"{message} ({code})" if code else message
    else:
        text = str(exc).strip() or exc.__class__.__name__
    return text.splitlines()[0][:300]


class Neo4jClient:
    """Executes Cypher against Neo4j with cached availability and graceful degradation.

    Parameters
    ----------
    driver:
        A ``neo4j.Driver``. When omitted the shared driver from
        :func:`app.db.neo4j.get_neo4j_driver` is used (resolved lazily, so merely
        constructing the client never touches the network).
    database:
        Target database; defaults to ``settings.neo4j_database``.
    cache_ttl:
        Seconds an availability verdict (up *or* down) is trusted before it is
        re-checked.
    transaction_timeout:
        Server-side timeout (seconds) applied to every managed transaction.
    """

    def __init__(
        self,
        driver: Driver | None = None,
        database: str | None = None,
        *,
        cache_ttl: float = 30.0,
        transaction_timeout: float = 120.0,
    ) -> None:
        self._driver = driver
        self._driver_from_settings = driver is None
        self._database = database
        self._cache_ttl = cache_ttl
        self._transaction_timeout = transaction_timeout
        self._available: bool | None = None
        self._checked_at: float = 0.0
        self._warned = False
        self._edition: str | None = None
        self.last_error: str | None = None

    # ------------------------------------------------------------------ wiring

    @property
    def driver(self) -> Driver:
        if self._driver is None:
            from app.db.neo4j import get_neo4j_driver

            self._driver = get_neo4j_driver()
        return self._driver

    @property
    def database(self) -> str:
        if self._database is None:
            from app.core.config import get_settings

            self._database = get_settings().neo4j_database
        return self._database

    def _session(self):
        """Open a session on the configured database.

        ``UNRECOGNIZED`` server notifications ("property key does not exist") are muted:
        they fire for optional properties that are ``null`` everywhere (e.g. a
        ``reference_url`` that OSV did not provide) and would otherwise spam the log.
        """
        return self.driver.session(
            database=self.database,
            notifications_disabled_classifications=["UNRECOGNIZED"],
        )

    def _describe_target(self) -> str:
        """Best-effort ``uri (database=...)`` for log lines (never raises)."""
        uri: str | None = None
        if self._driver_from_settings:
            try:
                from app.core.config import get_settings

                uri = get_settings().neo4j_uri
            except Exception:  # noqa: BLE001 - description only
                uri = None
        else:
            address = getattr(getattr(self._driver, "_pool", None), "address", None)
            uri = str(address) if address else None
        try:
            database = self.database
        except Exception:  # noqa: BLE001
            database = self._database or "?"
        return f"{uri or 'neo4j'} (database={database})"

    # ------------------------------------------------------------ availability

    def available(self) -> bool:
        """Return whether Neo4j can be used, re-checking at most every ``cache_ttl`` seconds."""
        now = time.monotonic()
        if self._available is not None and (now - self._checked_at) < self._cache_ttl:
            return self._available
        try:
            self.driver.verify_connectivity()
            with self._session() as session:
                session.run("RETURN 1 AS ok").consume()
        except Exception as exc:  # noqa: BLE001 - any failure means "not usable"
            self._mark_unavailable(exc)
            return False
        self._mark_available()
        return True

    def invalidate(self) -> None:
        """Forget the cached availability verdict (next call re-checks immediately)."""
        self._available = None
        self._checked_at = 0.0

    def _mark_available(self) -> None:
        if self._available is False or self._warned:
            log.info("Neo4j connection restored: %s", self._describe_target())
        self._available = True
        self._checked_at = time.monotonic()
        self._warned = False
        self.last_error = None

    def _mark_unavailable(self, exc: BaseException) -> None:
        self.last_error = f"Neo4j unavailable: {_first_line(exc)}"
        if not self._warned:
            log.warning(
                "Neo4j unavailable at %s: %s - knowledge graph features are disabled "
                "(retrying in %.0f s)",
                self._describe_target(),
                _first_line(exc),
                self._cache_ttl,
            )
            self._warned = True
        else:
            log.debug("Neo4j still unavailable: %s", _first_line(exc))
        self._available = False
        self._checked_at = time.monotonic()

    def edition(self) -> str | None:
        """Return the server edition (``community`` / ``enterprise``) or ``None`` when unknown."""
        if self._edition is None:
            rows = self.run("CALL dbms.components() YIELD name, edition RETURN name, edition")
            for row in rows:
                if row.get("edition"):
                    self._edition = str(row["edition"]).lower()
                    break
        return self._edition

    # --------------------------------------------------------------- execution

    def run(self, cypher: str, **params: Any) -> list[dict]:
        """Execute a read statement and return its records as plain dicts (``[]`` when unavailable)."""
        results = self._execute(lambda tx: _run_all(tx, [(cypher, params)]), write=False)
        return results[0] if results else []

    def run_write(self, cypher: str, **params: Any) -> list[dict]:
        """Execute one write statement in its own transaction (``[]`` when unavailable)."""
        results = self._execute(lambda tx: _run_all(tx, [(cypher, params)]), write=True)
        return results[0] if results else []

    def run_write_batch(self, statements: Sequence[Statement]) -> list[list[dict]]:
        """Execute several write statements atomically in ONE transaction.

        Returns one record list per statement, or ``[]`` when Neo4j is unavailable
        (nothing is committed in that case).
        """
        if not statements:
            return []
        return self._execute(lambda tx: _run_all(tx, statements), write=True)

    def _execute(self, work: Callable[[Any], list[list[dict]]], *, write: bool) -> list[list[dict]]:
        if not self.available():
            return []
        unit = unit_of_work(timeout=self._transaction_timeout)(work)
        try:
            with self._session() as session:
                runner = session.execute_write if write else session.execute_read
                return runner(unit)
        except CONNECTIVITY_ERRORS as exc:
            self._mark_unavailable(exc)
            return []
        except Neo4jError as exc:
            # ClientError (syntax / constraint / type) or DatabaseError: a bug or data
            # problem, not an outage - surface it to the service layer.
            self.last_error = _first_line(exc)
            code = getattr(exc, "code", None) or exc.__class__.__name__
            log.error("Neo4j rejected a statement (%s): %s", code, _first_line(exc))
            raise GraphQueryError(f"Neo4j query failed: {_first_line(exc)}", details={"code": code}) from exc


def _run_all(tx: Any, statements: Sequence[Statement]) -> list[list[dict]]:
    """Run statements sequentially inside ``tx`` and eagerly materialise every result."""
    out: list[list[dict]] = []
    for cypher, params in statements:
        result = tx.run(cypher, dict(params))
        out.append([record.data() for record in result])
    return out


__all__ = [
    "CONNECTIVITY_ERRORS",
    "GraphClient",
    "GraphQueryError",
    "Neo4jClient",
    "Statement",
]
