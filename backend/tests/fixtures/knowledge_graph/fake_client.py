"""An in-memory stand-in for :class:`app.services.knowledge_graph.client.Neo4jClient`.

Records every statement (mode, tag, Cypher, parameters) so tests can assert on the
batches the service builds, and answers with canned rows keyed by the ``// kg:<tag>``
comment that heads every statement of the service.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

_TAG_RE = re.compile(r"^\s*//\s*kg:([a-z0-9-]+)", re.IGNORECASE)

Rows = list[dict[str, Any]]
Responder = Callable[[dict[str, Any]], Rows]


def statement_tag(cypher: str) -> str:
    """``// kg:merge-dependencies`` -> ``merge-dependencies``; schema DDL -> ``schema``."""
    match = _TAG_RE.match(cypher)
    if match:
        return match.group(1).lower()
    head = cypher.lstrip().upper()
    if head.startswith("CREATE CONSTRAINT") or head.startswith("CREATE INDEX"):
        return "schema"
    return "other"


@dataclass
class FakeCall:
    mode: str  # "read" | "write" | "batch"
    tag: str
    cypher: str
    params: dict[str, Any]


@dataclass
class FakeNeo4jClient:
    """Implements the ``GraphClient`` protocol without a database.

    ``responses`` maps a statement tag to canned rows (or a callable receiving the
    parameters). Sync statements without an explicit response answer with a realistic
    ``{"n": <batch size>}`` counter so ``GraphSyncResult`` totals can be asserted, and the
    ``dependency-exists`` probe answers "1 node" (set ``[{"n": 0}]`` to simulate a
    dependency that was never synced). ``fail_with`` maps a tag to an exception raised
    when that statement executes.
    """

    is_available: bool = True
    responses: dict[str, Rows | Responder] = field(default_factory=dict)
    fail_with: dict[str, Exception] = field(default_factory=dict)
    server_edition: str | None = "community"
    calls: list[FakeCall] = field(default_factory=list)
    last_error: str | None = None

    def __post_init__(self) -> None:
        if not self.is_available and self.last_error is None:
            self.last_error = "Neo4j unavailable: fake connection refused"

    # -- GraphClient protocol ------------------------------------------------

    def available(self) -> bool:
        return self.is_available

    def edition(self) -> str | None:
        return self.server_edition if self.is_available else None

    def run(self, cypher: str, **params: Any) -> Rows:
        return self._execute("read", cypher, params)

    def run_write(self, cypher: str, **params: Any) -> Rows:
        return self._execute("write", cypher, params)

    def run_write_batch(self, statements: Sequence[tuple[str, dict[str, Any]]]) -> list[Rows]:
        if not self.is_available:
            return []
        return [self._execute("batch", cypher, params) for cypher, params in statements]

    # -- helpers for assertions ------------------------------------------------

    def calls_for(self, tag: str) -> list[FakeCall]:
        return [call for call in self.calls if call.tag == tag]

    def tags(self, mode: str | None = None) -> list[str]:
        return [call.tag for call in self.calls if mode is None or call.mode == mode]

    # -- internals ---------------------------------------------------------------

    def _execute(self, mode: str, cypher: str, params: dict[str, Any]) -> Rows:
        tag = statement_tag(cypher)
        self.calls.append(FakeCall(mode, tag, cypher, dict(params)))
        if not self.is_available:
            return []
        if tag in self.fail_with:
            raise self.fail_with[tag]
        if tag in self.responses:
            response = self.responses[tag]
            rows = response(params) if callable(response) else response
            return [dict(row) for row in rows]
        return self._default_rows(tag, params)

    @staticmethod
    def _default_rows(tag: str, params: dict[str, Any]) -> Rows:
        if tag == "merge-repository":
            return [{"n": 1}]
        if tag.startswith("merge-"):
            return [{"n": len(params.get("rows") or [])}]
        if tag.startswith(("delete-", "prune-", "remove-")):
            return [{"n": 0}]
        if tag == "dependency-exists":
            return [{"n": 1}]
        return []
