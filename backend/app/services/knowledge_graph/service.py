"""Software knowledge graph service (Neo4j) - contract §4.4.

Graph schema (populated from *actual* analysis results only)::

    (:Repository {repository_id, name, source_url, source_type, language})
      -[:CONTAINS]-> (:Component {repository_id, path, name, component_type})
      -[:USES]->     (:Dependency {repository_id, ecosystem, name, version, scope, source_file,
                                   status, dependency_id, analysis_id, version_spec})
    (:Component)-[:USES]->(:Dependency)
    (:Dependency)-[:DEPENDS_ON]->(:Dependency)
    (:Dependency)-[:AFFECTED_BY]->(:Vulnerability {identifier, severity, cvss_score, summary,
                                                    source, aliases, reference_url})

Node identity (natural keys used by every ``MERGE``):

* ``Repository{repository_id}``
* ``Component{repository_id, path}``
* ``Dependency{repository_id, ecosystem, name, version}`` (``version`` is ``""`` when unknown)
* ``Vulnerability{identifier}`` (global - shared between repositories)

Schema management: uniqueness constraints exist for ``Repository.repository_id`` and
``Vulnerability.identifier`` (plus plain ``repository_id`` indexes on ``Component`` and
``Dependency`` for per-repository lookups). Composite NODE KEY constraints (``Component`` and
``Dependency``) require Neo4j *Enterprise*; on *Community* edition the service creates
composite RANGE indexes with the same properties instead and relies on ``MERGE`` (all
writes go through this module) to keep the keys unique. Both variants are created with
``IF NOT EXISTS`` so the call is idempotent.

Every write of one analysis happens inside ONE Neo4j transaction built from a handful
of ``UNWIND`` statements (never one statement per node): nodes are merged, the
repository's stale edges are deleted, relationships are merged, and orphaned
``Dependency`` / ``Component`` nodes of the repository are pruned. Neo4j being down is
never fatal: results/contexts simply say ``available=False``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.core.logging import get_stage_logger
from app.models.component import Component
from app.models.dependency import Dependency, DependencyRelation
from app.models.repository import Repository
from app.models.vulnerability import Vulnerability
from app.services.agents.schemas import GraphContext
from app.services.knowledge_graph.client import GraphClient, GraphQueryError, Neo4jClient, Statement

log = get_stage_logger("KnowledgeGraph")

RELATIONSHIP_TYPES: tuple[str, ...] = ("CONTAINS", "USES", "DEPENDS_ON", "AFFECTED_BY")
NODE_LABELS: tuple[str, ...] = ("Repository", "Component", "Dependency", "Vulnerability")

#: Hard cap on the variable-length expansion used by :meth:`KnowledgeGraphService.dependency_paths`.
MAX_PATH_DEPTH = 8


# ------------------------------------------------------------------------------ results


@dataclass
class GraphSyncResult:
    """Outcome of :meth:`KnowledgeGraphService.sync_analysis`."""

    available: bool
    nodes_written: int = 0
    relationships_written: int = 0
    error: str | None = None
    # Extra diagnostics (not part of the minimal contract, all optional).
    stale_relationships_deleted: int = 0
    nodes_pruned: int = 0
    skipped: dict[str, int] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.available and self.error is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "nodes_written": self.nodes_written,
            "relationships_written": self.relationships_written,
            "error": self.error,
            "stale_relationships_deleted": self.stale_relationships_deleted,
            "nodes_pruned": self.nodes_pruned,
            "skipped": dict(self.skipped),
        }


@dataclass
class SyncBatches:
    """De-duplicated ``UNWIND`` parameter batches for one repository sync (pure data)."""

    repository_id: int
    repository: dict[str, Any]
    components: list[dict[str, Any]] = field(default_factory=list)
    dependencies: list[dict[str, Any]] = field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    contains: list[dict[str, Any]] = field(default_factory=list)
    repository_uses: list[dict[str, Any]] = field(default_factory=list)
    component_uses: list[dict[str, Any]] = field(default_factory=list)
    depends_on: list[dict[str, Any]] = field(default_factory=list)
    affected_by: list[dict[str, Any]] = field(default_factory=list)
    skipped: dict[str, int] = field(default_factory=dict)

    def _skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1


@dataclass(frozen=True)
class SyncStatement:
    """One Cypher statement of the sync transaction, tagged so results can be summed by kind."""

    tag: str
    kind: str  # "node" | "delete" | "relationship" | "prune"
    cypher: str
    params: dict[str, Any]

    def as_statement(self) -> Statement:
        return self.cypher, self.params


# ------------------------------------------------------------------------ small helpers


def _text(value: Any) -> str | None:
    """Coerce enum members / other scalars to plain ``str`` (Neo4j properties), keeping ``None``."""
    if value is None:
        return None
    return str(value)


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def dependency_key(dep: Dependency, repository_id: int | None = None) -> dict[str, Any]:
    """Natural key of a ``Dependency`` node for the given ORM row."""
    return {
        "repository_id": int(repository_id if repository_id is not None else dep.repository_id),
        "ecosystem": _text(dep.ecosystem) or "",
        "name": _text(dep.package_name) or "",
        "version": _text(dep.version) or "",
    }


def dependency_label(name: Any, version: Any = None) -> str:
    """Human readable ``pkg@version`` (or ``pkg`` when the version is unknown)."""
    name_text = _text(name) or "?"
    version_text = _text(version) or ""
    return f"{name_text}@{version_text}" if version_text else name_text


def render_node_label(labels: Iterable[str], props: Mapping[str, Any]) -> str:
    """Render a graph node as ``Label:key`` (``Repository:name``, ``Component:src``, ``Dependency:pkg@1.0``)."""
    label_set = set(labels or ())
    if "Repository" in label_set:
        return f"Repository:{props.get('name') or props.get('repository_id')}"
    if "Component" in label_set:
        return f"Component:{props.get('path')}"
    if "Dependency" in label_set:
        return f"Dependency:{dependency_label(props.get('name'), props.get('version'))}"
    if "Vulnerability" in label_set:
        return f"Vulnerability:{props.get('identifier')}"
    first = next(iter(label_set), "Node")
    return f"{first}:{props.get('name') or props.get('path') or props.get('identifier') or '?'}"


def node_display_name(label: str, props: Mapping[str, Any]) -> str:
    """Short caption for a node in the UI (``app``, ``src``, ``pkg@1.0``, ``GHSA-...``)."""
    return render_node_label([label], props).split(":", 1)[1]


def graph_node_id(label: str, props: Mapping[str, Any]) -> str:
    """Stable UI identifier ``<label>:<key>`` built from the node's natural key."""
    if label == "Repository":
        return f"Repository:{props.get('repository_id')}"
    if label == "Component":
        return f"Component:{props.get('repository_id')}:{props.get('path')}"
    if label == "Dependency":
        return (
            f"Dependency:{props.get('repository_id')}:{props.get('ecosystem')}:"
            f"{dependency_label(props.get('name'), props.get('version'))}"
        )
    if label == "Vulnerability":
        return f"Vulnerability:{props.get('identifier')}"
    return f"{label}:{props.get('name') or props.get('path') or props.get('identifier') or id(props)}"


def _primary_label(labels: Iterable[str]) -> str:
    for known in NODE_LABELS:
        if known in labels:
            return known
    return next(iter(labels), "Node")


def _count(rows: Sequence[Mapping[str, Any]] | None) -> int:
    """Read the ``n`` counter returned by the sync statements (``0`` when nothing came back)."""
    if not rows:
        return 0
    value = rows[0].get("n")
    return int(value) if value is not None else 0


# --------------------------------------------------------------------- batch building


def build_sync_batches(
    repository: Repository,
    components: Sequence[Component],
    dependencies: Sequence[Dependency],
    relations: Sequence[DependencyRelation],
    dep_vulns: Mapping[Any, Sequence[Vulnerability]] | None,
    component_usage: Mapping[Any, Sequence[str]] | None,
) -> SyncBatches:
    """Turn ORM rows into de-duplicated parameter batches keyed by the graph's natural keys.

    * duplicate components (same path) / dependencies (same ecosystem+name+version) /
      vulnerabilities (same identifier) collapse to one row (first occurrence wins);
    * relations, vulnerabilities and usage that reference a ``dependency_id`` not in
      ``dependencies``, usage pointing at unknown component paths, and self relations are
      skipped and counted in ``SyncBatches.skipped``.
    """
    repository_id = int(repository.repository_id)
    batches = SyncBatches(
        repository_id=repository_id,
        repository={
            "name": _text(repository.name),
            "source_url": _text(repository.source_url),
            "source_type": _text(repository.source_type),
            "language": _text(repository.language),
        },
    )

    known_paths: set[str] = set()
    for component in components:
        path = _text(component.path) or ""
        if path in known_paths:
            batches._skip("duplicate_components")
            continue
        known_paths.add(path)
        batches.components.append(
            {
                "path": path,
                "props": {"name": _text(component.name), "component_type": _text(component.component_type)},
            }
        )
        batches.contains.append({"path": path})

    key_by_dependency_id: dict[int, dict[str, Any]] = {}
    seen_dependency_keys: set[tuple[str, str, str]] = set()
    for dep in dependencies:
        key = dependency_key(dep, repository_id)
        if dep.dependency_id is not None:
            key_by_dependency_id[int(dep.dependency_id)] = key
        tuple_key = (key["ecosystem"], key["name"], key["version"])
        if tuple_key in seen_dependency_keys:
            batches._skip("duplicate_dependencies")
            continue
        seen_dependency_keys.add(tuple_key)
        batches.dependencies.append(
            {
                **key,
                "props": {
                    "name": key["name"],
                    "version": key["version"],
                    "ecosystem": key["ecosystem"],
                    "scope": _text(dep.direct_or_transitive) or "unknown",
                    "source_file": _text(dep.source_file),
                    "status": _text(dep.vulnerability_status) or "UNCHECKED",
                    "dependency_id": _int_or_none(dep.dependency_id),
                    "analysis_id": _int_or_none(dep.analysis_id),
                    "version_spec": _text(dep.version_spec),
                },
            }
        )
        batches.repository_uses.append(dict(key))

    def _resolve(dependency_id: Any, reason: str) -> dict[str, Any] | None:
        resolved = _int_or_none(dependency_id)
        key = key_by_dependency_id.get(resolved) if resolved is not None else None
        if key is None:
            batches._skip(reason)
        return key

    seen_relations: set[tuple[tuple[str, str, str], tuple[str, str, str]]] = set()
    for relation in relations:
        parent = _resolve(relation.parent_dependency_id, "relations_unknown_dependency")
        if parent is None:
            continue
        child = _resolve(relation.child_dependency_id, "relations_unknown_dependency")
        if child is None:
            continue
        pair = (
            (parent["ecosystem"], parent["name"], parent["version"]),
            (child["ecosystem"], child["name"], child["version"]),
        )
        if pair[0] == pair[1]:
            batches._skip("relations_self_reference")
            continue
        if pair in seen_relations:
            batches._skip("duplicate_relations")
            continue
        seen_relations.add(pair)
        batches.depends_on.append({"parent": dict(parent), "child": dict(child)})

    seen_vulns: set[str] = set()
    seen_affected: set[tuple[tuple[str, str, str], str]] = set()
    for dependency_id, vulns in (dep_vulns or {}).items():
        key = _resolve(dependency_id, "vulnerabilities_unknown_dependency")
        if key is None:
            continue
        for vuln in vulns or ():
            identifier = _text(vuln.identifier)
            if not identifier:
                batches._skip("vulnerabilities_without_identifier")
                continue
            if identifier not in seen_vulns:
                seen_vulns.add(identifier)
                batches.vulnerabilities.append({"identifier": identifier, "props": _vulnerability_props(vuln)})
            pair = ((key["ecosystem"], key["name"], key["version"]), identifier)
            if pair in seen_affected:
                batches._skip("duplicate_affected_by")
                continue
            seen_affected.add(pair)
            batches.affected_by.append({**key, "identifier": identifier})

    seen_usage: set[tuple[str, tuple[str, str, str]]] = set()
    for dependency_id, paths in (component_usage or {}).items():
        key = _resolve(dependency_id, "usage_unknown_dependency")
        if key is None:
            continue
        for raw_path in paths or ():
            path = _text(raw_path) or ""
            if path not in known_paths:
                batches._skip("usage_unknown_component")
                continue
            pair = (path, (key["ecosystem"], key["name"], key["version"]))
            if pair in seen_usage:
                batches._skip("duplicate_component_uses")
                continue
            seen_usage.add(pair)
            batches.component_uses.append({"path": path, **key})

    return batches


def _vulnerability_props(vuln: Vulnerability) -> dict[str, Any]:
    aliases = vuln.aliases if isinstance(vuln.aliases, (list, tuple)) else []
    return {
        "identifier": _text(vuln.identifier),
        "severity": _text(vuln.severity) or "UNKNOWN",
        "cvss_score": float(vuln.cvss_score) if vuln.cvss_score is not None else None,
        "summary": _text(vuln.summary),
        "source": _text(vuln.source),
        "aliases": [str(a) for a in aliases if a is not None],
        "reference_url": _text(vuln.reference_url),
    }


# ------------------------------------------------------------------------ Cypher text

_DEPENDENCY_MATCH = (
    "(d:Dependency {repository_id: $repository_id, ecosystem: $ecosystem, name: $name, version: $version})"
)

CYPHER_MERGE_REPOSITORY = """// kg:merge-repository
MERGE (r:Repository {repository_id: $repository_id})
SET r += $props
RETURN count(r) AS n"""

CYPHER_MERGE_COMPONENTS = """// kg:merge-components
UNWIND $rows AS row
MERGE (c:Component {repository_id: $repository_id, path: row.path})
SET c += row.props
RETURN count(c) AS n"""

CYPHER_MERGE_DEPENDENCIES = """// kg:merge-dependencies
UNWIND $rows AS row
MERGE (d:Dependency {repository_id: $repository_id, ecosystem: row.ecosystem, name: row.name, version: row.version})
SET d += row.props
RETURN count(d) AS n"""

CYPHER_MERGE_VULNERABILITIES = """// kg:merge-vulnerabilities
UNWIND $rows AS row
MERGE (v:Vulnerability {identifier: row.identifier})
SET v += row.props
RETURN count(v) AS n"""

CYPHER_DELETE_STALE_REPOSITORY_EDGES = """// kg:delete-stale-repository-edges
MATCH (:Repository {repository_id: $repository_id})-[rel:CONTAINS|USES]->()
DELETE rel
RETURN count(*) AS n"""

CYPHER_DELETE_STALE_COMPONENT_EDGES = """// kg:delete-stale-component-edges
MATCH (:Component {repository_id: $repository_id})-[rel:USES]->()
DELETE rel
RETURN count(*) AS n"""

CYPHER_DELETE_STALE_DEPENDENCY_EDGES = """// kg:delete-stale-dependency-edges
MATCH (:Dependency {repository_id: $repository_id})-[rel:DEPENDS_ON|AFFECTED_BY]->()
DELETE rel
RETURN count(*) AS n"""

CYPHER_MERGE_CONTAINS = """// kg:merge-contains
MATCH (r:Repository {repository_id: $repository_id})
UNWIND $rows AS row
MATCH (c:Component {repository_id: $repository_id, path: row.path})
MERGE (r)-[:CONTAINS]->(c)
RETURN count(*) AS n"""

CYPHER_MERGE_REPOSITORY_USES = """// kg:merge-repository-uses
MATCH (r:Repository {repository_id: $repository_id})
UNWIND $rows AS row
MATCH (d:Dependency {repository_id: $repository_id, ecosystem: row.ecosystem, name: row.name, version: row.version})
MERGE (r)-[:USES]->(d)
RETURN count(*) AS n"""

CYPHER_MERGE_COMPONENT_USES = """// kg:merge-component-uses
UNWIND $rows AS row
MATCH (c:Component {repository_id: $repository_id, path: row.path})
MATCH (d:Dependency {repository_id: $repository_id, ecosystem: row.ecosystem, name: row.name, version: row.version})
MERGE (c)-[:USES]->(d)
RETURN count(*) AS n"""

CYPHER_MERGE_DEPENDS_ON = """// kg:merge-depends-on
UNWIND $rows AS row
MATCH (p:Dependency {repository_id: $repository_id, ecosystem: row.parent.ecosystem, name: row.parent.name, version: row.parent.version})
MATCH (c:Dependency {repository_id: $repository_id, ecosystem: row.child.ecosystem, name: row.child.name, version: row.child.version})
MERGE (p)-[:DEPENDS_ON]->(c)
RETURN count(*) AS n"""

CYPHER_MERGE_AFFECTED_BY = """// kg:merge-affected-by
UNWIND $rows AS row
MATCH (d:Dependency {repository_id: $repository_id, ecosystem: row.ecosystem, name: row.name, version: row.version})
MATCH (v:Vulnerability {identifier: row.identifier})
MERGE (d)-[:AFFECTED_BY]->(v)
RETURN count(*) AS n"""

CYPHER_PRUNE_ORPHAN_DEPENDENCIES = """// kg:prune-orphan-dependencies
MATCH (r:Repository {repository_id: $repository_id})
MATCH (d:Dependency {repository_id: $repository_id})
WHERE NOT (r)-[:USES]->(d)
DETACH DELETE d
RETURN count(*) AS n"""

CYPHER_PRUNE_ORPHAN_COMPONENTS = """// kg:prune-orphan-components
MATCH (r:Repository {repository_id: $repository_id})
MATCH (c:Component {repository_id: $repository_id})
WHERE NOT (r)-[:CONTAINS]->(c)
DETACH DELETE c
RETURN count(*) AS n"""

CYPHER_COMPONENTS_USING = f"""// kg:components-using-dependency
MATCH {_DEPENDENCY_MATCH}<-[:USES]-(c:Component)
RETURN c.path AS path, c.name AS name, c.component_type AS component_type
ORDER BY c.path"""

_RELATED_RETURN = """RETURN x.name AS name, x.version AS version, x.ecosystem AS ecosystem, x.scope AS scope,
       x.status AS status, x.dependency_id AS dependency_id
ORDER BY x.name, x.version"""

CYPHER_DEPENDS_ON = f"""// kg:depends-on
MATCH {_DEPENDENCY_MATCH}-[:DEPENDS_ON]->(x:Dependency)
{_RELATED_RETURN}"""

CYPHER_DEPENDED_ON_BY = f"""// kg:depended-on-by
MATCH {_DEPENDENCY_MATCH}<-[:DEPENDS_ON]-(x:Dependency)
{_RELATED_RETURN}"""

CYPHER_VULNERABILITIES_FOR = f"""// kg:vulnerabilities-for-dependency
MATCH {_DEPENDENCY_MATCH}-[:AFFECTED_BY]->(v:Vulnerability)
RETURN v.identifier AS identifier, v.severity AS severity, v.cvss_score AS cvss_score,
       v.summary AS summary, v.source AS source, v.aliases AS aliases, v.reference_url AS reference_url
ORDER BY v.identifier"""

CYPHER_DEPENDENCY_EXISTS = f"""// kg:dependency-exists
MATCH {_DEPENDENCY_MATCH}
RETURN count(d) AS n"""

# Paths of exactly ``length`` hops. :meth:`KnowledgeGraphService.dependency_paths` runs this once
# per length (1, 2, ...) so short paths are always found first and the work stays bounded by
# ``$limit`` *matching* paths - a single ``*1..N`` expansion with a LIMIT would truncate the
# enumeration before it could be sorted and drop the direct paths on dense lock-file graphs.
# Cypher variable-length patterns only guarantee relationship uniqueness, so the predicate
# keeps *simple* paths (no node visited twice - ``a -> b -> a -> d`` is not a dependency path).
CYPHER_DEPENDENCY_PATHS_TEMPLATE = """// kg:dependency-paths
MATCH (r:Repository {{repository_id: $repository_id}})
MATCH (d:Dependency {{repository_id: $repository_id, ecosystem: $ecosystem, name: $name, version: $version}})
MATCH p = (r)-[:CONTAINS|USES|DEPENDS_ON*{length}..{length}]->(d)
WITH nodes(p) AS ns
WHERE all(i IN range(0, size(ns) - 2) WHERE NOT ns[i] IN ns[i + 1..])
WITH ns LIMIT $limit
RETURN [n IN ns | {{eid: elementId(n), labels: labels(n), name: n.name, path: n.path, version: n.version,
                    identifier: n.identifier, repository_id: n.repository_id}}] AS nodes"""

CYPHER_REPOSITORY_GRAPH = """// kg:repository-graph
MATCH (r:Repository {repository_id: $repository_id})
OPTIONAL MATCH (r)-[:CONTAINS]->(c:Component)
WITH r, collect(DISTINCT c) AS components
OPTIONAL MATCH (r)-[:USES]->(d:Dependency)
WITH r, components, d
ORDER BY CASE WHEN d.status = 'VULNERABLE' THEN 0 ELSE 1 END, d.name, d.version
WITH r, components, collect(d) AS all_deps
WITH r, components, all_deps[0..$limit] AS deps, size(all_deps) AS total_dependencies
OPTIONAL MATCH (r)-[:USES]->(:Dependency)-[:AFFECTED_BY]->(v:Vulnerability)
WITH r, components, deps, total_dependencies, collect(DISTINCT v) AS vulns
WITH [r] + components + vulns + deps AS nodes, size(components) AS total_components,
     total_dependencies, size(vulns) AS total_vulnerabilities
UNWIND nodes AS a
OPTIONAL MATCH (a)-[rel:CONTAINS|USES|DEPENDS_ON|AFFECTED_BY]->(b)
WHERE b IN nodes
WITH nodes, total_components, total_dependencies, total_vulnerabilities,
     collect(DISTINCT CASE WHEN rel IS NULL THEN null
                           ELSE {source: elementId(a), target: elementId(b), type: type(rel)} END) AS edges
RETURN [n IN nodes | {eid: elementId(n), labels: labels(n), props: properties(n)}] AS nodes, edges,
       total_components, total_dependencies, total_vulnerabilities"""

CYPHER_REMOVE_REPOSITORY = """// kg:remove-repository
MATCH (n {repository_id: $repository_id})
WHERE n:Repository OR n:Component OR n:Dependency
DETACH DELETE n
RETURN count(*) AS n"""

# Schema statements: constraints on Community, NODE KEY constraints where the edition allows.
SCHEMA_STATEMENTS_COMMON: tuple[str, ...] = (
    "CREATE CONSTRAINT repository_id_unique IF NOT EXISTS "
    "FOR (r:Repository) REQUIRE r.repository_id IS UNIQUE",
    "CREATE CONSTRAINT vulnerability_identifier_unique IF NOT EXISTS "
    "FOR (v:Vulnerability) REQUIRE v.identifier IS UNIQUE",
    # Composite indexes/keys only serve seeks with ALL key properties bound; stale-edge
    # deletion and pruning look nodes up by repository_id alone, hence these two.
    "CREATE INDEX component_repository_idx IF NOT EXISTS FOR (c:Component) ON (c.repository_id)",
    "CREATE INDEX dependency_repository_idx IF NOT EXISTS FOR (d:Dependency) ON (d.repository_id)",
)
SCHEMA_STATEMENTS_ENTERPRISE: tuple[str, ...] = (
    "CREATE CONSTRAINT component_key IF NOT EXISTS "
    "FOR (c:Component) REQUIRE (c.repository_id, c.path) IS NODE KEY",
    "CREATE CONSTRAINT dependency_key IF NOT EXISTS "
    "FOR (d:Dependency) REQUIRE (d.repository_id, d.ecosystem, d.name, d.version) IS NODE KEY",
)
SCHEMA_STATEMENTS_COMMUNITY: tuple[str, ...] = (
    "CREATE INDEX component_key_idx IF NOT EXISTS FOR (c:Component) ON (c.repository_id, c.path)",
    "CREATE INDEX dependency_key_idx IF NOT EXISTS "
    "FOR (d:Dependency) ON (d.repository_id, d.ecosystem, d.name, d.version)",
)


def sync_statements(batches: SyncBatches) -> list[SyncStatement]:
    """The ordered statements of one sync transaction: nodes → stale-edge deletion → edges → pruning."""
    rid = batches.repository_id
    return [
        SyncStatement("merge-repository", "node", CYPHER_MERGE_REPOSITORY,
                      {"repository_id": rid, "props": batches.repository}),
        SyncStatement("merge-components", "node", CYPHER_MERGE_COMPONENTS,
                      {"repository_id": rid, "rows": batches.components}),
        SyncStatement("merge-dependencies", "node", CYPHER_MERGE_DEPENDENCIES,
                      {"repository_id": rid, "rows": batches.dependencies}),
        SyncStatement("merge-vulnerabilities", "node", CYPHER_MERGE_VULNERABILITIES,
                      {"repository_id": rid, "rows": batches.vulnerabilities}),
        SyncStatement("delete-stale-repository-edges", "delete", CYPHER_DELETE_STALE_REPOSITORY_EDGES,
                      {"repository_id": rid}),
        SyncStatement("delete-stale-component-edges", "delete", CYPHER_DELETE_STALE_COMPONENT_EDGES,
                      {"repository_id": rid}),
        SyncStatement("delete-stale-dependency-edges", "delete", CYPHER_DELETE_STALE_DEPENDENCY_EDGES,
                      {"repository_id": rid}),
        SyncStatement("merge-contains", "relationship", CYPHER_MERGE_CONTAINS,
                      {"repository_id": rid, "rows": batches.contains}),
        SyncStatement("merge-repository-uses", "relationship", CYPHER_MERGE_REPOSITORY_USES,
                      {"repository_id": rid, "rows": batches.repository_uses}),
        SyncStatement("merge-component-uses", "relationship", CYPHER_MERGE_COMPONENT_USES,
                      {"repository_id": rid, "rows": batches.component_uses}),
        SyncStatement("merge-depends-on", "relationship", CYPHER_MERGE_DEPENDS_ON,
                      {"repository_id": rid, "rows": batches.depends_on}),
        SyncStatement("merge-affected-by", "relationship", CYPHER_MERGE_AFFECTED_BY,
                      {"repository_id": rid, "rows": batches.affected_by}),
        SyncStatement("prune-orphan-dependencies", "prune", CYPHER_PRUNE_ORPHAN_DEPENDENCIES,
                      {"repository_id": rid}),
        SyncStatement("prune-orphan-components", "prune", CYPHER_PRUNE_ORPHAN_COMPONENTS,
                      {"repository_id": rid}),
    ]


# ---------------------------------------------------------------------------- service


class KnowledgeGraphService:
    """Populates and queries the software knowledge graph (contract §4.4)."""

    def __init__(self, client: GraphClient | None = None) -> None:
        self.client: GraphClient = client if client is not None else Neo4jClient()
        self._schema_ready = False

    # ------------------------------------------------------------ availability

    def available(self) -> bool:
        return self.client.available()

    # ------------------------------------------------------------------ schema

    def ensure_constraints(self) -> bool:
        """Create constraints / indexes (idempotent). Returns ``False`` when Neo4j is unavailable.

        Raises :class:`GraphQueryError` if the server rejects a schema statement.
        """
        if self._schema_ready:
            return True
        if not self.client.available():
            return False
        edition = self.client.edition()
        enterprise = edition == "enterprise"
        statements = SCHEMA_STATEMENTS_COMMON + (
            SCHEMA_STATEMENTS_ENTERPRISE if enterprise else SCHEMA_STATEMENTS_COMMUNITY
        )
        for cypher in statements:
            self.client.run_write(cypher)
        if not self.client.available():
            return False
        self._schema_ready = True
        log.info(
            "Graph schema ensured (%s edition: %s)",
            edition or "unknown",
            "NODE KEY constraints" if enterprise else "composite indexes + MERGE uniqueness",
        )
        return True

    # -------------------------------------------------------------------- sync

    def sync_analysis(
        self,
        repository: Repository,
        components: Sequence[Component],
        dependencies: Sequence[Dependency],
        relations: Sequence[DependencyRelation],
        dep_vulns: Mapping[Any, Sequence[Vulnerability]] | None,
        component_usage: Mapping[Any, Sequence[str]] | None,
    ) -> GraphSyncResult:
        """Write one analysis into the graph (one transaction, UNWIND batches). Never raises."""
        if not self.client.available():
            return self._unavailable_result()

        batches = build_sync_batches(repository, components, dependencies, relations, dep_vulns, component_usage)
        statements = sync_statements(batches)
        try:
            if not self.ensure_constraints():
                return self._unavailable_result()
            results = self.client.run_write_batch([s.as_statement() for s in statements])
        except GraphQueryError as exc:
            log.error("Graph sync failed for repository %s: %s", batches.repository_id, exc.message)
            return GraphSyncResult(available=True, error=exc.message, skipped=dict(batches.skipped))
        except Exception as exc:  # noqa: BLE001 - the graph must never break the pipeline
            log.error("Graph sync failed for repository %s: %s", batches.repository_id, exc)
            return GraphSyncResult(available=True, error=f"Graph sync failed: {exc}", skipped=dict(batches.skipped))

        if not results:
            return self._unavailable_result()

        totals: dict[str, int] = {"node": 0, "delete": 0, "relationship": 0, "prune": 0}
        for statement, rows in zip(statements, results, strict=False):
            totals[statement.kind] += _count(rows)

        result = GraphSyncResult(
            available=True,
            nodes_written=totals["node"],
            relationships_written=totals["relationship"],
            stale_relationships_deleted=totals["delete"],
            nodes_pruned=totals["prune"],
            skipped=dict(batches.skipped),
        )
        log.info(
            "Graph synced for repository %s: %d nodes (%d components, %d dependencies, %d vulnerabilities), "
            "%d relationships; %d stale relationships removed, %d orphan nodes pruned",
            batches.repository_id,
            result.nodes_written,
            len(batches.components),
            len(batches.dependencies),
            len(batches.vulnerabilities),
            result.relationships_written,
            result.stale_relationships_deleted,
            result.nodes_pruned,
        )
        if batches.skipped:
            log.info("Graph sync skipped rows: %s", ", ".join(f"{k}={v}" for k, v in sorted(batches.skipped.items())))
        return result

    def remove_repository(self, repository_id: int) -> int:
        """Detach-delete the repository, its components and dependencies (vulnerabilities are global).

        Returns the number of deleted nodes (``0`` when Neo4j is unavailable).
        """
        if not self.client.available():
            return 0
        rows = self.client.run_write(CYPHER_REMOVE_REPOSITORY, repository_id=int(repository_id))
        deleted = _count(rows)
        log.info("Removed repository %s from the graph (%d nodes)", repository_id, deleted)
        return deleted

    def _unavailable_result(self) -> GraphSyncResult:
        error = getattr(self.client, "last_error", None) or "Neo4j unavailable"
        return GraphSyncResult(available=False, error=error)

    # ----------------------------------------------------------------- queries

    def components_using_dependency(self, dep: Dependency) -> list[dict[str, Any]]:
        """Components whose files reference ``dep``: ``[{path, name, component_type}, ...]``."""
        rows = self.client.run(CYPHER_COMPONENTS_USING, **dependency_key(dep))
        return [
            {"path": row.get("path"), "name": row.get("name"), "component_type": row.get("component_type")}
            for row in rows
        ]

    def related_dependencies(self, dep: Dependency) -> dict[str, list[dict[str, Any]]]:
        """Direct ``DEPENDS_ON`` neighbours: ``{"depends_on": [...], "depended_on_by": [...]}``."""
        key = dependency_key(dep)
        return {
            "depends_on": [_related_row(row) for row in self.client.run(CYPHER_DEPENDS_ON, **key)],
            "depended_on_by": [_related_row(row) for row in self.client.run(CYPHER_DEPENDED_ON_BY, **key)],
        }

    def vulnerabilities_for_dependency(self, dep: Dependency) -> list[dict[str, Any]]:
        """Vulnerabilities linked to ``dep`` via ``AFFECTED_BY``."""
        rows = self.client.run(CYPHER_VULNERABILITIES_FOR, **dependency_key(dep))
        return [
            {
                "identifier": row.get("identifier"),
                "severity": row.get("severity"),
                "cvss_score": row.get("cvss_score"),
                "summary": row.get("summary"),
                "source": row.get("source"),
                "aliases": list(row.get("aliases") or []),
                "reference_url": row.get("reference_url"),
            }
            for row in rows
        ]

    def has_dependency(self, dep: Dependency) -> bool:
        """Whether the ``Dependency`` node for ``dep`` exists in the graph (``False`` when unavailable)."""
        rows = self.client.run(CYPHER_DEPENDENCY_EXISTS, **dependency_key(dep))
        return _count(rows) > 0

    def dependency_paths(self, dep: Dependency, max_depth: int = 4, limit: int = 25) -> list[list[str]]:
        """Simple paths from the Repository node to ``dep`` rendered as ``["Repository:app", "Component:src", ...]``.

        Shortest paths come first: paths are enumerated one length at a time (1 hop, then 2,
        ... up to ``max_depth``) and the enumeration stops as soon as ``limit`` paths were
        collected, so the direct ``Repository -USES-> dep`` path is never crowded out by the
        thousands of longer paths a dense lock-file graph has, and no more than ``limit``
        matching paths are ever expanded per length. Paths that visit a node twice (cycles
        in ``DEPENDS_ON``) are excluded.
        """
        depth = max(1, min(int(max_depth), MAX_PATH_DEPTH))
        cap = max(1, int(limit))
        key = dependency_key(dep)
        paths: list[list[str]] = []
        seen: set[tuple[str, ...]] = set()
        for length in range(1, depth + 1):
            remaining = cap - len(paths)
            if remaining <= 0:
                break
            cypher = CYPHER_DEPENDENCY_PATHS_TEMPLATE.format(length=length)
            for row in self.client.run(cypher, **key, limit=remaining):
                rendered = _render_simple_path(row.get("nodes") or [])
                if rendered is None or tuple(rendered) in seen:
                    continue
                seen.add(tuple(rendered))
                paths.append(rendered)
                if len(paths) >= cap:
                    break
        return paths

    def repository_graph(self, repository_id: int, limit: int = 500) -> dict[str, Any]:
        """UI-ready sub-graph: ``{"nodes": [{id, label, type, props}], "edges": [{source, target, type}]}``.

        Nodes are ordered repository → components → vulnerabilities → dependencies
        (vulnerable ones first) and truncated to ``limit``; edges are those between
        returned nodes. ``truncated`` and ``stats`` are extra diagnostics for the UI.
        """
        cap = max(1, int(limit))
        rows = self.client.run(CYPHER_REPOSITORY_GRAPH, repository_id=int(repository_id), limit=cap)
        empty: dict[str, Any] = {
            "nodes": [],
            "edges": [],
            "truncated": False,
            "stats": {"components": 0, "dependencies": 0, "vulnerabilities": 0},
        }
        if not rows:
            return empty
        row = rows[0]
        raw_nodes = list(row.get("nodes") or [])
        stats = {
            "components": int(row.get("total_components") or 0),
            "dependencies": int(row.get("total_dependencies") or 0),
            "vulnerabilities": int(row.get("total_vulnerabilities") or 0),
        }
        available_total = 1 + stats["components"] + stats["dependencies"] + stats["vulnerabilities"]

        id_by_eid: dict[str, str] = {}
        seen_ids: set[str] = set()
        nodes: list[dict[str, Any]] = []
        for raw in raw_nodes[:cap]:
            props = dict(raw.get("props") or {})
            label = _primary_label(raw.get("labels") or [])
            node_id = graph_node_id(label, props)
            if node_id in seen_ids:
                continue
            seen_ids.add(node_id)
            id_by_eid[str(raw.get("eid"))] = node_id
            nodes.append({"id": node_id, "label": node_display_name(label, props), "type": label, "props": props})

        edges: list[dict[str, str]] = []
        seen_edges: set[tuple[str, str, str]] = set()
        for raw_edge in row.get("edges") or []:
            source = id_by_eid.get(str(raw_edge.get("source")))
            target = id_by_eid.get(str(raw_edge.get("target")))
            edge_type = str(raw_edge.get("type"))
            if source is None or target is None:
                continue
            triple = (source, target, edge_type)
            if triple in seen_edges:
                continue
            seen_edges.add(triple)
            edges.append({"source": source, "target": target, "type": edge_type})

        return {
            "nodes": nodes,
            "edges": edges,
            "truncated": available_total > len(nodes),
            "stats": stats,
        }

    def dependency_context(self, dep: Dependency) -> GraphContext:
        """Graph facts for the AI agents; ``available=False`` whenever Neo4j cannot answer.

        The context is also ``available=False`` when the ``Dependency`` node does not exist
        (the sync for this analysis failed or was pruned): "no graph facts" must never be
        rendered as the FACT "no components use it / no known vulnerabilities".
        """
        if not self.client.available():
            return GraphContext(available=False)
        try:
            if not self.has_dependency(dep):
                if self.client.available():
                    log.info(
                        "Dependency %s (repository %s) is not in the knowledge graph: no graph facts for this finding",
                        dependency_label(dep.package_name, dep.version),
                        dep.repository_id,
                    )
                return GraphContext(available=False)
            components = self.components_using_dependency(dep)
            related = self.related_dependencies(dep)
            vulnerabilities = self.vulnerabilities_for_dependency(dep)
            paths = self.dependency_paths(dep)
        except GraphQueryError as exc:
            log.warning("Graph context unavailable for %s: %s", dependency_label(dep.package_name, dep.version), exc.message)
            return GraphContext(available=False)
        if not self.client.available():  # connection dropped while querying
            return GraphContext(available=False)
        return GraphContext(
            available=True,
            components_using=[c["path"] for c in components if c.get("path")],
            depends_on=[dependency_label(x["name"], x["version"]) for x in related["depends_on"]],
            depended_on_by=[dependency_label(x["name"], x["version"]) for x in related["depended_on_by"]],
            vulnerabilities=[v["identifier"] for v in vulnerabilities if v.get("identifier")],
            paths=paths,
        )


def _render_simple_path(nodes: Sequence[Mapping[str, Any]]) -> list[str] | None:
    """Render one ``dependency-paths`` row; ``None`` for an empty path or one that revisits a node.

    Node identity is the ``eid`` (``elementId``) the query returns, falling back to the rendered
    label, so the "simple path" guarantee holds even if the Cypher predicate is ever relaxed.
    """
    rendered: list[str] = []
    visited: set[Any] = set()
    for node in nodes:
        label = render_node_label(node.get("labels") or [], node)
        identity = node.get("eid") if node.get("eid") is not None else label
        if identity in visited:
            return None
        visited.add(identity)
        rendered.append(label)
    return rendered or None


def _related_row(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "name": row.get("name"),
        "version": row.get("version") or None,
        "ecosystem": row.get("ecosystem"),
        "scope": row.get("scope"),
        "status": row.get("status"),
        "dependency_id": row.get("dependency_id"),
        "label": dependency_label(row.get("name"), row.get("version")),
    }


__all__ = [
    "GraphSyncResult",
    "KnowledgeGraphService",
    "SyncBatches",
    "SyncStatement",
    "build_sync_batches",
    "dependency_key",
    "dependency_label",
    "graph_node_id",
    "node_display_name",
    "render_node_label",
    "sync_statements",
]
