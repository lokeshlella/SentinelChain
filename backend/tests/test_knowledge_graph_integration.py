"""Integration tests against a live Neo4j (run with SENTINEL_INTEGRATION=1).

Connection settings come from ``Settings`` (NEO4J_URI / NEO4J_USERNAME / NEO4J_PASSWORD /
NEO4J_DATABASE). Every node written here carries the distinctive repository id 999999
and is deleted at the end; the advisory node is removed only if nothing else references it.
"""

from __future__ import annotations

import pytest
from neo4j import GraphDatabase

from app.core.config import get_settings
from app.models import Dependency
from app.services.agents.schemas import GraphContext
from app.services.knowledge_graph.client import Neo4jClient
from app.services.knowledge_graph.service import KnowledgeGraphService
from tests.fixtures.knowledge_graph.graph_fixture import ADVISORY_ID, build_graph_fixture

pytestmark = pytest.mark.integration

TEST_REPOSITORY_ID = 999999


def _cleanup(client: Neo4jClient) -> None:
    client.run_write(
        "MATCH (n {repository_id: $rid}) WHERE n:Repository OR n:Component OR n:Dependency DETACH DELETE n",
        rid=TEST_REPOSITORY_ID,
    )
    client.run_write(
        "MATCH (v:Vulnerability {identifier: $id}) WHERE NOT (v)<-[:AFFECTED_BY]-() DELETE v",
        id=ADVISORY_ID,
    )


@pytest.fixture
def client():
    client = Neo4jClient()
    if not client.available():
        pytest.skip(f"Neo4j not reachable at {get_settings().neo4j_uri}: {client.last_error}")
    _cleanup(client)
    yield client
    _cleanup(client)


@pytest.fixture
def service(client):
    return KnowledgeGraphService(client=client)


@pytest.fixture
def fixture(db):
    return build_graph_fixture(db, repository_id=TEST_REPOSITORY_ID, name="sentinel-graph-it")


@pytest.fixture
def synced(service, fixture):
    result = service.sync_analysis(
        fixture.repository,
        fixture.components,
        fixture.dependency_list,
        fixture.relations,
        fixture.dep_vulns(),
        fixture.component_usage(),
    )
    assert result.ok, result
    return result


def _count(client, cypher, **params) -> int:
    rows = client.run(cypher, **params)
    return int(rows[0]["n"]) if rows else 0


def test_schema_exists_after_sync(client, synced):
    names = {row["name"] for row in client.run("SHOW CONSTRAINTS YIELD name RETURN name")}
    assert {"repository_id_unique", "vulnerability_identifier_unique"} <= names
    index_names = {row["name"] for row in client.run("SHOW INDEXES YIELD name RETURN name")}
    if client.edition() == "enterprise":
        assert {"component_key", "dependency_key"} <= names
    else:
        assert {"component_key_idx", "dependency_key_idx"} <= index_names
    assert {"component_repository_idx", "dependency_repository_idx"} <= index_names


def test_sync_writes_expected_nodes_and_edges(client, synced):
    assert synced.available is True
    assert synced.nodes_written == 7  # 1 repository + 2 components + 3 dependencies + 1 vulnerability
    assert synced.relationships_written == 10  # 2 CONTAINS + 3 USES + 3 component USES + 1 DEPENDS_ON + 1 AFFECTED_BY
    assert synced.skipped == {"duplicate_dependencies": 1, "duplicate_affected_by": 1}

    rid = TEST_REPOSITORY_ID
    assert _count(client, "MATCH (r:Repository {repository_id: $rid}) RETURN count(r) AS n", rid=rid) == 1
    assert _count(client, "MATCH (c:Component {repository_id: $rid}) RETURN count(c) AS n", rid=rid) == 2
    assert _count(client, "MATCH (d:Dependency {repository_id: $rid}) RETURN count(d) AS n", rid=rid) == 3
    assert _count(client, "MATCH (d:Dependency {repository_id: $rid, name: 'requests'}) RETURN count(d) AS n", rid=rid) == 1
    row = client.run(
        "MATCH (d:Dependency {repository_id: $rid, name: 'flask'}) RETURN d.version AS version, d.status AS status, "
        "d.version_spec AS spec, d.scope AS scope",
        rid=rid,
    )[0]
    assert row == {"version": "", "status": "UNKNOWN", "spec": ">=2.0", "scope": "unknown"}
    edges = client.run(
        "MATCH (a {repository_id: $rid})-[rel]->(b) RETURN type(rel) AS type, count(rel) AS n ORDER BY type", rid=rid
    )
    assert {e["type"]: e["n"] for e in edges} == {"AFFECTED_BY": 1, "CONTAINS": 2, "DEPENDS_ON": 1, "USES": 6}
    vuln = client.run("MATCH (v:Vulnerability {identifier: $id}) RETURN v.severity AS s, v.cvss_score AS c", id=ADVISORY_ID)
    assert vuln == [{"s": "MEDIUM", "c": 6.1}]


def test_components_using_dependency(service, fixture, synced):
    rows = service.components_using_dependency(fixture.dependencies["requests"])
    assert [(r["path"], r["component_type"]) for r in rows] == [("src", "source"), ("tests", "tests")]
    # Either PostgreSQL row of the duplicated dependency resolves to the same node.
    assert service.components_using_dependency(fixture.dependencies["requests_dev"]) == rows
    assert service.components_using_dependency(fixture.dependencies["flask"]) == []


def test_related_dependencies(service, fixture, synced):
    related = service.related_dependencies(fixture.dependencies["requests"])
    assert [d["label"] for d in related["depends_on"]] == ["urllib3@1.26.15"]
    assert related["depends_on"][0]["dependency_id"] == fixture.dependencies["urllib3"].dependency_id
    assert related["depended_on_by"] == []

    reverse = service.related_dependencies(fixture.dependencies["urllib3"])
    assert reverse["depends_on"] == []
    assert [d["label"] for d in reverse["depended_on_by"]] == ["requests@2.28.2"]
    assert reverse["depended_on_by"][0]["status"] == "VULNERABLE"


def test_vulnerabilities_for_dependency(service, fixture, synced):
    rows = service.vulnerabilities_for_dependency(fixture.dependencies["requests"])
    assert len(rows) == 1
    assert rows[0]["identifier"] == ADVISORY_ID
    assert rows[0]["severity"] == "MEDIUM"
    assert rows[0]["cvss_score"] == 6.1
    assert rows[0]["aliases"] == ["CVE-2023-32681"]
    assert rows[0]["source"] == "osv"
    assert service.vulnerabilities_for_dependency(fixture.dependencies["urllib3"]) == []


def test_dependency_paths(service, fixture, synced):
    paths = service.dependency_paths(fixture.dependencies["urllib3"])
    assert paths[0] == ["Repository:sentinel-graph-it", "Dependency:urllib3@1.26.15"]  # shortest first
    assert ["Repository:sentinel-graph-it", "Dependency:requests@2.28.2", "Dependency:urllib3@1.26.15"] in paths
    assert ["Repository:sentinel-graph-it", "Component:src", "Dependency:urllib3@1.26.15"] in paths
    assert [
        "Repository:sentinel-graph-it", "Component:src", "Dependency:requests@2.28.2", "Dependency:urllib3@1.26.15"
    ] in paths
    assert all(len(p) <= 5 for p in paths)  # max_depth=4 -> at most 5 nodes

    # Depth 1 only reaches the direct USES edge.
    assert service.dependency_paths(fixture.dependencies["urllib3"], max_depth=1) == [
        ["Repository:sentinel-graph-it", "Dependency:urllib3@1.26.15"]
    ]
    assert service.dependency_paths(fixture.dependencies["flask"]) == [["Repository:sentinel-graph-it", "Dependency:flask"]]


def _add_packages(client: Neo4jClient, names: list[str], *, component: str | None = "src") -> None:
    """Add npm ``Dependency`` nodes (USED by the repository and optionally by ``component``)."""
    client.run_write(
        """MATCH (r:Repository {repository_id: $rid})
           OPTIONAL MATCH (c:Component {repository_id: $rid, path: $component})
           UNWIND $names AS name
           MERGE (d:Dependency {repository_id: $rid, ecosystem: 'npm', name: name, version: '1.0'})
           MERGE (r)-[:USES]->(d)
           FOREACH (_ IN CASE WHEN c IS NULL THEN [] ELSE [1] END | MERGE (c)-[:USES]->(d))""",
        rid=TEST_REPOSITORY_ID,
        names=names,
        component=component,
    )


def _depends_on(client: Neo4jClient, edges: list[tuple[str, str]]) -> None:
    client.run_write(
        """UNWIND $edges AS e
           MATCH (a:Dependency {repository_id: $rid, ecosystem: 'npm', name: e[0], version: '1.0'})
           MATCH (b:Dependency {repository_id: $rid, ecosystem: 'npm', name: e[1], version: '1.0'})
           MERGE (a)-[:DEPENDS_ON]->(b)""",
        rid=TEST_REPOSITORY_ID,
        edges=[list(e) for e in edges],
    )


def _npm_dependency(name: str, version: str = "1.0") -> Dependency:
    return Dependency(
        repository_id=TEST_REPOSITORY_ID, analysis_id=1, package_name=name, version=version,
        ecosystem="npm", source_file="package-lock.json",
    )


def test_dependency_paths_on_a_dense_graph_keep_the_direct_paths_first(client, service, synced):
    """Thousands of paths (a popular package in a lock-file graph): the 1- and 2-hop paths must still come first."""
    names = [f"pkg{i}" for i in range(60)]
    _add_packages(client, names)  # repository USES all, src USES all
    _depends_on(client, [(a, b) for a in names for b in names if a != b])  # complete DEPENDS_ON graph
    target = _npm_dependency("pkg59")
    total = _count(
        client,
        "MATCH (r:Repository {repository_id: $rid}) MATCH (d:Dependency {repository_id: $rid, name: 'pkg59'}) "
        "MATCH p = (r)-[:CONTAINS|USES|DEPENDS_ON*1..3]->(d) RETURN count(p) AS n",
        rid=TEST_REPOSITORY_ID,
    )
    assert total > 1000  # far more than any single-query scan window

    paths = service.dependency_paths(target)
    assert len(paths) == 25
    assert paths[0] == ["Repository:sentinel-graph-it", "Dependency:pkg59@1.0"]  # the only 1-hop path
    assert [len(p) for p in paths] == [2] + [3] * 24  # then 2-hop paths only: shortest first, never 3-hop ones
    assert all(len(set(p)) == len(p) for p in paths)  # simple paths only
    assert len({tuple(p) for p in paths}) == len(paths)

    # Once the limit accommodates all 60 two-hop paths, the Component path is among them, before any 3-hop path.
    wide = service.dependency_paths(target, limit=100)
    assert len(wide) == 100 and [len(p) for p in wide] == [2] + [3] * 60 + [4] * 39
    assert ["Repository:sentinel-graph-it", "Component:src", "Dependency:pkg59@1.0"] in wide[1:61]

    # A smaller limit stops the expansion early and still starts with the direct path.
    assert service.dependency_paths(target, limit=3)[0] == ["Repository:sentinel-graph-it", "Dependency:pkg59@1.0"]
    context = service.dependency_context(target)
    assert context.available is True and context.paths[0] == ["Repository:sentinel-graph-it", "Dependency:pkg59@1.0"]
    assert context.components_using == ["src"]


def test_dependency_paths_exclude_walks_through_dependency_cycles(client, service, synced):
    _add_packages(client, ["cyc-a", "cyc-b", "cyc-d"], component=None)
    _depends_on(client, [("cyc-a", "cyc-b"), ("cyc-b", "cyc-a"), ("cyc-a", "cyc-d")])
    paths = service.dependency_paths(_npm_dependency("cyc-d"))
    assert paths == [
        ["Repository:sentinel-graph-it", "Dependency:cyc-d@1.0"],
        ["Repository:sentinel-graph-it", "Dependency:cyc-a@1.0", "Dependency:cyc-d@1.0"],
        ["Repository:sentinel-graph-it", "Dependency:cyc-b@1.0", "Dependency:cyc-a@1.0", "Dependency:cyc-d@1.0"],
    ]  # and NOT r -> a -> b -> a -> d


def test_dependency_context_for_a_dependency_missing_from_the_graph(service, fixture, synced):
    """Neo4j is up but this dependency was never written: no facts, not "no components / no vulnerabilities"."""
    assert service.has_dependency(fixture.dependencies["requests"]) is True
    missing = Dependency(
        repository_id=TEST_REPOSITORY_ID, analysis_id=fixture.analysis.analysis_id, package_name="requests",
        version="2.99.0", ecosystem="PyPI", source_file="requirements.txt",
    )
    assert service.has_dependency(missing) is False
    assert service.dependency_context(missing) == GraphContext(available=False)
    assert service.dependency_context(_npm_dependency("never-synced")) == GraphContext(available=False)
    assert service.dependency_context(fixture.dependencies["requests"]).available is True


def test_repository_graph(service, synced):
    graph = service.repository_graph(TEST_REPOSITORY_ID)
    ids = [n["id"] for n in graph["nodes"]]
    rid = TEST_REPOSITORY_ID
    assert ids[0] == f"Repository:{rid}"
    assert set(ids) == {
        f"Repository:{rid}",
        f"Component:{rid}:src",
        f"Component:{rid}:tests",
        f"Vulnerability:{ADVISORY_ID}",
        f"Dependency:{rid}:PyPI:requests@2.28.2",
        f"Dependency:{rid}:PyPI:urllib3@1.26.15",
        f"Dependency:{rid}:PyPI:flask",
    }
    # vulnerable dependency is listed before the safe/unknown ones
    dep_ids = [i for i in ids if i.startswith("Dependency:")]
    assert dep_ids[0].endswith("requests@2.28.2")
    edges = {(e["source"], e["target"], e["type"]) for e in graph["edges"]}
    assert (f"Repository:{rid}", f"Component:{rid}:src", "CONTAINS") in edges
    assert (f"Component:{rid}:src", f"Dependency:{rid}:PyPI:requests@2.28.2", "USES") in edges
    assert (f"Dependency:{rid}:PyPI:requests@2.28.2", f"Dependency:{rid}:PyPI:urllib3@1.26.15", "DEPENDS_ON") in edges
    assert (f"Dependency:{rid}:PyPI:requests@2.28.2", f"Vulnerability:{ADVISORY_ID}", "AFFECTED_BY") in edges
    assert len(graph["edges"]) == 10
    assert graph["truncated"] is False
    assert graph["stats"] == {"components": 2, "dependencies": 3, "vulnerabilities": 1}
    node_types = {n["type"] for n in graph["nodes"]}
    assert node_types == {"Repository", "Component", "Dependency", "Vulnerability"}
    labels = {n["label"] for n in graph["nodes"]}
    assert {"sentinel-graph-it", "src", "requests@2.28.2", "flask", ADVISORY_ID} <= labels

    small = service.repository_graph(TEST_REPOSITORY_ID, limit=4)
    assert len(small["nodes"]) == 4 and small["truncated"] is True
    kept = {n["id"] for n in small["nodes"]}
    assert all(e["source"] in kept and e["target"] in kept for e in small["edges"])


def test_dependency_context(service, fixture, synced):
    context = service.dependency_context(fixture.dependencies["requests"])
    assert isinstance(context, GraphContext)
    assert context.available is True
    assert context.components_using == ["src", "tests"]
    assert context.depends_on == ["urllib3@1.26.15"]
    assert context.depended_on_by == []
    assert context.vulnerabilities == [ADVISORY_ID]
    assert ["Repository:sentinel-graph-it", "Dependency:requests@2.28.2"] in context.paths
    assert ["Repository:sentinel-graph-it", "Component:src", "Dependency:requests@2.28.2"] in context.paths


def test_resync_replaces_stale_edges_and_prunes_orphans(client, service, fixture, synced):
    # Second analysis: flask disappeared, urllib3 is no longer used by src, requests now SAFE.
    remaining = [fixture.dependencies["requests"], fixture.dependencies["urllib3"]]
    fixture.dependencies["requests"].vulnerability_status = "SAFE"
    result = service.sync_analysis(
        fixture.repository,
        fixture.components,
        remaining,
        [],  # no lock-file relations this time
        {},  # no vulnerabilities this time
        {fixture.dependencies["requests"].dependency_id: ["src"]},
    )
    assert result.ok
    assert result.stale_relationships_deleted == 10
    assert result.nodes_pruned == 1  # flask
    assert result.relationships_written == 2 + 2 + 1  # CONTAINS x2, repo USES x2, component USES x1

    rid = TEST_REPOSITORY_ID
    assert _count(client, "MATCH (d:Dependency {repository_id: $rid}) RETURN count(d) AS n", rid=rid) == 2
    assert service.related_dependencies(fixture.dependencies["requests"]) == {"depends_on": [], "depended_on_by": []}
    assert service.vulnerabilities_for_dependency(fixture.dependencies["requests"]) == []
    assert service.components_using_dependency(fixture.dependencies["requests"]) == [
        {"path": "src", "name": "src", "component_type": "source"}
    ]
    assert service.components_using_dependency(fixture.dependencies["urllib3"]) == []
    status = client.run("MATCH (d:Dependency {repository_id: $rid, name: 'requests'}) RETURN d.status AS s", rid=rid)
    assert status == [{"s": "SAFE"}]
    # The advisory node is global and survives (other repositories may reference it).
    assert _count(client, "MATCH (v:Vulnerability {identifier: $id}) RETURN count(v) AS n", id=ADVISORY_ID) == 1


def test_remove_repository(client, service, synced):
    assert service.remove_repository(TEST_REPOSITORY_ID) == 6
    assert _count(client, "MATCH (n {repository_id: $rid}) RETURN count(n) AS n", rid=TEST_REPOSITORY_ID) == 0
    assert service.repository_graph(TEST_REPOSITORY_ID)["nodes"] == []


def test_unreachable_server_degrades_gracefully(fixture):
    settings = get_settings()
    dead = GraphDatabase.driver("bolt://127.0.0.1:1", auth=(settings.neo4j_username, "irrelevant"), connection_timeout=2)
    try:
        service = KnowledgeGraphService(client=Neo4jClient(dead, settings.neo4j_database))
        result = service.sync_analysis(fixture.repository, fixture.components, fixture.dependency_list, [], {}, {})
        assert result.available is False and result.error
        assert service.dependency_context(fixture.dependencies["requests"]) == GraphContext(available=False)
        assert service.repository_graph(TEST_REPOSITORY_ID)["nodes"] == []
    finally:
        dead.close()


def test_wrong_credentials_degrade_gracefully(fixture):
    settings = get_settings()
    wrong = GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_username, "definitely-wrong"), connection_timeout=5)
    try:
        client = Neo4jClient(wrong, settings.neo4j_database)
        assert client.available() is False
        assert "unauthorized" in client.last_error.lower() or "authentication" in client.last_error.lower()
        assert KnowledgeGraphService(client=client).dependency_paths(fixture.dependencies["requests"]) == []
    finally:
        wrong.close()
