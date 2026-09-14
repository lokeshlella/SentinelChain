"""Unit tests for KnowledgeGraphService (no Neo4j: a FakeNeo4jClient records the Cypher)."""

from __future__ import annotations

import pytest

from app.models import Dependency, DependencyRelation
from app.services.agents.schemas import GraphContext
from app.services.knowledge_graph.client import GraphQueryError
from app.services.knowledge_graph.service import (
    MAX_PATH_DEPTH,
    GraphSyncResult,
    KnowledgeGraphService,
    build_sync_batches,
    dependency_key,
    dependency_label,
    graph_node_id,
    render_node_label,
    sync_statements,
)
from tests.fixtures.knowledge_graph.fake_client import FakeNeo4jClient
from tests.fixtures.knowledge_graph.graph_fixture import ADVISORY_ID, build_graph_fixture

NODE_TAGS = ["merge-repository", "merge-components", "merge-dependencies", "merge-vulnerabilities"]
DELETE_TAGS = ["delete-stale-repository-edges", "delete-stale-component-edges", "delete-stale-dependency-edges"]
EDGE_TAGS = ["merge-contains", "merge-repository-uses", "merge-component-uses", "merge-depends-on", "merge-affected-by"]
PRUNE_TAGS = ["prune-orphan-dependencies", "prune-orphan-components"]


@pytest.fixture
def fixture(db):
    return build_graph_fixture(db)


@pytest.fixture
def fake():
    return FakeNeo4jClient()


@pytest.fixture
def service(fake):
    return KnowledgeGraphService(client=fake)


def _sync(service, fixture, **overrides):
    kwargs = {
        "repository": fixture.repository,
        "components": fixture.components,
        "dependencies": fixture.dependency_list,
        "relations": fixture.relations,
        "dep_vulns": fixture.dep_vulns(),
        "component_usage": fixture.component_usage(),
    }
    kwargs.update(overrides)
    return service.sync_analysis(**kwargs)


# ------------------------------------------------------------------- batch building


def test_batches_use_natural_keys_and_dedupe(fixture):
    batches = build_sync_batches(
        fixture.repository,
        fixture.components,
        fixture.dependency_list,
        fixture.relations,
        fixture.dep_vulns(),
        fixture.component_usage(),
    )
    rid = fixture.repository.repository_id
    assert batches.repository_id == rid
    assert batches.repository == {
        "name": "sentinel-demo",
        "source_url": "https://github.com/example/sentinel-demo",
        "source_type": "github",
        "language": "Python",
    }
    assert [c["path"] for c in batches.components] == ["src", "tests"]
    assert batches.components[0]["props"] == {"name": "src", "component_type": "source"}

    # requests appears twice in PostgreSQL (two requirement files) but is ONE graph node.
    assert [(d["name"], d["version"]) for d in batches.dependencies] == [
        ("requests", "2.28.2"),
        ("urllib3", "1.26.15"),
        ("flask", ""),  # unknown version -> "" so MERGE has a non-null key
    ]
    requests_row = batches.dependencies[0]
    assert set(requests_row) == {"repository_id", "ecosystem", "name", "version", "props"}
    assert requests_row["props"] == {
        "name": "requests",
        "version": "2.28.2",
        "ecosystem": "PyPI",
        "scope": "direct",
        "source_file": "requirements.txt",
        "status": "VULNERABLE",
        "dependency_id": fixture.dependencies["requests"].dependency_id,
        "analysis_id": fixture.analysis.analysis_id,
        "version_spec": "==2.28.2",
    }
    assert batches.repository_uses == [
        {"repository_id": rid, "ecosystem": "PyPI", "name": "requests", "version": "2.28.2"},
        {"repository_id": rid, "ecosystem": "PyPI", "name": "urllib3", "version": "1.26.15"},
        {"repository_id": rid, "ecosystem": "PyPI", "name": "flask", "version": ""},
    ]

    # The same advisory is attached to both requests rows -> one Vulnerability, one AFFECTED_BY.
    assert [v["identifier"] for v in batches.vulnerabilities] == [ADVISORY_ID]
    vuln_props = batches.vulnerabilities[0]["props"]
    assert vuln_props["severity"] == "MEDIUM"
    assert vuln_props["cvss_score"] == 6.1
    assert vuln_props["aliases"] == ["CVE-2023-32681"]
    assert vuln_props["source"] == "osv"
    assert batches.affected_by == [
        {"repository_id": rid, "ecosystem": "PyPI", "name": "requests", "version": "2.28.2", "identifier": ADVISORY_ID}
    ]
    assert batches.depends_on == [
        {
            "parent": {"repository_id": rid, "ecosystem": "PyPI", "name": "requests", "version": "2.28.2"},
            "child": {"repository_id": rid, "ecosystem": "PyPI", "name": "urllib3", "version": "1.26.15"},
        }
    ]
    assert batches.component_uses == [
        {"path": "src", "repository_id": rid, "ecosystem": "PyPI", "name": "requests", "version": "2.28.2"},
        {"path": "tests", "repository_id": rid, "ecosystem": "PyPI", "name": "requests", "version": "2.28.2"},
        {"path": "src", "repository_id": rid, "ecosystem": "PyPI", "name": "urllib3", "version": "1.26.15"},
    ]
    assert batches.skipped == {"duplicate_dependencies": 1, "duplicate_affected_by": 1}


def test_batches_skip_unknown_ids_and_bad_relations(fixture, db):
    requests_id = fixture.dependencies["requests"].dependency_id
    urllib3_id = fixture.dependencies["urllib3"].dependency_id
    relations = fixture.relations + [
        DependencyRelation(parent_dependency_id=requests_id, child_dependency_id=urllib3_id),  # duplicate
        DependencyRelation(parent_dependency_id=requests_id, child_dependency_id=requests_id),  # self loop
        DependencyRelation(parent_dependency_id=requests_id, child_dependency_id=424242),  # foreign id
    ]
    usage = fixture.component_usage()
    usage[requests_id] = ["src", "does-not-exist", "src"]
    usage[424242] = ["src"]
    dep_vulns = fixture.dep_vulns()
    dep_vulns[424242] = [fixture.vulnerability]

    batches = build_sync_batches(
        fixture.repository, fixture.components, fixture.dependency_list, relations, dep_vulns, usage
    )
    assert len(batches.depends_on) == 1
    assert [(u["path"], u["name"]) for u in batches.component_uses] == [("src", "requests"), ("src", "urllib3")]
    assert batches.skipped == {
        "duplicate_dependencies": 1,
        "duplicate_affected_by": 1,
        "duplicate_relations": 1,
        "relations_self_reference": 1,
        "relations_unknown_dependency": 1,
        "vulnerabilities_unknown_dependency": 1,
        "usage_unknown_component": 1,
        "duplicate_component_uses": 1,
        "usage_unknown_dependency": 1,
    }


def test_batches_accept_string_ids_and_missing_maps(fixture):
    requests_id = fixture.dependencies["requests"].dependency_id
    batches = build_sync_batches(
        fixture.repository, fixture.components, fixture.dependency_list, [], None, {str(requests_id): ["tests"]}
    )
    assert batches.vulnerabilities == [] and batches.affected_by == [] and batches.depends_on == []
    assert [(u["path"], u["name"]) for u in batches.component_uses] == [("tests", "requests")]


def test_sync_statements_order_nodes_then_stale_deletes_then_edges_then_prune(fixture):
    batches = build_sync_batches(fixture.repository, fixture.components, fixture.dependency_list, [], {}, {})
    statements = sync_statements(batches)
    assert [s.tag for s in statements] == NODE_TAGS + DELETE_TAGS + EDGE_TAGS + PRUNE_TAGS
    kinds = {s.tag: s.kind for s in statements}
    assert all(kinds[t] == "node" for t in NODE_TAGS)
    assert all(kinds[t] == "delete" for t in DELETE_TAGS)
    assert all(kinds[t] == "relationship" for t in EDGE_TAGS)
    assert all(kinds[t] == "prune" for t in PRUNE_TAGS)
    for statement in statements:
        assert statement.params["repository_id"] == fixture.repository.repository_id
        if statement.tag.startswith("merge-") and statement.tag != "merge-repository":
            assert "UNWIND $rows AS row" in statement.cypher
            assert isinstance(statement.params["rows"], list)


# ---------------------------------------------------------------------- sync_analysis


def test_sync_runs_schema_then_one_batched_transaction(service, fake, fixture):
    result = _sync(service, fixture)

    assert result == GraphSyncResult(
        available=True,
        nodes_written=1 + 2 + 3 + 1,
        relationships_written=2 + 3 + 3 + 1 + 1,
        error=None,
        stale_relationships_deleted=0,
        nodes_pruned=0,
        skipped={"duplicate_dependencies": 1, "duplicate_affected_by": 1},
    )
    assert result.ok

    # Schema first (own transactions), then every sync statement inside ONE batch.
    schema_calls = fake.calls_for("schema")
    assert schema_calls and all(c.mode == "write" for c in schema_calls)
    assert all("IF NOT EXISTS" in c.cypher for c in schema_calls)
    batch_tags = fake.tags(mode="batch")
    assert batch_tags == NODE_TAGS + DELETE_TAGS + EDGE_TAGS + PRUNE_TAGS
    first_batch_index = next(i for i, c in enumerate(fake.calls) if c.mode == "batch")
    assert all(c.mode == "write" for c in fake.calls[:first_batch_index])

    # Stale-edge deletion is executed strictly before any relationship MERGE.
    last_delete = max(batch_tags.index(t) for t in DELETE_TAGS)
    first_edge = min(batch_tags.index(t) for t in EDGE_TAGS)
    assert last_delete < first_edge
    for tag in DELETE_TAGS:
        cypher = fake.calls_for(tag)[0].cypher
        assert "DELETE rel" in cypher and "$repository_id" in cypher
    assert "CONTAINS|USES" in fake.calls_for("delete-stale-repository-edges")[0].cypher
    assert "DEPENDS_ON|AFFECTED_BY" in fake.calls_for("delete-stale-dependency-edges")[0].cypher

    deps_call = fake.calls_for("merge-dependencies")[0]
    assert [r["name"] for r in deps_call.params["rows"]] == ["requests", "urllib3", "flask"]
    assert fake.calls_for("merge-repository")[0].params["props"]["name"] == "sentinel-demo"


def test_sync_community_edition_uses_composite_indexes(service, fake, fixture):
    _sync(service, fixture)
    schema = [c.cypher for c in fake.calls_for("schema")]
    assert any("Repository" in s and "IS UNIQUE" in s for s in schema)
    assert any("Vulnerability" in s and "IS UNIQUE" in s for s in schema)
    assert any("CREATE INDEX" in s and "(d.repository_id, d.ecosystem, d.name, d.version)" in s for s in schema)
    assert any("CREATE INDEX" in s and "(c.repository_id, c.path)" in s for s in schema)
    assert not any("NODE KEY" in s for s in schema)


def test_sync_enterprise_edition_uses_node_key_constraints(fixture):
    fake = FakeNeo4jClient(server_edition="enterprise")
    _sync(KnowledgeGraphService(client=fake), fixture)
    schema = [c.cypher for c in fake.calls_for("schema")]
    assert sum("IS NODE KEY" in s for s in schema) == 2


def test_schema_is_ensured_once_per_service(service, fake, fixture):
    _sync(service, fixture)
    _sync(service, fixture)
    assert len(fake.calls_for("schema")) == len({c.cypher for c in fake.calls_for("schema")})
    assert len(fake.calls_for("merge-dependencies")) == 2


def test_sync_counts_come_from_the_database_rows(fixture):
    fake = FakeNeo4jClient(
        responses={
            "delete-stale-repository-edges": [{"n": 4}],
            "delete-stale-dependency-edges": [{"n": 2}],
            "prune-orphan-dependencies": [{"n": 1}],
            "merge-component-uses": [{"n": 2}],  # one usage row matched no node
        }
    )
    result = _sync(KnowledgeGraphService(client=fake), fixture)
    assert result.stale_relationships_deleted == 6
    assert result.nodes_pruned == 1
    assert result.relationships_written == 2 + 3 + 2 + 1 + 1


def test_sync_when_neo4j_unavailable(fixture):
    fake = FakeNeo4jClient(is_available=False)
    result = KnowledgeGraphService(client=fake).sync_analysis(
        fixture.repository, fixture.components, fixture.dependency_list, fixture.relations, {}, {}
    )
    assert result.available is False
    assert result.nodes_written == 0 and result.relationships_written == 0
    assert "unavailable" in (result.error or "").lower()
    assert fake.calls == []  # nothing attempted


def test_sync_reports_query_errors_instead_of_raising(fixture):
    fake = FakeNeo4jClient(fail_with={"merge-dependencies": GraphQueryError("Neo4j query failed: boom")})
    result = _sync(KnowledgeGraphService(client=fake), fixture)
    assert result.available is True
    assert result.ok is False
    assert "boom" in result.error
    assert result.nodes_written == 0


def test_sync_reports_unexpected_errors(fixture):
    fake = FakeNeo4jClient(fail_with={"merge-contains": RuntimeError("driver exploded")})
    result = _sync(KnowledgeGraphService(client=fake), fixture)
    assert result.available is True and "driver exploded" in result.error


def test_sync_result_to_dict(fixture):
    result = _sync(KnowledgeGraphService(client=FakeNeo4jClient()), fixture)
    payload = result.to_dict()
    assert payload["available"] is True
    assert payload["nodes_written"] == 7
    assert set(payload) == {
        "available", "nodes_written", "relationships_written", "error",
        "stale_relationships_deleted", "nodes_pruned", "skipped",
    }


def test_remove_repository(service, fake, fixture):
    fake.responses["remove-repository"] = [{"n": 6}]
    assert service.remove_repository(fixture.repository.repository_id) == 6
    call = fake.calls_for("remove-repository")[0]
    assert call.mode == "write" and "DETACH DELETE" in call.cypher
    assert call.params == {"repository_id": fixture.repository.repository_id}
    assert KnowledgeGraphService(client=FakeNeo4jClient(is_available=False)).remove_repository(1) == 0


# ------------------------------------------------------------------------- queries


def test_dependency_key_uses_empty_string_for_unknown_version(fixture):
    flask = fixture.dependencies["flask"]
    assert dependency_key(flask) == {
        "repository_id": fixture.repository.repository_id,
        "ecosystem": "PyPI",
        "name": "flask",
        "version": "",
    }
    assert dependency_key(fixture.dependencies["requests"])["version"] == "2.28.2"


def test_components_using_dependency_shapes_rows(service, fake, fixture):
    fake.responses["components-using-dependency"] = [
        {"path": "src", "name": "src", "component_type": "source"},
        {"path": "tests", "name": "tests", "component_type": "tests"},
    ]
    dep = fixture.dependencies["requests"]
    rows = service.components_using_dependency(dep)
    assert rows == [
        {"path": "src", "name": "src", "component_type": "source"},
        {"path": "tests", "name": "tests", "component_type": "tests"},
    ]
    call = fake.calls_for("components-using-dependency")[0]
    assert call.mode == "read"
    assert call.params == dependency_key(dep)
    assert "<-[:USES]-(c:Component)" in call.cypher


def test_related_dependencies_shape(service, fake, fixture):
    fake.responses["depends-on"] = [
        {"name": "urllib3", "version": "1.26.15", "ecosystem": "PyPI", "scope": "transitive",
         "status": "SAFE", "dependency_id": 7},
        {"name": "certifi", "version": "", "ecosystem": "PyPI", "scope": "unknown", "status": "UNKNOWN",
         "dependency_id": None},
    ]
    fake.responses["depended-on-by"] = []
    related = service.related_dependencies(fixture.dependencies["requests"])
    assert related["depended_on_by"] == []
    assert related["depends_on"][0] == {
        "name": "urllib3", "version": "1.26.15", "ecosystem": "PyPI", "scope": "transitive",
        "status": "SAFE", "dependency_id": 7, "label": "urllib3@1.26.15",
    }
    assert related["depends_on"][1]["version"] is None  # "" in the graph -> unknown
    assert related["depends_on"][1]["label"] == "certifi"
    assert {c.tag for c in fake.calls} == {"depends-on", "depended-on-by"}


def test_vulnerabilities_for_dependency_shape(service, fake, fixture):
    fake.responses["vulnerabilities-for-dependency"] = [
        {"identifier": ADVISORY_ID, "severity": "MEDIUM", "cvss_score": 6.1,
         "summary": "Unintended leak of Proxy-Authorization header in requests", "source": "osv",
         "aliases": ["CVE-2023-32681"], "reference_url": None}
    ]
    rows = service.vulnerabilities_for_dependency(fixture.dependencies["requests"])
    assert rows == [
        {"identifier": ADVISORY_ID, "severity": "MEDIUM", "cvss_score": 6.1,
         "summary": "Unintended leak of Proxy-Authorization header in requests", "source": "osv",
         "aliases": ["CVE-2023-32681"], "reference_url": None}
    ]
    # Missing list property -> empty list, never None.
    fake.responses["vulnerabilities-for-dependency"] = [{"identifier": "X", "aliases": None}]
    assert service.vulnerabilities_for_dependency(fixture.dependencies["requests"])[0]["aliases"] == []


REPO_NODE = {"eid": "4:x:0", "labels": ["Repository"], "name": "sentinel-demo", "path": None, "version": None}
SRC_NODE = {"eid": "4:x:1", "labels": ["Component"], "name": "src", "path": "src", "version": None}
REQUESTS_NODE = {"eid": "4:x:2", "labels": ["Dependency"], "name": "requests", "path": None, "version": "2.28.2"}
URLLIB3_NODE = {"eid": "4:x:3", "labels": ["Dependency"], "name": "urllib3", "path": None, "version": "1.26.15"}
FLASK_NODE = {"eid": "4:x:4", "labels": ["Dependency"], "name": "flask", "path": None, "version": ""}


def _path_length(cypher: str) -> int:
    """The fixed hop count ``*k..k`` of one ``dependency-paths`` statement."""
    low, high = cypher.split("DEPENDS_ON*")[1].split("]")[0].split("..")
    assert low == high, cypher  # one exact length per statement, never a range
    return int(low)


def _paths_by_length(fake: FakeNeo4jClient, rows_by_length: dict[int, list[list[dict]]]) -> None:
    """Answer ``dependency-paths`` per requested length (read from the recorded call), honouring ``$limit``."""

    def respond(params):
        length = _path_length(fake.calls[-1].cypher)
        rows = [{"nodes": nodes} for nodes in rows_by_length.get(length, [])]
        return rows[: params["limit"]]

    fake.responses["dependency-paths"] = respond


def test_dependency_paths_enumerate_length_by_length_shortest_first(service, fake, fixture):
    _paths_by_length(
        fake,
        {
            1: [[REPO_NODE, URLLIB3_NODE]],
            2: [
                [REPO_NODE, REQUESTS_NODE, URLLIB3_NODE],
                [REPO_NODE, REQUESTS_NODE, URLLIB3_NODE],  # duplicate row
                [],  # empty row is ignored
            ],
            3: [[REPO_NODE, SRC_NODE, REQUESTS_NODE, URLLIB3_NODE]],
        },
    )
    paths = service.dependency_paths(fixture.dependencies["urllib3"], max_depth=3)
    assert paths == [
        ["Repository:sentinel-demo", "Dependency:urllib3@1.26.15"],
        ["Repository:sentinel-demo", "Dependency:requests@2.28.2", "Dependency:urllib3@1.26.15"],
        ["Repository:sentinel-demo", "Component:src", "Dependency:requests@2.28.2", "Dependency:urllib3@1.26.15"],
    ]
    calls = fake.calls_for("dependency-paths")
    assert [_path_length(c.cypher) for c in calls] == [1, 2, 3]
    assert all(c.mode == "read" for c in calls)
    # The limit shrinks by what was already collected: never more than ``limit`` paths are expanded.
    assert [c.params["limit"] for c in calls] == [25, 24, 23]
    assert calls[0].params["name"] == "urllib3" and calls[0].params["repository_id"] == fixture.repository.repository_id
    for call in calls:
        # LIMIT applies only after the simple-path predicate; there is no truncation before ordering.
        assert "WHERE all(i IN range(0, size(ns) - 2) WHERE NOT ns[i] IN ns[i + 1..])" in call.cypher
        assert call.cypher.index("WHERE all(") < call.cypher.index("LIMIT $limit")
        assert "ORDER BY" not in call.cypher and "scan_limit" not in call.cypher


def test_dependency_paths_stop_expanding_once_the_limit_is_reached(service, fake, fixture):
    # A "popular" package: thousands of length-3 paths would exist; the direct path must still be first.
    many = [[REPO_NODE, {**REQUESTS_NODE, "eid": f"4:x:{100 + i}", "name": f"pkg{i}"}, URLLIB3_NODE] for i in range(50)]
    _paths_by_length(
        fake, {1: [[REPO_NODE, URLLIB3_NODE]], 2: [[REPO_NODE, SRC_NODE, URLLIB3_NODE]] + many, 3: many, 4: many}
    )
    paths = service.dependency_paths(fixture.dependencies["urllib3"], limit=5)
    assert len(paths) == 5
    assert paths[0] == ["Repository:sentinel-demo", "Dependency:urllib3@1.26.15"]
    assert paths[1] == ["Repository:sentinel-demo", "Component:src", "Dependency:urllib3@1.26.15"]
    assert [len(p) for p in paths] == sorted(len(p) for p in paths)  # shortest first
    calls = fake.calls_for("dependency-paths")
    assert [_path_length(c.cypher) for c in calls] == [1, 2]  # lengths 3 and 4 were never expanded
    assert [c.params["limit"] for c in calls] == [5, 4]


def test_dependency_paths_exclude_paths_that_revisit_a_node(service, fake, fixture):
    a = {"eid": "4:x:10", "labels": ["Dependency"], "name": "a", "path": None, "version": "1"}
    b = {"eid": "4:x:11", "labels": ["Dependency"], "name": "b", "path": None, "version": "1"}
    # Same rendered label, distinct nodes (different ecosystems): a legitimate simple path.
    npm_x = {"eid": "4:x:20", "labels": ["Dependency"], "name": "x", "path": None, "version": "1"}
    pypi_x = {"eid": "4:x:21", "labels": ["Dependency"], "name": "x", "path": None, "version": "1"}
    _paths_by_length(
        fake,
        {
            1: [[REPO_NODE, FLASK_NODE]],
            3: [
                [REPO_NODE, a, b, FLASK_NODE],
                [REPO_NODE, npm_x, pypi_x, FLASK_NODE],
                [{k: v for k, v in n.items() if k != "eid"} for n in (REPO_NODE, a, b, a, FLASK_NODE)],  # no eids
            ],
            4: [[REPO_NODE, a, b, a, FLASK_NODE]],  # a -> b -> a: a walk, not a dependency path
        },
    )
    paths = service.dependency_paths(fixture.dependencies["flask"])
    assert paths == [
        ["Repository:sentinel-demo", "Dependency:flask"],
        ["Repository:sentinel-demo", "Dependency:a@1", "Dependency:b@1", "Dependency:flask"],
        ["Repository:sentinel-demo", "Dependency:x@1", "Dependency:x@1", "Dependency:flask"],
    ]


def test_dependency_paths_depth_is_clamped(service, fake, fixture):
    service.dependency_paths(fixture.dependencies["flask"], max_depth=0)
    assert [_path_length(c.cypher) for c in fake.calls_for("dependency-paths")] == [1]
    fake.calls.clear()
    service.dependency_paths(fixture.dependencies["flask"], max_depth=99)
    assert [_path_length(c.cypher) for c in fake.calls_for("dependency-paths")] == list(range(1, MAX_PATH_DEPTH + 1))
    assert service.dependency_paths(fixture.dependencies["flask"], limit=0) == []


def test_render_helpers():
    assert render_node_label(["Repository"], {"name": "app"}) == "Repository:app"
    assert render_node_label(["Repository"], {"repository_id": 3}) == "Repository:3"
    assert render_node_label(["Component"], {"path": "src/api"}) == "Component:src/api"
    assert render_node_label(["Dependency"], {"name": "lodash", "version": "4.17.20"}) == "Dependency:lodash@4.17.20"
    assert render_node_label(["Dependency"], {"name": "lodash", "version": ""}) == "Dependency:lodash"
    assert render_node_label(["Vulnerability"], {"identifier": "GHSA-x"}) == "Vulnerability:GHSA-x"
    assert dependency_label("pkg", None) == "pkg"
    assert graph_node_id("Dependency", {"repository_id": 1, "ecosystem": "npm", "name": "lodash", "version": "4.17.20"}) == (
        "Dependency:1:npm:lodash@4.17.20"
    )
    assert graph_node_id("Component", {"repository_id": 1, "path": "src"}) == "Component:1:src"
    assert graph_node_id("Repository", {"repository_id": 1}) == "Repository:1"
    assert graph_node_id("Vulnerability", {"identifier": "GHSA-x"}) == "Vulnerability:GHSA-x"


def _graph_row(rid: int):
    return {
        "nodes": [
            {"eid": "4:a:0", "labels": ["Repository"], "props": {"repository_id": rid, "name": "sentinel-demo"}},
            {"eid": "4:a:1", "labels": ["Component"], "props": {"repository_id": rid, "path": "src", "name": "src"}},
            {"eid": "4:a:2", "labels": ["Vulnerability"], "props": {"identifier": ADVISORY_ID, "severity": "MEDIUM"}},
            {"eid": "4:a:3", "labels": ["Dependency"],
             "props": {"repository_id": rid, "ecosystem": "PyPI", "name": "requests", "version": "2.28.2",
                       "status": "VULNERABLE"}},
            {"eid": "4:a:4", "labels": ["Dependency"],
             "props": {"repository_id": rid, "ecosystem": "PyPI", "name": "urllib3", "version": "1.26.15"}},
        ],
        "edges": [
            {"source": "4:a:0", "target": "4:a:1", "type": "CONTAINS"},
            {"source": "4:a:0", "target": "4:a:3", "type": "USES"},
            {"source": "4:a:0", "target": "4:a:4", "type": "USES"},
            {"source": "4:a:1", "target": "4:a:3", "type": "USES"},
            {"source": "4:a:3", "target": "4:a:4", "type": "DEPENDS_ON"},
            {"source": "4:a:3", "target": "4:a:2", "type": "AFFECTED_BY"},
            {"source": "4:a:3", "target": "4:a:2", "type": "AFFECTED_BY"},  # duplicate
            {"source": "4:a:3", "target": "4:a:99", "type": "USES"},  # target not returned
        ],
        "total_components": 1,
        "total_dependencies": 2,
        "total_vulnerabilities": 1,
    }


def test_repository_graph_shapes_nodes_and_edges(service, fake):
    fake.responses["repository-graph"] = [_graph_row(1)]
    graph = service.repository_graph(1)
    assert [n["id"] for n in graph["nodes"]] == [
        "Repository:1",
        "Component:1:src",
        f"Vulnerability:{ADVISORY_ID}",
        "Dependency:1:PyPI:requests@2.28.2",
        "Dependency:1:PyPI:urllib3@1.26.15",
    ]
    assert [n["type"] for n in graph["nodes"]] == ["Repository", "Component", "Vulnerability", "Dependency", "Dependency"]
    assert [n["label"] for n in graph["nodes"]] == ["sentinel-demo", "src", ADVISORY_ID, "requests@2.28.2", "urllib3@1.26.15"]
    assert graph["nodes"][3]["props"]["status"] == "VULNERABLE"
    assert graph["edges"] == [
        {"source": "Repository:1", "target": "Component:1:src", "type": "CONTAINS"},
        {"source": "Repository:1", "target": "Dependency:1:PyPI:requests@2.28.2", "type": "USES"},
        {"source": "Repository:1", "target": "Dependency:1:PyPI:urllib3@1.26.15", "type": "USES"},
        {"source": "Component:1:src", "target": "Dependency:1:PyPI:requests@2.28.2", "type": "USES"},
        {"source": "Dependency:1:PyPI:requests@2.28.2", "target": "Dependency:1:PyPI:urllib3@1.26.15", "type": "DEPENDS_ON"},
        {"source": "Dependency:1:PyPI:requests@2.28.2", "target": f"Vulnerability:{ADVISORY_ID}", "type": "AFFECTED_BY"},
    ]
    assert graph["truncated"] is False
    assert graph["stats"] == {"components": 1, "dependencies": 2, "vulnerabilities": 1}
    call = fake.calls_for("repository-graph")[0]
    assert call.mode == "read" and call.params == {"repository_id": 1, "limit": 500}


def test_repository_graph_truncates_to_limit(service, fake):
    fake.responses["repository-graph"] = [_graph_row(1)]
    graph = service.repository_graph(1, limit=3)
    assert [n["id"] for n in graph["nodes"]] == ["Repository:1", "Component:1:src", f"Vulnerability:{ADVISORY_ID}"]
    assert graph["edges"] == [{"source": "Repository:1", "target": "Component:1:src", "type": "CONTAINS"}]
    assert graph["truncated"] is True
    assert fake.calls_for("repository-graph")[0].params["limit"] == 3


def test_repository_graph_for_unknown_repository_or_unavailable(service, fake):
    fake.responses["repository-graph"] = []
    assert service.repository_graph(12345) == {
        "nodes": [], "edges": [], "truncated": False,
        "stats": {"components": 0, "dependencies": 0, "vulnerabilities": 0},
    }
    down = KnowledgeGraphService(client=FakeNeo4jClient(is_available=False))
    assert down.repository_graph(1)["nodes"] == []


# ---------------------------------------------------------------- dependency_context


def test_dependency_context_collects_graph_facts(service, fake, fixture):
    repo_node = {"labels": ["Repository"], "name": "sentinel-demo"}
    fake.responses.update(
        {
            "components-using-dependency": [{"path": "src", "name": "src", "component_type": "source"}],
            "depends-on": [{"name": "urllib3", "version": "1.26.15"}],
            "depended-on-by": [{"name": "httpx-helper", "version": ""}],
            "vulnerabilities-for-dependency": [{"identifier": ADVISORY_ID}],
            "dependency-paths": [
                {"nodes": [repo_node, {"labels": ["Dependency"], "name": "requests", "version": "2.28.2"}]}
            ],
        }
    )
    context = service.dependency_context(fixture.dependencies["requests"])
    assert isinstance(context, GraphContext)
    assert context == GraphContext(
        available=True,
        components_using=["src"],
        depends_on=["urllib3@1.26.15"],
        depended_on_by=["httpx-helper"],
        vulnerabilities=[ADVISORY_ID],
        paths=[["Repository:sentinel-demo", "Dependency:requests@2.28.2"]],
    )
    # The facts are only collected after the node was confirmed to exist.
    tags = fake.tags()
    assert tags[0] == "dependency-exists"
    assert fake.calls[0].params == dependency_key(fixture.dependencies["requests"])
    assert {"components-using-dependency", "depends-on", "depended-on-by", "vulnerabilities-for-dependency",
            "dependency-paths"} <= set(tags[1:])


def test_dependency_context_is_unavailable_when_the_dependency_is_not_in_the_graph(service, fake, fixture, caplog):
    """A dependency that was never synced (sync failed / pruned) must not yield "no components, no vulns" FACTS."""
    fake.responses["dependency-exists"] = [{"n": 0}]
    fake.responses["vulnerabilities-for-dependency"] = [{"identifier": ADVISORY_ID}]  # must never be consulted
    dep = fixture.dependencies["requests"]
    with caplog.at_level("INFO"):
        context = service.dependency_context(dep)
    assert context == GraphContext(available=False)
    assert context.available is False and context.vulnerabilities == [] and context.components_using == []
    assert fake.tags() == ["dependency-exists"]  # no fact query ran against a missing node
    assert "requests@2.28.2" in caplog.text and "not in the knowledge graph" in caplog.text


def test_has_dependency(service, fake, fixture):
    dep = fixture.dependencies["flask"]
    assert service.has_dependency(dep) is True
    assert fake.calls[-1].mode == "read" and fake.calls[-1].params == dependency_key(dep)
    assert "RETURN count(d) AS n" in fake.calls[-1].cypher
    fake.responses["dependency-exists"] = [{"n": 0}]
    assert service.has_dependency(dep) is False
    assert KnowledgeGraphService(client=FakeNeo4jClient(is_available=False)).has_dependency(dep) is False


def test_dependency_context_when_unavailable(fixture):
    service = KnowledgeGraphService(client=FakeNeo4jClient(is_available=False))
    context = service.dependency_context(fixture.dependencies["requests"])
    assert context == GraphContext(available=False)
    assert service.has_dependency(fixture.dependencies["requests"]) is False
    assert service.components_using_dependency(fixture.dependencies["requests"]) == []
    assert service.related_dependencies(fixture.dependencies["requests"]) == {"depends_on": [], "depended_on_by": []}
    assert service.vulnerabilities_for_dependency(fixture.dependencies["requests"]) == []
    assert service.dependency_paths(fixture.dependencies["requests"]) == []


def test_dependency_context_is_unavailable_when_the_connection_drops_during_the_existence_check(fixture):
    """``[]`` from the existence probe while the client reports down is an outage, not a missing node."""
    fake = FakeNeo4jClient()

    def drop_connection(params):
        fake.is_available = False
        fake.last_error = "Neo4j unavailable: connection reset"
        return []

    fake.responses["dependency-exists"] = drop_connection
    context = KnowledgeGraphService(client=fake).dependency_context(fixture.dependencies["requests"])
    assert context == GraphContext(available=False)
    assert fake.tags() == ["dependency-exists"]


def test_dependency_context_swallows_query_errors(fixture):
    fake = FakeNeo4jClient(fail_with={"dependency-paths": GraphQueryError("Neo4j query failed: syntax")})
    context = KnowledgeGraphService(client=fake).dependency_context(fixture.dependencies["requests"])
    assert context.available is False and context.paths == []


def test_query_helpers_propagate_query_errors(fixture):
    """A rejected statement is a bug, not an outage: the API layer gets a 502-style error."""
    fake = FakeNeo4jClient(fail_with={"components-using-dependency": GraphQueryError("Neo4j query failed: x")})
    with pytest.raises(GraphQueryError):
        KnowledgeGraphService(client=fake).components_using_dependency(fixture.dependencies["requests"])


def test_service_defaults_to_real_client_without_connecting():
    from app.services.knowledge_graph.client import Neo4jClient

    service = KnowledgeGraphService()
    assert isinstance(service.client, Neo4jClient)
    assert service.client._driver is None  # resolved lazily, never at construction


def test_transient_dependency_objects_work_without_session():
    """Queries only need the natural key, so unsaved ORM objects are fine too."""
    dep = Dependency(repository_id=9, analysis_id=1, package_name="lodash", version="4.17.20",
                     ecosystem="npm", source_file="package.json")
    fake = FakeNeo4jClient(responses={"components-using-dependency": [{"path": ".", "name": "root", "component_type": "source"}]})
    rows = KnowledgeGraphService(client=fake).components_using_dependency(dep)
    assert rows[0]["path"] == "."
    assert fake.calls[0].params == {"repository_id": 9, "ecosystem": "npm", "name": "lodash", "version": "4.17.20"}
