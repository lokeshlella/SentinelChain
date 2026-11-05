"""The interactive docs of a build list only what it exposes (Phase-1 builds leave out Phase 2)."""

from __future__ import annotations

import json
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.api.openapi import FEATURE_KEY, filter_openapi
from app.core.config import Settings
from app.main import app

PHASE_2_PATHS = {
    "/api/findings/{finding_id}/analyze",
    "/api/findings/{finding_id}/remediate",
    "/api/findings/{finding_id}/report",
    "/api/remediations/{remediation_id}",
    "/api/remediations/{remediation_id}/validations",
    "/api/remediations/{remediation_id}/validate",
    "/api/remediations/{remediation_id}/report",
    "/api/remediations/{remediation_id}/pull-request",
    "/api/validations/{validation_id}",
    "/api/validations/{validation_id}/logs",
    "/api/pull-requests",
    "/api/pull-requests/{pr_id}",
}
PHASE_2_ONLY_SCHEMAS = {"RemediationDetail", "ValidationSummary", "ValidationDetail", "PullRequestSummary", "PullRequestDetail"}


def openapi(**overrides) -> dict:
    with patch("app.main.get_settings", return_value=Settings(_env_file=None, **overrides)):
        return TestClient(app).get("/openapi.json").json()


def test_the_complete_product_documents_every_route():
    schema = openapi()
    assert PHASE_2_PATHS <= set(schema["paths"])
    assert PHASE_2_ONLY_SCHEMAS <= set(schema["components"]["schemas"])
    assert FEATURE_KEY not in json.dumps(schema)


def test_phase_1_docs_leave_out_phase_2_operations_and_their_schemas():
    schema = openapi(sentinel_phase=1)
    assert not PHASE_2_PATHS & set(schema["paths"])
    assert {"/api/repositories", "/api/analyses/{analysis_id}", "/api/findings/{finding_id}", "/api/features", "/api/health"} <= set(schema["paths"])
    names = set(schema["components"]["schemas"])
    assert not PHASE_2_ONLY_SCHEMAS & names
    assert {"FindingDetail", "AnalysisDetail", "RepositoryDetail", "DashboardOut"} <= names
    assert FEATURE_KEY not in json.dumps(schema)


def test_an_extra_feature_brings_back_only_its_own_operations():
    paths = set(openapi(sentinel_phase=1, sentinel_features="ai")["paths"])
    assert "/api/findings/{finding_id}/analyze" in paths
    assert not {"/api/findings/{finding_id}/remediate", "/api/remediations/{remediation_id}", "/api/pull-requests"} & paths


def test_a_path_keeps_its_open_operations_and_the_input_is_not_modified():
    schema = {
        "paths": {"/x": {"get": {"responses": {}}, "post": {FEATURE_KEY: "ai", "responses": {}}}, "/y": {"post": {FEATURE_KEY: "ai", "responses": {}}}},
        "components": {"schemas": {}},
    }
    out = filter_openapi(schema, {"ai": False})
    assert out["paths"] == {"/x": {"get": {"responses": {}}}}
    assert schema["paths"]["/x"]["post"][FEATURE_KEY] == "ai"
