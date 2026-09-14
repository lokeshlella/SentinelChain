# Sentinel Chain — REST API (V1)

Base URL: `http://localhost:8000/api` — interactive documentation at `http://localhost:8000/docs`
(OpenAPI / Swagger UI) and `/redoc`.

All errors share one shape:

```json
{"error": "NotFoundError", "message": "Finding 99 not found", "details": {}}
```

| Status | Error class | When |
|---|---|---|
| 400 | `ValidationFailedError`, `RepositoryError` | invalid URL/path, inaccessible repository, invalid request |
| 404 | `NotFoundError` | unknown id |
| 409 | `ConflictError` | duplicate repository, analysis already running, PR on a failed validation |
| 422 | `UnsupportedProjectError` / request validation | no supported dependency files, malformed body |
| 502 | `ExternalServiceError` | an external service failed in a way that blocks the request |

Long-running work (analysis, sandbox validation) is started with `202 Accepted` and polled
through `GET` until `status` is `COMPLETED` or `FAILED`.

## Health

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Status of PostgreSQL, Neo4j, Ollama (model present), Docker, GitHub token |
| GET | `/health/live` | Liveness probe |

## Dashboard

| Method | Path | Description |
|---|---|---|
| GET | `/dashboard` | Counts (repositories, dependencies, vulnerable dependencies, findings by risk, remediations, validations, PRs), recent analyses, high-risk findings, recent repositories |

## Repositories

| Method | Path | Body / query | Description |
|---|---|---|---|
| POST | `/repositories` | `{"source_url": "https://github.com/owner/repo" \| "/abs/path", "source_type"?: "github"\|"local", "branch"?: str}` | Register **and ingest** (clone / copy + structure profile + components). `201` |
| GET | `/repositories` | | List with latest analysis summary and dependency counts |
| GET | `/repositories/{id}` | | Detail: profile, components, analyses |
| DELETE | `/repositories/{id}` | | Removes rows, workspace copy and graph nodes. `204` |
| GET | `/repositories/{id}/dependencies` | `?status=SAFE\|VULNERABLE\|UNKNOWN` | Dependencies of the latest completed analysis |
| GET | `/repositories/{id}/analyses` | | Analyses (newest first) |
| GET | `/repositories/{id}/findings` | | Findings of the latest completed analysis |
| GET | `/repositories/{id}/graph` | `?limit=500` | Knowledge-graph nodes/edges (`available=false` when Neo4j is down) |
| POST | `/repositories/{id}/analyze` | `{"refresh"?: false, "run_ai"?: true}` | Start an analysis in the background. `202` with the `Analysis` |

## Analyses

| Method | Path | Description |
|---|---|---|
| GET | `/analyses` | Recent analyses |
| GET | `/analyses/{id}` | Status, per-stage status (`stages`), counters and warnings (`summary`), `overall_risk` |
| GET | `/analyses/{id}/findings` | Findings with nested dependency + vulnerability summaries |
| GET | `/analyses/{id}/dependencies` | Dependency snapshot of this analysis (`?status=` filter) |

`stages` keys: `repository`, `dependencies`, `vulnerabilities`, `usage`, `knowledge_graph`, `ai`
with values `PENDING | RUNNING | OK | PARTIAL | UNAVAILABLE | FAILED | SKIPPED`.

## Dependencies & vulnerabilities

| Method | Path | Description |
|---|---|---|
| GET | `/dependencies/{id}` | Dependency with its vulnerabilities, findings and lock-file relations |
| GET | `/dependencies/{id}/graph` | Components using it, related dependencies, vulnerabilities, paths (from Neo4j) |
| GET | `/dependencies/{id}/usage` | Live source-usage scan of the working copy |
| GET | `/vulnerabilities/{id}` | Vulnerability record (severity, CVSS, affected ranges, fixed versions) |
| GET | `/vulnerabilities/by-identifier/{identifier}` | Same, by OSV/GHSA/CVE identifier |

## Findings

| Method | Path | Body / query | Description |
|---|---|---|---|
| GET | `/findings` | `?analysis_id=&risk_level=&limit=` | Findings |
| GET | `/findings/{id}` | | Full finding: usage evidence (facts), `ai_results` (dependency analysis, impact, risk, failures, dropped components), `reasoning`, remediations |
| POST | `/findings/{id}/analyze` | | Run the AI agents for this finding now (synchronous; used for findings skipped by the per-analysis limit) |
| POST | `/findings/{id}/remediate` | | Generate a remediation: candidate versions (OSV + registry) → LLM recommendation → proposed change in a temporary workspace. `201` |
| GET | `/findings/{id}/report` | `?format=json\|markdown` | Evidence report (reproducible from stored data) |

## Remediations, validations, pull requests

| Method | Path | Body | Description |
|---|---|---|---|
| GET | `/remediations/{id}` | | Candidates, AI result, proposed change (file + unified diff), validations, PRs |
| POST | `/remediations/{id}/validate` | | Start Docker sandbox validation in the background. `202` with the `Validation` |
| GET | `/remediations/{id}/validations` | | Validations of the remediation |
| GET | `/remediations/{id}/report` | `?format=` | Evidence report for this remediation |
| POST | `/remediations/{id}/pull-request` | `{"force"?: false}` | Create a **draft** GitHub PR from a validated (or partially validated) workspace; `force` allows a failed/unknown validation. `201` |
| GET | `/validations/{id}` | | build / test / security / overall results, step details, logs |
| GET | `/validations/{id}/logs` | | Raw sandbox logs (`text/plain`) |
| GET | `/pull-requests` | | All pull requests |
| GET | `/pull-requests/{id}` | | Title, body, status (`DRAFT`, `OPEN`, `UNAVAILABLE`, `FAILED`), GitHub URL, evidence, manual instructions |

Validation result values: `PASS | FAIL | SKIPPED | UNKNOWN`. `overall_result` is `PASS` only
when build, tests **and** security scan passed. A skipped test suite is never counted as
passing: build + security `PASS` with tests `SKIPPED` gives `overall_result: UNKNOWN`, remediation
status `PARTIALLY_VALIDATED`, the report decision "Apply with manual testing", and a draft PR
can still be opened (the PR body states that the change is not behaviourally verified).

## Typical workflow with curl

```bash
# 1. register the demo project (local) — or a GitHub URL
curl -s -X POST localhost:8000/api/repositories -H 'Content-Type: application/json' \
  -d '{"source_url": "'"$PWD"'/examples/demo-project"}'

# 2. analyse (background) and poll
curl -s -X POST localhost:8000/api/repositories/1/analyze -H 'Content-Type: application/json' -d '{"run_ai": true}'
curl -s localhost:8000/api/analyses/1 | jq '.status, .stages, .overall_risk'

# 3. inspect findings, pick one, generate a remediation
curl -s localhost:8000/api/analyses/1/findings | jq '.[] | {finding_id, pkg: .dependency.package_name, vuln: .vulnerability.identifier, risk_level}'
curl -s -X POST localhost:8000/api/findings/5/remediate | jq '{remediation_id, recommended_version, status}'

# 4. validate in the Docker sandbox and poll
curl -s -X POST localhost:8000/api/remediations/1/validate | jq .validation_id
curl -s localhost:8000/api/validations/1 | jq '{status, build_status, test_status, security_scan_status, overall_result}'

# 5. evidence report and draft PR
curl -s 'localhost:8000/api/remediations/1/report?format=markdown'
curl -s -X POST localhost:8000/api/remediations/1/pull-request | jq '{review_status, pr_url, instructions}'
```
