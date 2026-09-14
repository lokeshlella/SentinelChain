# Sentinel Chain — Agentic AI for Secure Software Supply Chains (V1)

> An extensible Agentic AI-based foundation for application-aware software dependency
> security analysis and assisted remediation.

Sentinel Chain ingests a repository, extracts its dependencies, checks them against
[OSV.dev](https://osv.dev), builds a software knowledge graph in Neo4j, asks a **local** LLM
(Ollama) to reason about application impact and risk using only observed evidence, proposes a
dependency upgrade, validates it in a Docker sandbox, produces an evidence report and opens a
**draft** GitHub pull request for developer review.

```
Repository → Repository Analysis → Dependency Extraction → Knowledge Graph (Neo4j)
          → Vulnerability Detection (OSV) → AI Dependency Analysis → Impact Assessment
          → Risk Evaluation → Remediation Recommendation → Proposed Change
          → Docker Sandbox Validation → Evidence Report → Draft Pull Request → Developer Review
```

V1 is an academic prototype: a working, understandable, modular, locally runnable end-to-end
workflow — not a production system. See `docs/` for the specification, architecture, API and
implementation status.

## Requirements

| Component | Version | Notes |
|---|---|---|
| Python | 3.11+ | backend (3.12 in Docker, 3.13 tested locally) |
| Node.js | 20+ | frontend build (Vite) |
| Docker Desktop / Engine | any recent | PostgreSQL + Neo4j via Compose **and** the validation sandbox |
| Ollama | 0.5+ | local LLM; runs on the host machine |
| git | any | cloning repositories |

## Quick start (backend + frontend on the host, databases in Docker)

```bash
# 1. Configuration
cp .env.example .env            # defaults work for the compose services below

# 2. Backing services
docker compose up -d postgres neo4j

# 3. Local LLM (host machine)
ollama serve &                  # or: brew services start ollama
ollama pull llama3.2:3b         # any model works; set OLLAMA_MODEL in .env

# 4. Backend
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload --port 8000

# 5. Frontend (new terminal)
cd frontend
npm install
npm run dev                     # http://localhost:5173 (proxies /api to :8000)
```

Open http://localhost:5173 (dashboard) and http://localhost:8000/docs (OpenAPI).
`GET http://localhost:8000/api/health` reports the status of PostgreSQL, Neo4j, Ollama,
Docker and GitHub configuration.

## Full Docker Compose run

```bash
docker compose --profile full up --build
```

* Frontend: http://localhost:3000 — Backend: http://localhost:8000
* The backend container reaches Ollama on the host through `http://host.docker.internal:11434`
  (override with `OLLAMA_BASE_URL_DOCKER`).
* The backend container mounts `/var/run/docker.sock` so the sandbox can start validation
  containers on the host daemon ("Docker-outside-of-Docker"). Workspaces are copied into
  sandbox containers (no bind mounts), so this works from inside the container as well.

## Configuration (`.env`)

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | PostgreSQL SQLAlchemy URL (`postgresql+psycopg://...`) |
| `NEO4J_URI`, `NEO4J_USERNAME`, `NEO4J_PASSWORD` | Knowledge graph connection |
| `OLLAMA_BASE_URL`, `OLLAMA_MODEL` | Local LLM endpoint and model name (never hard-coded in code) |
| `OLLAMA_TIMEOUT`, `AI_MAX_FINDINGS_PER_ANALYSIS` | LLM call timeout; cap on findings analysed per run |
| `GITHUB_TOKEN` | Optional. Enables private clones and draft PR creation |
| `REPOSITORY_WORKSPACE` | Directory for clones, working copies, sandbox logs (default `./workspace`) |
| `DOCKER_TIMEOUT`, `DOCKER_PYTHON_IMAGE`, `DOCKER_NODE_IMAGE` | Sandbox limits and base images |

Never commit `.env`.

## Tests

```bash
cd backend
.venv/bin/pytest -q                                  # unit tests (no external services)
SENTINEL_INTEGRATION=1 .venv/bin/pytest -q -m integration   # live OSV / Neo4j / Ollama / Docker
```

## Running the demo

The bundled demo project (`examples/demo-project`, a small Flask + lodash application that
pins publicly documented vulnerable versions — nothing malicious) exercises every stage.
Follow `docs/DEMO.md`; in short:

1. Dashboard → *Add repository* → absolute path of `examples/demo-project` (or a GitHub URL).
2. Repository page → *Analyze* → watch the stages complete (≈2 min with `llama3.2:3b`).
3. Open a finding → *Generate remediation* → *Validate in Docker sandbox* → *Create draft pull request*.
4. Read the evidence report (`…/report?format=markdown`) — a real one is in
   `docs/EXAMPLE_EVIDENCE_REPORT.md`, the matching PR description in `docs/EXAMPLE_PR_DESCRIPTION.md`.

## How a finding flows through the system

| Stage | Module | What is real |
|---|---|---|
| Ingestion | `services/repository` | GitPython clone / safe local copy; structure profile; components |
| Extraction | `services/dependencies` | `requirements*.txt` (PEP 508), `package.json` + `package-lock.json` (v1/v2/v3, Node resolution) |
| Detection | `services/vulnerabilities` | OSV.dev batch API, CVSS 3.x scoring, alias-group merging; `UNKNOWN` when OSV is unreachable — never "safe" |
| Graph | `services/knowledge_graph` | Neo4j nodes/relations per the spec, queries for components / related deps / paths |
| Evidence | `services/analysis/usage.py` | import/require scan of the working copy → files, lines, components |
| Agents | `services/llm`, `services/agents` | Ollama via `/api/chat` with JSON-schema output; dependency → impact → risk → remediation agents; Pydantic validation, correction re-prompts, guardrails against invented components/versions |
| Remediation | `services/remediation` | OSV fixed versions → registry (PyPI/npm, yanked/deprecated skipped) → OSV re-verification → LLM choice → deterministic edit in a temporary copy |
| Validation | `services/sandbox` | Docker container (no mounts, caps dropped, limits, timeout): install + tests; OSV security scan of the new version |
| Report | `services/reports` | 10-section evidence report (facts / AI reasoning / recommendations / validation) in JSON + Markdown |
| PR | `services/github` | branch + commit + push + **draft** PR via PyGithub; manual instructions without a token |

Long stages (analysis, validation) run as background tasks with status polling
(`GET /api/analyses/{id}`, `GET /api/validations/{id}`). See `docs/API.md` for every endpoint
and `docs/ARCHITECTURE.md` for the module contract.

## Project layout

```
backend/app/
  api/            routes, dependency factories, serializers
  core/           settings, logging, exceptions, version helpers
  db/             SQLAlchemy engine/session, Neo4j driver
  models/         ORM entities (Repository, Component, Dependency, DependencyRelation,
                  Vulnerability, Analysis, Finding, Remediation, Validation, PullRequest)
  schemas/        Pydantic API models
  services/       one package per stage (see table above)
backend/alembic/  migrations            backend/tests/  pytest suite (776 unit + 20 integration)
frontend/src/     React pages: Dashboard, Repository, Analysis, Finding, Remediation,
                  Validation, Pull request(s), Health
examples/demo-project/   deliberately vulnerable demo application (documented, verified with OSV)
docs/             specification, architecture, API, demo, example report & PR description
workspace/        (git-ignored) clones, remediation working copies, sandbox logs, reports
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `/api/health` → ollama *unreachable* | `ollama serve`; from Docker use `OLLAMA_BASE_URL=http://host.docker.internal:11434` |
| ollama *model not pulled* | `ollama pull <OLLAMA_MODEL>` — the name must match `ollama list` exactly (tags included) |
| LLM calls time out on a small machine | use a 3B model, raise `OLLAMA_TIMEOUT`, lower `AI_MAX_FINDINGS_PER_ANALYSIS` |
| Validation `FAILED` with a Docker error | start Docker Desktop / the daemon; the first run pulls `python:3.12-slim` / `node:20-slim` |
| Dependencies `UNKNOWN: Version not pinned` | pin versions or add a lock file — Sentinel Chain never guesses a version |
| Dependencies `UNKNOWN: Vulnerability check unavailable` | OSV.dev unreachable (network / `OSV_API_URL`) |
| PR `UNAVAILABLE` | set `GITHUB_TOKEN` and use a GitHub-hosted repository; otherwise follow the printed manual steps |

## Status and limitations

See `V1_IMPLEMENTATION_STATUS.md` for the implemented / partial features, known limitations
and the V2 roadmap. Sentinel Chain V1 is an academic prototype: it assists developers with
evidence-backed dependency upgrades; it does not merge, deploy or act autonomously.
