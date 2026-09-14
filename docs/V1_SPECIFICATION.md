# Sentinel Chain — V1 Specification

**Agentic AI for Secure Software Supply Chains**

V1 is a working, understandable, modular, extensible, locally runnable, academically
demonstrable foundation — NOT a production system. The single most important requirement
is a REAL end-to-end workflow: no fake vulnerability data, no hard-coded AI responses, no
unnecessary microservices, no over-engineering. One clean monolithic FastAPI application
with modular internal services.

## 1. Vision / long-term workflow

Repository → Repository Analysis → Dependency Extraction → Software Knowledge Graph →
Vulnerability Detection → AI Dependency Analysis → Application Impact Assessment →
Risk Evaluation → Remediation Recommendation → Proposed Dependency Change →
Docker Sandbox Validation → Evidence Generation → Pull Request → Developer Review

## 2. V1 scope

1. GitHub repository URL input  2. Local repository input  3. Repository cloning/ingestion
4. Basic repository analysis  5. Dependency extraction  6. PostgreSQL persistence
7. OSV.dev vulnerability detection  8. Basic Software Knowledge Graph (Neo4j)
9. Ollama-based local LLM analysis  10. Application-aware dependency usage analysis
11. AI-assisted risk assessment  12. AI-assisted remediation recommendation
13. Safe dependency modification in a temporary workspace  14. Docker-based validation
15. Evidence report generation  16. Basic GitHub Pull Request generation  17. Simple web dashboard

Future versions add: more ecosystems, more vulnerability sources, more sophisticated agents,
better graph reasoning, advanced code analysis, more validation strategies, webhooks,
continuous monitoring, CI/CD, advanced PR workflows.

## 3. Technology stack (fixed)

Backend: Python 3.11+, FastAPI, Pydantic, SQLAlchemy, Alembic. Database: PostgreSQL.
Graph: Neo4j + official Python driver. LLM: **Ollama only** (no OpenAI/Anthropic/cloud),
through `LLMProvider → OllamaProvider`, configured by `OLLAMA_BASE_URL` / `OLLAMA_MODEL`
(never hard-code a model in code). Repository: GitPython, PyGithub. Vulnerability data: OSV.dev
via `VulnerabilityProvider → OSVProvider` (GHSA/NVD later). Sandbox: Docker.
Frontend: React + Vite. Testing: pytest. Docker Compose for the dev environment.

## 4. Architecture principle

No microservices. One FastAPI backend with clear internal modules:
`backend/app/{api,core,db,models,schemas,services/{repository,dependencies,vulnerabilities,
knowledge_graph,analysis,agents,llm,remediation,sandbox,reports,github}}`, `backend/tests`,
`frontend/src`, `docker-compose.yml`, `.env.example`, `README.md`, `docs/`.

## 5. Database (PostgreSQL, Alembic)

Entities: Repository, Component, Dependency, DependencyRelation, Vulnerability, Analysis,
Finding, Remediation, Validation, PullRequest — with proper foreign keys and indexes.
Do not add entities just to look large.

## 6. Repository ingestion

GitHub URL: clone into a workspace owned by Sentinel Chain; never modify the user's original
repository; record metadata. Local path: read it; create a safe temporary working copy when
modifications are needed. Basic analysis identifies: project name, language, dependency files,
source directories, test directories, basic structure. No sophisticated static analysis.

## 7. Dependency extraction

Python: `requirements.txt`. JavaScript: `package.json` (+ `package-lock.json` when available).
Extract package name, version/range, ecosystem, direct/transitive (only when reliably known —
never pretend), source file. `DependencyExtractor → PythonDependencyExtractor,
JavaScriptDependencyExtractor` (Maven/Gradle/Go/Cargo/... later).

## 8. OSV vulnerability detection

Real OSV.dev API integration querying ecosystem + package + version for every dependency.
Store results in PostgreSQL. Display id, severity, CVSS score if available, summary,
affected version info, reference URL. Classify SAFE / VULNERABLE / UNKNOWN. Never invent
results. Handle API failures, timeouts, rate limits, malformed responses gracefully. If OSV
cannot be reached show "Vulnerability check unavailable" — never "Safe".

## 9. Software knowledge graph (Neo4j)

Nodes: Repository, Component, Dependency, Vulnerability. Relationships:
`(Repository)-[:CONTAINS]->(Component)`, `(Repository)-[:USES]->(Dependency)`,
`(Component)-[:USES]->(Dependency)`, `(Dependency)-[:DEPENDS_ON]->(Dependency)`,
`(Dependency)-[:AFFECTED_BY]->(Vulnerability)`. Populated from actual analysis results.
Queries: components using a dependency; dependencies related to a dependency; vulnerabilities
affecting a dependency; dependency paths. No advanced graph reasoning in V1.

## 10. Application-aware impact analysis

For an affected dependency: find where it is imported/referenced in source files; identify
related components/directories; query Neo4j relationships; send this evidence to the LLM; ask
it to assess application impact. The LLM must NOT invent affected files — it receives actual
evidence (dependency, referencing files, component paths, graph relationships, vulnerability
info) and must distinguish FACT ("package X is imported by src/auth/service.py") from
INFERENCE ("changes to X may affect authentication").

## 11. Agentic AI V1

Modular agent classes (no AI microservices): `AIOrchestrator → DependencyAnalysisAgent →
ImpactAssessmentAgent → RiskEvaluationAgent → RemediationAgent`, all using OllamaProvider.
Inputs: repository + dependency + graph + vulnerability context + source usage evidence.

## 12. Structured LLM output

Never rely on free-form output for application logic. Pydantic models:
`DependencyAnalysisResult(summary, usage_evidence, confidence)`,
`ImpactAssessmentResult(affected_components, impact_level, reasoning, confidence)`,
`RiskAssessmentResult(risk_level, factors, reasoning, confidence)`,
`RemediationResult(recommended_version, alternative_package, reasoning, compatibility_notes,
confidence)`. Robust parsing + validation; on failure retry with a correction prompt, otherwise
mark the agent result as failed. Never silently fabricate output.

## 13. Remediation

Supports `package.json` and `requirements.txt`. Finding → candidate safer version →
compatibility check where possible → LLM recommendation → proposed change. The LLM does not
execute commands; deterministic code performs the file modification in a temporary workspace
(never the original repository). Store the proposed change.

## 14. Docker sandbox

Real Docker validation: temporary repository → apply change → isolated container → install
dependencies → build/install validation → run available tests → basic security/dependency
verification → collect logs → result with `build_status`, `test_status`,
`security_scan_status`, `overall_result` ∈ {PASS, FAIL, SKIPPED, UNKNOWN}. Never mark a
skipped test as PASS. Timeouts. Clean up containers/workspaces. Never execute untrusted code
on the host.

## 15. Security scan V1

Use OSV/dependency information to verify the proposed dependency state no longer contains
known vulnerabilities. Designed so Trivy/Semgrep can be added later.

## 16. Evidence report

Sections: 1 Repository, 2 Analysis, 3 Dependency, 4 Vulnerability, 5 Evidence,
6 Application Impact, 7 Risk Assessment, 8 Recommended Remediation, 9 Validation,
10 Final Recommendation. Clearly separate Observed Facts / AI Reasoning / Recommendations /
Validation Results. Reproducible from stored data. JSON + Markdown.

## 17. GitHub pull request

Validated temporary repository → branch → apply change → commit → push → DRAFT PR (never
auto-merge). Description contains vulnerability, dependency, current/recommended version,
impact, risk, validation results, evidence. Without credentials: do not fail — generate
branch/commit instructions, PR title, PR description and show "GitHub PR creation unavailable".

## 18. Frontend (simple, functional)

Pages: Dashboard (repositories, dependencies, vulnerable dependencies, high-risk findings,
recent analyses), Repository (details, dependency list, vulnerability status), Analysis
(status, findings, risk, affected components), Finding (dependency, vulnerability, affected
files/components, AI analysis, impact, risk, remediation), Validation (proposed change,
build/test/security results, logs), Pull Request (title, status, evidence, GitHub URL).

## 19. API (minimum)

`POST/GET /repositories`, `GET /repositories/{id}`, `POST /repositories/{id}/analyze`,
`GET /analyses/{id}`, `GET /analyses/{id}/findings`, `GET /dependencies/{id}`,
`GET /vulnerabilities/{id}`, `POST /findings/{id}/remediate`, `POST /remediations/{id}/validate`,
`POST /remediations/{id}/pull-request`, `GET /pull-requests/{id}` — with request validation,
response schemas, HTTP errors, logging.

## 20. Demonstration (primary success criterion)

User enters GitHub repo → clone + analyse → dependencies extracted → stored in PostgreSQL →
knowledge graph in Neo4j → OSV finds a vulnerable dependency → source usage found → Ollama
analyses purpose/impact/risk → Ollama recommends remediation → change applied to a temporary
copy → Docker validates → evidence report → draft PR when credentials exist.

## 21-24. Extensibility, configuration, compose, testing

Interfaces: RepositoryProvider, DependencyExtractor, VulnerabilityProvider, LLMProvider,
SandboxProvider, GitProvider. `.env` with DATABASE_URL, NEO4J_*, OLLAMA_BASE_URL, OLLAMA_MODEL,
GITHUB_TOKEN, REPOSITORY_WORKSPACE, DOCKER_TIMEOUT. Compose: PostgreSQL, Neo4j, backend,
frontend; Ollama stays on the host. Tests for ingestion, extraction, OSV provider, persistence,
graph creation, AI parsing, remediation modification, Docker result parsing, report generation,
plus one integration test dependency → vulnerability → finding. Normal tests mock the
OllamaProvider interface.

## 25-27. Demo data, logging, error handling

Demo project in `examples/demo-project/` with a deliberately selected dependency version that
is verifiable against OSV (never invent a vulnerability ID; document how to verify). Stage
logs: `[Repository] [Dependencies] [Vulnerability] [KnowledgeGraph] [AI] [Remediation]
[Sandbox] [Report] [GitHub]`. Handle invalid URLs, inaccessible repos, unsupported projects,
missing dependency files, OSV/Ollama/Neo4j/PostgreSQL/Docker/GitHub failures, failed builds
and tests. A failure in an optional feature must not destroy the application.

## 28. Not in V1

Autonomous deployment, auto-merge, Kubernetes, CI/CD pipelines, monitoring, webhooks, advanced
graph algorithms, RL, model training/fine-tuning, every ecosystem, multiple LLM providers,
complex auth/RBAC, frontend animations, microservices.

## 32. Academic positioning

"An extensible Agentic AI-based foundation for application-aware software dependency security
analysis and assisted remediation." No unsupported autonomy claims.
