# Sentinel Chain — V1 Implementation Status

_Status as of 2026-09-14. Verified live on macOS (Apple M2, 8 GB) with PostgreSQL 16, Neo4j 5,
Ollama `llama3.2:3b`, Docker 29 and the real OSV.dev / PyPI / npm APIs. Test suite: 776 unit
tests + 20 integration tests, all passing._

## Definition of done (spec §29)

| Item | Status | Evidence |
|---|---|---|
| Application starts | ✅ | `uvicorn app.main:app`, `docker compose --profile full build` succeeds |
| PostgreSQL works | ✅ | Alembic migration `171587e9a254`, 10 tables |
| Neo4j works | ✅ | `/api/health`; 31 nodes / 33 relationships for the demo project |
| Ollama connection works | ✅ | `/api/health` checks model presence; agents run with `llama3.2:3b` |
| GitHub repository ingested | ✅ | `octocat/Hello-World`, `pallets/flask` cloned and analysed |
| Local repository ingested | ✅ | `examples/demo-project` copied to `workspace/repos/<id>` |
| Python dependencies extracted | ✅ | PEP 508 `requirements*.txt`, `requirements/*.txt` |
| JavaScript dependencies extracted | ✅ | `package.json` + `package-lock.json` v1/v2/v3 incl. workspaces and nested duplicates |
| Dependencies stored in PostgreSQL | ✅ | per-analysis snapshot + `DependencyRelation` |
| Knowledge graph populated | ✅ | `CONTAINS`, `USES` (repository + component), `DEPENDS_ON`, `AFFECTED_BY` |
| OSV vulnerability detection | ✅ | batch `querybatch` + `vulns/{id}`, CVSS 3.x, alias merging, `UNKNOWN` on outage |
| Findings created | ✅ | 9 findings for the demo project (3 vulnerable dependencies) |
| Source usage identified | ✅ | `weather.py:12`, `test_weather.py:5`, `format.js:6` |
| Ollama analyses a finding | ✅ | dependency / impact / risk agents, structured JSON, FACT vs INFERENCE |
| Impact assessment | ✅ | guardrail drops components not in the evidence |
| Risk assessment | ✅ | provisional severity-based risk until the AI result exists |
| Remediation recommendation | ✅ | OSV fixed versions → registry → OSV re-check → LLM choice (or deterministic fallback) |
| Modification in a temporary workspace | ✅ | `workspace/remediations/<id>`, unified diff stored |
| Docker validation | ✅ | isolated container, install + tests + OSV re-scan; `PASS/FAIL/SKIPPED/UNKNOWN` |
| Evidence report | ✅ | 10 sections, JSON + Markdown, reproducible from PostgreSQL (`docs/EXAMPLE_EVIDENCE_REPORT.md`) |
| Draft PR when credentials exist | ✅ | live: https://github.com/lokeshlella/sentinel-chain-demo/pull/1 (draft, branch `sentinel-chain/pypi-requests-2.33.0`, +1/−1 in `requirements.txt`, committed as *Sentinel Chain*); manual instructions without a token (`docs/EXAMPLE_PR_DESCRIPTION.md`) |
| Frontend displays the workflow | ✅ | Dashboard, Repository, Analysis, Finding, Remediation, Validation, Pull request(s), Health |
| Tests pass | ✅ | `pytest -q` → 776 passed; `SENTINEL_INTEGRATION=1 pytest -m integration` → 20 passed |
| README with exact setup | ✅ | `README.md`, `docs/DEMO.md` |
| One complete end-to-end demo | ✅ | local path and GitHub URL: analysis ≈2 min, remediation 12 s, validation ≈5 s, report, real draft PR |

## Implemented features

* **Repository ingestion** — GitHub URLs (`https`, `.git`, `/tree/<branch>`, `git@` form),
  local directories (safe copy, `.git` kept, system roots refused), duplicate detection,
  structure profile (language, components, dependency files, test hints), workspace cleanup.
* **Dependency extraction** — `PythonDependencyExtractor` (PEP 508 parsing, includes/editables
  reported, UTF-16 files), `JavaScriptDependencyExtractor` (direct/transitive scope only when a
  lock file proves it, Node resolution for relations, workspaces, non-workspace manifests kept
  lock-less), snapshot persistence per analysis.
* **Vulnerability detection** — `OSVProvider` with retries/back-off/pagination, CVSS 3.0/3.1
  base score computation, severity labels, alias-group de-duplication that never merges
  different CVEs and only advertises group-safe fixed versions, invalid versions never sent.
* **Knowledge graph** — `KnowledgeGraphService` with UNWIND batch sync, stale-edge cleanup
  (preserve mode keeps last known vulnerability edges when OSV was unavailable — audit F-03),
  component usage edges, queries (components using a dependency, related dependencies,
  vulnerabilities, dependency paths, repository graph) and graceful unavailability.
* **Application-aware evidence** — import/require scanning with a curated import-name map,
  component mapping, manifest references, caps and deterministic ordering.
* **Agentic AI** — `OllamaProvider` (`/api/chat`, JSON-schema `format` with `"json"`
  fallback, connect/read timeouts, actionable errors), `generate_structured` with correction
  re-prompts, `DependencyAnalysisAgent`, `ImpactAssessmentAgent`, `RiskEvaluationAgent`,
  `RemediationAgent`, `AIOrchestrator` guardrails (evidence-only components, candidate-only
  versions), per-analysis finding cap with on-demand analysis.
* **Remediation** — `PackageRegistryClient` (PyPI/npm; yanked and deprecated releases
  excluded), `select_candidates`, `RequirementsTxtModifier` / `PackageJsonModifier`
  (formatting preserved), temporary working copies, deterministic fallback when the LLM is
  unavailable, remediation history per finding.
* **Docker sandbox** — `DockerSandboxProvider` (no host mounts, `cap_drop ALL`,
  `no-new-privileges`, memory/CPU/pid limits, timeout kill, step markers, log capture,
  lock-file artifact copy-back, guaranteed container removal), `DependencySecurityScanner`,
  `ValidationService` with the documented `overall_result` rules.
* **Evidence report** — `ReportService` (10 sections, facts / AI reasoning / recommendations /
  validation results kept apart, deterministic final recommendation, JSON + Markdown files).
* **GitHub PR** — `GitHubProvider` (branch, commit as *Sentinel Chain*, one-off token URL push
  with redaction, PyGithub draft PR, existing-PR reuse, auth/422 handling) and
  `PullRequestService` (validation required, `force` for failed validations, PR body with
  vulnerability / versions / impact / risk / validation / diff / checklist, manual instructions).
* **API & UI** — 33 REST endpoints with typed errors, background execution + polling; React
  dashboard covering the whole workflow, facts and inferences labelled everywhere.
* **Operations** — `503 DatabaseUnavailable` when PostgreSQL is down (audit F-04),
  health endpoint for every backing service, stage-prefixed logs, startup sweep
  that fails jobs interrupted by a restart, Docker Compose for PostgreSQL / Neo4j / backend /
  frontend (`full` profile) with Ollama on the host.

## Partially implemented

| Area | What V1 does | What is missing |
|---|---|---|
| Manifest coverage | `requirements*.txt`, `package.json`, `package-lock.json` | `pyproject.toml`, `Pipfile(.lock)`, `poetry.lock`, `yarn.lock`, `pnpm-lock.yaml` are detected/warned about but not parsed |
| Unpinned dependencies | reported `UNKNOWN` with the reason | no range resolution against the registry (npm ranges without a lock, Python `>=` specs) |
| Direct/transitive | exact for npm with a lock file | `requirements.txt` cannot tell, so scope is `unknown`; no Python transitive resolution |
| Security scan | re-checks the remediated package against OSV | other dependencies are not re-scanned; no Trivy/Semgrep |
| Remediation targets | direct dependencies in the manifest | transitive (lock-file only) dependencies are refused with an explanation |
| AI coverage | top-N findings per analysis (`AI_MAX_FINDINGS_PER_ANALYSIS`), rest on demand | no batching / caching across identical dependencies |
| PR creation | draft PR on a repository the token can push to | no fork-based flow; local repositories need a GitHub `origin` |
| Knowledge graph | populated + basic queries + table view in the UI | no graph visualisation, no reasoning over the graph |

## Known limitations

* A 3B local model produces grounded but shallow reasoning; confidence values are the model's
  own estimate. Larger models improve quality at the cost of latency/RAM.
* Background jobs run inside the API process; a restart marks in-flight jobs `FAILED`
  (they are not resumed). One analysis per repository and one validation per remediation at a time.
* The sandbox needs network access to install packages; it is isolated from the host but not
  from the internet.
* OSV data changes over time — the demo README documents how to re-verify the advisory ids.
* No authentication: the API is meant for a local, single-user setup.
* Path-based local repositories are copied entirely (minus build artefacts); very large
  repositories take time and disk.

## Future extensions (V2 candidates)

More ecosystems (Maven, Gradle, Go, Cargo, Ruby, PHP) via new `DependencyExtractor`s;
`GHSAProvider` / `NVDProvider`; `OpenAIProvider` / `AnthropicProvider` behind `LLMProvider`;
Trivy / Semgrep in the validation stage; `KubernetesSandboxProvider`; a job queue with
resumable workers; GitHub webhooks and continuous monitoring; CI/CD integration; richer graph
reasoning (blast radius through `DEPENDS_ON` chains); fork-based PRs and PR status sync.

## How the architecture supports V2

* Every external system sits behind an interface with one V1 implementation:
  `RepositoryProvider`, `DependencyExtractor`, `VulnerabilityProvider`, `LLMProvider`,
  `SandboxProvider`, `GitProvider`. Adding a provider means adding a class and registering it
  in `api/deps.py`; the pipeline, services and API do not change.
* Agents are plain classes over `LLMProvider` with Pydantic result models
  (`services/agents/schemas.py`); new agents (e.g. a code-change agent) plug into
  `AIOrchestrator` without touching the persistence layer.
* Findings store evidence (`usage_evidence`, `affected_components`) separately from AI output
  (`ai_results`), so richer static analysis can replace the scanner without schema changes.
* Dependencies are per-analysis snapshots, so continuous monitoring can append analyses
  without rewriting history; the knowledge graph uses stable natural keys.
* Long-running stages already run through factories (`get_pipeline_factory`,
  `get_validation_factory`) that a queue-backed worker can call unchanged.
