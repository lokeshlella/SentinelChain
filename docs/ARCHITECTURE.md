# Sentinel Chain — Architecture & Implementation Contract (V1)

This document is the binding contract between modules. Every service must be implemented
against the interfaces described here so the workflow composes without rewrites.
Read `docs/V1_SPECIFICATION.md` for the product requirements.

## 1. Runtime topology

```
 React/Vite (frontend, :5173 dev / :3000 compose)
        │  /api  (JSON)
 FastAPI backend (backend/app, :8000)  ── one process, modular services
   ├── PostgreSQL  (SQLAlchemy 2.x, Alembic)          — system of record
   ├── Neo4j       (official driver)                    — software knowledge graph (optional)
   ├── Ollama      (HTTP, host machine)                 — local LLM (optional)
   ├── OSV.dev     (HTTPS)                              — vulnerability data (optional → UNKNOWN)
   ├── Docker      (SDK, host daemon)                   — sandbox validation (optional)
   └── GitHub      (PyGithub + git push)                — draft PRs (optional)
```

"Optional" = the application keeps working and reports the feature as unavailable.

## 2. Code layout

```
backend/app/
  main.py                    FastAPI app, error handlers, CORS
  core/config.py             Settings (pydantic-settings), get_settings()
  core/logging.py            configure_logging(), get_stage_logger("Repository") -> "[Repository] ..."
  core/exceptions.py         SentinelError(status_code), NotFoundError, ValidationFailedError,
                             ConflictError, ExternalServiceError, RepositoryError, UnsupportedProjectError
  core/versions.py           parse/compare/sort versions (PyPI: PEP 440, npm: SemVer), normalize_package_name
  db/base.py, db/session.py  Base, utcnow(), get_engine(), get_session_factory(), get_db()
  db/neo4j.py                get_neo4j_driver(), check_neo4j()
  models/                    ORM (see §3), models/enums.py (all StrEnums)
  schemas/                   Pydantic API request/response models (one module per resource)
  api/router.py              aggregates api/routes/*.py under settings.api_prefix ("/api")
  api/deps.py                FastAPI dependencies: get_db, service factories
  services/<module>/         one folder per workflow stage (see §4)
backend/tests/               pytest; conftest.py gives an in-memory SQLite `db` session fixture
backend/alembic/             migrations (single initial revision in V1)
frontend/src/                React pages (see §9)
examples/demo-project/       deliberately vulnerable demo application
workspace/ (git-ignored)     repos/<repository_id>/  remediations/<remediation_id>/  validations/<id>/
```

Conventions: type hints everywhere; small functions; every stage logs via
`get_stage_logger(<Stage>)`; services receive their collaborators via constructor
(dependency injection) and default to the real implementation when none is passed;
SQLAlchemy `Session` is passed in (never created inside services except background jobs).
ORM primary keys are named `<entity>_id` (`repository_id`, `finding_id`, ...).
All enum-like columns are plain strings holding `app.models.enums` values.

## 3. Data model (PostgreSQL)

| Table | Key columns (beyond the spec) | Notes |
|---|---|---|
| repositories | `local_path` (workspace-relative, e.g. `repos/3`), `commit_sha`, `profile` (JSON) | `profile` = RepositoryProfile dict |
| components | `file_count` | unique (repository_id, path); upserted at ingest |
| dependencies | **`analysis_id`**, `version_spec`, `vulnerability_status`, `status_reason`, `last_checked_at` | per-analysis snapshot; unique (analysis_id, ecosystem, package_name, version, source_file) |
| dependency_relations | | parent → child, from lock files |
| vulnerabilities | `aliases`, `cvss_vector`, `summary`, `modified_at`, `affected` (JSON) | global, unique `identifier` |
| analyses | `stages` (JSON), `summary` (JSON), `error_message` | `stages` keys: repository, dependencies, vulnerabilities, knowledge_graph, usage, ai |
| findings | `usage_evidence` (JSON), `ai_results` (JSON), `ai_status`, `ai_error` | unique (analysis_id, dependency_id, vulnerability_id) |
| remediations | `candidates` (JSON), `ai_result` (JSON), `proposed_change` (JSON), `error_message` | |
| validations | `status`, `details` (JSON), `error_message` | |
| pull_requests | `pr_number`, `branch_name`, `body`, `instructions`, `error_message` | |

Status vocabularies live in `app/models/enums.py` — use them, do not invent new strings.

## 4. Services and contracts

### 4.1 repository/  (stage logger "Repository")
* `base.py` — `RepositorySource`, `FetchedRepository`, `RepositoryProvider(ABC)`: `supports(location)`, `validate(source)`, `fetch(source, destination) -> FetchedRepository`.
* `github_provider.py` — `GitHubRepositoryProvider`: accepts `https://github.com/owner/repo[.git]`, `git@github.com:owner/repo.git`, `owner/repo` is NOT accepted. Validates format; clones with GitPython (`single_branch`, `GIT_TERMINAL_PROMPT=0`, timeout `settings.git_clone_timeout`); uses `GITHUB_TOKEN` for private repos when configured (token never logged); records branch, commit sha, `github_full_name`. Maps git errors to `RepositoryError` with a clear message (not found / auth / network).
* `local_provider.py` — `LocalRepositoryProvider`: validates the directory exists and is readable; copies it into `destination` (`shutil.copytree`, ignoring `.venv venv node_modules dist build __pycache__ .pytest_cache .tox .mypy_cache`; **keeps `.git`**); records commit sha + github_full_name when the copy is a git repo with a GitHub remote.
* `analyzer.py` — `RepositoryAnalyzer.analyze(local_path) -> RepositoryProfile` (dataclass with `to_dict()`): `name`, `language` (dominant by source-file count: Python/JavaScript/TypeScript/...), `languages` (counts), `dependency_files`, `source_dirs`, `test_dirs`, `components: list[ComponentInfo(name, path, component_type, description, file_count)]`, `total_files`, `hints` (`has_pytest`, `has_tests_dir`, `npm_test_script`, `has_dockerfile`, `readme_present`). Components = top-level directories containing files (plus `.` root when it holds source files), typed via enums.ComponentType; skip ignored dirs. Paths are POSIX relative.
* `service.py` — `RepositoryService(db, settings, providers=None)`:
  `register(source_url, source_type=None, branch=None) -> Repository` (detect type, validate, create row, then `ingest`);
  `ingest(repository, refresh=False) -> Repository` (fetch into `workspace/repos/<repository_id>`, analyse, store `profile`, `language`, `local_path`, `commit_sha`, upsert components);
  `get(repository_id)`, `list()`, `delete(repository_id)` (removes workspace dir too).

### 4.2 dependencies/  (stage logger "Dependencies")
* `base.py` — `ExtractedDependency`, `ExtractedRelation`, `ExtractionResult`, `DependencyExtractor(ABC)`: `detect(repo_path)`, `extract(repo_path)`.
* `python_extractor.py` — `PythonDependencyExtractor` (ecosystem PyPI): finds `requirements.txt`, `requirements-*.txt`, `requirements/*.txt` anywhere except ignored dirs (depth ≤ 3). Parses PEP 508 lines with `packaging.requirements.Requirement`; `==x` (and `===`) → `version=x`; other specifiers → `version=None`, `version_spec=raw`; handles comments, blank lines, `-r/-c/-e/--` options (record `-r` includes as warnings, do not follow recursively beyond the detected set), environment markers, extras, URL requirements (`version=None`, warning). `scope=UNKNOWN` (requirements.txt cannot tell direct vs transitive). `dev=True` for files whose name contains `dev` or `test`.
* `javascript_extractor.py` — `JavaScriptDependencyExtractor` (ecosystem npm): `package.json` in root and workspaces (depth ≤ 2, skip node_modules). `dependencies`/`devDependencies`/`optionalDependencies`/`peerDependencies` → DIRECT with `version_spec`; `version` = the exact version when the spec is exact (`1.2.3`, `=1.2.3`, `v1.2.3`), else resolved from `package-lock.json` when present, else `None`. With a lock file (v1 `dependencies` tree or v2/v3 `packages` map): every installed package becomes a dependency (`source_file="package-lock.json"`, scope TRANSITIVE unless it is a direct dep, in which case the direct entry from package.json carries the resolved version and `source_file="package.json"`), plus `ExtractedRelation`s from the lock's `dependencies`/`requires` using Node resolution over the `node_modules/...` keys. Nested duplicates (same name, different version) are separate dependencies. `link:`, `file:`, `git+`, `workspace:` specs → `version=None` + warning.
* `service.py` — `DependencyService(extractors=None)`: `extract(repo_path) -> ExtractionResult` (all extractors; raises `UnsupportedProjectError` only if NO extractor finds a file), `persist(db, repository, analysis, result) -> list[Dependency]` (inserts snapshot rows for `analysis`, de-duplicating identical identities, then `DependencyRelation` rows by matching (name, version)), and `summarize(result) -> dict` (counts by ecosystem/scope/pinned).

### 4.3 vulnerabilities/  (stage logger "Vulnerability")
* `base.py` — `PackageQuery`, `AffectedRange`, `AffectedPackage`, `VulnerabilityRecord`, `PackageVulnerabilityResult`, `VulnerabilityProvider(ABC)`, `VulnerabilityProviderError`.
* `cvss.py` — `cvss_v3_base_score(vector) -> float | None` (full CVSS 3.0/3.1 base score formula, rounded per spec), `severity_from_score(score) -> Severity` (None→UNKNOWN, 0→NONE treated as LOW, 0.1–3.9 LOW, 4.0–6.9 MEDIUM, 7.0–8.9 HIGH, 9.0–10 CRITICAL).
* `osv_provider.py` — `OSVProvider(base_url, timeout, client=None)`: `query` → `POST {base}/query`; `query_batch` → `POST {base}/querybatch` in chunks of ≤ 1000 (ids only) then `GET {base}/vulns/{id}` for each unique id (cache within the call; tolerate individual failures → that vuln is kept with minimal info only if the id is known, otherwise the query result becomes UNKNOWN with a reason). Retries 429/5xx with backoff (3 attempts). Any transport/timeout/JSON error → `status=UNKNOWN`, `reason="Vulnerability check unavailable: <cause>"`. Parses: `id`, `aliases`, `summary`, `details`, `published`, `modified`, `references` (`reference_url` = first ADVISORY, else first WEB, else first), `severity[]` (CVSS_V3 → vector + computed score; CVSS_V4 → vector only), `database_specific.severity` (GHSA labels; MODERATE→MEDIUM) takes precedence for the label, else score band, else UNKNOWN; `affected[]` filtered to the queried ecosystem+package with ranges/events (`introduced`, `fixed`, `last_affected`) and `versions`; `fixed_versions` derived from `fixed` events. Version strings in `PackageQuery` are used verbatim. `health()` → GET `{base}/vulns/GHSA-xxxx`? No: use `POST {base}/query` with a well-known tiny payload and treat any HTTP 200/400 as reachable.
* `service.py` — `VulnerabilityService(db, provider=None, settings=None)`:
  `check_dependencies(dependencies: list[Dependency]) -> VulnerabilityCheckSummary` — builds queries for dependencies with a concrete version (others → UNKNOWN, reason "Version not pinned; add a lock file or pin the version"), calls `query_batch`, de-duplicates records that share an alias group (prefer GHSA > CVE > PYSEC/other ids; merged aliases), upserts `Vulnerability` rows by identifier, sets `dependency.vulnerability_status/status_reason/last_checked_at`, returns `{dependency_id: [Vulnerability,...]}` + counts + `provider_available: bool`.
  `create_findings(analysis, dep_vulns) -> list[Finding]` — one Finding per (dependency, vulnerability), `ai_status=PENDING`, `risk_level` initialised from severity via `analysis/risk.py` (documented as a provisional, non-AI value), `impact_level=None`.
  `check_package(ecosystem, name, version) -> PackageVulnerabilityResult` — single query (used by remediation candidates and the security scan).

### 4.4 knowledge_graph/  (stage logger "KnowledgeGraph")
* `client.py` — `Neo4jClient(driver=None, database=None)`: `available() -> bool` (cached for 30 s), `run(cypher, **params) -> list[dict]`, `run_write(...)`. Never raises to callers on connectivity problems — logs a warning and returns `[]`/`False`; the service reports `available=False`.
* `service.py` — `KnowledgeGraphService(client=None)`:
  `ensure_constraints()` (uniqueness on `Repository.repository_id`, `Vulnerability.identifier`; composite key on `Dependency(repository_id, ecosystem, name, version)` and `Component(repository_id, path)`);
  `sync_analysis(repository, components, dependencies, relations, dep_vulns, component_usage) -> GraphSyncResult(available, nodes, relationships)` — MERGE nodes by natural keys, set `dependency_id`/`analysis_id`/`status` props, delete the repository's stale USES / DEPENDS_ON / AFFECTED_BY / CONTAINS edges first, then MERGE relationships (`component_usage: {dependency_id: [component_path, ...]}`);
  queries returning plain dicts: `components_using_dependency(dep)`, `related_dependencies(dep) -> {"depends_on": [...], "depended_on_by": [...]}`, `vulnerabilities_for_dependency(dep)`, `dependency_paths(dep, max_depth=4) -> list[list[str]]` (paths from the Repository/Component node to the dependency, rendered as labels like `Repository:name`, `Component:src`, `Dependency:pkg@1.0`), `repository_graph(repository_id, limit=500) -> {"nodes": [{id,label,type,props}], "edges": [{source,target,type}]}`, `dependency_context(dep) -> GraphContext` (agents/schemas.py).
  Node identity: `Repository{repository_id}`, `Component{repository_id, path}`, `Dependency{repository_id, ecosystem, name, version}` (`version` may be "" when unknown), `Vulnerability{identifier}`.

### 4.5 analysis/  (stage loggers "Analysis", "Usage")
* `usage.py` — `SourceUsageAnalyzer.find_usage(repo_path, package_name, ecosystem, component_paths) -> UsageEvidence(package_name, ecosystem, import_names, references[UsageReference(file,line,snippet,kind)], files, components, truncated)`. Python: import names from a built-in mapping for common packages (`pyyaml→yaml`, `pillow→PIL`, `beautifulsoup4→bs4`, `scikit-learn→sklearn`, `python-dateutil→dateutil`, `python-dotenv→dotenv`, `msgpack-python→msgpack`, `psycopg2-binary→psycopg2`, `opencv-python→cv2`, `attrs→attr`, `pyjwt→jwt`, `markupsafe→markupsafe`, `jinja2→jinja2`, `flask-*→flask_*`, ...) plus heuristics (`-`→`_`, strip `python-`/`py` prefixes, lowercase); regex over `*.py` (`^\s*(import|from)\s+<name>(\.|\s|$)`). JS: `require('<pkg>')`, `import ... from '<pkg>'`, `import '<pkg>'`, dynamic `import('<pkg>')` incl. sub-paths (`<pkg>/x`) over `*.js *.jsx *.ts *.tsx *.mjs *.cjs *.vue`. Also flags `kind="config"` references in dependency files. Ignore dirs as in §4.1; cap 5000 files / 100 references (set `truncated`). `components` = component paths whose directory contains a referencing file (root `.` for top-level files).
* `risk.py` — `provisional_risk_from_severity(severity) -> RiskLevel`, `aggregate_overall_risk(findings) -> RiskLevel` (max of AI risk when present else provisional), `risk_rank(level) -> int`.
* `pipeline.py` — `AnalysisPipeline(db, settings, repository_service, dependency_service, vulnerability_service, graph_service, usage_analyzer, orchestrator)`, `run(analysis_id)`. Stages update `analysis.stages[<stage>]` (StageStatus) + `analysis.summary` counters, commit after each stage, log `[Stage] ...` lines. Repository/dependency failure → analysis FAILED with `error_message`; OSV/Neo4j/AI failures → UNAVAILABLE/PARTIAL but analysis COMPLETED. AI runs for at most `settings.ai_max_findings_per_analysis` findings ordered by severity rank (others `ai_status=SKIPPED`, reason recorded) and can be (re)run per finding via `run_ai_for_finding(finding_id)`. Findings of the same dependency share usage evidence (computed once per dependency). `analysis.overall_risk` = `aggregate_overall_risk`.

### 4.6 llm/ + agents/  (stage logger "AI")
* `llm/base.py` — `LLMProvider(ABC)`, `LLMResponse`, `LLMError`.
* `llm/ollama_provider.py` — `OllamaProvider(base_url, model, timeout, num_ctx, temperature, client=None)`: `POST {base}/api/chat` with `stream=false`, `format=<json schema dict>` when given (fallback to `"json"` if the server rejects the schema with 400), `options={temperature, num_ctx}`; `health()` = GET `/api/tags` and model present (prefix match on `name`). Maps connection errors/timeouts/404-model-missing to `LLMError` with actionable text (`ollama pull <model>`).
* `llm/structured.py` — `extract_json(text) -> dict` (strips code fences, finds the outermost `{...}`), `StructuredOutputError`, `generate_structured(provider, prompt, system, output_model, max_retries) -> output_model` (on validation failure re-prompts with the error message and the previous output; after `max_retries` raises `StructuredOutputError(raw_output=...)`).
* `agents/schemas.py` — context + result models (already written; do not change field names).
* `agents/prompts.py` — system prompt (rules: use only provided evidence, label FACT vs INFERENCE, return JSON only, never invent file paths/versions) and per-agent prompt builders taking a `FindingContext` (+ candidates for remediation). Prompts render the evidence as compact bullet lists.
* `agents/base.py` — `BaseAgent(provider, settings)`, `.name`, `.run(context) -> ResultModel` raising `AgentError(agent, error, raw_output)`.
* `agents/dependency_agent.py`, `impact_agent.py`, `risk_agent.py`, `remediation_agent.py` — one class each; the impact agent receives the dependency-analysis result; the risk agent receives both previous results; the remediation agent receives `CandidateSet` info and returns `RemediationResult`.
* `agents/orchestrator.py` — `AIOrchestrator(provider, settings)`: `analyze_finding(context: FindingContext) -> FindingAIResult` (runs the three agents sequentially; on `LLMError` at the first call → status UNAVAILABLE; per-agent failure recorded in `failures`, later agents still run with what is available; **guardrail:** `impact.affected_components` is filtered to `context.usage.components ∪ context.repository.components`, dropped names go to `dropped_components`), `recommend_remediation(context, candidates) -> RemediationResult` (guardrail: `recommended_version` must be in `candidates.allowed_versions`, else replaced by `candidates.preferred_version` and the substitution noted in `reasoning`), `available() -> tuple[bool,str]`.

### 4.7 remediation/  (stage logger "Remediation")
* `registry.py` — `PackageRegistryClient(timeout, client=None)`: `versions(ecosystem, name) -> RegistryInfo(versions: list[str], latest: str|None, available: bool, error: str|None)` (PyPI JSON API `https://pypi.org/pypi/<name>/json`; npm `https://registry.npmjs.org/<name>`); excludes yanked/pre-releases from `latest`.
* `candidates.py` — `CandidateSet` (`current_version`, `minimum_fixed_version`, `preferred_version`, `allowed_versions`, `latest_version`, `same_major: bool|None`, `verified_safe: bool|None`, `remaining_vulnerabilities: list[str]`, `notes: list[str]`, `registry_available`) and `select_candidates(dependency, vulnerabilities, registry, vulnerability_service, ecosystem) -> CandidateSet`: minimum fixed = max over the dependency's vulnerabilities of the smallest fixed version > current; snap to an existing registry version (`min_version_at_least`); verify with `check_package` (OSV) and bump to the next fixed version if still vulnerable (≤ 5 iterations); `preferred_version` = lowest verified-safe version in the same major if one exists, else lowest verified-safe; `allowed_versions` = {preferred, latest-in-same-major, latest} that are verified safe (or unverified when OSV unavailable, noted).
* `modifiers.py` — `DependencyFileModifier(ABC).apply(workspace, relative_file, package_name, current_version, new_version) -> FileChange(file, before, after, diff, line_number)`; `RequirementsTxtModifier` (rewrites the matching requirement line preserving extras/markers/comments; `==new`), `PackageJsonModifier` (rewrites the spec in whichever dependency section holds the package, preserving the range operator style: `^1.2.3`→`^new`, `~`→`~new`, exact→exact; preserves indentation/formatting via `json.dumps(indent=detected)` + trailing newline); `get_modifier(source_file)`.
* `workspace.py` — `create_working_copy(source_path, destination) -> Path` (same ignore list as §4.1, keeps `.git`), `remove_workspace(path)`.
* `service.py` — `RemediationService(db, settings, orchestrator=None, registry=None, vulnerability_service=None)`: `remediate(finding_id) -> Remediation` (PENDING → candidates → LLM (or deterministic-only with a note when LLM unavailable, confidence 0.5, `ai_result=None`) → working copy under `workspace/remediations/<remediation_id>` → modifier → `proposed_change={file, before, after, diff, line_number, workspace_path}` → status PROPOSED; failures → FAILED with `error_message`), `get`, `list_for_finding`.

### 4.8 sandbox/  (stage logger "Sandbox")
* `base.py` — `SandboxRequest`, `StepResult`, `SandboxResult`, `SandboxProvider(ABC)`, `SandboxError`.
* `docker_provider.py` — `DockerSandboxProvider(settings, client=None)`: image by ecosystem (`docker_python_image` / `docker_node_image`); creates a container (`network_mode="bridge"`, `mem_limit`, `nano_cpus`, `pids_limit=512`, `security_opt=["no-new-privileges"]`, `cap_drop=["ALL"]`, `user` default, working dir `/workspace`), copies the workspace in via `put_archive` (excluding ignored dirs), runs a generated shell script that writes step markers (`::step build start/end <exit>`), waits with `docker_timeout` (kill on timeout → `timed_out=True`, statuses UNKNOWN with note), collects logs, copies back `package-lock.json` when regenerated (npm), always removes the container (`finally`). Python build: `pip install -r <file>`; tests: if `hints.has_pytest` or `tests/`/`test_*.py` exist → `pip install pytest && python -m pytest -q` else SKIPPED. npm build: `npm install` (`npm ci` when a lock exists and was not modified — V1 uses `npm install` always so the lock is refreshed); tests: `npm test` when `scripts.test` exists and is not the npm placeholder, else SKIPPED. `parse_step_markers(logs) -> dict[str, int]` is a pure function (unit-tested).
* `security_scan.py` — `DependencySecurityScanner(vulnerability_service, dependency_service).scan(workspace_path, ecosystem, package_name, new_version) -> SecurityScanResult(status: CheckResult, target_vulnerabilities: list[str], other_vulnerable: list[dict], provider_available, notes)`: re-extracts dependencies from the modified workspace, verifies the target package now has the new version, checks it against OSV → PASS when it has no vulnerabilities, FAIL when it still has, UNKNOWN when OSV unavailable; also reports (does not fail on) other still-vulnerable dependencies.
* `service.py` — `ValidationService(db, settings, sandbox=None, scanner=None)`: `validate(remediation_id) -> Validation` (creates row RUNNING, runs sandbox + scanner, writes `logs_path` under `workspace/validations/<validation_id>/logs.txt`, computes `overall_result`: FAIL if any check FAILed; PASS only when build, tests **and** security all PASSed; UNKNOWN otherwise — a SKIPPED test suite is never counted as passing. When build and security passed but tests were SKIPPED (`is_partial_pass`) the remediation becomes `PARTIALLY_VALIDATED` (warning "No test suite detected"); otherwise VALIDATED / VALIDATION_FAILED), `get`, `read_logs`.

### 4.9 reports/  (stage logger "Report")
* `service.py` — `EvidenceReport` (Pydantic) with `sections` 1–10 exactly as the spec names them, each section carrying `observed_facts: dict`, `ai_reasoning: dict|None`, `recommendations: dict|None`, `validation_results: dict|None` as applicable, plus `generated_at`, `finding_id`, `remediation_id`, `validation_id`, `pull_request_id`; `ReportService(db).build(finding_id, remediation_id=None) -> EvidenceReport` (uses the latest remediation/validation/PR when not given), `to_markdown(report) -> str` (Jinja2 template in `reports/templates/evidence_report.md.j2`), `final_recommendation(...)` deterministic rule: "Apply" when overall PASS, "Apply with manual testing" when build + security PASSed but tests were SKIPPED (overall UNKNOWN), "Do not apply yet" for any other FAIL/UNKNOWN, "Analysis only — not validated" when no validation.

### 4.10 github/  (stage logger "GitHub")
* `base.py` — `PullRequestSpec`, `PullRequestResult`, `GitProvider(ABC)`.
* `github_provider.py` — `GitHubProvider(token, client=None)`: `is_configured()`; `create_pull_request(spec)` — in `spec.workspace_path`: create branch, stage `changed_files`, commit (author "Sentinel Chain <sentinel-chain@localhost>"), push via HTTPS with `x-access-token:<token>` (token never written to `.git/config` — use a one-off remote URL via `GIT_ASKPASS`-free `git push https://x-access-token:TOKEN@github.com/owner/repo.git HEAD:branch` and redact the token in errors), then PyGithub `create_pull(draft=True)`. Errors → `PullRequestResult(status=FAILED, error=..., instructions=...)`. When unconfigured → `status=UNAVAILABLE` with manual instructions (branch name, files, commit message, `gh pr create --draft ...`).
* `service.py` — `PullRequestService(db, settings, provider=None, report_service=None)`: `create(remediation_id) -> PullRequest` (requires remediation status VALIDATED or VALIDATION_FAILED? → requires a completed validation; refuses (ConflictError) unless overall_result is PASS or the validation is a partial pass (build + security PASS, tests SKIPPED — the PR body then says the change is not behaviourally verified), or `force=True`), builds title `Sentinel Chain: bump <pkg> <old> → <new> (<vuln id>)`, body from the evidence report markdown (sections: vulnerability, dependency, versions, impact, risk, validation, evidence link) + the footer `🤖 Generated with Sentinel Chain (draft — review required)`, `branch = sentinel-chain/<ecosystem>-<pkg>-<new_version>`, stores `evidence` (report JSON). For local repositories without a GitHub remote → UNAVAILABLE with instructions.

## 5. Analysis pipeline data flow

```
POST /repositories            RepositoryService.register → ingest (clone/copy + profile + components)
POST /repositories/{id}/analyze  → Analysis(PENDING) → BackgroundTask AnalysisPipeline.run
   [Repository]     ensure working copy (refresh optional)
   [Dependencies]   DependencyService.extract + persist (snapshot for this analysis)
   [Vulnerability]  VulnerabilityService.check_dependencies → Vulnerability rows, statuses → create_findings
   [Usage]          SourceUsageAnalyzer per vulnerable dependency → finding.usage_evidence/affected_components
   [KnowledgeGraph] KnowledgeGraphService.sync_analysis
   [AI]             AIOrchestrator.analyze_finding for top-N findings → finding.ai_results/impact/risk/reasoning
   overall_risk, summary, COMPLETED
POST /findings/{id}/analyze   → run_ai_for_finding (re-run / run skipped)
POST /findings/{id}/remediate → RemediationService.remediate (sync; LLM call)
POST /remediations/{id}/validate → Validation(PENDING) → BackgroundTask ValidationService.validate
POST /remediations/{id}/pull-request → PullRequestService.create (sync)
GET  /findings/{id}/report?format=json|markdown → ReportService
```

## 6. API surface (all under /api)

Repositories: `POST /repositories {source_url, source_type?, branch?}` (201), `GET /repositories`, `GET /repositories/{id}` (+ latest analysis summary, dependency counts), `DELETE /repositories/{id}`, `GET /repositories/{id}/dependencies` (latest analysis), `GET /repositories/{id}/analyses`, `GET /repositories/{id}/graph`, `POST /repositories/{id}/analyze {refresh?: bool, run_ai?: bool}` (202).
Analyses: `GET /analyses`, `GET /analyses/{id}`, `GET /analyses/{id}/findings`, `GET /analyses/{id}/dependencies`.
Dependencies: `GET /dependencies/{id}` (+ vulnerabilities, findings, relations), `GET /dependencies/{id}/graph` (components_using, related, vulnerabilities, paths), `GET /dependencies/{id}/usage`.
Vulnerabilities: `GET /vulnerabilities/{id}`, `GET /vulnerabilities/by-identifier/{identifier}`.
Findings: `GET /findings`, `GET /findings/{id}`, `POST /findings/{id}/analyze`, `POST /findings/{id}/remediate`, `GET /findings/{id}/report`.
Remediations: `GET /remediations/{id}`, `POST /remediations/{id}/validate` (202), `GET /remediations/{id}/validations`, `POST /remediations/{id}/pull-request`, `GET /remediations/{id}/report`.
Validations: `GET /validations/{id}`, `GET /validations/{id}/logs` (text/plain).
Pull requests: `GET /pull-requests/{id}`, `GET /pull-requests`.
Dashboard: `GET /dashboard` (counts + recent analyses + high-risk findings), `GET /health`.
Errors: `{"error": "<ExceptionName>", "message": "...", "details": {}}` via `SentinelError` handlers.

## 7. Testing rules

Unit tests use the `db` fixture (SQLite in-memory) and mocked providers (`unittest.mock` /
fake classes implementing the ABCs). No network, no Docker, no Ollama, no Neo4j in unit
tests. Tests requiring real services are marked `@pytest.mark.integration` (skipped unless
`SENTINEL_INTEGRATION=1`). Fixture data for OSV/Ollama responses lives in
`backend/tests/fixtures/*.json` and must be realistic (copied from real API responses).

## 8. Logging

`get_stage_logger("Repository")` etc. Messages describe outcomes with counts:
`[Dependencies] 42 dependencies extracted (PyPI=40, npm=2)`.

## 9. Frontend (React + Vite, plain CSS in `src/styles.css`)

`src/api/client.js` (fetch wrapper), pages: `Dashboard`, `Repository`, `Analysis`, `Finding`,
`Validation`, `PullRequest`, `Health`; components: `StatusBadge`, `Table`, `Section`,
`JsonBlock`, `Loading`. Polling (every 3 s) for RUNNING analyses/validations. No UI library.

## 10. As-built notes (V1, 2026-09-14)

The implementation follows this contract with the following clarifications:

* `app/services/analysis/context.py` holds `build_finding_context()` and `fixed_versions_for()`;
  both the pipeline and the remediation service use it (no pipeline instance is needed to
  build agent input).
* `RepositoryProvider.normalize()` (non-abstract) canonicalises locations before duplicate
  detection; GitHub URLs are compared case-insensitively and local directories always conflict
  with an existing registration (branches cannot be selected for local copies).
* Alias-group merging (`vulnerabilities/aliases.py`) never merges records that name different
  CVE sets, takes the highest CVSS score of the group, and advertises only fixed versions that
  lie outside every affected range of the group.
* Versions that are not valid PEP 440 / SemVer strings are reported `UNKNOWN` and never sent
  to OSV (OSV would otherwise treat them as `0` and return every advisory).
* Nested `package.json` manifests are governed by an ancestor `package-lock.json` only when the
  lock (or the root `workspaces` globs) names them as workspace members.
* `PackageRegistryClient` excludes yanked PyPI releases and `deprecated` npm versions from the
  candidate list (`RegistryInfo.yanked` / `deprecations`).
* `ValidationService` exposes `start()` (creates the `PENDING` row) and `run()` (executes) so
  the API can return `202` and run the sandbox in the background; `validate()` chains both.
* `OllamaProvider.health()` requires an exact model match (or `<model>:latest`), because a
  prefix match reports models that `generate()` would 404 on.
* On startup, `app/main.py` marks analyses/validations still `PENDING`/`RUNNING` from a
  previous process as `FAILED` ("interrupted by a backend restart").
* The Docker sandbox copies the workspace into the container (`put_archive`); no host paths
  are mounted, which is what allows the backend itself to run inside Compose with the Docker
  socket mounted.
