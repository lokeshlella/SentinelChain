# Sentinel Chain V1 — Audit Report

_Audit date: 2026-09-14. Auditor stance: assume broken until proven otherwise. Findings only —
nothing was fixed in this pass. Every claim below is backed by a command that was run (output
quoted) or a `file:line`. Anything not verified is listed under **Unverified**._

Environment: macOS 25.5 / Apple M2 / 8 GB, Docker 29.7.2, PostgreSQL 16.15 (container),
Neo4j 5.26.30 (container), Ollama 0.33.3 with `llama3.2:3b` on the host, Python 3.13.5 venv,
real OSV.dev / PyPI / npm / GitHub. Commit audited: `1747055` (plus the untracked
`AUDIT_V1.md` produced by this pass). `pytest-cov` was installed into the venv for the
coverage run (not added to `requirements.txt`).

Method note: three read-only audit agents (spec contracts, security, test gaps) were launched
and all three died on the session usage limit without returning results; sections 2, 5 and 6
were therefore done by hand with the probes shown.

---

## 0. Findings summary

| ID | Sev | Title |
|---|---|---|
| F-01 | **HIGH** | Sandbox result markers are forgeable by the repository under test; forged markers beat the timeout → `overall PASS` |
| F-02 | **HIGH** | A local repository's `.git/hooks` execute on the **host** during PR commit (working copy keeps `.git`, hooks not disabled) |
| F-03 | MEDIUM | A degraded analysis (OSV unavailable) overwrites the knowledge graph and deletes all previously known `AFFECTED_BY` edges |
| F-04 | MEDIUM | PostgreSQL down → every data endpoint returns `500` with raw psycopg text instead of a degradation message |
| F-05 | MEDIUM | Long synchronous work on the request thread: clone (≤300 s), remediate (observed 3 m 01 s), on-demand AI (worst case ≈27 min) |
| F-06 | MEDIUM | A crashed/killed process leaves analyses `RUNNING` until the next restart; no watchdog; `POST /analyze` answers `409` meanwhile |
| F-07 | MEDIUM | `DELETE /repositories/{id}` cascades rows but leaves remediation workspaces, validation logs and reports on disk |
| F-08 | MEDIUM | Sandbox container runs as **root**, with a writable rootfs and full outbound network |
| F-09 | MEDIUM | `overall_result = PASS` when tests were `SKIPPED` — conflicts with the spec sentence "Never mark a skipped test as PASS" (decision needed) |
| F-10 | MEDIUM | Absolute workspace paths stored in DB rows → a second backend instance (Compose vs host) cannot validate/delete what the other created |
| F-11 | LOW | `security_scan_status = PASS` is reported on a validation whose sandbox never ran (Docker down) |
| F-12 | LOW | Non-draft PR is opened when GitHub answers 422 "drafts not supported" — deviates from "default to DRAFT" |
| F-13 | LOW | `POST …/pull-request` returns `201` for a `FAILED` PR record |
| F-14 | LOW | No DB-level uniqueness on `repositories.source_url`; duplicate detection is code-only (race window) |
| F-15 | LOW | Out-of-range LLM `confidence` values are silently clamped instead of rejected |
| F-16 | LOW | An invalid `GITHUB_TOKEN` is silently accepted for public clones; the bad token surfaces only at PR time |
| F-17 | LOW | No authentication on an API that clones arbitrary URLs and starts containers; CORS allows credentials |
| F-18 | LOW | Compose: `backend`/`frontend` have no healthchecks; `frontend` starts before the backend is ready |
| F-19 | LOW | AI stage counters are ambiguous under outage (`analyzed: 1, unavailable: 5`) and `ai: PARTIAL` when only the per-run cap skipped findings |

Per-finding detail is in §7. Contract checks that **hold** (with proof) are in §2; the
failure-injection matrix in §3; Definition-of-Done in §8; demo risks in §9.

---

## 1. Execution reality

### 1.1 `docker compose --profile full up -d`

```
$ docker compose --profile full ps
NAME                STATUS                    PORTS
sentinel-backend    Up 25 seconds             0.0.0.0:8000->8000/tcp
sentinel-frontend   Up 25 seconds             0.0.0.0:3000->80/tcp
sentinel-neo4j      Up 46 seconds (healthy)   7474, 7687
sentinel-postgres   Up 46 seconds (healthy)   5432
$ curl :8000/api/health  → ok  postgresql ✓ neo4j ✓ ollama ✓ ("model 'llama3.2:3b' available" via host.docker.internal) docker ✓ github ✗ (no token)
$ curl :3000/ → 200 ; curl :3000/api/health/live → {"status":"ok"}
```

No service failed. `backend`/`frontend` report `Up` not `healthy` because they define no
healthcheck (F-18). Then, entirely inside the Compose backend (workspace volume `/workspace`,
Docker socket mounted): register `https://github.com/lokeshlella/sentinel-chain-demo` →
analysis 5 `COMPLETED` (stages all OK, ai SKIPPED by request) → remediation 7 `PROPOSED
2.30.0 → 2.33.0` (LLM reached through `host.docker.internal`) → validation 4 `COMPLETED`
`build PASS / tests PASS / security PASS → overall PASS` (container log:
`Sandbox 4969cedf27e7 started … python:3.12-slim … finished in 4.0s`). Compose mode works.

Observed while doing this (F-10): `POST /api/remediations/6/validate` against a remediation
created by the **host** backend answered
`Remediation 6 cannot be validated in status PR_CREATED` (status gate hit first); rows
created by the host store `/Users/…/workspace/...` which does not exist in the container, so
a proposed remediation created on the host would fail with "working copy is missing" in the
container, and `DELETE /repositories/5` executed in the container left
`/Users/…/workspace/repos/5` on the host (see §4.3).

### 1.2 `alembic upgrade head` on a clean database

```
$ psql … -c "CREATE DATABASE sentinel_audit;"
$ DATABASE_URL=postgresql+psycopg://sentinel:sentinel@localhost:5432/sentinel_audit alembic upgrade head
INFO  Running upgrade  -> 171587e9a254, initial schema
$ … alembic check
No new upgrade operations detected.
```

No schema drift versus `app/models`. Foreign keys: 12, all `ON DELETE CASCADE`
(`analyses→repositories`, `components→repositories`, `dependencies→{analyses,repositories}`,
`dependency_relations→dependencies ×2`, `findings→{analyses,dependencies,vulnerabilities}`,
`remediations→findings`, `pull_requests→remediations`, `validations→remediations`). Indexes:
33 total, 22 non-PK (`ix_analyses_repository_id/status`, `uq_component_repo_path`,
`ix_dependency_pkg`, `uq_dependency_identity`, `uq_dependency_relation`,
`ix_findings_{analysis,dependency,vulnerability}_id/risk_level`, `uq_finding_identity`,
`ix_remediations_finding_id/status`, `ix_vulnerabilities_identifier`, …). Missing:
uniqueness on `repositories(source_url[, branch])` (F-14); `pull_requests.review_status`
and `validations.status` are unindexed (dashboard/list queries are small in V1 — informational).

### 1.3 Test suite with coverage

```
$ .venv/bin/pytest -q --cov=app
777 passed, 20 skipped (integration), 1 warning in 12.97s
TOTAL 8572 statements, 849 missed, 90%
$ SENTINEL_INTEGRATION=1 .venv/bin/pytest -q -m integration   (run earlier the same day, live services)
20 passed
```

Per-module coverage (modules under 90 % in bold):

| Module | Stmts | Missed | Cov |
|---|---:|---:|---:|
| `db/neo4j.py` | 17 | 10 | **41%** |
| `api/routes/health.py` | 43 | 22 | **49%** |
| `db/session.py` | 26 | 13 | **50%** |
| `api/deps.py` | 76 | 32 | **58%** |
| `services/github/github_provider.py` | 303 | 112 | **63%** |
| `services/remediation/workspace.py` | 28 | 10 | **64%** |
| `api/routes/dependencies.py` | 55 | 18 | **67%** |
| `services/sandbox/security_scan.py` | 120 | 34 | **72%** |
| `api/routes/repositories.py` | 85 | 21 | **75%** |
| `services/remediation/registry.py` | 130 | 32 | **75%** |
| `services/sandbox/docker_provider.py` | 357 | 76 | **79%** |
| `api/routes/analyses.py` | 40 | 8 | **80%** |
| `services/sandbox/service.py` | 220 | 40 | **82%** |
| `api/routes/findings.py` | 41 | 7 | **83%** |
| `services/remediation/candidates.py` | 249 | 42 | **83%** |
| `services/analysis/context.py` | 32 | 5 | **84%** |
| `services/reports/markdown.py` | 111 | 15 | **86%** |
| `services/analysis/pipeline.py` | 283 | 38 | **87%** |
| `services/remediation/modifiers.py` | 226 | 30 | **87%** |
| `services/reports/service.py` | 363 | 47 | **87%** |
| `main.py` | 56 | 7 | **88%** |
| `services/github/service.py` | 150 | 18 | **88%** |
| `services/repository/local_provider.py` | 130 | 16 | **88%** |
| all other modules | | | 90–100% |

Tests that assert nothing (AST scan of 529 test functions for `assert`/`pytest.raises`/mock
`assert_*`): **1** — `tests/test_repository_github_provider.py:231 test_valid_branch_names`
(a legitimate "does not raise" parametrised test). Tests that mostly test the mock (the
asserted value is the fake's canned answer; only glue is exercised):

* `tests/test_api_workflow.py:116` — `overall_result == "PASS"` comes straight from `FakeSandbox`/`FakeScanner`; the route/service plumbing is real, the sandbox is not.
* `tests/test_sandbox_modules.py:213` (`test_validation_pass_writes_logs…`) and the parametrised `test_validation_failure_rules` — statuses are injected; only `overall_result()` composition and persistence are real.
* `tests/test_agents_orchestrator.py:66` — `FakeLLMProvider` returns valid JSON; asserts `COMPLETED` and result chaining (prompt content is asserted, model behaviour is not).
* `tests/test_reports_and_github.py:211` — `FakeProvider` returns `DRAFT`; asserts `DRAFT` (the real git work is covered separately at `:155` on a real temp repo with a fake GitHub client).
* Every `check_package`/OSV-dependent test uses a fake provider by design; the live behaviour is only covered by the 20 integration tests.

### 1.4 Full end-to-end demo (host backend, `examples/demo-project`, `run_ai=true`)

Condensed real stage log (per-agent "querying/parsed" lines removed; nothing else edited):

```
11:11:02 [Analysis] Analysis 6 started for repository 1 (demo-project)
11:11:02 [Repository] Copying local repository …/examples/demo-project into …/workspace/repos/1
11:11:02 [Repository] Copied demo-project (git=False, branch=-, remote=-)
11:11:02 [Repository] Analysed weather-notes-widget: 19 files, language=Python, 3 components, 3 dependency files, 2 test dirs
11:11:02 [Repository] Repository 'demo-project' (id=1) ingested: 19 files, language=Python, components +0/~3/-0, 3 dependency files
11:11:02 [Dependencies] requirements.txt: 17 requirements parsed
11:11:02 [Dependencies] package-lock.json: lockfileVersion 3 with 2 entries
11:11:02 [Dependencies] package.json: 1 direct dependencies
11:11:02 [Dependencies] 18 dependencies extracted (PyPI=17, npm=1), 0 relations, 3 files, 0 warnings
11:11:02 [Dependencies] 18 dependencies persisted for analysis 6 (0 duplicates skipped, 0 already present); 0 relations stored
11:11:08 [Vulnerability] OSV batch: 18 queries (18 unique), 0 unknown, 16 vulnerability ids fetched (0 failed)
11:11:08 [Vulnerability] 18 dependencies checked: 3 vulnerable, 15 safe, 0 unknown (0 unpinned); 9 distinct vulnerabilities; provider available; stage OK
11:11:08 [Vulnerability] 9 findings created for analysis 6 (0 already existed)
11:11:08 [Usage] Jinja2 (PyPI): 0 import reference(s) in 0 file(s), 1 config reference(s), components=[], scanned 11 files
11:11:08 [Usage] requests (PyPI): 2 import reference(s) in 2 file(s), 1 config reference(s), components=['src', 'tests'], scanned 11 files
11:11:08 [Usage] lodash (npm): 1 import reference(s) in 1 file(s), 1 config reference(s), components=['src'], scanned 3 files
11:11:08 [KnowledgeGraph] Graph synced for repository 1: 31 nodes (3 components, 18 dependencies, 9 vulnerabilities), 33 relationships; 33 stale relationships removed
11:11:08 [AI] Analysing finding lodash@4.17.15 / GHSA-35jh-r3h4-6jhm with model llama3.2:3b
11:11:35 [AI] Finding 48 (lodash 4.17.15 / GHSA-35jh-r3h4-6jhm): COMPLETED in 26.6s   (impact=HIGH risk=HIGH failures=0 dropped_components=0)
11:11:55 [AI] Finding 50 (lodash 4.17.15 / GHSA-p6mc-m468-83gw): COMPLETED in 20.3s
11:12:17 [AI] Finding 49 (lodash 4.17.15 / GHSA-xxjr-mmjv-4gpg): COMPLETED in 21.8s
11:12:46 [AI] Finding 46 (requests 2.30.0 / GHSA-j8r2-6x86-q33q): COMPLETED in 28.4s
11:13:15 [AI] Finding 44 (requests 2.30.0 / GHSA-9wx4-h78v-vm56): COMPLETED in 28.7s
11:13:15 [Analysis] Analysis 6 finished with status COMPLETED in 132.4s
11:13:40 [Remediation] Remediation 8 started for requests 2.30.0 (GHSA-j8r2-6x86-q33q) in repository 1
11:13:40 [Remediation] Registry PyPI requests: 158 versions, latest 2.34.2
11:13:40 [Vulnerability] PyPI requests 2.33.0 -> SAFE (0 vulnerabilities)
11:13:40 [Vulnerability] PyPI requests 2.34.2 -> SAFE (0 vulnerabilities)
11:13:40 [Remediation] Candidates for requests: preferred=2.33.0 allowed=['2.33.0', '2.34.2'] latest=2.34.2 (verified_safe=True)
11:13:56 [AI] Remediation recommendation: 2.30.0 -> 2.33.0 (confidence 0.95, 15.0s)
11:13:56 [Remediation] Working copy created at …/workspace/remediations/8
11:13:56 [Remediation] requirements.txt: requests 2.30.0 -> ==2.33.0 (line 26)
11:13:56 [Sandbox] Sandbox 6ab35ba852d1 started for requirements.txt (python:3.12-slim, 80 KB workspace, timeout 600s, tests enabled)
11:14:01 [Sandbox] Sandbox 6ab35ba852d1 finished in 4.9s: build PASS, tests PASS
11:14:02 [Sandbox] Security scan for requests 2.33.0: PASS (found 2.33.0, 0 vulnerabilities, provider available)
11:14:02 [Sandbox] Validation 5 COMPLETED in 5.7s: build PASS, tests PASS, security PASS -> overall PASS
11:14:06 [Report] Evidence report built for finding 46 (remediation=8, validation=5, pull_request=None): Apply
11:14:06 [GitHub] Pull request 3 prepared for remediation 8 (branch sentinel-chain/pypi-requests-2.33.0)
11:14:06 WARN [GitHub] GitHub PR creation unavailable: GITHUB_TOKEN is not configured
```

API state afterwards: analysis 6 `COMPLETED`, stages
`{repository OK, dependencies OK, vulnerabilities OK, usage OK, knowledge_graph OK, ai PARTIAL}`
(PARTIAL only because 4 findings exceeded `AI_MAX_FINDINGS_PER_ANALYSIS=5`; all 5 analysed
succeeded — F-19), `overall_risk HIGH`; remediation 8 `PROPOSED`; validation 5 `PASS`; report
decision `Apply`; PR 3 `UNAVAILABLE` with manual instructions. Earlier the same day with a
token: real draft PR https://github.com/lokeshlella/sentinel-chain-demo/pull/1
(`draft=true`, `+1/-1 requirements.txt`, author `Sentinel Chain <sentinel-chain@localhost>`,
verified with `gh pr view`). Note the naming inconsistency in the log: the analyser names the
project `weather-notes-widget` (from `package.json`) while the row is `demo-project`.

---

## 2. Spec contract checks

| Contract | Result | Evidence |
|---|---|---|
| OSV unreachable/timeout/5xx/429/malformed → `UNKNOWN`, never `SAFE` | **HOLDS** | Live: `OSV_API_URL=http://127.0.0.1:9` → all 18 deps `UNKNOWN`, reason `Vulnerability check unavailable: connection error calling POST /querybatch…`, stage `UNAVAILABLE`, analysis `COMPLETED`. Probe with `httpx.MockTransport` (`osv_provider.py`): fewer results than queries → `UNKNOWN` ("malformed /querybatch response"); `results` not a list → `UNKNOWN`; empty body → `UNKNOWN` ("malformed JSON"); HTTP 500 ×3 → `UNKNOWN`; 429 ×3 → `UNKNOWN`; batch entry without `id` → `UNKNOWN`. Batch ok but detail `GET /vulns/{id}` 500 → `VULNERABLE` with a minimal record (id known) — never SAFE. Invalid version strings are not sent at all (`service.py` `invalid_version_reason`). |
| Security scan / candidate verification under OSV outage | **HOLDS** | Validation 7 with OSV blocked: `security_scan_status UNKNOWN`, `overall UNKNOWN`, note `Vulnerability check unavailable…`. Candidates: `verified_safe=None`, `osv_available=False` (`tests/test_remediation_modules.py::test_osv_unavailable_yields_unverified_candidate_with_note`). |
| Skipped/absent build or tests never `PASS` | **BREAKS (F-01)** and **DECISION NEEDED (F-09)** | `parse_step_markers`: no markers → `build None/tests None` → `UNKNOWN`; missing tests end marker → `UNKNOWN`; "17 passed" but exit 1 → `FAIL` (exit code governs). BUT forged markers from the repo's own output are accepted (`docker_provider.py:57` regex, `:532-541` uses the parsed exit code even when `timed_out=True`) → see F-01. `overall_result("PASS","SKIPPED","PASS") == PASS` (`sandbox/service.py:327`) → F-09. |
| Original repository / local path never written | **HOLDS** | Local ingest copies with `shutil.copytree(symlinks=True, ignore=…)` into `workspace/repos/<id>` (`local_provider.py`); remediation copies again into `workspace/remediations/<id>` (`workspace.py`); `modifiers.resolve_target` (`modifiers.py:101-110`) rejects targets whose resolved path leaves the workspace — proven with a `requirements.txt → ../outside/requirements.txt` symlink: `modifier REFUSED: Dependency file 'requirements.txt' is outside the working copy`, original unchanged. Artifact copy-back checks `workspace.resolve() in target.parents` (`sandbox/service.py:211-212`). After the whole e2e run `examples/demo-project/requirements.txt` still reads `requests==2.30.0`. |
| LLM output always through Pydantic; malformed → retry then loud failure | **HOLDS** (one low note, F-15) | `structured.py` `generate_structured` validates with `model_validate`, catches `ValidationError`/`TypeError`/`ValueError`, re-prompts up to `llm_max_retries`, then raises `StructuredOutputError` → `AgentError` → recorded in `FindingAIResult.failures`, `ai_status=FAILED`. Live evidence: analysis 4 on the GitHub demo had `ai: {analyzed 5, completed 4, failed 1}` with the failure text stored in `ai_error`. Deterministic remediation fallback is labelled `Deterministic recommendation (LLM unavailable: …)` with `confidence 0.5`, `ai_result=None` (`remediation/service.py` `_deterministic`). Guardrails: invented components dropped (`tests/test_pipeline.py::test_invented_component_is_dropped_by_guardrail`), non-candidate versions substituted and noted (`test_llm_choosing_non_candidate_version_is_overridden`). |
| No hard-coded vulnerability data / AI responses / model names outside config | **HOLDS** | `grep -rnE 'GHSA-[0-9a-z]{4}-\|CVE-[0-9]{4}-\|PYSEC-' app/` → only a docstring example in `vulnerabilities/aliases.py:4-5`; `grep -rniE 'llama\|qwen\|mistral' app/` → only `core/config.py` default `llama3.2:3b`. |
| PRs draft-only; no merge path | **HOLDS with deviation (F-12)** | `grep -rniE '\.merge\(\|enable_automerge\|squash\|git merge\|rebase\|push --force[^-]' app/` → no matches (only `ExtractionResult.merge`, a list merge). `create_pull(draft=True)` at `github_provider.py:349-352`; fallback `draft=False` only on GitHub 422 "Draft pull requests are not supported" (`:358`). Push uses `--force-with-lease=<branch>[:<sha>]` (`:290`). Live PR #1 verified `isDraft=true`. |
| Provenance of `risk_level` (AI vs provisional) | **HOLDS** | `ai_results.risk` present ⇒ AI; otherwise `risk_level` is severity-derived (`analysis/risk.py:82`); the report labels it "provisional (severity-based)" vs "AI" (`reports/service.py` risk_section). Ollama-down run: findings kept `risk_level` `HIGH/MEDIUM` with `ai_status=UNAVAILABLE`. |

---

## 3. Failure injection (one at a time; `POST /repositories/1/analyze` unless noted)

| Service down | Method | Observed | Verdict |
|---|---|---|---|
| **Neo4j** | `docker stop sentinel-neo4j` | Analysis 7 `COMPLETED` in 6 s; stages `knowledge_graph: UNAVAILABLE`, warning `Knowledge graph unavailable: Neo4j could not be reached`; `GET /repositories/1/graph` → `200 {"available": false, …}`; `GET /dependencies/{id}/graph` → `200 {"available": false}`; health `neo4j: false`. Log: one warning per call ("retrying in 30 s"). | clean degradation |
| **Ollama** | `brew services stop ollama` | Analysis 8 (`run_ai=true`) `COMPLETED` in 12 s; `ai: UNAVAILABLE`, warning `AI analysis unavailable: Ollama unreachable at http://localhost:11434; start it with \`ollama serve\``; findings `UNAVAILABLE`/`SKIPPED`, provisional risk kept. `POST /findings/{id}/remediate` → `PROPOSED 2.33.0`, `confidence 0.5`, text `Deterministic recommendation (LLM unavailable…)` in 1 s. `POST /findings/{id}/analyze` → `ai_status UNAVAILABLE` in <1 s. | clean degradation |
| **Docker daemon** | second instance `DOCKER_HOST=unix:///tmp/none.sock` | health `docker: false`; `POST /remediations/9/validate` → validation 6 `FAILED` in 3 s, `build UNKNOWN / tests UNKNOWN / security PASS / overall UNKNOWN`, error `Docker is not available: could not connect to the Docker daemon (…). Start Docker (…)`; remediation → `VALIDATION_FAILED`. | clean degradation; F-11 |
| **OSV (network blocked)** | second instance `OSV_API_URL=http://127.0.0.1:9/v1` | Analysis 9 `COMPLETED` in 3 s; `vulnerabilities: UNAVAILABLE`, all 18 deps `UNKNOWN` ("Vulnerability check unavailable: connection error…"), 0 findings, `usage: SKIPPED`, `ai: SKIPPED`; **`knowledge_graph: OK` with "33 stale relationships removed"** → Neo4j afterwards: `deps 18, affected_by_edges 0, statuses ["UNKNOWN"]`. Validation 7: `security UNKNOWN → overall UNKNOWN`. | degradation OK but **state regression (F-03)** |
| **GITHUB_TOKEN unset** | default `.env` | PR 3 `UNAVAILABLE`, `error_message: GitHub PR creation unavailable: GITHUB_TOKEN is not configured`, manual `git`/`gh pr create --draft` instructions stored. | clean |
| **GITHUB_TOKEN invalid** | instance `GITHUB_TOKEN=ghp_invalid…` | Clone of public repo **succeeds** (log `auth=token`) — F-16. PR: `201 {review_status: FAILED, error_message: "GitHub authentication failed or the token lacks push permission for lokeshlella/sentinel-chain-demo: remote: Invalid username or token…"}` in 2 s; token appears **0** times in the server log and **0** times in the workspace `.git/config`; working copy left on branch `sentinel-chain/pypi-requests-2.33.0` with the commit (expected; retried creation deletes the stale local branch). | clean, F-13 |
| **PostgreSQL** | `docker stop sentinel-postgres` | `GET /api/health` → `200 status=degraded`; `GET /repositories`, `GET /dashboard`, `GET /analyses/6`, `POST /repositories`, `POST /repositories/1/analyze` → **`500 {"error":"InternalServerError","message":"(psycopg.OperationalError) connection failed: connection to server at \"::1\", port 5432 failed: … Connection refused …"}`**. No credentials in the text (verified: `check_database()` with password `SUPERSECRET` in the URL → `contains password: False`). After restart: health `ok`. | **F-04** (500, raw driver text); no hang, no corrupt state |

Nothing hung; no request exceeded 20 s in these cases; no corrupt rows were produced.

---

## 4. State and resources

### 4.1 PostgreSQL vs Neo4j consistency
* Postgres commit OK, Neo4j write fails (Neo4j down): rows kept, stage `UNAVAILABLE`, graph unchanged from the previous sync (verified in §3; the sync is skipped entirely when `client.available()` is False, `knowledge_graph/service.py:643-644`).
* Postgres OK, Neo4j **reachable**, but the analysis was degraded (OSV outage): the graph is rewritten from the degraded snapshot, deleting `AFFECTED_BY` edges (F-03). Same would happen if usage evidence fails.
* Neo4j write OK, Postgres commit fails afterwards: **Unverified** (not injectable without corrupting the shared DB); by code order (`pipeline.py:85` graph sync happens after the vulnerability rows are committed, and `_fail` rolls back only the current transaction) the graph would hold the newer state while the analysis row says `FAILED`; the next successful analysis overwrites it (natural keys).

### 4.2 Stuck `RUNNING`
* Stage exception → `_fail()` marks `FAILED` with `error_message` (`pipeline.py` `run()` catches `SentinelError` and `Exception`; unit test `test_missing_dependency_files_fails_analysis_clearly`).
* Process killed mid-analysis (`kill -9` during the AI stage): DB row `11|RUNNING|` while the process is dead; after restart `FAILED — Interrupted by a backend restart; start it again` (log `Marked 1 analyses and 0 validations interrupted by restart`). Between crash and restart the row stays `RUNNING` and `POST /analyze` returns `409` (F-06).

### 4.3 Cleanup
* Sandbox containers: after 9 validations including the Docker-timeout kill (`DOCKER_TIMEOUT=3`: `Sandbox 9cc7de8aad28 exceeded 3s; killing the container … tests UNKNOWN (timed out)`): `docker ps -a --filter label=sentinel-chain=sandbox | wc -l` → **0**. `container.remove(force=True)` is in a `finally` (`docker_provider.py:351-379`).
* Failed registrations: repository ids 2 and 8 (clone failures) → `workspace/repos/2`, `/8` do not exist (`register()` deletes the row and directory on ingest failure).
* Repository deletion: `DELETE /repositories/7` → `repos/7` removed, but `remediations/10`, `validations/8`, `reports/10` remain on disk while their rows are gone (F-07). Inventory after the audit: repos on disk `1 3 4 5 7` vs DB `1 3 4` (5 and 7 orphaned by cross-instance/ordering effects — F-07/F-10); remediation dirs `1 2 3 4 5 6 8 9 10` vs rows `1 2 3 4 5 8 9`.
* Remediation failure path removes its half-built workspace (`remediation/service.py` `remove_workspace(workspace)` in the `except`); success keeps it by design (needed for validation/PR).

### 4.4 Long work on the request thread (F-05)
* `POST /repositories` → `RepositoryService.register → ingest → clone` synchronously (`api/routes/repositories.py:37`); bounded only by `git_clone_timeout=300` (`core/config.py:81`).
* `POST /findings/{id}/remediate` (`api/routes/remediations.py:62`) → registry + up to 6 OSV calls + one LLM call with `ollama_timeout=180 × (llm_max_retries+1)=3` → observed **3 m 01 s** wall time when Ollama stalled (`curl … /remediate  … 3:01.60 total`, transcript 2026-09-14 09:06–09:09).
* `POST /findings/{id}/analyze` (`api/routes/findings.py:55`) → three agents × 3 attempts × 180 s worst case ≈ 27 min on the request thread.
* Browser `fetch` and most proxies time out well before that; the work continues server-side but the client sees an error.

---

## 5. Security of the tool itself

| Check | Result | Evidence |
|---|---|---|
| Repo/branch/URL → shell | HOLDS | Clone is `git.Git().execute([...clone --single-branch [--branch <b>] -- <url> <dest>])` with `validate_branch_name` (rejects `-x`, `--upload-pack=`, spaces, `..`, `~^:?*[`, `@{`, `.lock`; 19 negative cases in `tests/test_repository_github_provider.py:234`) and a regex-parsed owner/repo; no `shell=True` anywhere (`grep -rn "shell=True\|os.system" app/` → none). |
| Package/file names → `sh -c` script in the container | HOLDS | `build_script` quotes the dependency file: probe `dependency_file="requirements-$(touch /tmp/pwned).txt"` → `python -m pip install --no-cache-dir -r 'requirements-$(touch /tmp/pwned).txt'`. (Executes inside the throw-away container anyway.) |
| Cypher | HOLDS | All values are `$parameters` (36 markers in `knowledge_graph/service.py`); f-strings only splice constant fragments (`_DEPENDENCY_MATCH`, `:458-481`) and an integer path length (`:491-494`, `.format(length=length)` from a `range` loop `:764`). |
| SQL | HOLDS | Only `text("select version()")` (`db/session.py:39`); everything else is SQLAlchemy ORM. |
| Path traversal | HOLDS | `resolve_target` (`modifiers.py:101-110`), artifact copy-back (`sandbox/service.py:211-212`), local provider refuses `/`, `~`, `/usr`… (`local_provider.py` `_is_system_root`), `delete()` only rmtree's a `local_path` inside its own `workspace/repos/<id>` (`repository/service.py:153-170`). |
| Repo code executing on the host | **BREAKS for local sources (F-02)** | Extraction/analysis/usage use `json.loads`, `packaging`, regex only (no `exec/eval/import` of repo code; `grep -rn "exec(\|eval(\|importlib" app/services` → none). pip/npm/pytest run only in the container. BUT `LocalRepositoryProvider` copies `.git` including `hooks/`, `create_working_copy` copies it again, and `GitHubProvider` runs `git checkout/add/commit` in that copy (`github_provider.py:251-269`) without `core.hooksPath` (`grep -rn hooksPath app/` → none). Proof: local repo with `.git/hooks/pre-commit` writing a marker → `HOOK RAN ON HOST: True -> hook executed on host by saidaraojasti`. GitHub clones do not receive hooks, so the vector is local paths only. |
| Container hardening (F-08) | PARTIAL | `container_kwargs` → `user=None` (**root** in container), `network_mode='bridge'` (**outbound network on**; required for `pip/npm install`), `read_only=None` (writable rootfs), `mem_limit='2g'`, `nano_cpus=2e9`, `pids_limit=512`, `cap_drop=['ALL']`, `security_opt=['no-new-privileges']`, no `volumes`/`mounts`/`privileged`; timeout via `container.wait(timeout)` then `kill` (verified live with `DOCKER_TIMEOUT=3`); images referenced by tag, not digest. |
| Marker spoofing (F-01) | **BREAKS** | see §7 F-01. |
| Secrets in logs/API/report | HOLDS | Token: 0 occurrences in server logs and `.git/config` in both the valid-token PR run and the invalid-token run (`grep -c ghp_invalidtoken …log → 0`); push URL is command-line only with `redact()` on errors (`github_provider.py:92, :288`). DB password: `check_database()` with `SUPERSECRET` in the URL → detail does not contain it; the 500 handler echoes `str(exc)[:500]` (`main.py:90`) — psycopg messages carry host/port only. Report/PR `source_url` is the canonical token-less URL or the local path (`report section 1: source_url = /Users/…/examples/demo-project` — a local absolute path is disclosed in reports/PR bodies: informational). Frontend: no `dangerouslySetInnerHTML`/`innerHTML` (`grep -rn … frontend/src` → none). CORS at `main.py:68-74`. |
| Auth / CORS (F-17) | NOTE | No authentication on any endpoint; `allow_credentials=True` with an explicit origin allow-list (`main.py:57-63`). Anyone reaching :8000 can clone arbitrary public URLs to disk, start sandbox containers and delete repositories. |

---

## 6. Test gaps

**Modules without meaningful unit tests** (only reached through fakes or integration):
`api/deps.py` (factories `build_*`, `run_analysis_job`/`run_validation_job` crash logging — 58 %),
`db/session.py`/`db/neo4j.py` (real connections — 50 %/41 %), `api/routes/health.py`
(real checks are patched — 49 %), `services/github/github_provider.py` push/ls-remote/existing-PR
reuse/422 fallback (63 %), `services/remediation/workspace.py` error branches (64 %),
`services/sandbox/security_scan.py` mismatch/other-vulnerable branches (72 %),
`services/remediation/registry.py` transport/timeout branches (75 %), the **frontend (0 tests)**.

**Highest-risk untested paths, ranked**
1. Sandbox marker trust + timeout precedence (F-01) — no test for forged markers or "exit code present but timed_out".
2. Git hooks executing on the host for local repositories (F-02) — no test.
3. Graph rewrite on a degraded analysis (F-03) — no test asserts edges survive an OSV outage.
4. `GitHubProvider` against a real remote: push rejection, `--force-with-lease` mismatch, existing PR reuse, 422 draft fallback (`github_provider.py:318-332, 357-367`).
5. `DockerSandboxProvider.run` with a hanging/unresponsive daemon (`wait` raising `ConnectionError` vs `ReadTimeout`) — only the fake-client timeout is tested.
6. `run_analysis_job` / `run_validation_job` exception paths and `mark_interrupted_jobs` for validations.
7. `PackageJsonModifier` on exotic formatting (tabs, CRLF, comments-in-JSON5, duplicate keys).
8. OSV `next_page_token` pagination for `querybatch` (only `/query` pagination is tested at `tests/test_vulnerabilities_osv_provider.py:348`).
9. `RepositoryService.delete` with `local_path` outside the workspace and concurrent registration races (F-14).
10. Frontend pages under `UNAVAILABLE`/`FAILED` data (null handling was eyeballed, never tested).

**Top 10 test cases to add (names + assertions; not written)**
1. `test_forged_markers_do_not_yield_pass_when_timed_out` — logs with `::step tests end 0` + `timed_out=True` ⇒ tests `UNKNOWN`, overall `UNKNOWN`.
2. `test_markers_are_nonce_scoped` — after fix: markers without the per-run nonce are ignored.
3. `test_local_repo_hooks_never_run_on_host` — working copy with a `pre-commit` hook ⇒ commit succeeds without executing it (marker file absent).
4. `test_degraded_analysis_keeps_previous_affected_by_edges` — OSV unavailable ⇒ graph sync skipped or edges preserved.
5. `test_postgres_down_returns_503_with_message` — `OperationalError` ⇒ `503 {"error":"DatabaseUnavailable"}`, no driver text.
6. `test_remediate_endpoint_is_async_or_bounded` — LLM stall ⇒ request returns within N s (202 + polling) instead of blocking.
7. `test_running_analysis_watchdog_marks_stale_rows` — `RUNNING` older than X min with no heartbeat ⇒ `FAILED`.
8. `test_delete_repository_removes_remediation_workspaces_logs_reports` — dirs under `workspace/{remediations,validations,reports}` belonging to the repo are removed.
9. `test_sandbox_container_runs_as_non_root_with_readonly_rootfs` — `container_kwargs` has `user`, `read_only=True`, tmpfs for `/workspace` or writable subpath only.
10. `test_querybatch_follows_next_page_token_per_result` — multi-page batch answer ⇒ all ids collected, no query marked SAFE prematurely.

---

## 7. Findings in detail

### F-01 — HIGH — Forged sandbox markers override the timeout → `overall PASS`
* **Where:** `backend/app/services/sandbox/docker_provider.py:57` (`_MARKER_RE`, fixed literal `::step …`), `:91-96` (markers echoed by the generated script), `:532-541` (`_step_result` returns `PASS` whenever a parsed exit code is `0`, before checking `timed_out`).
* **Ran:** `DockerSandboxProvider(...).run()` with `FakeDockerClient(logs=<repo output containing "::step build end 0" and "::step tests end 0" then a hang>, wait_timeout=True)`.
* **Observed:** `timed_out: True | build: PASS | tests: PASS | note: None`; `overall_result → PASS`. **Expected:** `UNKNOWN`/`FAIL` — a killed container must never validate.
* **Blast radius:** any repository under test (its test suite, or a package's `setup.py` printing during `pip install`) can make Sentinel Chain report a passing validation and get a "Apply" recommendation / draft PR with green evidence.
* **Fix:** per-run random nonce in the markers (`::step <nonce> …`), ignore markers whose nonce does not match, and short-circuit to `UNKNOWN` when `timed_out` regardless of parsed codes; additionally read the step exit codes from a file written by the wrapper script and fetched with `get_archive`, not from stdout.

### F-02 — HIGH — Local repository git hooks execute on the host
* **Where:** `backend/app/services/repository/local_provider.py` (copies `.git` incl. `hooks/`), `backend/app/services/remediation/workspace.py:29` (`copytree` keeps `.git`), `backend/app/services/github/github_provider.py:251-269` (`git checkout -b`, `git add`, `git -c commit.gpgsign=false commit …`) — no `-c core.hooksPath=/dev/null`, no `--no-verify`.
* **Ran:** local repo with `.git/hooks/pre-commit` writing a marker; `create_working_copy` + `GitHubProvider("ghp_fake", github_client=Fake, git_runner=real-git-except-network).create_pull_request(...)`.
* **Observed:** `hook copied into working copy: True`; `HOOK RAN ON HOST: True -> hook executed on host by saidaraojasti`. **Expected:** no repository-controlled code runs outside the container.
* **Blast radius:** any local path registered (e.g. a clone the user made of an untrusted project) gets arbitrary code execution as the backend user at PR time. GitHub-cloned sources are unaffected (git does not transfer hooks).
* **Fix:** run all git commands with `-c core.hooksPath=/dev/null` (and `commit --no-verify`); optionally strip `.git/hooks` when copying local sources.

### F-03 — MEDIUM — Degraded analysis overwrites the knowledge graph
* **Where:** `backend/app/services/analysis/pipeline.py:85` (`_stage_graph` always runs after `_stage_vulnerabilities`, regardless of `check.stage_status`), `backend/app/services/knowledge_graph/service.py:633-690` (`sync_analysis` deletes the repository's existing `USES/DEPENDS_ON/AFFECTED_BY/CONTAINS` edges before re-merging).
* **Ran:** analysis 9 with `OSV_API_URL=http://127.0.0.1:9/v1`; then `cypher-shell "MATCH (r:Repository {repository_id:1})-[:USES]->(d) OPTIONAL MATCH (d)-[a:AFFECTED_BY]->() RETURN count(DISTINCT d), count(a), collect(DISTINCT d.status)"`.
* **Observed:** log `Graph synced … 0 vulnerabilities … 33 stale relationships removed`; Neo4j: `18, 0, ["UNKNOWN"]` — the 9 `AFFECTED_BY` edges from analysis 6 are gone and the stage is reported `OK`. **Expected:** an analysis that could not check vulnerabilities must not erase previously known vulnerability relationships (or must mark the graph as degraded).
* **Blast radius:** dashboard/graph views and `GET /dependencies/{id}/graph` silently lose data after any OSV hiccup; the AI's `GraphContext` for later on-demand runs is empty.
* **Fix:** skip the graph sync (stage `SKIPPED` with a reason) when `check.stage_status != OK`, or merge without deleting `AFFECTED_BY` edges when the vulnerability stage was unavailable.

### F-04 — MEDIUM — PostgreSQL outage surfaces as HTTP 500 with driver text
* **Where:** `backend/app/main.py:85-91` (generic handler returns `str(exc)[:500]`); no `OperationalError` handler; `get_db` (`db/session.py:23-32`) raises on first use.
* **Ran:** `docker stop sentinel-postgres`; `GET /api/repositories`, `/api/dashboard`, `/api/analyses/6`, `POST /api/repositories`, `POST /api/repositories/1/analyze`.
* **Observed:** all `500 {"error":"InternalServerError","message":"(psycopg.OperationalError) connection failed: … Connection refused …"}`. Health stays `200 degraded`. **Expected:** `503` with "Database unavailable" (spec §27: meaningful errors, optional-feature failures must not look like crashes).
* **Blast radius:** every page of the dashboard shows a generic 500 during a DB blip; the frontend cannot distinguish outage from bug.
* **Fix:** add a `sqlalchemy.exc.OperationalError`/`DBAPIError` handler → `503 DatabaseUnavailable`.

### F-05 — MEDIUM — Synchronous long-running endpoints
* **Where:** `api/routes/repositories.py:37` (`create_repository` clones inline), `api/routes/remediations.py:62` (`remediate_finding`), `api/routes/findings.py:55` (`analyze_finding`); timeouts `core/config.py:53` (`ollama_timeout=180`), `:56` (`llm_max_retries=2`), `:81` (`git_clone_timeout=300`).
* **Ran:** `time curl -X POST …/findings/5/remediate` on 2026-09-14 09:06 with a stalled model.
* **Observed:** `3:01.60 total`; the UI button spun the whole time. Worst cases by configuration: clone 300 s; on-demand AI 3 agents × 3 attempts × 180 s ≈ 27 min. **Expected:** `202` + polling like analysis/validation, or hard bounds well under typical client timeouts.
* **Blast radius:** demo freezes / browser or nginx (`proxy_read_timeout 600s`) timeouts while the server keeps working; duplicate clicks create duplicate remediations.
* **Fix:** make remediate/analyze-finding/register-with-clone background jobs with status rows, or cap total LLM time per request.

### F-06 — MEDIUM — No watchdog for in-flight jobs
* **Where:** `backend/app/main.py:32-58` (`mark_interrupted_jobs` runs only at startup); background jobs are plain `BackgroundTasks` threads (`api/deps.py:105-118`).
* **Ran:** `kill -9` the uvicorn process during the AI stage; `psql select analysis_id,status from analyses where analysis_id=11`.
* **Observed:** `11|RUNNING|` until the next start, then `FAILED — Interrupted by a backend restart`. While `RUNNING`, `POST /repositories/1/analyze` → `409 Analysis 11 is already RUNNING`. **Expected:** stale `RUNNING` rows time out on their own.
* **Blast radius:** a single crash of the job thread that does not kill the process (e.g. `os._exit` from a C extension) blocks the repository until someone restarts the backend.
* **Fix:** `started_at`-based staleness check (e.g. `> 2 × expected max`) in the analyze/validate endpoints or a periodic sweeper; a heartbeat column.

### F-07 — MEDIUM — Orphaned files after repository deletion
* **Where:** `backend/app/services/repository/service.py:153-170` (removes only `workspace/repos/<id>`); remediation workspaces (`workspace/remediations/<rid>`), validation logs (`workspace/validations/<vid>`), reports (`workspace/reports/<rid>`) are keyed by their own ids and never removed.
* **Ran:** `DELETE /api/repositories/7` (repo with remediation 10, validation 8, report 10); `ls workspace/*`.
* **Observed:** `repos/7 exists: no`, `remediations/10 exists: yes`, `validations/8 exists: yes`, `reports/10 exists: yes`, `DB rows for remediation 10: 0`. **Expected:** all artefacts of the repository removed (or retained deliberately and documented).
* **Blast radius:** disk growth over time (each remediation copy of a real project is the full working tree); stale evidence files with no owner row.
* **Fix:** collect remediation/validation/report ids before the cascade and remove their directories in `delete()`; or nest everything under `workspace/repos/<id>/…`.

### F-08 — MEDIUM — Sandbox runs as root with network and writable rootfs
* **Where:** `backend/app/services/sandbox/docker_provider.py:423-460` (`container_kwargs`), `core/config.py` (no user/read-only settings).
* **Ran:** `DockerSandboxProvider(Settings()).container_kwargs("python:3.12-slim", "true", req)`.
* **Observed:** `user=None, network_mode='bridge', read_only=None` (plus `cap_drop ALL`, `no-new-privileges`, `pids_limit 512`, `mem 2g`, `2 CPUs`, no mounts). **Expected (audit brief):** non-root, no network. Network is a genuine trade-off (installs need it); root and writable rootfs are not.
* **Blast radius:** a malicious package/test runs as root inside the container with internet access (data exfiltration, crypto-mining until timeout, container-escape surface larger than needed). Host mounts are absent, which limits escape.
* **Fix:** `user="65534:65534"` (or create a user in a custom image), `read_only=True` + `tmpfs={"/workspace": "rw,size=…", "/tmp": ""}`, restrict egress to the package registries (proxy or network policy), pin images by digest.

### F-09 — MEDIUM — `overall PASS` with tests `SKIPPED` (needs an owner decision)
* **Where:** `backend/app/services/sandbox/service.py:327` (`overall_result`: `PASS` when build PASS, security PASS and tests `PASS or SKIPPED`), warning `TESTS_SKIPPED_WARNING` at `:47`; documented in `docs/ARCHITECTURE.md §4.8`.
* **Ran:** `overall_result("PASS","SKIPPED","PASS")` → `PASS`; unit test `test_validation_with_skipped_tests_passes_with_warning` encodes it.
* **Observed vs spec:** `test_status` is truthfully `SKIPPED` and the report decision becomes "Apply with manual testing", but `overall_result=PASS` and `remediation.status=VALIDATED` for a change whose tests never ran. Spec §14: "Never mark a skipped test as PASS."
* **Blast radius:** a repo without tests gets a green validation badge and a PR body saying `Overall: PASS`.
* **Fix:** introduce `overall_result = "PASS_WITHOUT_TESTS"` (or keep `UNKNOWN`) and make the PR body/UI show it; keep the final-recommendation wording.

### F-10 — MEDIUM — Absolute paths in DB couple rows to one backend instance
* **Where:** `repositories.local_path`, `remediations.proposed_change.workspace_path`, `validations.logs_path` store absolute host/container paths (`repository/service.py`, `remediation/service.py`, `sandbox/service.py:233`).
* **Ran:** Compose backend (`/workspace`) against rows created by the host backend (`/Users/…/workspace`): `DELETE /repositories/5` from the container → host directory `workspace/repos/5` survives; validating a host-created `PROPOSED` remediation from the container fails "working copy is missing" (`_check_validatable`, `sandbox/service.py:306-312`).
* **Blast radius:** running host + Compose backends against the same DB (or moving the workspace) silently breaks validation/PR/delete for older rows.
* **Fix:** store paths relative to `REPOSITORY_WORKSPACE` and resolve at use time.

### F-11 — LOW — Security scan `PASS` on a validation whose sandbox never ran
* **Where:** `backend/app/services/sandbox/service.py:189-200` (`except SandboxError` path still calls `_run_scan`).
* **Ran:** validation 6 with `DOCKER_HOST` dead → `{'status': 'FAILED', 'build_status': 'UNKNOWN', 'test_status': 'UNKNOWN', 'security_scan_status': 'PASS', 'overall_result': 'UNKNOWN'}`.
* **Blast radius:** a green "security PASS" badge next to a failed validation confuses reviewers; overall is correctly `UNKNOWN`.
* **Fix:** skip (or label) the scan when the sandbox could not run.

### F-12 — LOW — Non-draft PR fallback
* **Where:** `backend/app/services/github/github_provider.py:355-358`.
* **Evidence:** code path retries `create_pull(**{**kwargs, "draft": False})` when GitHub answers 422 "Draft pull requests are not supported"; result status becomes `OPEN` (`:390`). Not reachable on public repos (drafts supported) — **unverified live**.
* **Fix:** fail with instructions instead of opening a non-draft PR, or make the fallback opt-in.

### F-13 — LOW — `201 Created` for a `FAILED` PR record
* **Where:** `backend/app/api/routes/remediations.py:129-141` (`create_pull_request`, `status_code=201`).
* **Evidence:** invalid-token run → `http 201 | status FAILED`. A client treating 2xx as success shows "PR created".
* **Fix:** return `502`/`409` with the record, or `201` only for `DRAFT/OPEN`.

### F-14 — LOW — Duplicate repositories not enforced by the database
* **Where:** `backend/app/models/repository.py` (no unique constraint), `repository/service.py:203-241` (`_ensure_not_registered` select-then-insert).
* **Evidence:** `pg_indexes` for `repositories`: only `repositories_pkey` and `ix_repositories_name`. Two concurrent `POST /repositories` with the same URL can both pass the check.
* **Fix:** unique index on `(lower(source_url), coalesce(branch,''))`.

### F-15 — LOW — Out-of-range confidence silently clamped
* **Where:** `backend/app/services/agents/schemas.py:21` (`_clamp`), validators at `:118, :134, :151, :171`.
* **Evidence:** `DependencyAnalysisResult(summary="x", confidence=90)` → `confidence=1.0` (no error, no note). A model that answers percentages looks maximally confident.
* **Fix:** reject values outside `[0, 1]` (forcing the correction round) or record the raw value.

### F-16 — LOW — Invalid token accepted for public clones
* **Where:** `backend/app/services/repository/github_provider.py` `_clone_url` (embeds the token whenever configured).
* **Evidence:** instance with `GITHUB_TOKEN=ghp_invalid…` → log `Cloning … (branch=default, auth=token)` and registration succeeded in 1 s; the bad token was only detected at `POST …/pull-request`.
* **Fix:** validate the token once at startup/health (`GET /user`) and report it in `/api/health`.

### F-17 — LOW — Unauthenticated side-effecting API
* **Where:** all routes; `main.py:68-74` CORS with `allow_credentials=True`.
* **Evidence:** by inspection; local-only single-user deployment is the documented scope (`V1_IMPLEMENTATION_STATUS.md`).
* **Fix:** bind to `127.0.0.1` by default in docs/compose, add an API key header for non-local use.

### F-18 — LOW — Compose healthchecks/ordering
* **Where:** `docker-compose.yml` `backend`/`frontend` services.
* **Evidence:** `docker compose ps` shows `Up` (no health) for both; `frontend` `depends_on: [backend]` without `condition: service_healthy`.
* **Fix:** add `healthcheck` (`curl -f localhost:8000/api/health/live`) and `condition: service_healthy`.

### F-19 — LOW — Ambiguous AI counters / PARTIAL semantics
* **Where:** `backend/app/services/analysis/pipeline.py:238-289`.
* **Evidence:** Ollama-down run → `ai: {'analyzed': 1, 'completed': 0, 'failed': 0, 'unavailable': 5, 'skipped': 4}`; normal run → stage `PARTIAL` although `completed == analyzed == 5` (4 skipped by the cap).
* **Fix:** count `analyzed` only for findings that reached the model; use `OK` when every attempted finding completed and note the cap separately.

---

## 8. Definition of Done (spec §29 — the specification lists 25 checkbox items)

| # | Item | Status | Evidence |
|---|---|---|---|
| 1 | Application starts successfully | VERIFIED | §1.1 (`docker compose --profile full up`, host `uvicorn`) |
| 2 | PostgreSQL works | VERIFIED | §1.2 migration + `alembic check`; e2e rows |
| 3 | Neo4j works | VERIFIED | §1.4 `31 nodes / 33 relationships`; cypher-shell counts |
| 4 | Ollama connection works | VERIFIED | health `model 'llama3.2:3b' available`; 5 findings analysed in §1.4 |
| 5 | GitHub repository can be ingested | VERIFIED | `lokeshlella/sentinel-chain-demo` (§1.1, §3), earlier `pallets/flask`, `octocat/Hello-World` |
| 6 | Local repository can be ingested | VERIFIED | §1.4 `[Repository] Copied demo-project` |
| 7 | Python dependencies extracted | VERIFIED | `requirements.txt: 17 requirements parsed` |
| 8 | JavaScript dependencies extracted | VERIFIED | `package.json: 1 direct`, lock v3 parsed |
| 9 | Dependencies stored in PostgreSQL | VERIFIED | `18 dependencies persisted for analysis 6` |
| 10 | Knowledge graph populated | VERIFIED (with F-03 caveat) | §1.4; but a degraded run wipes `AFFECTED_BY` |
| 11 | OSV vulnerability detection works | VERIFIED | `3 vulnerable, 15 safe … 9 distinct vulnerabilities`, ids match `docs/examples`; outage → `UNKNOWN` |
| 12 | Findings created | VERIFIED | `9 findings created for analysis 6` |
| 13 | Source usage identified | VERIFIED | `requests … components=['src','tests']`, `lodash … ['src']` |
| 14 | Ollama can analyze a finding | VERIFIED | 5 × `COMPLETED`, structured JSON stored in `ai_results` |
| 15 | Impact assessment generated | VERIFIED | `impact=HIGH/MEDIUM` per finding; guardrail test |
| 16 | Risk assessment generated | VERIFIED | `risk=HIGH/MEDIUM`; provisional fallback under outage |
| 17 | Remediation recommendation generated | VERIFIED | `2.30.0 -> 2.33.0 (confidence 0.95, 15.0s)`; deterministic fallback when Ollama down |
| 18 | Dependency modification in a temporary workspace | VERIFIED | `Working copy created at …/remediations/8`; original file unchanged; symlink probe refused |
| 19 | Docker validation works | PARTIAL | Real runs PASS (`Sandbox 6ab35ba852d1 … build PASS, tests PASS`), timeout kill works, containers cleaned; **but results are forgeable (F-01)** and the container is root/networked (F-08) |
| 20 | Evidence report generated | VERIFIED | `GET /remediations/8/report` → 10 sections, decision `Apply`; `docs/EXAMPLE_EVIDENCE_REPORT.md` |
| 21 | Draft PR when credentials exist | VERIFIED | https://github.com/lokeshlella/sentinel-chain-demo/pull/1 `isDraft=true` (`gh pr view`); without token → `UNAVAILABLE` + instructions |
| 22 | Frontend displays the workflow | PARTIAL | Pages render live data (browser session 2026-09-14, screenshots of Dashboard/Finding/Remediation/Validation/PR); **zero automated tests**; DB outage shows generic 500s (F-04) |
| 23 | Tests pass | VERIFIED | `777 passed, 20 skipped`; `20 passed` integration |
| 24 | README contains exact setup instructions | VERIFIED | `README.md` quick start reproduced by the auditor's commands (compose, venv, alembic, uvicorn, npm) |
| 25 | One complete end-to-end demo works | VERIFIED | §1.4 log: 132 s analysis → remediation → validation PASS → report `Apply` → PR record; real PR earlier the same day |

---

## 9. Ten things most likely to break during a live demo

1. **Ollama stalls under memory pressure** (8 GB, Docker + Neo4j + model): one LLM call hit the 180 s timeout on 2026-09-14 09:06; remediation then blocks the browser for 3 minutes (F-05) and falls back to the deterministic candidate. Mitigation: warm the model (`ollama run llama3.2:3b ""`) and close other apps before starting.
2. **3B model produces invalid JSON after retries** — analysis 4 had `failed: 1` of 5; the finding shows `FAILED` with the error, which is honest but awkward on stage. Re-run via "Run AI analysis".
3. **Backing containers stopped overnight** — happened during this build (Postgres/Neo4j `Exited`); every data page then 500s (F-04). Run `docker compose up -d postgres neo4j` and check `/api/health` first.
4. **First sandbox run pulls `python:3.12-slim` / `node:20-slim`** (tens of seconds to minutes on slow Wi-Fi); pre-pull them.
5. **OSV.dev slow or rate-limited** (429 after several analyses in a row): dependencies flip to `UNKNOWN` and — worse — the graph loses its `AFFECTED_BY` edges (F-03). Keep one clean analysis as the reference and avoid re-analysing repeatedly.
6. **npm deprecation surprises**: `lodash@4.18.0` was deprecated between OSV's "fixed" version and the registry; the selector skips it, but the OSV data changes over time — verify the demo README's ids the morning of the demo.
7. **`409 Analysis already RUNNING`** after a crash/kill until the backend is restarted (F-06).
8. **Wrong `OLLAMA_MODEL` tag** (`llama3.2` vs `llama3.2:3b`): health now reports it as missing, but a stale `.env` still causes every AI call to 404.
9. **Compose vs host mix-up**: rows created by one instance cannot be validated/deleted by the other (F-10); pick one mode for the demo.
10. **GitHub PR step**: token scope/permission errors surface only at PR time (F-16) and return `201 FAILED` (F-13); test the token with `gh auth status`/a dry run before presenting, and remember drafts show as "Draft" only on repos where the token has push rights.

---

## 10. Unverified

* Neo4j write succeeds but the subsequent PostgreSQL commit fails (not injectable safely on the shared DB) — reasoning from code order only.
* Docker daemon becoming unresponsive **mid-run** (`container.wait` hanging vs raising) — only the dead-socket case and the timeout path were exercised.
* GitHub 422 "drafts not supported" fallback (F-12) — needs a plan/repo without draft support.
* `put_archive` with symlinks or very large workspaces (>100 MB) — not exercised; the demo workspace is 80 KB.
* Two analyses of different repositories running concurrently in the thread pool.
* Frontend behaviour under every failure state — verified visually for the happy path and the `UNAVAILABLE` PR only.
* Windows / Linux hosts (only macOS/arm64 exercised).
