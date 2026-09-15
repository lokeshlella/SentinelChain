# Sentinel Chain V1 — Second-pass Audit (AUDIT-V2)

_Date: 2026-09-15. Commit audited: `cbb6042` (`main`, all seven audit-fix PRs merged). Read-only pass:
no repository edits were made; three tools (`ruff`, `mypy`, `pip-audit`) were installed into a
throw-away venv under the session scratchpad. Every claim below cites a command that was run in
this session or a `file:line` of the current tree. Prior audit: `AUDIT_V1.md` (commit `f95fec6`)._

**Framing note that governs Step 2.** The brief describes a *symbol-level reachability analyser*.
Sentinel Chain V1 is not one, and nowhere claims to be: the words "reachable"/"reachability" do not
occur in `app/` or `docs/` (`grep -rn reachab app/ docs/` → only the OSV *network* reachability
probe, `osv_provider.py:462-464`). What exists is (1) package+version matching delegated to OSV,
(2) a regex import/require scan producing *file-level usage evidence*
(`app/services/analysis/usage.py`), (3) an LLM impact/risk assessment over that evidence. Every
Step 2 item below is evaluated against that real pipeline; where a requested construct has no
counterpart (call graphs, symbol matching, hop-2 traversal) it is marked *N/A — not implemented*,
and the closest real behaviour is examined instead.

---

## Step 1 — Prior state

### 1.1 Toolchain today

| Tool | Command | Result |
|---|---|---|
| pytest (unit) | `.venv/bin/pytest -q` | **819 passed, 21 skipped** (integration) |
| ruff, default rules (E4,E7,E9,F) | `ruff check app tests --select E4,E7,E9,F` | **7 errors**, all in tests, all auto-fixable: 6 × F401 unused import (`tests/test_audit_low_findings.py:15`, `test_git_safety.py:9`, `test_paths.py:5`, `test_reports_and_github.py:14`, `test_sandbox_modules.py:23`), 1 × F541 (`tests/test_api.py:134`), 1 × E401 (`tests/test_sandbox_modules.py:135`). `app/` is clean. |
| ruff, extended (E,F,W,B,S) on `app/` | `ruff check app --select E,F,W,B,S` | 1652: **1613 × E501** (no line-length configured; the code is written at ~120 cols), 30 × B008 (FastAPI `Depends()` in defaults — idiomatic, false positive), 3 × S105 (`config.py:49` default `neo4j_password="sentinelchain"` — real default credential, see V2-13; `enums.py:107` `PASS`, `instructions.py:15` — false positives), 1 × S701 (`reports/service.py:777` Jinja2 `autoescape=False`, Markdown output — see V2-14), 1 × S603 (`repository/github_provider.py:379` `subprocess.Popen(command, …)` list form, no shell — reviewed, fine), 2 × S108 (`/tmp` **inside the sandbox container**, `docker_provider.py:83, 403` — fine). |
| mypy | `mypy app --ignore-missing-imports` | **67 errors in 25 files**. 19 are `name-defined` on SQLAlchemy string forward references in `app/models/*.py` (harmless under `from __future__ import annotations`, mypy cannot see them). ~48 are real typing defects, none observed to fail at runtime — e.g. `core/versions.py:105,147` compare `Version \| SemVer` unions (correct only because ecosystems never mix; nothing enforces it), `vulnerabilities/aliases.py:156` `max(key=…)` over `float \| None`, `javascript_extractor.py:549-565` `Any \| str \| None` flowing into `ExtractedDependency(package_name: str)`, `analysis/usage.py:490` `Match \| None .group`. See V2-12. |
| pip-audit | `pip-audit -r backend/requirements.txt` (resolved) and `pip-audit -r <pip freeze of .venv> --no-deps` (51 packages) | **No known vulnerabilities found** (both). |
| npm audit (frontend) | `npm audit` | **4 advisories**: `react-router`/`react-router-dom` 6.x **moderate** (runtime dependency; "open redirect via backslash in `<Link>`/`useNavigate`" + SSR hydration issue; fix 7.18.3), `vite` ≤6.4.2 **high** and `esbuild` ≤0.24.2 moderate (devDependencies — build/dev server only; fix vite 8.3.0). See V2-11. |

### 1.2 Prior findings — status

Verification was against the **current tree**, not the PR descriptions; two fixes that could
plausibly have regressed in the merge sequence were re-executed live (F-01 attack, F-08 ordering).

| ID | V1 severity | Status | Evidence (commit · current code) |
|---|---|---|---|
| F-01 forged sandbox markers | HIGH | **FIXED** | PR #2 (`b821714`). Each step is a `docker exec` whose exit code comes from the daemon: `sandbox/docker_provider.py:466` (`container.exec_run(["sh","-c",command]…`); a timed-out step is `UNKNOWN` before any exit code is consulted: `:567-569`. **Re-run today on `main`**: repo whose tests print `::step … end 0` then hang, deadline 20 s → `build=PASS tests=UNKNOWN timed_out=True overall=UNKNOWN`, 0 containers left. |
| F-02 local repo hooks run on host | HIGH | **FIXED** | PR #2. `repository/ignore.py:69` never copies `.git/hooks`; `repository/git_safety.py:26` `SAFE_GIT_OPTIONS` (`core.hooksPath=/dev/null`, `core.fsmonitor=false`, …) applied to every git call via `github/github_provider.py:174` `_hardened(...)`; commit uses `--no-verify` (`:279`). Regression test `tests/test_git_safety.py` passes (hook marker absent). |
| F-03 degraded analysis wiped graph edges | MEDIUM | **FIXED** | PR #3. `analysis/pipeline.py:215` passes `preserve_unknown_vulnerability_edges=preserve`; `knowledge_graph/service.py:422` `CYPHER_DELETE_STALE_DEPENDENCY_EDGES_PRESERVE` keeps `AFFECTED_BY` for `status='UNKNOWN'`; stage reported `PARTIAL` with warning. Live Neo4j integration test `test_preserve_mode_keeps_affected_by_edges_of_unchecked_dependencies` passes. |
| F-04 Postgres down → raw 500 | MEDIUM | **FIXED** | PR #3. `main.py:96-109` maps `OperationalError`/`InterfaceError` → `503 DatabaseUnavailable`, `Retry-After: 5`; `tests/test_api.py::test_database_unavailable_is_reported_as_503_not_500`. |
| F-05 long work on request thread | MEDIUM | **FIXED** | PR #4. `api/routes/repositories.py:37,51` (202 + `run_ingest_job`), `:57` retry endpoint; `routes/remediations.py:71` (`run_remediation_job`); `routes/findings.py:74` (`run_finding_ai_job`). |
| F-06 no watchdog for `RUNNING` rows | MEDIUM | **FIXED** | PR #4. `services/jobs.py:30` `heartbeat_timeout`, `:59` `expire_if_stale`; called on read (`routes/analyses.py:11` import, used in `get_analysis`) and before job start. Heartbeats: `pipeline._commit`, `sandbox/service.run`, `remediation/service.run`. |
| F-07 orphaned artefacts on delete | MEDIUM | **FIXED** | PR #8 (re-opened #5). `repository/service.py:205,214` `_artefact_dirs` removes `remediations/<rid>`, `validations/<vid>`, `reports/<rid>`; test `test_delete_removes_remediation_validation_and_report_artefacts`. |
| F-08 sandbox root / writable / network | MEDIUM | **FIXED** (network deliberately kept, documented) | PR #8. `docker_provider.py:397` `"user": f"{uid}:{gid}"` (root refused by `parse_user`), `:399` `read_only`, `:401` tmpfs `/workspace` + `/tmp`; `container.start()` precedes the exec-stdin copy-in (`:317-318`). Network mode is `DOCKER_SANDBOX_NETWORK` (`bridge` default; `none` verified to fail installs cleanly). |
| F-09 `overall PASS` with tests `SKIPPED` | MEDIUM | **FIXED** | PR #6. `sandbox/service.py` `overall_result` is PASS only when all three pass; `is_partial_pass` → `RemediationStatus.PARTIALLY_VALIDATED` (`:111`, validatable set `:46`); PR body flags it (`github/service.py`). |
| F-10 absolute paths in rows | MEDIUM | **FIXED** | PR #6. `core/paths.py:17,33`; writer `repository/service.py:164`; readers resolve (`analysis/pipeline.py`, `sandbox/service.py::_workspace_of`, `github/service.py`). Legacy absolute rows still resolve (`tests/test_paths.py`). |
| F-11 security `PASS` when sandbox never ran | LOW | **FIXED** | PR #7. `sandbox/service.py:148-156` → `UNKNOWN`, note "security scan not run: the sandbox could not be started". |
| F-12 non-draft PR fallback | LOW | **FIXED** | PR #7. `github/github_provider.py:365-373` raises `_PullRequestFailure("…never opens non-draft pull requests…")`; the `draft: False` retry no longer exists (`grep -n "draft.: False"` → none). |
| F-13 `201` for FAILED PR | LOW | **FIXED** | PR #7. `routes/remediations.py:153-161`: 201 opened / 200 prepared / 502 refused. |
| F-14 no DB uniqueness on `source_url` | LOW | **FIXED** | PR #7. `models/repository.py:47` `uq_repositories_source_branch` (`lower(source_url)`, `coalesce(branch,'')`), migration `a3c1e5f7b9d2` (applied: `alembic heads` → `a3c1e5f7b9d2`); race → `ConflictError` (`repository/service.py:112`). |
| F-15 confidence clamped | LOW | **FIXED** | PR #7. `agents/schemas.py:37-38` raises on `<0`/`>1`; `tests/test_llm_structured.py::test_out_of_range_confidence_triggers_a_correction_round_not_a_clamp`. |
| F-16 invalid token only seen at PR time | LOW | **FIXED** | PR #7. `routes/health.py:49-60` verifies against `GET https://api.github.com/user` (401/403 → "rejected by GitHub"). Cost noted in V2-10. |
| F-17 no auth, CORS credentials | LOW | **FIXED (optional guard)** | PR #7. `main.py:62` `allow_credentials=False`; `:69-84` `api_key_guard` (`secrets.compare_digest`), health exempt. Off unless `API_KEY` is set — still a local single-user default, now documented. |
| F-18 compose healthchecks | LOW | **FIXED** | PR #7. `docker-compose.yml:21,39` healthchecks (IPv4 loopback), `:51,53` `condition: service_healthy`. |
| F-19 AI counters ambiguous / PARTIAL on cap | LOW | **FIXED** | PR #7. `analysis/pipeline.py:262` counters `attempted/completed/failed/unavailable/skipped_by_limit`; `:290` un-counts an unavailable attempt; cap alone → `OK` + note. |

No finding was **WRONGLY CLOSED**; none is **OBSOLETE**.

V1's *Unverified* list, re-classified:

| V1 unverified item | Now |
|---|---|
| GitHub 422 "drafts not supported" fallback | **OBSOLETE** — the fallback code path was removed (F-12); the failure path is unit-tested with a fake 422. |
| `put_archive` with symlinks / >100 MB workspaces | **OBSOLETE** — `put_archive` is no longer used; the tar is streamed through an exec (`docker_provider.py`), symlinks are stored as symlinks, and `MAX_WORKSPACE_BYTES = 256 MB` refuses larger trees with a `SandboxError`. |
| Neo4j write OK then Postgres commit fails | **UNVERIFIED** (unchanged) — would need a fault-injecting session wrapper; the graph is written after the vulnerability rows commit (`pipeline.py:88` `_stage_graph`). |
| Docker daemon unresponsive mid-run | **UNVERIFIED** — the dead-socket and deadline-kill paths are exercised; a hung `exec_run` is now bounded by the host deadline (`_exec_step` future timeout), but a daemon that neither answers nor errors after `kill()` would block on `future.result(timeout=KILL_GRACE_SECONDS)`=10 s then return `UNKNOWN`; not exercised live. |
| Two concurrent analyses of different repositories | **UNVERIFIED** — not exercised; code paths are per-session and per-repository (409 only per repository). |
| Frontend under every failure state | **UNVERIFIED** — still zero frontend tests; failure states were only eyeballed. |
| Windows / Linux hosts | **UNVERIFIED** — macOS/arm64 only; the Compose backend is Linux/arm64 and works. |

V1 Definition-of-Done `PARTIAL` items: *Docker validation* → now VERIFIED (F-01/F-08 fixed and re-executed today); *Frontend* → still PARTIAL (no automated tests; `npm audit` moderate runtime advisory).

---

## Step 2 — What a generic audit misses here

### 2a. Fail-open: confident "not reachable" without proof

The system never emits the words "not reachable". Its equivalent is **empty usage evidence** →
which the impact prompt turns into an asserted FACT of non-use → which the risk agent is told to
weigh → which then **overwrites** the severity-derived risk. Every step is quoted:

`app/services/agents/prompts.py:301-309` (the empty-usage branch of `build_impact_prompt`):
```python
components_rule = (
    '- "affected_components": MUST be an empty list [] because no source file references the package '
    "(FACT). Do not list any component."
)
level_rule = (
    f'- "impact_level": one of {LEVEL_VALUES}. The package is declared but no source file references it, '
    "so choose NONE, LOW or UNKNOWN and say why."
)
```
`prompts.py:337` (risk prompt): `… whether the package is actually referenced by the application code (FACT) …`

`app/services/analysis/pipeline.py:353-356` (`_store_ai_result`):
```python
if result.impact is not None:
    finding.impact_level = result.impact.impact_level
if result.risk is not None and result.risk.risk_level != RiskLevel.UNKNOWN:
    finding.risk_level = result.risk.risk_level
```
`app/services/analysis/risk.py:94-97` (`effective_risk_level`): `if finding.risk_level: return normalise_risk_level(finding.risk_level)` — the AI value wins over the provisional one.
`app/api/routes/dashboard.py` high-risk list: `Finding.risk_level.in_(["CRITICAL", "HIGH"])`.

**Live proof** (real agents, real advisory, 3 runs): the real OSV record `GHSA-qccp-gfcp-xxvc`
(urllib3 2.0.7, **HIGH**, sensitive headers forwarded across origins) with the usage evidence a
transitive dependency always has (`references=[] files=[] components=[]`; `requests` depends on
`urllib3`, nothing imports `urllib3` directly):

```
provisional (severity-derived) risk: HIGH
run 1: impact=NONE    risk=MEDIUM (29.5s)
run 2: impact=UNKNOWN risk=HIGH   (22.4s)
run 3: impact=UNKNOWN risk=HIGH   (19.4s)
```
In run 1 the stored `finding.risk_level` becomes `MEDIUM`: the finding drops out of the dashboard's
high-risk list and `aggregate_overall_risk` (which uses `effective_risk_level`) can lower the
analysis' `overall_risk`. That is a real vulnerability in a library the application definitely
executes (every `requests` call goes through urllib3), suppressed on the strength of "no source file
references the package".

Every path that can produce the empty-usage state without proof of non-use (all
`app/services/analysis/usage.py`):

| # | Path | Where | Surfaced? |
|---|---|---|---|
| a | Transitive dependency (never imported directly by design) | scope `transitive` (npm) or `unknown` (Python, `requirements.txt` cannot tell) — the prompt does **not** branch on scope (`prompts.py:123` only renders it) | **No** — rendered exactly like "unused" (see 2d) |
| b | File larger than 1 MB skipped | `usage.py:50` `MAX_FILE_SIZE_BYTES = 1024 * 1024`, `:780` `if st.st_size > MAX_FILE_SIZE_BYTES:` — skipped, **`truncated` stays `False`**. Verified: a 1.53 MB module whose line 1 is `import requests` → `files=[] truncated=False` | **No** |
| c | More than `max_files=5000` eligible files | `usage.py:692-695`; sets `truncated=True` and the prompt says so (`prompts.py` usage section, `if usage.truncated`) | Yes |
| d | Import form the regex does not recognise (multi-statement line, `exec("import …")`, non-literal `import_module(name)`, `sys.modules[...]`, re-export through another module, notebook, `.pyi`) | `usage.py:429-433` (`_import_re`, `_from_re`, `_dynamic_re`) — see 2b matrix | **No** |
| e | Import name mapping miss (`enum34`→`enum34`, `from google.cloud import storage` for `google-cloud-storage`) | `usage.py::python_import_candidates` — see 2b | **No** |
| f | Unreadable file (`OSError`) | `usage.py` walk: logged/skipped | No |

Only (c) is communicated as uncertainty. (a), (b), (d), (e) feed the "FACT: not referenced" prompt
verbatim.

**Two mitigating facts, to be fair:** (i) `risk_level != UNKNOWN` is required before overwrite
(`pipeline.py:355`), so a model answering `UNKNOWN` keeps the provisional level — runs 2 and 3 above;
(ii) the finding row itself is never deleted, the OSV `VULNERABLE` status on the dependency row is
untouched, and the remediation candidate logic ignores AI risk entirely. The suppression is in
*prioritisation and display*, not in detection. It is still the one unacceptable error class the
brief names.

### 2b. Missed and invented edges

Measured by running `SourceUsageAnalyzer().find_usage()` (the shipped code) over purpose-built
fixtures (Python: 15 files; JS: 6 files) in this session. No construct **crashed**.

| Construct | Python | JavaScript |
|---|---|---|
| `getattr(...)` / `globals()[...]` / `sys.modules[...]` | **Silently missed** (`getattr_use.py`, `dynamic.py:6`) — no regex covers attribute/dict access | N/A |
| `importlib.import_module("lit")` / `__import__("lit")` | **Handled** when the argument is a string literal (`usage.py:433` `_dynamic_re`; `dynamic.py:2,3` found). **Silently missed** when the name is a variable (`dynamic.py:5`) | `require(name)` variable: **missed**; `await import('lodash')`: handled (`a.js:6`) |
| `eval` / `exec` | `exec("import requests as hidden")` **missed** (regex anchored at line start); `eval("__import__('requests')")` **matched** — by accident, the dynamic regex is not anchored (`dynamic.py:8`) | N/A |
| Decorators, callbacks, higher-order functions | **N/A — not implemented.** Evidence is file-level presence of an import; there is no call graph, so whether the imported name is ever *called* is never established. (`framework.py`: the import inside a route function body is found — `:5`.) | same |
| Inheritance, `super()`, duck typing | **N/A — not implemented** (no symbol resolution) | same |
| Framework entry points with no in-repo caller (FastAPI routes, Celery tasks, `console_scripts`, pytest fixtures) | **N/A / neutral**: nothing needs a caller because nothing is a call graph. A route module importing the package counts as usage. `console_scripts` in `setup.py`/`pyproject.toml` are not parsed for imports (only manifests, as "config" references) | same |
| `__init__.py` re-exports | **Silently missed at file level**: `reexport_b.py` (`from .reexport_a import Session`) is not attributed to the package; `reexport_a.py` is. Component attribution survives when both files share a component | same (`export { default as L } from 'lodash'` in the re-exporting file is found, `a.js:5`; consumers of that re-export are not) |
| `import x as y` | **Handled** (`aliased.py:1`) | Handled |
| `try: import x / except ImportError` | **Handled** — counted as usage (`optional.py:2`), arguably correct (the code path exists) | — |
| C extensions / stdlib boundary | Package→import-name mapping is heuristic (`python_import_candidates`): `enum34` → `['enum34']` (**missed**; had it mapped to `enum` it would collide with the stdlib module and produce a false positive), `google-cloud-storage` → `['google.cloud.storage']` so the idiomatic `from google.cloud import storage` is **missed** (verified: only `import google.cloud.storage as gcs` found) | npm names are import names; no mapping problem |
| Same symbol exported by two modules | **N/A** (no symbols) | N/A |
| Test-only / script-only code counted as application | **Invented application usage**: `tests/`, `scripts/`, `vendor/` files are scanned and their components become `affected_components`. Real demo data: analysis 6, finding 43 (`requests`) → `affected_components = ["src", "tests"]`, so the PR body claims the *tests* component is affected | `test/x.test.js` → component `test` counted |
| Multi-statement lines (`import os; import requests`, `if True: import yaml`) | **Silently missed** (`one_liner.py` not found for either package) — regexes are `^\s*import`/`^\s*from` | — |
| Imports inside docstrings / string literals | **Invented**: `comment_and_string.py:3` (`import requests` inside a triple-quoted string) counted; commented lines correctly skipped | **Invented**: `e.js:3` `const s = "require('lodash')"` counted; comment lines skipped |
| Prefix collisions (`lodash-es`, `lodash.get`) | — | **Handled** correctly (not matched) |
| Notebooks (`.ipynb`), stubs (`.pyi`) | **Not scanned** (extension list) — a notebook-only import is missed | `.vue`, `.ts` (`import _ = require(...)`, `import type`) handled; `import type` counted although erased at runtime (conservative) |
| Deeply nested / malformed / binary source | 1 MB single-line `from requests.requests.….x import y` scanned in **0.02 s** (no catastrophic backtracking); 20 000-deep parenthesis file, `\x00\xff` bytes, 3 MB file — no crash; the 3 MB file is *skipped silently* (2a-b) | 100 000-deep JSON in `package.json` → `RecursionError` caught, warning, file skipped |

Illustrative numbers from the Python fixture (file-level, `requests`, 12 files that really import it
incl. tests/scripts/vendor/notebook/stub, 3 that do not): **9 true positives, 1 false positive
(docstring), 3 false negatives** (`one_liner.py`, `notebook.ipynb`, `typed.pyi`) → precision 0.90,
recall 0.75. This is one hand-built fixture, not a benchmark; Step 3 designs the real one.

### 2c. Advisory → symbol

**There is no advisory→symbol step.** Vulnerability records are matched at
(ecosystem, package, version) by OSV itself (`osv_provider.py` `POST /querybatch`); nothing in
`vulnerabilities/`, `agents/` or `analysis/` extracts function or class names from an advisory
(`grep -rniE "symbol|vulnerable_function|call.?graph"` → no hits). What the LLM receives is the
advisory `summary` and `description` **truncated to 1500 characters** (`analysis/context.py:47`:
`description=(vuln.description or "")[:1500]`) — for `GHSA-j8r2-6x86-q33q` that cuts the record
before its "Patches"/"Workarounds" sections. Any "affected functions" the model mentions are its own
inference from that text and are labelled INFERENCE by the prompt rules.

Consequences of the three cases in the brief:

* *Advisory names no function* — no difference; nothing is consumed at that level.
* *Advisory names a since-renamed function* — no difference; never matched against code.
* *Installed version's API differs* — no difference; the sandbox validates the **upgrade**
  (install + tests), not the vulnerable API surface.

What *is* reliable in this step: package identity and version. Verified today that OSV normalises
PyPI names case- and separator-insensitively (`PyYAML`/`pyyaml` → 2 advisories;
`python-multipart`/`python_multipart`/`Python.Multipart` → 18 each), the name is sent verbatim
(`vulnerabilities/service.py:147`), invalid versions are never sent (`UNKNOWN`), alias groups are
merged per CVE set, fixed versions are derived from `fixed` events with GIT ranges excluded, and a
missing fixed version makes the remediation **fail** ("No fixed version is available") rather than
invent one. **Rating: package-level matching — reliable; symbol-level — absent, so the "weakest
link" here is the prompt that turns *absence of an import line* into an impact verdict (2a).**

### 2d. Depth boundary

Stated scope (`docs/ARCHITECTURE.md`, `V1_IMPLEMENTATION_STATUS.md`): direct imports of the
vulnerable package in the repository's own source; npm transitive dependencies come from the lock
file (`DEPENDS_ON` edges in Neo4j); Python has **no** transitive resolution at all
(`requirements.txt` scope is always `unknown`).

Provably lost at hop ≥ 2 (Python and npm alike): any vulnerable package used only through another
package. The urllib3 experiment in 2a is exactly this case. For npm the graph *knows* the edge
(`requests`-style `DEPENDS_ON` chains, `dependency_paths`), but that knowledge is only rendered as
context text; the impact prompt still asserts non-use.

**"Not reachable" and "beyond analysis depth" render identically.**
`frontend/src/pages/Finding.jsx:236`:
```jsx
… : <span className="muted">none (not referenced by application code)</span> },
```
and `:243` `empty="No source references found for this package."` — shown for a genuinely unused
direct dependency *and* for a transitive one. The report's Evidence section shows
`affected_components: []` with no depth caveat; `reports/service.py:405` prints `scope`, which for
Python is `unknown`. Nothing in the API (`UsageContext`, `FindingDetail`) carries an
"analysis depth exceeded" marker. The only place the difference is visible is the Neo4j
`depended_on_by` list for npm — which the UI does not use for this decision.

### 2e. Determinism

| Aspect | Finding | Evidence |
|---|---|---|
| Usage scan | Deterministic: results sorted (`usage.py:379,400,711,726,729`); no timeout, no randomness | 1 MB pathological input: 0.02 s |
| Which findings get AI under the cap | Deterministic: `sort_findings_by_priority` = severity desc, CVSS desc, identifier asc (`risk.py:131-132`) | — |
| LLM verdicts | **Non-deterministic**: `ollama_temperature = 0.1` (`config.py`, wired at `llm/factory.py:22`), **no `seed`** option is sent (`grep -n seed app/services/llm/*` → none). Same input → `impact NONE/UNKNOWN/UNKNOWN`, `risk MEDIUM/HIGH/HIGH` in three runs (2a). Also observed across sessions: lodash `GHSA-p6mc-m468-83gw` → `risk CRITICAL` (analysis 1) vs `HIGH` (analysis 6) | urllib3 experiment above |
| Cyclic imports | N/A for Python (no traversal). npm `DEPENDS_ON` cycles: Neo4j path queries are relationship-unique per path; covered by `test_dependency_paths_exclude_walks_through_dependency_cycles` | — |
| Timeouts that silently truncate | LLM timeout → finding `FAILED`/`UNAVAILABLE` (visible); OSV → `UNKNOWN` (visible); Neo4j `dependency_paths(limit=25)` (`knowledge_graph/service.py:782`) silently caps the path list (display only); usage scanner has **no** timeout but has the silent 1 MB/file cap (2a-b) | — |

### 2f. Security of the analyser

| Check | Result | Evidence |
|---|---|---|
| Never imports/executes/pip-installs the package under analysis on the host | **Holds.** Host-side subprocess usage is exclusively `git` in list form (`repository/github_provider.py:379` `subprocess.Popen(command, stdin=DEVNULL…)`, `github/github_provider.py::run_git`); no `pip`/`npm`/`eval`/`exec`/`import_module` of repository code anywhere outside the sandbox provider (`grep -rn` shown in session). Extraction is `json.loads` + `packaging.requirements` + regex. Installs and tests run **only** inside the container (`docker_provider.py:463-470` `exec_run`). |
| Parser robustness (malformed, adversarial, deeply nested) | **Holds** for the inputs tried: 200 000-char requirement name → parsed as a (truncated-at-persist) name; `a[b,b,…×5000]==1` → warning; `\x00\xff` line → warning; 100 000-deep JSON → `RecursionError` caught, warning; 1 MB single-line import → 0.02 s; binary `.py` → skipped. |
| Path traversal on repo input | **Holds.** No archive upload endpoint exists. Local paths: `local_provider.py` refuses `/`, `~`, system roots and the workspace itself; lock-file workspace keys are bounded by `is_within(...)`; the modifier refuses targets whose resolved path leaves the working copy (`modifiers.py:103-104`); stored relative paths with `..` are rejected (`core/paths.py`); artefact read-back is a fixed name via `head -c` (`docker_provider.py:508`). |
| Tokens/secrets in logs | **Holds** for tokens: 0 occurrences in server logs and `.git/config` during both the valid-token and invalid-token runs (V1 §3, unchanged code). |
| Secrets in the evidence payload / PR | **BREAKS (new, V2-04).** A credentialed index URL in the manifest is copied verbatim into the unified diff's context lines and into `before`/`after`: verified with `--extra-index-url https://deploy:s3cr3tT0k3n@pypi.internal.example/simple` → `diff contains the token: True`, `before/after contain the token: True/True`. That JSON is stored in `remediations.proposed_change`, rendered by `Remediation.jsx:208-210`, copied into the evidence report (`reports/service.py:734-740` `_proposed_change` includes `diff`) and into the **PR body** (`github/service.py:216,269`, "## Proposed change" fenced diff) — i.e. pushed to GitHub. |
| Container hardening (re-checked) | non-root `65534:65534`, read-only rootfs, tmpfs `/workspace`/`/tmp`, `cap_drop ALL`, `no-new-privileges`, pids/memory/CPU limits, no mounts, network `bridge` (documented trade-off; `none` available). Image tags, not digests (`python:3.12-slim`, `node:20-slim`). |

---

## New findings

| ID | Sev | Effort | Title |
|---|---|---|---|
| V2-01 | **Critical** | M | Absence of an import line is asserted as a FACT of non-use, and the model's downgraded risk overwrites the severity-derived risk (`prompts.py:301-309`, `pipeline.py:353-356`, `risk.py:94-97`). Proven to downgrade a HIGH transitive advisory to `impact NONE / risk MEDIUM`. |
| V2-02 | **High** | S | "Beyond analysis depth" and "not referenced" are indistinguishable in UI, report and API (`Finding.jsx:236,243`; no depth marker in `UsageContext`/`FindingDetail`; Python scope always `unknown`). |
| V2-03 | **High** | S | Files > 1 MB are skipped without setting `truncated` (`usage.py:50,780`); verified 1.53 MB module importing the package → `files=[] truncated=False`. |
| V2-04 | **High** | S | Index-URL credentials in `requirements.txt` (`--extra-index-url https://user:token@…`, also `-i`) propagate through diff context lines into `proposed_change`, the UI, the evidence report and the GitHub PR body (`modifiers.py` diff, `reports/service.py:740`, `github/service.py:216`). |
| V2-05 | **Medium** | M | Regex import scanner silently misses: multi-statement lines, `exec("import …")`, non-literal `import_module`, `sys.modules`/`getattr` access, re-export consumers, `.ipynb`/`.pyi` (`usage.py:429-433`, extension list). |
| V2-06 | **Medium** | M | Invented usage: imports inside docstrings/string literals counted (`comment_and_string.py:3`, `e.js:3`); tests/scripts/vendor directories counted as *application* components (analysis 6 finding 43 → `["src","tests"]`), inflating "affected components" in reports and PR bodies. |
| V2-07 | **Medium** | M | Import-name mapping gaps: unmapped packages (`enum34`), dotted namespace packages only match the fully-dotted form (`from google.cloud import storage` missed) — `usage.py::python_import_candidates`. |
| V2-08 | **Medium** | S | LLM verdicts are non-deterministic (temperature 0.1, no `seed`; `ollama_provider.py:51`, `factory.py:22`): identical input gave `risk MEDIUM` vs `HIGH`. Combined with V2-01 the suppression is random. |
| V2-09 | **Medium** | S | Advisory text is cut at 1500 chars before the model sees it (`context.py:47`); for real GHSA records this removes the Patches/Workarounds sections the model is asked to reason about. |
| V2-10 | **Low** | S | `/api/health` now performs a network call to `api.github.com` on every request (`health.py:49`, 5 s timeout) — health latency and GitHub rate limit coupled to UI/health polling. |
| V2-11 | **Low** | S | `react-router-dom` 6.26 (runtime) has a moderate open-redirect advisory; `vite` 5.4 / `esbuild` (dev) high/moderate (`npm audit`). The app only navigates to integer ids, so exploitability is low, but the dashboard of a supply-chain tool ships a known-vulnerable runtime dependency. |
| V2-12 | **Low** | M | 48 real mypy errors (excluding 19 model forward-refs); e.g. `core/versions.py:105,147` compare `Version \| SemVer` unions — correct only because ecosystems never mix, unenforced; `aliases.py:156` `max(key=…)` over `float \| None`. No `mypy`/`ruff` config or CI. |
| V2-13 | **Low** | S | Default credentials in code and Compose: `config.py:49` `neo4j_password = "sentinelchain"`, `DATABASE_URL` default `sentinel:sentinel` (`config.py`), matching `docker-compose.yml` — fine for the documented local single-user setup; must not be the shipped default if the Compose file is used elsewhere. |
| V2-14 | **Low** | S | `reports/service.py:777` Jinja2 `autoescape=False` and the f-string PR body (`github/service.py`) interpolate repository-/advisory-controlled text into Markdown without escaping; PyPI/npm name rules limit package names, but advisory summaries and file paths are free text (Markdown/link injection into the PR body). |

### V2-01 — detail
* **Impact:** the only unacceptable error class of the brief: a real, HIGH-severity vulnerability in code the application executes is de-prioritised out of the high-risk list and can lower `overall_risk`, on the basis of a heuristic with the documented gaps in 2b/2d.
* **Fix (M):** (1) never let the stored risk go *below* the provisional level — store the model's value in a new `ai_risk_level` and define `effective_risk_level = max(provisional, ai)` (or keep `risk_level` = provisional and add `ai_risk_level`); (2) when `usage.files` is empty, the prompt must say "no *direct* import found; transitive and dynamic use are not analysed" and forbid `NONE` (allow `LOW` only with a stated reason, default `UNKNOWN`); (3) for npm `scope == transitive` and Python `scope == unknown`, state that in the prompt (`prompts.py:292-309`); (4) the dashboard high-risk query must use `effective_risk_level` semantics.

### V2-02 — detail
* **Fix (S):** add `analysis_depth: Literal["direct-import-scan"]` and `reason_no_usage: "transitive" | "no-direct-import" | "scan-truncated" | "file-too-large"` to `UsageEvidence`/`UsageContext`; render distinct text in `Finding.jsx:236,243` and in the report's Evidence section; never print "not referenced by application code" unless the scan was complete and the dependency is direct.

### V2-03 — detail
* **Fix (S):** in `usage.py:780` record skipped files (`skipped_large_files: list[str]`) and set `truncated = True`; add the list to `UsageContext` so the prompt's existing `if usage.truncated` branch fires.

### V2-04 — detail
* **Fix (S):** redact `scheme://user:pass@host` userinfo in `FileChange.before/after/diff` (`modifiers.py`, one regex: `(?<=://)[^/@\s:]+:[^/@\s]+@` → `***:***@`), and drop `-i/--index-url/--extra-index-url/--find-links` lines from the diff **context** included in `build_pr_body`. Also scan `before/after` for `_authToken=` (`.npmrc` is not a manifest today, but `package.json` `publishConfig.registry` with userinfo is possible).

### V2-05 / V2-06 / V2-07 — detail
* **Fix (M):** parse `.py` with `ast.parse` (tolerant: on `SyntaxError` fall back to the regex) and collect `Import`/`ImportFrom` nodes — this removes the docstring false positives, handles multi-statement lines, and can flag `importlib.import_module(<Name>)`/`exec(<str>)` call sites as *dynamic — unresolved* evidence (surfaced, not silently missed). Tag each reference with its component type (`tests`, `scripts`, `source`) and keep test-only usage out of `affected_components` (report it separately). For import names, extend the curated map and, for dotted candidates `a.b.c`, also match `from a.b import c` and `from a import b`.

### V2-08 — detail
* **Fix (S):** send `options.seed` (fixed) and `temperature: 0` from `OllamaProvider._build_payload`; record model name+digest in `ai_results` (the digest is available from `/api/tags`).

---

## Step 3 — Evaluation

### What accuracy evidence exists today
* **No labelled benchmark, no precision/recall numbers** anywhere (`grep -rn "precision|recall|benchmark|ground truth" docs/ README.md V1_IMPLEMENTATION_STATUS.md` → none).
* 37 unit tests in `tests/test_usage_analyzer.py` (synthetic repos, asserting specific lines) — behavioural tests, not a corpus.
* The demo project (`examples/demo-project`): 3 vulnerable dependencies, hand-verifiable — `requests` (2 import sites), `lodash` (1), `Jinja2` (0 direct imports; used through Flask — a hop-2 case that the system reports as "not referenced").
* This session's fixtures (2b): 15 Python + 6 JS files — illustrative only.

### Benchmark design (proposed, not built)

**Corpus.** `benchmarks/usage/` with one fixture repository per case, each containing
`requirements.txt` and/or `package.json` (+ lock), source files, and `expected.json`:
```json
{"package": "requests", "ecosystem": "PyPI",
 "expected_files": ["src/app.py"], "expected_components": ["src"],
 "reachable": true, "reason": "direct import", "must_not_report": ["docs/notes.py"]}
```
Cases (one directory each; ≥ 2 variants where noted):
1. Easy: direct `import x`; `from x import y`; `import x as y`; submodule import; nested-function import.
2. Multi-statement lines; imports after `;`/`:`.
3. Docstring / string / comment containing an import (must **not** count).
4. `importlib.import_module("lit")`, `__import__("lit")`, `import_module(var)`, `exec("import …")`, `sys.modules[...]`, `getattr(module, name)` — expected: literal forms counted; non-literal forms reported as *dynamic/unresolved*, never as "not referenced".
5. Re-export chain: `pkg/__init__.py` re-exports, consumer imports from the package — expected file set includes the re-exporting module; component attribution must survive.
6. Transitive-only: package present only via another dependency (Python and npm) — expected `reachable: null` with `reason: "beyond-depth"`; the system must **not** output "not referenced".
7. Test-only, script-only, vendored, `docs/` usage — expected: reported as evidence but **excluded** from `affected_components`.
8. Import-name mapping: `PyYAML`, `Pillow`, `beautifulsoup4`, `python-dateutil`, `enum34`, `google-cloud-storage` (both import forms), `Flask-Login`.
9. Stdlib collision (a requirement whose import name equals a stdlib module) — expected: no false positive.
10. Framework entry points with no caller (FastAPI route module, Celery task module, `console_scripts` target module, pytest fixture in `conftest.py`) — expected: counted as usage of their imports (they *are* executed), attributed to their component.
11. Large files: 1.2 MB source with the import on line 1 — expected: found, or at minimum `truncated=True` with the file listed.
12. Notebooks (`.ipynb`) and stubs (`.pyi`).
13. JS: `require`, ESM default/named, `export … from`, dynamic `import()`, template-literal `require`, TS `import =`, `import type`, `.vue`, scoped packages, prefix collisions (`lodash-es`, `lodash.get`), `jest.mock`, `require(var)`.
14. Monorepo/workspaces: non-workspace nested `package.json` (verified in V1 to be lock-less), workspace member.
15. Adversarial: 100 000-deep JSON, 1 MB single line, binary `.py`, `\x00` bytes, 20 000 nested parentheses — expected: no crash, warnings present.

**Metrics** (computed per fixture, aggregated micro-averaged):
* *File-level usage* — TP/FP/FN over `(package, file)` pairs → **precision**, **recall**.
* *Component-level* — same over `(package, component)`.
* **Wrongly-suppressed rate (reported separately):** among fixtures whose ground truth is
  `reachable: true` or `beyond-depth`, the fraction for which the pipeline output would have been
  rendered as "not referenced" *or* whose stored `risk_level` ends below the severity-derived level.
  Target: **0**. This is the metric that matters for the brief's error class; precision/recall must
  never be traded against it.
* *Dynamic-unresolved rate*: fraction of case-4 sites surfaced as unresolved (target 1.0).

**Harness.** `backend/tests/benchmark/test_usage_benchmark.py`, parametrised over
`benchmarks/usage/*/expected.json`, runs `SourceUsageAnalyzer.find_usage()` (pure, deterministic,
no services) and writes `benchmarks/usage/results.json` + a Markdown table; a second, opt-in job
(`SENTINEL_BENCHMARK_LLM=1`) runs `AIOrchestrator.analyze_finding()` with `temperature=0`,
fixed `seed`, **N = 5 repetitions** per fixture against the real Ollama model, recording the
distribution of `impact_level`/`risk_level` and computing the wrongly-suppressed rate against the
provisional level. Reproduce with:
```bash
cd backend && .venv/bin/pytest -q tests/benchmark --benchmark-report   # scanner metrics, < 5 s
SENTINEL_BENCHMARK_LLM=1 OLLAMA_MODEL=llama3.2:3b .venv/bin/pytest -q tests/benchmark -m llm   # ~10 min
```
The numbers in this document (P 0.90 / R 0.75 on one Python fixture; 1 of 3 LLM runs suppressing a
HIGH) are what this harness would have produced for two of its cases and should be treated as the
first, unofficial data points.

---

## (a) Fix before the October code freeze — ordered

1. **V2-01 risk floor + prompt wording (M).** It is the only path that turns a detected HIGH
   vulnerability into a de-prioritised one, it is triggered by the most common real-world situation
   (transitive dependencies), and the fix is mechanical: `effective = max(provisional, ai)` plus two
   prompt sentences. Everything else in this list is about *how well* usage is found; this is about
   never letting a bad usage answer hide a finding.
2. **V2-04 credential redaction in diffs/PR bodies (S).** Small, self-contained, and the only new
   finding that can leak a secret *outside* the machine (to GitHub). Do it before anyone points the
   tool at a repository with a private index.
3. **V2-03 + V2-02 depth/size honesty (S+S).** Set `truncated` for large files and render
   "transitive / not analysed" distinctly from "not referenced". Cheap, and it makes V2-01's prompt
   sentence truthful in the UI and the report.
4. **V2-08 seed/temperature 0 (S).** Removes the randomness that makes V2-01 intermittent and makes
   the demo reproducible.
5. **V2-05/06 AST-based Python scan (M).** Fixes the docstring false positives, one-liner misses and
   surfaces dynamic imports as *unresolved*. Land it with the benchmark harness (Step 3) so the
   change is measured; keep the regex path for `SyntaxError` files.
6. **V2-09 advisory truncation (S)** — raise the cap or select sections; low risk.
7. **V2-11 `react-router-dom` upgrade (S)** and **V2-10 health cache (S)** — housekeeping with a
   test each.

Defer past the freeze: V2-07 (mapping coverage is open-ended; add a curated list as cases appear),
V2-12 (typing debt; add `mypy` to CI first), V2-13/14 (document, see (b)).

## (b) Genuine scope limitations — document, don't fix

* **No symbol-level reachability / call graph** (2b, 2c). V1 evidence is "this file imports the
  package". Whether the vulnerable function is *called* is not established and should be stated
  on every finding as an inference boundary.
* **Hop-2+ dependencies are not analysed** (2d). Python has no transitive resolution at all; npm
  has lock-file edges but no usage attribution through them. Document as "transitive usage is
  assumed, never disproved" once V2-01/02 land.
* **The LLM assesses; it does not detect.** Detection is OSV; the agents only prioritise. Say so
  in the report's "AI reasoning" header and in the README's positioning sentence.
* **Sandbox network access** is required for installs; `DOCKER_SANDBOX_NETWORK=none` exists for
  vendored projects (F-08 trade-off).
* **Default local credentials** (`sentinel:sentinel`, `neo4j/sentinelchain`) and no authentication
  by default (`API_KEY` optional) — the documented local single-user scope; not for shared hosts.
* **Manifest coverage**: `pyproject.toml`, `Pipfile`, `poetry.lock`, `yarn.lock`, `pnpm-lock.yaml`
  are detected but not parsed (V1 status doc already says so).

---

## What could not be inspected, and why

* **Real-world corpus behaviour** of the usage scanner beyond the demo project, `pallets/flask`,
  `pallets/click` and this session's fixtures — no benchmark exists yet (Step 3).
* **LLM behaviour across models**: only `llama3.2:3b` was exercised; a larger model may answer
  `UNKNOWN` more consistently in the empty-usage case, which would not change the structural
  problem in V2-01.
* **Neo4j-write-then-Postgres-fail ordering, a mid-run hung Docker daemon, concurrent analyses of
  different repositories, non-macOS hosts, frontend failure states** — carried over unverified from
  V1 (see Step 1 table); each needs a fault-injection harness or a second host.
* **GitHub-side behaviour of the PR body with injected Markdown (V2-14)** — not exercised against a
  live PR to avoid posting test content to the user's public repository.
* **The frontend has no automated tests**, so every UI statement above rests on reading the JSX and
  the earlier manual sessions.
