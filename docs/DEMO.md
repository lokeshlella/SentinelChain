# Sentinel Chain — End-to-end demo (V1)

This walkthrough reproduces the primary V1 success criterion (specification §20) with the
bundled demo repository. Everything shown here was executed for real on 2026-09-14; the
timings are from an 8 GB Apple M2 with `llama3.2:3b`.

## 0. Prerequisites

```bash
docker compose up -d postgres neo4j        # backing services
ollama serve & ollama pull llama3.2:3b     # local LLM (any model; set OLLAMA_MODEL)
cd backend && source .venv/bin/activate && alembic upgrade head
uvicorn app.main:app --port 8000           # backend
cd ../frontend && npm run dev              # dashboard on http://localhost:5173
```

Check http://localhost:8000/api/health — PostgreSQL, Neo4j, Ollama and Docker must be `ok`.
GitHub may be `unavailable` (no token): the demo still works, the PR step then produces the
description plus manual instructions.

## 1. Register the repository (STEP 1–2)

Dashboard → **Add repository** → paste the absolute path of `examples/demo-project`
(or the URL of your own GitHub copy of it, see §8). Registration copies/clones the repository
into `workspace/repos/<id>` — the original is never modified — and profiles it:
language *Python*, components `src`, `tests`, `test`, dependency files `requirements.txt`,
`package.json`, `package-lock.json`, test hints (`pytest`, `node --test`).

```bash
curl -s -X POST localhost:8000/api/repositories -H 'Content-Type: application/json' \
  -d '{"source_url": "'"$PWD"'/examples/demo-project"}'
```

## 2. Analyse (STEP 3–8)

Repository page → **Analyze** (keep *run AI* checked). The Analysis page polls the stages:

| Stage | What happened in the demo run |
|---|---|
| Repository | working copy ready, 3 components |
| Dependencies | **18** dependencies (17 PyPI from `requirements.txt`, 1 npm from `package.json` resolved through `package-lock.json`), all pinned |
| Vulnerability | OSV batch query → **3 vulnerable** (`requests 2.30.0`, `Jinja2 3.1.5`, `lodash 4.17.15`), 15 safe, **9 findings**, 9 vulnerability records |
| Usage | source scan → `requests` imported by `src/weather_notes/services/weather.py:12` and `tests/test_weather.py:5`; `lodash` required by `src/widget/format.js:6`; `Jinja2` not imported directly (used via Flask) |
| KnowledgeGraph | Neo4j: 31 nodes / 33 relationships (`CONTAINS`, `USES`, `AFFECTED_BY`) |
| AI | 5 highest-priority findings analysed by the dependency → impact → risk agents (4 skipped by the per-run limit, runnable on demand); overall risk **CRITICAL** (lodash prototype pollution, HIGH severity, used in `src`) |

Total: **2 min 17 s** including the LLM calls.

Open a finding (e.g. `requests` / `GHSA-j8r2-6x86-q33q`). The page separates
**Observed facts** (files, lines, snippets, components from the scanner) from
**AI reasoning (inference)** — every FACT the model cites points at a real file/line, and any
component it invents is dropped by the guardrail (`dropped_components`).

## 3. Remediation (STEP 9–10)

Finding page → **Generate remediation**. Deterministic code first computes the candidates:

* OSV fixed versions of *every* advisory of the dependency in this analysis
  (`2.31.0`, `2.32.0`, `2.32.4`, `2.33.0` → minimum covering all: **2.33.0**),
* snapped to a version PyPI really publishes (yanked / npm-deprecated releases are skipped),
* re-verified against OSV (`2.33.0` SAFE, `2.34.2` SAFE).

Only then does the LLM choose among the allowed versions and explain the choice (12 s with
the 3B model; if Ollama is down the deterministic candidate is used and clearly labelled).
The change is applied to a fresh working copy `workspace/remediations/<id>` and shown as a
unified diff (`-requests==2.30.0` / `+requests==2.33.0`).

For the JavaScript finding (`lodash`) the same flow rewrites `package.json`; the deprecated
`4.18.0` "bad release" is skipped in favour of `4.18.1`.

## 4. Docker sandbox validation (STEP 11)

Remediation page → **Validate in Docker sandbox**. A `python:3.12-slim` (or `node:20-slim`)
container with no host mounts, all capabilities dropped, memory/CPU/pid limits and a timeout
receives a tar of the working copy, runs `pip install -r requirements.txt` then `pytest`
(or `npm install` + `npm test`, copying the regenerated `package-lock.json` back), and the
target package is re-checked against OSV:

```
build PASS (3.0 s)   tests PASS — 17 passed   security PASS (requests 2.33.0: no known vulnerabilities)
overall PASS in 4.8 s; container removed
```

## 5. Evidence report (STEP 12)

`GET /api/remediations/<id>/report?format=markdown` (link on the Finding page) renders the
10-section report — see `docs/EXAMPLE_EVIDENCE_REPORT.md` for the real output of this run.
Final recommendation: **Apply** (validation passed with tests executed).

## 6. Draft pull request (STEP 13)

Remediation page → **Create draft pull request**.

* With `GITHUB_TOKEN` set and a GitHub-hosted repository: branch
  `sentinel-chain/pypi-requests-2.33.0` is created in the validated working copy, the change
  committed as *Sentinel Chain*, pushed with a one-off token URL (never stored), and a
  **draft** PR opened with the description in `docs/EXAMPLE_PR_DESCRIPTION.md`.
* Without a token (this run): the PR record is stored with status `UNAVAILABLE`, the full
  title/body, and the exact `git` / `gh pr create --draft` commands to do it by hand.

Nothing is ever merged automatically.

## 7. Failure modes you can show

| Try | Result |
|---|---|
| Invalid URL `not a url` | 400 `ValidationFailedError` listing the accepted forms |
| `https://github.com/octocat/this-repo-does-not-exist-123456` | 400 `RepositoryError: Repository not found or not accessible…` — nothing left behind |
| `https://github.com/octocat/Hello-World` (no dependency files) | clone succeeds; analysis `FAILED` with *No supported dependency files found…* |
| `https://github.com/pallets/flask` | real project: 21 dependencies from `examples/celery/requirements.txt`, 4 vulnerable (pyproject.toml is not parsed in V1) |
| Stop Ollama | analysis completes; AI stage `UNAVAILABLE`, findings keep their provisional severity-based risk; remediation uses the deterministic candidate |
| `OSV_API_URL=http://127.0.0.1:9` | dependencies `UNKNOWN` with *Vulnerability check unavailable* — never SAFE |
| Stop Neo4j | analysis completes; knowledge-graph stage `UNAVAILABLE` |
| Stop Docker | validation `FAILED` with build/tests `UNKNOWN` and a clear Docker error |

## 8. Demonstrating the real GitHub PR

1. Create an empty repository under your GitHub account and push `examples/demo-project` to it.
2. Put a token with `contents:write` + `pull_requests:write` (fine-grained) or `repo`
   (classic) into `.env` as `GITHUB_TOKEN`, restart the backend.
3. Register the repository by URL, analyse, remediate, validate, then create the PR — the
   Pull Request page shows the GitHub URL of the draft PR.
