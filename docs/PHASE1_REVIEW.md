# Phase-1 review — demo runbook

Everything here runs the **real** system: real OSV.dev data, real Neo4j, real source scans. Phase 1
simply leaves the Phase-2 features switched off (`SENTINEL_PHASE=1`); nothing is mocked and nothing is
deleted. Your full-product data (the `sentinelchain` database) is never touched — the demo uses its own
database (`sentinelchain_phase1`) and workspace (`workspace/phase1`).

## What Phase 1 shows — and what is held back

Phase 1 is the first half of the specification's demonstration flow (§20): everything up to *"source
usage found"*. Phase 2 is the agentic half that acts on those findings.

| Phase 1 — shown | Phase 2 — hidden until the final review |
|---|---|
| GitHub URL and local-path ingestion (clone / copy, never modifies the original) | Ollama AI agents: dependency analysis → impact assessment → risk evaluation |
| Repository profiling: language, components, dependency files, test hints | AI-assisted remediation (deterministic candidates + remediation agent) |
| Dependency extraction: `requirements.txt`, `package.json` + `package-lock.json` | Safe dependency change in a temporary workspace |
| PostgreSQL persistence (per-analysis snapshots) | Docker sandbox validation (build, tests, security re-check) |
| OSV.dev detection: SAFE / VULNERABLE / UNKNOWN, CVSS, aliases, fixed versions | Evidence report (JSON + Markdown) |
| Application-aware source-usage evidence (file, line, snippet, component) | Draft GitHub pull request |
| Neo4j software knowledge graph | |
| Dashboard, live pipeline tracker, system health | |

In a Phase-1 build those features are absent from every page, their API routes answer 404, `/docs`
lists only Phase-1 endpoints, and the backend never contacts Ollama, Docker or GitHub.

## Before the review (once, with internet)

```bash
cd ~/SentinelChain
git pull                                # get this build (after the PR is merged)
scripts/phase1-demo.sh reset --yes      # empty demo database (drops only sentinelchain_phase1)
scripts/phase1-demo.sh start            # everything up + pre-flight checks; opens the dashboard
scripts/phase1-demo.sh prepare          # registers examples/demo-project and runs one analysis
```

`start` must end with **All checks passed**. `prepare` gives you a finished analysis to fall back on if
the venue has no internet. Then rehearse the click path below once. **After rehearsing, delete the GitHub
repository you added** (its page → *Delete repository* → OK; this also removes its working copy and graph
nodes) so that step 2 registers it fresh during the review — keep repository #101. Also:

* macOS **Focus → Do Not Disturb** on, so no notification banners appear on the projector.
* Charge the laptop and bring the charger.
* Optional, frees ~0.5 GB: `brew services stop ollama` (Phase 1 does not use it).
* If you plan to use `start --lan`, run it once tonight and click **Allow** if macOS asks whether `node`
  may accept incoming connections — otherwise that dialog pops up during the review.

## 15 minutes before the review

1. Plug in power. Join the Wi-Fi — or your **phone hotspot** if the venue Wi-Fi is unreliable.
2. `scripts/phase1-demo.sh start` (safe to run again; it reuses what is already running).
3. Read the checks. Each problem line says what to do; the common ones are in the table at the end.
4. Keep the lid open. The script keeps the Mac awake while the backend runs, but closing the lid
   still sleeps it.

## The demo (about 8–10 minutes)

Open **http://localhost:4173**. The header reads *Agentic AI for Secure Software Supply Chains · Phase 1*.

1. **Dashboard.** Counters (repositories, analyses, dependencies, vulnerable dependencies, findings),
   findings by risk level, recent analyses, high-risk findings. *"Everything on this page comes from
   PostgreSQL; nothing is hard-coded."*
2. **Add repository** → paste `https://github.com/lokeshlella/sentinel-chain-demo` → **Add repository**.
   The repository page shows *Ingesting…* while it clones, then the **profile**: language, components
   (`src`, `test`, `tests`), dependency files, test hints. *"We clone into our own workspace — the
   original is never modified."*
   If it says *already registered*, it is left over from a rehearsal: open it from the dashboard's
   repository list and continue.
   **No internet? Do not press Analyze** — without OSV.dev every dependency is UNKNOWN and the new analysis
   has no findings. Open **Dashboard → Recent analyses → #1** (the ready-made run, real OSV data) and continue
   from step 4 with it.
3. **Analyze.** The analysis page polls every 3 s through five stages — Repository, Dependencies,
   Vulnerabilities, Source usage, Knowledge graph — and completes in about 10 s.
4. **Summary.** Tonight's run found 18 dependencies (17 PyPI, 1 npm), 6 vulnerable, 15 findings, overall
   risk CRITICAL, 37 graph nodes / 39 relationships. (Live OSV data: the numbers change when new
   advisories are published — that is the point.)
5. **Open the `requests@2.30.0` / `GHSA-j8r2-6x86-q33q` finding.**
   * *Vulnerability*: alias CVE-2023-32681, CVSS 6.1 with vector, fixed in 2.31.0, affected ranges — all
     from OSV.dev.
   * *Evidence — Observed facts*: `src/weather_notes/services/weather.py` line 12 `import requests`, and
     `tests/test_weather.py` line 5 → affected components `src`, `tests`. *"This is application-aware:
     not just 'you have a vulnerable package' but where your code uses it."*
   * Compare with `Jinja2` — vulnerable, but no direct import: the page says so honestly instead of
     claiming it is unused.
6. **Repository page → Dependencies**: filter by `VULNERABLE`; each row says which advisories.
   Scroll to **Knowledge graph → Show graph**: Repository, Component, Dependency and Vulnerability nodes
   with `CONTAINS`, `USES`, `AFFECTED_BY` edges.
7. **Neo4j Browser** (optional, very visual): http://localhost:7474, user `neo4j`, password
   `sentinelchain`. Use the repository number from the address bar (`/repositories/102` → 102):

   ```cypher
   MATCH p = (:Repository {repository_id: 102})-[:USES]->(:Dependency)-[:AFFECTED_BY]->(:Vulnerability) RETURN p
   ```

   or everything for that repository: `MATCH p = (:Repository {repository_id: 102})-[*1..3]->() RETURN p`.
8. **System health**: PostgreSQL, Neo4j and OSV.dev all OK.
9. **Robustness** (if time allows): add `not a url` → a clear validation message; add the local path
   `…/examples/demo-project` → *already registered* (the local path answers instantly; the same check for a
   GitHub URL needs the network). *"Failures are reported, never hidden: if OSV is unreachable, dependencies
   become UNKNOWN — never SAFE."*

Avoid opening on screen: the GitHub page of `sentinel-chain-demo` (its *Pull requests* tab shows the
draft PR Sentinel Chain opened in Phase 2 testing) and the demo project's README (it describes the full
pipeline). If you would rather hide that PR for the day, close it and reopen it afterwards — nothing is lost:
`gh pr close 1 --repo lokeshlella/sentinel-chain-demo` … `gh pr reopen 1 --repo lokeshlella/sentinel-chain-demo`.

## Questions you may get

* **Is this real data?** Yes — OSV.dev is queried live for every pinned dependency; identifiers, CVSS
  and fixed versions link to the advisories. The source evidence is a deterministic scan of the cloned code.
* **How is risk decided in Phase 1?** It follows the advisory's severity from OSV (CRITICAL/HIGH/…).
  Phase 2 adds application-aware AI risk assessment on top, which can raise but never lower it below the
  severity-derived level.
* **Why a knowledge graph?** Supply-chain questions are graph questions: which components use a
  dependency, which vulnerabilities reach which component. Neo4j stores exactly those relationships.
* **Why PostgreSQL *and* Neo4j?** PostgreSQL is the system of record (repositories, snapshots, findings);
  Neo4j is the relationship view built from it.
* **What if OSV is down?** The stage reports UNAVAILABLE and dependencies are UNKNOWN — the system never
  reports a package as safe without having checked it.
* **Can we see the API?** http://127.0.0.1:8001/docs lists the Phase-1 endpoints (the page loads its
  viewer from the internet). A few response fields (`ai_status`, `remediations`) are already part of the data
  model and stay empty until Phase 2 fills them.
* **What comes in Phase 2?** The agentic layer: three LLM agents (local Ollama, Pydantic-validated
  output that separates FACT from INFERENCE), remediation with deterministic version candidates,
  validation in an isolated Docker sandbox, an evidence report, and a draft GitHub pull request — never
  auto-merged.

## If something goes wrong

| What you see | What to do |
|---|---|
| `OSV.dev … NO INTERNET` in the checks | Switch to the phone hotspot and run `scripts/phase1-demo.sh check`. Still offline: **do not press Analyze**; present Dashboard → Recent analyses → #1, the ready-made run with real OSV data. |
| A live analysis shows Vulnerabilities `UNAVAILABLE` (Wi-Fi dropped mid-demo) | Say so — *"OSV could not be reached, so nothing is reported safe: overall risk UNKNOWN"* — then open analysis #1 from the dashboard. |
| `Neo4j is still starting` | Wait 30–60 s, then `scripts/phase1-demo.sh check`. |
| `port 4173 (or 8001) is in use by another process` | Quit that program, or start on other ports: `DEMO_WEB_PORT=4174 DEMO_API_PORT=8002 scripts/phase1-demo.sh start`. |
| `Docker did not start` | Open Docker Desktop from Applications, wait for the whale icon to settle, run `start` again. |
| A page looks stuck | Refresh the browser — all state is in the database, nothing is lost. |
| An analysis shows FAILED after the Mac slept | Click **Analyze** again (about 10 s). |
| Anything else | `scripts/phase1-demo.sh stop` then `scripts/phase1-demo.sh start`. Logs: `workspace/phase1/run/`. |

## After the review

`scripts/phase1-demo.sh stop`. The complete product is unchanged: run it exactly as before
(`docs/DEMO.md`; `SENTINEL_PHASE` unset means everything). The Phase-1 demo data can stay, or remove it
with `scripts/phase1-demo.sh reset --yes` (drops only `sentinelchain_phase1` and `workspace/phase1`).

To show one Phase-2 feature in a Phase-1 build, add it by name:
`SENTINEL_FEATURES=ai scripts/phase1-demo.sh start` (names: `ai`, `remediation`, `validation`, `reports`,
`pull_requests`; prerequisites are switched on with them). Analyses made that way keep their AI results in
the demo database; before presenting plain Phase 1 again, run `reset --yes`, `start` and `prepare`, and
reload any open dashboard tab.

## Why it runs on this laptop — and opening it elsewhere

Sentinel Chain is a web application with a server side: the FastAPI backend, PostgreSQL and Neo4j run on
this Mac, and the dashboard in the browser talks to them. `localhost` means "this computer", so another
laptop typing `localhost:4173` reaches *its own* machine, where nothing is running. To use it from elsewhere:

* **Another laptop on the same network** — `scripts/phase1-demo.sh start --lan` prints an address like
  `http://192.168.1.20:4173` that other laptops can open. College Wi-Fi often blocks device-to-device
  traffic; a phone hotspot works. Anyone on that network can then use the app, so only do this on a network
  you control.
* **Running it on another laptop** — that laptop needs Docker Desktop, Python 3.11+ and Node; then clone the
  repository, create the backend virtualenv, `npm install` in `frontend/`, and run the same script.
* **Open it from anywhere with a URL** — host it on a server (a cloud VM with ~4 GB RAM for PostgreSQL and
  Neo4j; more for Ollama in Phase 2). That is deployment work for later, not something to do the night
  before a review.
