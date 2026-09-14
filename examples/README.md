# Examples

## `demo-project/` — the end-to-end demo repository

`demo-project/` is a small, benign application (`weather-notes`, Flask + a lodash widget) that
pins a few **old, publicly documented vulnerable dependency versions** — `requests==2.30.0`,
`Jinja2==3.1.5` and `lodash@4.17.15`. It exists so that every stage of Sentinel Chain has real
work to do: OSV.dev reports genuine advisories for these versions, the source-usage analysis
finds where they are imported, the remediation step has real fixed versions to propose, and the
Docker sandbox can install the bumped dependencies and run the project's own tests.
See [`demo-project/README.md`](demo-project/README.md) for the advisory ids and how to
re-verify them; it contains no malicious code.

## Using it with Sentinel Chain

Start the stack as described in the top-level [README](../README.md) (PostgreSQL, Neo4j,
backend on `:8000`, frontend, Ollama on the host), then register the demo either as a
**local repository** or as a **GitHub repository**.

### Option A — local path (no GitHub needed)

Sentinel Chain copies the directory into its own workspace and never modifies the original.

```sh
curl -s -X POST http://localhost:8000/api/repositories \
  -H 'Content-Type: application/json' \
  -d "{\"source_url\": \"$(pwd)/examples/demo-project\", \"source_type\": \"local\"}"
```

(or paste the absolute path into the "Add repository" form of the web UI). Use the returned
`repository_id` to start an analysis:

```sh
curl -s -X POST http://localhost:8000/api/repositories/<repository_id>/analyze \
  -H 'Content-Type: application/json' -d '{}'
```

Then follow the workflow in the UI or via the API: `GET /api/analyses/{id}` →
`GET /api/analyses/{id}/findings` → `POST /api/findings/{id}/remediate` →
`POST /api/remediations/{id}/validate` (Docker) → `GET /api/findings/{id}/report`.
With a local repository that has no GitHub remote the pull-request step reports
`UNAVAILABLE` and prints the branch/commit instructions instead.

### Option B — your own GitHub repository (demonstrates the draft-PR step)

1. Push a copy of `demo-project/` to a repository you own:

   ```sh
   cp -r examples/demo-project /tmp/weather-notes && cd /tmp/weather-notes
   git init -b main && git add . && git commit -m "weather-notes demo project"
   git remote add origin https://github.com/<you>/weather-notes.git && git push -u origin main
   ```

2. Set `GITHUB_TOKEN` in `.env` (a fine-grained token with *Contents* and *Pull requests*
   write access to that repository) and restart the backend.

3. Register it by URL:

   ```sh
   curl -s -X POST http://localhost:8000/api/repositories \
     -H 'Content-Type: application/json' \
     -d '{"source_url": "https://github.com/<you>/weather-notes"}'
   ```

After a validated remediation, `POST /api/remediations/{id}/pull-request` pushes a
`sentinel-chain/...` branch and opens a **draft** pull request whose body is the evidence
report. Nothing is ever merged automatically.

## What to expect

* Dependencies: 17 PyPI packages from `requirements.txt` and `lodash` from
  `package.json` / `package-lock.json`.
* Vulnerable: `requests` (four advisories), `Jinja2` (one), `lodash` (six) — verified against
  OSV.dev on 2026-09-13; the numbers may grow as new advisories are published.
* Usage evidence: `src/weather_notes/services/weather.py` imports `requests`,
  `src/widget/format.js` requires `lodash`; Jinja2 is used through Flask's `render_template`.
* Validation: the Python sandbox runs `pip install -r requirements.txt` and `python -m pytest -q`
  (17 tests); the Node sandbox runs `npm install` and `npm test` (4 tests). Both pass before
  and after the bump to `requests==2.33.0`, `Jinja2==3.1.6` and `lodash@4.18.1`.
