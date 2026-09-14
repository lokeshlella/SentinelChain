# weather-notes — Sentinel Chain demo project

`weather-notes` is a deliberately small application used to demonstrate the Sentinel Chain
workflow end to end (repository → dependencies → OSV vulnerabilities → knowledge graph →
local-LLM analysis → remediation → Docker validation → evidence report → draft PR).

It has two independent parts living in one repository:

| Part | What it is | Dependency file | Tests |
|---|---|---|---|
| Python (primary) | A tiny Flask web service: an in-memory notes API (`/api/notes`), a Jinja2-rendered landing page (`/`), a `/weather` endpoint that fetches a JSON document with the `requests` library, and `/health`. | `requirements.txt` | `pytest` + Flask test client, `requests` mocked with `unittest.mock.patch` |
| JavaScript (secondary) | `weather-notes-widget`: three formatting helpers built on `lodash`. | `package.json` + `package-lock.json` | `node --test` (`node:test` + `node:assert`) |

**The project contains no malicious code.** It is vulnerable only because it pins
*old, publicly documented* versions of well-known open-source libraries; the application
code itself is ordinary and readable in a few minutes. The tests never access the network
(`requests.get` is patched, the configured weather URL points at a reserved `.invalid` host).

## Deliberately vulnerable dependencies

The versions below were verified against the real OSV.dev API on 2026-09-13. The advisory
identifiers are exactly what the API returned — nothing here is invented. Re-run the commands in
["How to re-verify"](#how-to-re-verify) to see the current answer (OSV data changes over time).

### Python: `requests==2.30.0` (target of the demo)

| OSV id | Aliases | Summary (from OSV) | Severity (GHSA) | Fixed in |
|---|---|---|---|---|
| GHSA-j8r2-6x86-q33q | CVE-2023-32681, PYSEC-2023-74 | Unintended leak of Proxy-Authorization header in requests | MODERATE | 2.31.0 |
| GHSA-9wx4-h78v-vm56 | CVE-2024-35195, PYSEC-2026-1873 | Requests `Session` object does not verify requests after making first request with verify=False | MODERATE | 2.32.0 |
| GHSA-9hjg-9r4m-mvj7 | CVE-2024-47081, PYSEC-2026-1872 | Requests vulnerable to .netrc credentials leak via malicious URLs | MODERATE | 2.32.4 |
| GHSA-gc5v-m9x4-r6x2 | CVE-2026-25645, PYSEC-2026-2275 | Requests has Insecure Temp File Reuse in its extract_zipped_paths() utility function | MODERATE | 2.33.0 |

OSV also returns the PYSEC duplicates of the same four advisories (Sentinel Chain merges
records that share an alias group). The first release with **no** OSV advisory is
`requests==2.33.0`; the latest release at the time of writing, `2.34.2`, is also clean.

Why 2.30.0 and not something older: `requests<2.30` declares `urllib3<1.27` / `idna<3`, which
cannot be installed next to the modern `urllib3` / `idna` pins used by Flask 3. `2.30.0` is the
oldest release that accepts urllib3 2.x, so the *same* `requirements.txt` installs both before
and after the fix — exactly what the Docker validation step needs.

### Python: `Jinja2==3.1.5` (second finding)

| OSV id | Aliases | Summary (from OSV) | Severity (GHSA) | Fixed in |
|---|---|---|---|---|
| GHSA-cpwx-vrp4-4pq7 | CVE-2025-27516, PYSEC-2026-1471 | Jinja2 vulnerable to sandbox breakout through attr filter selecting format method | MODERATE | 3.1.6 |

`Jinja2==3.1.6` (the latest release) returns no advisories.

### JavaScript: `lodash@4.17.15`

| OSV id | Aliases | Summary (from OSV) | Severity (GHSA) | Fixed in |
|---|---|---|---|---|
| GHSA-p6mc-m468-83gw | CVE-2020-8203 | Prototype Pollution in lodash | HIGH | 4.17.19 |
| GHSA-29mw-wpgm-hmr9 | CVE-2020-28500 | Regular Expression Denial of Service (ReDoS) in lodash | MODERATE | 4.17.21 |
| GHSA-35jh-r3h4-6jhm | CVE-2021-23337, CVE-2026-4800, GHSA-r5fr-rjxr-66jc | Command Injection in lodash | HIGH | 4.17.21 |
| GHSA-xxjr-mmjv-4gpg | CVE-2025-13465, CVE-2026-2950, GHSA-f23m-r3pf-42rh | Lodash has Prototype Pollution Vulnerability in `_.unset` and `_.omit` functions | MODERATE | 4.17.23 |
| GHSA-f23m-r3pf-42rh | CVE-2025-13465, CVE-2026-2950, GHSA-xxjr-mmjv-4gpg | lodash vulnerable to Prototype Pollution via array path bypass in `_.unset` and `_.omit` | MODERATE | 4.18.0 |
| GHSA-r5fr-rjxr-66jc | CVE-2021-23337, CVE-2026-4800, GHSA-35jh-r3h4-6jhm | lodash vulnerable to Code Injection via `_.template` imports key names | HIGH | 4.18.0 |

The first release with no OSV advisory is `lodash@4.18.0`, which npm marks as deprecated
("Bad release. Please use lodash@4.17.21 instead."); **`lodash@4.18.1`** (the current `latest`)
is clean and is the sensible target. The widget's tests pass with 4.17.15, 4.18.0 and 4.18.1.

### Everything else

All other pins in `requirements.txt` are the exact output of `pip freeze` after
`pip install Flask requests==2.30.0 Jinja2==3.1.5 pytest` inside `python:3.12-slim`, so they are
mutually compatible on Python 3.12 and `pip check` passes both before and after the bump.

## How to re-verify

Query OSV.dev for a package version (prints id, summary and the affected ranges of that package):

```sh
# requests 2.30.0
curl -s -X POST https://api.osv.dev/v1/query -H 'Content-Type: application/json' \
  -d '{"package":{"name":"requests","ecosystem":"PyPI"},"version":"2.30.0"}' \
  | python3 -c 'import json,sys; [print(v["id"], v.get("summary"), [ (a.get("ranges")) for a in v["affected"] if a["package"]["name"].lower()=="requests"]) for v in json.load(sys.stdin).get("vulns",[])]'

# Jinja2 3.1.5
curl -s -X POST https://api.osv.dev/v1/query -H 'Content-Type: application/json' \
  -d '{"package":{"name":"jinja2","ecosystem":"PyPI"},"version":"3.1.5"}' \
  | python3 -c 'import json,sys; [print(v["id"], v.get("summary"), [ (a.get("ranges")) for a in v["affected"] if a["package"]["name"].lower()=="jinja2"]) for v in json.load(sys.stdin).get("vulns",[])]'

# lodash 4.17.15
curl -s -X POST https://api.osv.dev/v1/query -H 'Content-Type: application/json' \
  -d '{"package":{"name":"lodash","ecosystem":"npm"},"version":"4.17.15"}' \
  | python3 -c 'import json,sys; [print(v["id"], v.get("summary"), [ (a.get("ranges")) for a in v["affected"] if a["package"]["name"].lower()=="lodash"]) for v in json.load(sys.stdin).get("vulns",[])]'
```

The same query with the fixed versions (`2.33.0`, `3.1.6`, `4.18.1`) returns `{}` — no
`vulns` key at all. Any single advisory can be inspected with
`curl -s https://api.osv.dev/v1/vulns/GHSA-j8r2-6x86-q33q`.

Confirm that the fixed versions exist in the registries:

```sh
curl -s https://pypi.org/pypi/requests/2.33.0/json | python3 -c 'import json,sys; print(json.load(sys.stdin)["info"]["version"])'
curl -s https://pypi.org/pypi/Jinja2/3.1.6/json   | python3 -c 'import json,sys; print(json.load(sys.stdin)["info"]["version"])'
curl -s https://registry.npmjs.org/lodash/4.18.1  | python3 -c 'import json,sys; print(json.load(sys.stdin)["version"])'
```

## Running the tests locally

Python (3.12 recommended):

```sh
cd examples/demo-project
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q          # pytest.ini sets pythonpath=src and testpaths=tests
```

Run the web service (optional): `FLASK_APP=weather_notes flask run` with `src` on
`PYTHONPATH`, e.g. `PYTHONPATH=src flask --app weather_notes run`. `WEATHER_URL` and
`WEATHER_TIMEOUT` configure the `/weather` endpoint.

JavaScript (Node 18+):

```sh
cd examples/demo-project
npm install --no-audit --no-fund
npm test                     # node --test → test/format.test.js
```

Reproducing the validation Sentinel Chain performs, without installing anything on the host
(Docker only):

```sh
cd examples/demo-project
docker run --rm -v "$PWD":/w -w /w python:3.12-slim sh -c "pip install -q -r requirements.txt && python -m pytest -q"
docker run --rm -v "$PWD":/w -w /w node:20-slim   sh -c "npm install --no-audit --no-fund && npm test"
```

Both commands were run on 2026-09-13 with the vulnerable pins (17 pytest tests / 4 node tests
passed) and again in a temporary copy with `requests==2.33.0` + `Jinja2==3.1.6` and with
`lodash@4.18.1` (same results), which is what makes this project a fair validation target.

## Layout

```
examples/demo-project/
├── requirements.txt            fully pinned Python dependencies (vulnerable requests / Jinja2)
├── pytest.ini                  pythonpath=src, testpaths=tests
├── src/weather_notes/          Flask application package
│   ├── __init__.py             create_app(): routes /, /weather, /health
│   ├── routes/notes.py         in-memory notes API (/api/notes)
│   ├── services/weather.py     WeatherClient built on `requests`
│   └── templates/index.html    Jinja2 template
├── tests/                      pytest suite (requests mocked, no network)
├── package.json                weather-notes-widget, "test": "node --test", lodash 4.17.15
├── package-lock.json           real lock file generated with `npm install --package-lock-only`
├── src/widget/format.js        helpers using lodash
└── test/format.test.js         node:test suite
```
