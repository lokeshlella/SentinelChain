#!/bin/bash
# Sentinel Chain — Phase-1 review demo.
#
#   scripts/phase1-demo.sh start      bring everything up, run the pre-flight checks, open the dashboard
#   scripts/phase1-demo.sh prepare    register examples/demo-project and run one analysis (a ready-made result)
#   scripts/phase1-demo.sh check      pre-flight checks only (services, internet/OSV, memory, ready-made result)
#   scripts/phase1-demo.sh status     what is running
#   scripts/phase1-demo.sh stop       stop the backend/frontend this script started (Docker services keep running)
#   scripts/phase1-demo.sh reset --yes   delete the Phase-1 demo database and workspace (never the main ones)
#
#   start --lan   also serve the dashboard on this Mac's network address (other laptops on the same Wi-Fi)
#
# Phase 1 = repository ingestion and profiling, dependency extraction, PostgreSQL, OSV.dev detection,
# source-usage evidence and the Neo4j knowledge graph (SENTINEL_PHASE=1). It runs against its own
# database and workspace — the full product's data is never touched — and on its own ports, so a dev
# server or the Docker "full" stack on 8000/5173/3000 cannot be picked up by mistake.
#
# Settings (environment): DEMO_API_PORT (8001), DEMO_WEB_PORT (4173), DEMO_DB_NAME (sentinelchain_phase1),
# DEMO_WORKSPACE (workspace/phase1), SENTINEL_FEATURES (add Phase-2 features, e.g. "ai"), SENTINEL_VENV,
# DEMO_NO_OPEN=1 (do not open the browser).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API_PORT="${DEMO_API_PORT:-8001}"
WEB_PORT="${DEMO_WEB_PORT:-4173}"
DB_NAME="${DEMO_DB_NAME:-sentinelchain_phase1}"
WORKSPACE="${DEMO_WORKSPACE:-$ROOT/workspace/phase1}"
VENV="${SENTINEL_VENV:-$ROOT/backend/.venv}"
RUN_DIR="$WORKSPACE/run"
API="http://127.0.0.1:$API_PORT/api"
WEB="http://localhost:$WEB_PORT"
DEMO_REPO="$ROOT/examples/demo-project"
FIRST_REPOSITORY_ID=101  # keeps the demo's Neo4j nodes apart from the main database's repositories

export PATH="/Applications/Docker.app/Contents/Resources/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"

if [ -t 1 ]; then
  BOLD=$'\033[1m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; RESET=$'\033[0m'
else
  BOLD=""; GREEN=""; YELLOW=""; RED=""; RESET=""
fi
say()  { printf '%s\n' "$*"; }
step() { printf '\n%s▸ %s%s\n' "$BOLD" "$*" "$RESET"; }
ok()   { printf '  %s✓%s %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '  %s!%s %s\n' "$YELLOW" "$RESET" "$*"; }
fail() { printf '  %s✗ %s%s\n' "$RED" "$*" "$RESET" >&2; exit 1; }

# The backend's environment: the Phase-1 build against the demo database and workspace.
# (Environment variables win over the .env file, so the main settings stay as they are.)
backend_env() {
  export SENTINEL_PHASE=1
  export SENTINEL_FEATURES="${SENTINEL_FEATURES:-}"
  export DATABASE_URL="postgresql+psycopg://sentinel:sentinel@localhost:5432/$DB_NAME"
  export REPOSITORY_WORKSPACE="$WORKSPACE"
  export APP_ENV=development
}

# JSON field from stdin, e.g. `curl ... | json phase` or `json "features.ai"`. Prints "" when absent.
json() {
  "$VENV/bin/python" -c '
import json, sys
try:
    value = json.load(sys.stdin)
    for key in sys.argv[1].split("."):
        value = value[int(key)] if isinstance(value, list) else value.get(key)
except Exception:
    value = None
print("" if value is None else (json.dumps(value) if isinstance(value, (dict, list)) else value))
' "$1"
}

port_pid() { lsof -nP -iTCP:"$1" -sTCP:LISTEN -t 2>/dev/null | head -1 || true; }
pid_alive() { [ -n "${1:-}" ] && kill -0 "$1" 2>/dev/null; }
read_pid() { [ -f "$RUN_DIR/$1.pid" ] && cat "$RUN_DIR/$1.pid" || true; }

wait_for() {  # wait_for <seconds> <description> <command...>
  local seconds="$1" what="$2"; shift 2
  local i=0
  until "$@" >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -ge "$seconds" ] && return 1
    sleep 1
  done
  return 0
}

# ------------------------------------------------------------------------------------------ checks

require_tools() {
  [ -x "$VENV/bin/uvicorn" ] || fail "backend virtualenv not found at $VENV (create it: cd backend && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt)"
  command -v node >/dev/null || fail "node is not installed"
  [ -x "$ROOT/frontend/node_modules/.bin/vite" ] || fail "frontend dependencies missing: run 'cd frontend && npm install' (needs internet, do it before the review)"
  [ -d "$DEMO_REPO" ] || fail "demo repository missing at $DEMO_REPO"
  command -v docker >/dev/null || fail "docker CLI not found (is Docker Desktop installed?)"
}

ensure_docker() {
  step "Docker"
  if docker info >/dev/null 2>&1; then ok "Docker is running"; return; fi
  say "  starting Docker Desktop…"
  open -a Docker || fail "could not start Docker Desktop"
  wait_for 180 docker docker info || fail "Docker did not start within 3 minutes — open Docker Desktop by hand, then re-run"
  ok "Docker is running"
}

# Docker Desktop brings back containers that were running when it quit — including the full
# product's backend/frontend (`--profile full`). They are not part of Phase 1: stop them so they
# cannot be opened by mistake and so their memory goes to the demo.
stop_full_stack() {
  local name
  for name in sentinel-backend sentinel-frontend; do
    if [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null || true)" = "true" ]; then
      docker stop "$name" >/dev/null && ok "stopped $name (not part of this demo)"
    fi
  done
}

start_services() {
  step "PostgreSQL and Neo4j"
  docker compose -p sentinelchain -f "$ROOT/docker-compose.yml" up -d postgres neo4j >/dev/null 2>&1 \
    || fail "docker compose could not start postgres/neo4j (see: docker compose -p sentinelchain logs postgres neo4j)"
  wait_for 90 postgres docker exec sentinel-postgres pg_isready -U sentinel -d sentinelchain \
    || fail "PostgreSQL did not become ready (docker logs sentinel-postgres)"
  ok "PostgreSQL is ready"
  if wait_for 150 neo4j curl -fsS -o /dev/null http://localhost:7474; then
    ok "Neo4j is ready (browser: http://localhost:7474)"
  else
    warn "Neo4j is still starting — analyses will report the knowledge graph as UNAVAILABLE until it is up; re-run 'check' in a minute"
  fi
}

ensure_database() {
  step "Demo database ($DB_NAME)"
  local exists
  exists="$(docker exec sentinel-postgres psql -U sentinel -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'" 2>/dev/null || true)"
  if [ "$exists" != "1" ]; then
    docker exec sentinel-postgres createdb -U sentinel "$DB_NAME" || fail "could not create database $DB_NAME"
    ok "created $DB_NAME"
  fi
  mkdir -p "$RUN_DIR"
  (backend_env; cd "$ROOT/backend" && "$VENV/bin/alembic" upgrade head) >"$RUN_DIR/migrations.log" 2>&1 \
    || fail "database migration failed — see $RUN_DIR/migrations.log"
  # Fresh database: number its repositories from $FIRST_REPOSITORY_ID (Neo4j nodes are keyed by id).
  docker exec sentinel-postgres psql -U sentinel -d "$DB_NAME" -tAc \
    "SELECT CASE WHEN (SELECT count(*) FROM repositories) = 0 AND (SELECT last_value FROM repositories_repository_id_seq) < $FIRST_REPOSITORY_ID
            THEN setval('repositories_repository_id_seq', $FIRST_REPOSITORY_ID, false) END" >/dev/null 2>&1 || true
  ok "schema up to date (the main 'sentinelchain' database is not touched)"
}

backend_phase() { curl -fsS -m 3 "$API/features" 2>/dev/null | json phase; }

start_backend() {
  step "Backend (Phase-1 build) on port $API_PORT"
  local pid
  pid="$(port_pid "$API_PORT")"
  if [ -n "$pid" ]; then
    if [ "$pid" = "$(read_pid backend)" ] && [ "$(backend_phase)" = "1" ]; then
      ok "already running (pid $pid)"; return
    fi
    fail "port $API_PORT is in use by another process (pid $pid: $(ps -o comm= -p "$pid" 2>/dev/null || echo '?')). Stop it, or set DEMO_API_PORT to a free port."
  fi
  mkdir -p "$RUN_DIR"
  (
    backend_env
    cd "$ROOT/backend"
    nohup "$VENV/bin/uvicorn" app.main:app --host 127.0.0.1 --port "$API_PORT" >"$RUN_DIR/backend.log" 2>&1 &
    echo $! >"$RUN_DIR/backend.pid"
  )
  wait_for 40 backend curl -fsS -m 2 "$API/health/live" || fail "backend did not start — see $RUN_DIR/backend.log"
  [ "$(backend_phase)" = "1" ] || fail "backend on port $API_PORT is not a Phase-1 build — see $RUN_DIR/backend.log"
  ok "running (pid $(read_pid backend)), log: $RUN_DIR/backend.log"
}

start_frontend() {
  local lan="${1:-}" host="127.0.0.1"
  [ "$lan" = "--lan" ] && host="0.0.0.0"
  step "Dashboard on port $WEB_PORT"
  local pid
  pid="$(port_pid "$WEB_PORT")"
  if [ -n "$pid" ]; then
    if [ "$pid" = "$(read_pid frontend)" ]; then ok "already running (pid $pid)"; return; fi
    fail "port $WEB_PORT is in use by another process (pid $pid: $(ps -o comm= -p "$pid" 2>/dev/null || echo '?')). Stop it, or set DEMO_WEB_PORT to a free port."
  fi
  (cd "$ROOT/frontend" && ./node_modules/.bin/vite build) >"$RUN_DIR/frontend-build.log" 2>&1 \
    || fail "frontend build failed — see $RUN_DIR/frontend-build.log"
  (
    cd "$ROOT/frontend"
    VITE_API_PROXY="http://127.0.0.1:$API_PORT" nohup ./node_modules/.bin/vite preview --host "$host" --port "$WEB_PORT" --strictPort \
      >"$RUN_DIR/frontend.log" 2>&1 &
    echo $! >"$RUN_DIR/frontend.pid"
  )
  wait_for 30 frontend curl -fsS -o /dev/null "$WEB/" || fail "dashboard did not start — see $RUN_DIR/frontend.log"
  [ "$(curl -fsS -m 3 "$WEB/api/features" 2>/dev/null | json phase)" = "1" ] \
    || fail "the dashboard is not talking to the Phase-1 backend — see $RUN_DIR/frontend.log"
  ok "running (pid $(read_pid frontend)), served from the production build"
}

# A sleeping Mac pauses the backend mid-analysis and the job watchdog then reports it as crashed.
keep_awake() {
  local backend caffeinate
  backend="$(read_pid backend)"
  caffeinate="$(read_pid caffeinate)"
  pid_alive "$caffeinate" && return
  if command -v caffeinate >/dev/null && pid_alive "$backend"; then
    nohup caffeinate -dims -w "$backend" >/dev/null 2>&1 &
    echo $! >"$RUN_DIR/caffeinate.pid"
    ok "this Mac will not sleep while the backend runs (do not close the lid)"
  fi
}

latest_completed_analysis() {
  curl -fsS -m 5 "$API/analyses?limit=50" 2>/dev/null | "$VENV/bin/python" -c '
import json, sys
try:
    rows = [a for a in json.load(sys.stdin) if a.get("status") == "COMPLETED"]
except Exception:
    rows = []
if rows:
    a = rows[0]
    print("#%s (%s findings, overall risk %s)" % (a["analysis_id"], a.get("findings_count", 0), a.get("overall_risk") or "n/a"))
'
}

preflight() {
  step "Pre-flight checks"
  local health features problems=0
  [ "$(backend_phase)" = "1" ] || fail "no Phase-1 backend on port $API_PORT — run: scripts/phase1-demo.sh start"
  features="$(curl -fsS -m 3 "$API/features" | json features)"
  if printf '%s' "$features" | grep -Eq '"(ai|remediation|validation|reports|pull_requests)": true'; then
    warn "extra Phase-2 features are enabled: $features"
  else
    ok "Phase-1 build confirmed"
  fi
  health="$(curl -fsS -m 30 "$API/health" 2>/dev/null || true)"
  [ -n "$health" ] || fail "the backend did not answer /api/health — see $RUN_DIR/backend.log"
  local name okv detail services
  # One line per service: name<TAB>1|0<TAB>detail
  services="$(printf '%s' "$health" | "$VENV/bin/python" -c '
import json, sys
try:
    for s in json.load(sys.stdin).get("services", []):
        print("%s\t%s\t%s" % (s.get("name"), 1 if s.get("ok") else 0, str(s.get("detail", "")).replace("\t", " ")))
except Exception:
    pass
' || true)"
  for name in postgresql neo4j osv; do
    okv="$(printf '%s\n' "$services" | awk -F'\t' -v n="$name" '$1 == n {print $2}')"
    detail="$(printf '%s\n' "$services" | awk -F'\t' -v n="$name" '$1 == n {print $3}')"
    [ -n "$okv" ] || detail="not reported by the backend"
    if [ "$okv" = "1" ]; then
      ok "$name: $detail"
    else
      problems=$((problems + 1))
      case "$name" in
        postgresql) warn "PostgreSQL: $detail — nothing works without it (docker compose -p sentinelchain up -d postgres)";;
        neo4j)      warn "Neo4j: $detail — the knowledge-graph stage will be UNAVAILABLE (wait for it, or: docker start sentinel-neo4j)";;
        osv)        warn "OSV.dev: $detail — NO INTERNET: dependencies will be UNKNOWN (never SAFE). Use a phone hotspot, or present the ready-made analysis below";;
      esac
    fi
  done
  local free_mb pressure
  pressure="$(memory_pressure 2>/dev/null | awk -F': ' '/System-wide memory free percentage/ {print $2}' || true)"
  free_mb="$(vm_stat 2>/dev/null | awk '/Pages free/ {gsub("\\.",""); printf "%d", $3*16384/1048576}' || true)"
  if [ -n "$pressure" ]; then
    case "${pressure%\%}" in
      ''|*[!0-9]*) ;;
      *) if [ "${pressure%\%}" -lt 15 ]; then warn "memory is low ($pressure free): close other apps"; else ok "memory: $pressure free"; fi;;
    esac
  elif [ -n "$free_mb" ]; then
    ok "memory: ${free_mb} MB free"
  fi
  local ready
  ready="$(latest_completed_analysis)"
  if [ -n "$ready" ]; then
    ok "ready-made analysis to fall back on: $ready"
  else
    warn "no completed analysis yet — run 'scripts/phase1-demo.sh prepare' once while you have internet"
  fi
  [ "$problems" -eq 0 ] && say "  ${GREEN}${BOLD}All checks passed.${RESET}" || say "  ${YELLOW}${BOLD}$problems check(s) need attention (see above).${RESET}"
}

urls() {
  step "Open"
  say "  Dashboard:     $WEB"
  say "  API docs:      http://127.0.0.1:$API_PORT/docs"
  say "  Neo4j browser: http://localhost:7474   (user neo4j / password sentinelchain)"
  if [ "$(lsof -nP -iTCP:"$WEB_PORT" -sTCP:LISTEN 2>/dev/null | awk 'NR==2 {print $9}')" != "127.0.0.1:$WEB_PORT" ]; then
    local ip
    ip="$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)"
    [ -n "$ip" ] && say "  Other laptops on this network: http://$ip:$WEB_PORT"
  fi
  say "  Demo repository path (Add repository): $DEMO_REPO"
}

# ------------------------------------------------------------------------------------------ commands

cmd_start() {
  require_tools
  ensure_docker
  stop_full_stack
  start_services
  ensure_database
  start_backend
  start_frontend "${1:-}"
  keep_awake
  preflight
  urls
  [ -n "${DEMO_NO_OPEN:-}" ] || open "$WEB" 2>/dev/null || true
}

cmd_prepare() {
  [ "$(backend_phase)" = "1" ] || fail "no Phase-1 backend on port $API_PORT — run: scripts/phase1-demo.sh start"
  step "Registering $DEMO_REPO"
  local body id status analysis i
  body="$(curl -sS -m 30 -X POST "$API/repositories" -H 'Content-Type: application/json' -d "{\"source_url\": \"$DEMO_REPO\"}")"
  id="$(printf '%s' "$body" | json repository_id)"
  [ -n "$id" ] || id="$(printf '%s' "$body" | json details.repository_id)"  # 409: already registered
  [ -n "$id" ] || fail "registration failed: $body"
  for i in $(seq 1 60); do
    status="$(curl -fsS -m 5 "$API/repositories/$id" | json status)"
    [ "$status" = "READY" ] && break
    [ "$status" = "FAILED" ] && fail "ingestion failed: $(curl -fsS "$API/repositories/$id" | json error_message)"
    sleep 2
  done
  [ "$status" = "READY" ] || fail "ingestion did not finish in 2 minutes"
  ok "repository #$id is ready"
  step "Analysing repository #$id"
  body="$(curl -sS -m 30 -X POST "$API/repositories/$id/analyze" -H 'Content-Type: application/json' -d '{"run_ai": false}')"
  analysis="$(printf '%s' "$body" | json analysis_id)"
  [ -n "$analysis" ] || analysis="$(printf '%s' "$body" | json details.analysis_id)"  # 409: one is running
  [ -n "$analysis" ] || fail "could not start the analysis: $body"
  for i in $(seq 1 150); do
    status="$(curl -fsS -m 5 "$API/analyses/$analysis" | json status)"
    case "$status" in COMPLETED|FAILED) break;; esac
    sleep 2
  done
  body="$(curl -fsS -m 5 "$API/analyses/$analysis")"
  say "  status:   $(printf '%s' "$body" | json status)"
  say "  stages:   $(printf '%s' "$body" | json stages)"
  say "  findings: $(printf '%s' "$body" | json findings_count), overall risk $(printf '%s' "$body" | json overall_risk)"
  [ "$(printf '%s' "$body" | json status)" = "COMPLETED" ] || fail "analysis did not complete: $(printf '%s' "$body" | json error_message)"
  ok "ready-made analysis: $WEB/analyses/$analysis"
}

cmd_stop() {
  step "Stopping the Phase-1 demo"
  local name pid
  for name in frontend backend caffeinate; do
    pid="$(read_pid "$name")"
    if pid_alive "$pid"; then kill "$pid" 2>/dev/null && ok "stopped $name (pid $pid)"; fi
    rm -f "$RUN_DIR/$name.pid"
  done
  say "  PostgreSQL/Neo4j keep running (stop them with: docker compose -p sentinelchain stop)"
}

cmd_status() {
  step "Status"
  local name pid
  for name in backend frontend caffeinate; do
    pid="$(read_pid "$name")"
    if pid_alive "$pid"; then ok "$name running (pid $pid)"; else warn "$name not running"; fi
  done
  [ "$(backend_phase)" = "1" ] && ok "backend answers as a Phase-1 build" || warn "no Phase-1 backend on port $API_PORT"
  urls
}

cmd_reset() {
  [ "${1:-}" = "--yes" ] || fail "this deletes the Phase-1 demo database '$DB_NAME' and $WORKSPACE (the main database is not touched). Re-run with: reset --yes"
  cmd_stop
  step "Resetting the Phase-1 demo data"
  docker exec sentinel-postgres dropdb -U sentinel --if-exists "$DB_NAME" && ok "dropped $DB_NAME"
  case "$WORKSPACE" in
    "$ROOT"/workspace/*) rm -rf "$WORKSPACE" && ok "removed $WORKSPACE";;
    *) warn "not removing $WORKSPACE (outside $ROOT/workspace); delete it by hand if you want";;
  esac
  say "  Start again with: scripts/phase1-demo.sh start"
}

case "${1:-}" in
  start)   cmd_start "${2:-}";;
  prepare) cmd_prepare;;
  check)   require_tools; preflight; urls;;
  status)  cmd_status;;
  stop)    cmd_stop;;
  reset)   cmd_reset "${2:-}";;
  *) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 2;;
esac
