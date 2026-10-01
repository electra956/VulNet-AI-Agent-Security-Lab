#!/usr/bin/env bash
# VulNet AI Agent Security Lab - one-command launcher (Linux / WSL / macOS)
#
#   ./start.sh            start Ollama (if installed), the API gateway and the dashboard
#   ./start.sh stop       stop everything this script started
#   ./start.sh status     show what is running
#   ./start.sh test       run the whole automated test suite
#   ./start.sh report     run every OWASP Agentic test and write reports/
#   ./start.sh --no-ollama   start without Ollama (chat then uses a labelled offline simulation)
set -u
cd "$(dirname "$0")"

RUN_DIR=".run"; LOG_DIR="logs"; mkdir -p "$RUN_DIR" "$LOG_DIR"
API_PORT="${API_PORT:-8000}"; UI_PORT="${UI_PORT:-8501}"; OLLAMA_URL="${OLLAMA_BASE_URL:-http://127.0.0.1:11434}"
CHAT_MODEL="${OLLAMA_MODEL:-llama3.2}"; EMBED_MODEL="${OLLAMA_EMBED_MODEL:-nomic-embed-text}"
WITH_OLLAMA=1
CMD="start"
for a in "$@"; do case "$a" in stop|status|test|report|start) CMD="$a";; --no-ollama) WITH_OLLAMA=0;; esac; done

say() { printf '%s\n' "$*"; }
up()  { curl -sf -m 3 "$1" >/dev/null 2>&1; }

find_python() {
  if [ -x venv/bin/python ]; then PY=venv/bin/python
  elif [ -x venv_win/bin/python ]; then PY=venv_win/bin/python
  else
    say "[setup] no virtual environment found - running ./setup.sh"
    bash ./setup.sh || { say "setup failed"; exit 1; }
    PY=venv/bin/python
  fi
}

stop_all() {
  for f in "$RUN_DIR"/*.pid; do
    [ -e "$f" ] || continue
    pid=$(cat "$f"); name=$(basename "$f" .pid)
    if kill -0 "$pid" 2>/dev/null; then kill "$pid" 2>/dev/null && say "stopped $name ($pid)"; fi
    rm -f "$f"
  done
}

status() {
  up "$OLLAMA_URL/api/tags" && say "ollama     : UP   $OLLAMA_URL" || say "ollama     : DOWN (chat uses offline simulation)"
  up "http://127.0.0.1:$API_PORT/health" && say "api        : UP   http://127.0.0.1:$API_PORT/docs" || say "api        : DOWN"
  up "http://127.0.0.1:$UI_PORT" && say "dashboard  : UP   http://localhost:$UI_PORT" || say "dashboard  : DOWN"
}

wait_for() { # url seconds label
  for _ in $(seq 1 "$2"); do up "$1" && return 0; sleep 1; done
  say "  ! $3 did not come up within $2s - see $LOG_DIR/"; return 1
}

start_ollama() {
  [ "$WITH_OLLAMA" = 1 ] || { say "[ollama] skipped (--no-ollama)"; return; }
  OLLAMA_BIN="$(command -v ollama || true)"; [ -z "$OLLAMA_BIN" ] && [ -x "$HOME/.local/ollama/bin/ollama" ] && OLLAMA_BIN="$HOME/.local/ollama/bin/ollama"
  if [ -z "$OLLAMA_BIN" ]; then
    say "[ollama] not installed. Install it (see README: 'Ollama Setup') or continue with --no-ollama."; return
  fi
  if ! up "$OLLAMA_URL/api/tags"; then
    say "[ollama] starting server..."
    nohup "$OLLAMA_BIN" serve >"$LOG_DIR/ollama.log" 2>&1 & echo $! >"$RUN_DIR/ollama.pid"
    wait_for "$OLLAMA_URL/api/tags" 30 "ollama" || return
  else
    say "[ollama] already running"
  fi
  for m in "$CHAT_MODEL" "$EMBED_MODEL"; do
    if ! "$OLLAMA_BIN" list 2>/dev/null | grep -q "^$m"; then
      say "[ollama] pulling model $m (first run only)..."; "$OLLAMA_BIN" pull "$m" || say "  ! could not pull $m"
    else
      say "[ollama] model $m ready"
    fi
  done
}

start_services() {
  find_python
  [ -f .env ] || { [ -f .env.example ] && cp .env.example .env && say "[env] created .env from .env.example"; }
  start_ollama
  if up "http://127.0.0.1:$API_PORT/health"; then say "[api] already running"
  else
    say "[api] starting on :$API_PORT ..."
    nohup "$PY" -m uvicorn api.main:app --host 127.0.0.1 --port "$API_PORT" >"$LOG_DIR/api.log" 2>&1 & echo $! >"$RUN_DIR/api.pid"
    wait_for "http://127.0.0.1:$API_PORT/health" 90 "API"
  fi
  if up "http://127.0.0.1:$UI_PORT"; then say "[ui] already running"
  else
    say "[ui] starting dashboard on :$UI_PORT ..."
    nohup "$PY" -m streamlit run chatbot/app.py --server.port "$UI_PORT" --server.headless true >"$LOG_DIR/ui.log" 2>&1 & echo $! >"$RUN_DIR/ui.pid"
    wait_for "http://127.0.0.1:$UI_PORT" 90 "dashboard"
  fi
  say ""; status; say ""
  say "Open http://localhost:$UI_PORT and sign in (password + simulated MFA code shown on screen):"
  say "  alex_morgan / Cust001Secure!2026   (customer CUST-001)     jordan_lee / Cust002Secure!2026 (CUST-002)"
  say "  sam_casey / Support001Secure!2026  riley_taylor / Fraud001Secure!2026  casey_reyes / Compliance001Secure!2026"
  say "  morgan_vance / Admin001Secure!2026 (admin)"
  say "Then use the sidebar: Chat, Attack Lab, and the ten 'OWASP Agentic Top 10' pages. Stop with ./start.sh stop"
}

case "$CMD" in
  start)  start_services ;;
  stop)   stop_all ;;
  status) status ;;
  test)   find_python; "$PY" -m pytest -q ;;
  report) find_python; "$PY" -m lab report && say "Reports written to reports/" ;;
esac
