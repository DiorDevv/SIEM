#!/bin/bash
set -e

MANAGER_URL="${MANAGER_URL:-http://backend:8000}"
DATA_DIR="${DATA_DIR:-/app/data}"
MAX_WAIT=120   # seconds to wait for backend

# ── Create data directory ─────────────────────────────────────────────────────
mkdir -p "$DATA_DIR"

# ── Wait for backend to be ready ─────────────────────────────────────────────
echo "[entrypoint] Waiting for backend at $MANAGER_URL ..."
elapsed=0
while ! curl -sf "$MANAGER_URL/api/health" > /dev/null 2>&1; do
    if [ $elapsed -ge $MAX_WAIT ]; then
        echo "[entrypoint] Backend not ready after ${MAX_WAIT}s — starting agent anyway (offline buffer will queue logs)"
        break
    fi
    sleep 3
    elapsed=$((elapsed + 3))
done

if curl -sf "$MANAGER_URL/api/health" > /dev/null 2>&1; then
    echo "[entrypoint] Backend is ready."
fi

# ── Set inotify limits (best-effort, may fail if not privileged) ──────────────
sysctl -w fs.inotify.max_user_watches=524288  2>/dev/null || true
sysctl -w fs.inotify.max_queued_events=32768  2>/dev/null || true

# ── Start agent ───────────────────────────────────────────────────────────────
echo "[entrypoint] Starting SecureWatch Agent v4.0..."
exec "$@"
