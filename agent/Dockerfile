FROM python:3.11-slim

# ── System tools needed for host monitoring ───────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Process / network inspection
    procps \
    iproute2 \
    net-tools \
    # File system tools (rootcheck, SUID scan)
    findutils \
    util-linux \
    # Module listing (kernel rootcheck)
    kmod \
    # curl for health checks
    curl \
    # Audit log reading
    auditd \
    # For auditd log parsing
    libaudit1 \
    # ps/top utilities
    sysstat \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Python dependencies ────────────────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Agent source ──────────────────────────────��────────────────────────────────
COPY . .

# ── Persistent data directory (buffer.db, .agent_id, state files) ────────────
RUN mkdir -p /app/data && chmod 750 /app/data

# ── Entrypoint ────────────────────────────────────────────────────────────────
RUN chmod +x /app/entrypoint.sh

# ── Environment ──────────────────────────────────���────────────────────────────
ENV MANAGER_URL=http://backend:8000 \
    DATA_DIR=/app/data \
    LOG_LEVEL=INFO \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# ── Health check — agent is alive if it can write to buffer DB ────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python3 -c "import sqlite3, os; \
        db=os.path.join(os.environ.get('DATA_DIR','/app/data'),'buffer.db'); \
        sqlite3.connect(db).execute('SELECT 1'); print('OK')" || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python", "agent.py"]
