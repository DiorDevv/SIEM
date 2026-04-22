# SecureWatch SIEM

A production-ready Security Information and Event Management (SIEM) system built with Python FastAPI, React, Elasticsearch, PostgreSQL, and Redis.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Internet / Browser                      │
└───────────────────────────┬────────────────────┬────────────────┘
                            │ :80                │
                   ┌────────▼────────┐           │
                   │     Nginx       │           │
                   │  Reverse Proxy  │           │
                   └──────┬──────────┘           │
                          │                      │
          ┌───────────────┼────────────────┐     │
          │ /api/*        │ /ws/*          │ /   │
          ▼               ▼                ▼     │
  ┌──────────────┐  ┌──────────┐  ┌──────────────────┐
  │   FastAPI    │  │WebSocket │  │  React Frontend  │
  │   Backend    │  │  :8000   │  │   (Vite+Tailwind) │
  │   :8000      │  └──────────┘  └──────────────────┘
  └──┬───┬───┬───┘
     │   │   │
  ┌──▼┐ ┌▼──┐ ┌▼──────┐
  │PG │ │ES │ │Redis  │
  │:54│ │:92│ │:6379  │
  │32 │ │00 │ │       │
  └───┘ └───┘ └───────┘

  ┌──────────────────────────────────┐
  │  SIEM Agent (any machine)        │
  │  - Log Collector                 │
  │  - System Metrics                │
  │  - File Integrity Monitor (FIM)  │
  │  → HTTP POST to /api/logs/ingest │
  └──────────────────────────────────┘
```

## Tech Stack

| Layer      | Technology                              |
|------------|-----------------------------------------|
| Backend    | Python 3.11, FastAPI, SQLAlchemy async  |
| Database   | PostgreSQL 15 (agents, alerts, rules)   |
| Search     | Elasticsearch 8.11 (log storage)        |
| Cache      | Redis 7 (future: sessions, rate limits) |
| Frontend   | React 18, Vite, TailwindCSS, Recharts   |
| Agent      | Python 3.11, cross-platform             |
| Realtime   | WebSocket (native FastAPI)              |
| Deploy     | Docker, Docker Compose, Nginx           |

## Quick Start

### Prerequisites
- Docker Engine 24+
- Docker Compose v2
- 4GB RAM minimum (Elasticsearch needs 1GB heap)

### Installation

```bash
# Clone / extract the project
cd my-siem

# Start all services
docker compose up -d --build

# Watch logs
docker compose logs -f backend
```

### First Login

Open http://localhost in your browser.

| Field    | Value      |
|----------|------------|
| Username | `admin`    |
| Password | `admin123` |

**Change the default password immediately in Settings!**

### Connect an Agent

**Docker (same host):**
```bash
docker compose --profile agent up -d agent
```

**Linux (bare metal / VM):**
```bash
cd agent
pip install -r requirements.txt
# Edit config.yaml: set manager_url to your server's IP
python agent.py
```

**Windows:**
```cmd
cd agent
pip install requests pyyaml psutil pywin32
python agent.py
```

**Custom agent config:**
```yaml
# agent/config.yaml
manager_url: http://YOUR_SERVER_IP:8000
agent_name: my-linux-server
check_interval: 60        # send logs every 60s
heartbeat_interval: 30    # heartbeat every 30s
log_paths:
  - /var/log/syslog
  - /var/log/auth.log
fim_paths:
  - /etc/passwd
  - /etc/shadow
fim_interval: 300         # FIM check every 5 minutes
```

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Login (returns JWT) |
| GET | `/api/auth/me` | Current user info |
| POST | `/api/agents/register` | Register agent |
| POST | `/api/agents/{id}/heartbeat` | Agent heartbeat |
| GET | `/api/agents` | List all agents |
| POST | `/api/logs/ingest` | Ingest logs (agent → server) |
| GET | `/api/logs` | Search logs |
| GET | `/api/alerts` | List alerts (filterable) |
| PUT | `/api/alerts/{id}/acknowledge` | Acknowledge alert |
| PUT | `/api/alerts/{id}/resolve` | Resolve alert |
| GET | `/api/rules` | List detection rules |
| POST | `/api/rules` | Create rule |
| GET | `/api/dashboard/stats` | Dashboard statistics |
| WS | `/ws/live` | Real-time WebSocket feed |

## Default Detection Rules

| Rule | Pattern | Severity |
|------|---------|----------|
| Failed SSH Login | `Failed password\|authentication failure` | MEDIUM |
| Successful Root Login | `Accepted.*root` | HIGH |
| Sudo Command Used | `sudo:.*COMMAND` | LOW |
| Service Crashed | `segfault\|core dumped\|killed process` | HIGH |
| Firewall Blocked | `UFW BLOCK\|iptables.*DROP` | LOW |
| Brute Force SSH | 5+ failures from same IP in 60s | CRITICAL |

## Services & Ports

| Service | Port | Description |
|---------|------|-------------|
| Nginx | 80 | Main entry point |
| Backend | 8000 | FastAPI (direct access) |
| Frontend | 3000 | React app (direct access) |
| PostgreSQL | 5432 | Database |
| Elasticsearch | 9200 | Log search |
| Redis | 6379 | Cache |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | postgresql+asyncpg://siem:siem123@localhost/siem | PostgreSQL connection |
| `ELASTICSEARCH_URL` | http://localhost:9200 | Elasticsearch endpoint |
| `REDIS_URL` | redis://localhost:6379 | Redis connection |
| `SECRET_KEY` | (change this!) | JWT signing key |
| `CORS_ORIGINS` | `["http://localhost:3000"]` | Allowed CORS origins |

## Useful Commands

```bash
# View all running containers
docker compose ps

# Restart a specific service
docker compose restart backend

# View backend logs
docker compose logs -f backend

# Access PostgreSQL
docker exec -it siem-postgres psql -U siem -d siem

# Access Elasticsearch
curl http://localhost:9200/_cluster/health?pretty

# Stop everything
docker compose down

# Stop and remove volumes (full reset)
docker compose down -v
```

## Security Notes

1. **Change the default admin password** immediately after first login
2. **Replace the `SECRET_KEY`** in docker-compose.yml with a random 64-char string
3. In production, enable HTTPS in nginx.conf and use SSL certificates
4. Consider placing Elasticsearch and PostgreSQL behind a firewall (not publicly exposed)
5. The agent sends logs over plain HTTP — use a VPN or mTLS in production

## License

MIT
