"""
System configuration API.
  GET  /api/system/config          — read current integration settings
  PUT  /api/system/config          — save API keys to .env (admin only)
  GET  /api/system/auditd-script   — download auditd setup script
  GET  /api/system/auditd-status   — check auditd status on the server host
"""
import os
import re
import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel

from routes.auth import get_current_user, require_admin
from models.user import User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/system", tags=["system"])

# .env lives next to this file (backend dir) or one level up
_ENV_CANDIDATES = [
    Path(__file__).resolve().parents[1] / ".env",
    Path(__file__).resolve().parents[2] / ".env",
]
_ENV_FILE = next((p for p in _ENV_CANDIDATES if p.exists()), _ENV_CANDIDATES[0])

_AGENT_SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "agent" / "scripts"


# ── Schemas ───────────────────────────────────────────────────────────────────

class SystemConfigUpdate(BaseModel):
    ABUSEIPDB_API_KEY:   Optional[str] = None
    ABUSEIPDB_ENABLED:   Optional[bool] = None
    ABUSEIPDB_MIN_SCORE: Optional[int]  = None
    NVD_API_KEY:         Optional[str] = None
    NVD_ENABLED:         Optional[bool] = None
    GEOIP_ENABLED:       Optional[bool] = None


# ── .env helpers ──────────────────────────────────────────────────────────────

def _read_env() -> dict:
    env: dict = {}
    if _ENV_FILE.exists():
        for line in _ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def _write_env(updates: dict) -> None:
    existing = {}
    lines: list = []

    if _ENV_FILE.exists():
        for line in _ENV_FILE.read_text().splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                k = stripped.split("=", 1)[0].strip()
                existing[k] = len(lines)
            lines.append(line)

    for key, value in updates.items():
        if key in existing:
            lines[existing[key]] = f'{key}={value}'
        else:
            lines.append(f'{key}={value}')

    _ENV_FILE.write_text("\n".join(lines) + "\n")
    logger.info(f"Updated .env: {list(updates.keys())}")


def _mask(val: str) -> str:
    if not val or len(val) < 8:
        return "****" if val else ""
    return val[:4] + "****" + val[-4:]


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/config")
async def get_system_config(current_user: User = Depends(get_current_user)):
    from config import settings
    env = _read_env()

    return {
        "abuseipdb": {
            "enabled":   settings.ABUSEIPDB_ENABLED,
            "has_key":   bool(settings.ABUSEIPDB_API_KEY),
            "key_masked": _mask(settings.ABUSEIPDB_API_KEY),
            "min_score": settings.ABUSEIPDB_MIN_SCORE,
            "free_tier": "1 000 checks/day",
            "signup_url": "https://www.abuseipdb.com/register",
        },
        "nvd": {
            "enabled":    settings.NVD_ENABLED,
            "has_key":    bool(settings.NVD_API_KEY),
            "key_masked":  _mask(settings.NVD_API_KEY),
            "free_tier":  "5 req/s without key, 50 req/s with key",
            "signup_url": "https://nvd.nist.gov/developers/request-an-api-key",
        },
        "geoip": {
            "enabled":   settings.GEOIP_ENABLED,
            "provider":  "ip-api.com",
            "free_tier": "45 req/min, no key required",
        },
        "env_file": str(_ENV_FILE),
        "env_exists": _ENV_FILE.exists(),
    }


@router.put("/config")
async def update_system_config(
    body: SystemConfigUpdate,
    current_user: User = Depends(require_admin),
):
    updates: dict = {}

    if body.ABUSEIPDB_API_KEY is not None:
        updates["ABUSEIPDB_API_KEY"] = body.ABUSEIPDB_API_KEY
    if body.ABUSEIPDB_ENABLED is not None:
        updates["ABUSEIPDB_ENABLED"] = "true" if body.ABUSEIPDB_ENABLED else "false"
    if body.ABUSEIPDB_MIN_SCORE is not None:
        updates["ABUSEIPDB_MIN_SCORE"] = str(body.ABUSEIPDB_MIN_SCORE)
    if body.NVD_API_KEY is not None:
        updates["NVD_API_KEY"] = body.NVD_API_KEY
    if body.NVD_ENABLED is not None:
        updates["NVD_ENABLED"] = "true" if body.NVD_ENABLED else "false"
    if body.GEOIP_ENABLED is not None:
        updates["GEOIP_ENABLED"] = "true" if body.GEOIP_ENABLED else "false"

    if not updates:
        raise HTTPException(400, "No fields to update")

    try:
        _write_env(updates)
    except Exception as e:
        raise HTTPException(500, f"Failed to write .env: {e}")

    return {
        "message": "Configuration saved to .env. Restart the backend to apply changes.",
        "updated": list(updates.keys()),
        "restart_required": True,
    }


@router.get("/auditd-script")
async def get_auditd_script(current_user: User = Depends(get_current_user)):
    script_path = _AGENT_SCRIPTS_DIR / "setup_auditd.sh"

    if script_path.exists():
        content = script_path.read_text()
    else:
        content = _generate_auditd_script()

    return Response(
        content=content,
        media_type="text/x-shellscript",
        headers={"Content-Disposition": 'attachment; filename="setup_auditd.sh"'},
    )


def _generate_auditd_script() -> str:
    return r"""#!/usr/bin/env bash
# ============================================================
#  SecureWatch SIEM — auditd CIS/STIG setup
#  Run as root on the monitored host (not in the container)
# ============================================================
set -euo pipefail

RED="\033[0;31m"; GRN="\033[0;32m"; YLW="\033[1;33m"; RST="\033[0m"
log()  { echo -e "${GRN}[✓]${RST} $*"; }
warn() { echo -e "${YLW}[!]${RST} $*"; }
err()  { echo -e "${RED}[✗]${RST} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || err "Run as root: sudo bash $0"

# ── Install auditd ────────────────────────────────────────────
if ! command -v auditctl &>/dev/null; then
  log "Installing auditd..."
  if   command -v apt-get &>/dev/null; then apt-get install -y auditd audispd-plugins
  elif command -v dnf     &>/dev/null; then dnf install -y audit
  elif command -v yum     &>/dev/null; then yum install -y audit
  else err "Unknown package manager"; fi
fi
log "auditd installed"

# ── Write rules ───────────────────────────────────────────────
RULES_FILE="/etc/audit/rules.d/securewatch.rules"
cat > "$RULES_FILE" <<'RULES'
## SecureWatch SIEM — CIS/STIG audit rules

# Remove old rules
-D
# Buffer size
-b 8192
# Failure mode: 1=log, 2=panic
-f 1

# ── Identity files ────────────────────────────────────────────
-w /etc/passwd   -p wa -k identity
-w /etc/shadow   -p wa -k identity
-w /etc/group    -p wa -k identity
-w /etc/gshadow  -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# ── Sudoers ───────────────────────────────────────────────────
-w /etc/sudoers      -p wa -k sudoers
-w /etc/sudoers.d/   -p wa -k sudoers

# ── SSH configuration ─────────────────────────────────────────
-w /etc/ssh/sshd_config -p wa -k sshd_config

# ── Privilege escalation ──────────────────────────────────────
-a always,exit -F path=/usr/bin/sudo    -F perm=x -F auid>=1000 -k privilege_esc
-a always,exit -F path=/usr/bin/su      -F perm=x -F auid>=1000 -k privilege_esc
-a always,exit -F path=/usr/bin/newgrp  -F perm=x -F auid>=1000 -k privilege_esc
-a always,exit -F path=/usr/bin/chsh    -F perm=x -F auid>=1000 -k privilege_esc
-a always,exit -F path=/usr/bin/passwd  -F perm=x -F auid>=1000 -k privilege_esc

# ── Setuid/setgid (32-bit and 64-bit) ────────────────────────
-a always,exit -F arch=b64 -S setuid   -F a0=0 -F exe=/usr/bin/su -k setuid
-a always,exit -F arch=b64 -S setresuid -F a0=0 -F exe=/usr/bin/sudo -k setuid
-a always,exit -F arch=b32 -S setuid   -F a0=0 -F exe=/usr/bin/su -k setuid
-a always,exit -F arch=b32 -S setresuid -F a0=0 -F exe=/usr/bin/sudo -k setuid

# ── Process execution ─────────────────────────────────────────
-a always,exit -F arch=b64 -S execve -k execve
-a always,exit -F arch=b32 -S execve -k execve

# ── Network activity ──────────────────────────────────────────
-a always,exit -F arch=b64 -S connect -k network_connect
-a always,exit -F arch=b64 -S bind    -k network_bind
-a always,exit -F arch=b32 -S connect -k network_connect
-a always,exit -F arch=b32 -S bind    -k network_bind

# ── File deletion ─────────────────────────────────────────────
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -k file_deletion
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -k file_deletion

# ── Kernel modules ────────────────────────────────────────────
-a always,exit -F arch=b64 -S init_module   -k kernel_module
-a always,exit -F arch=b64 -S finit_module  -k kernel_module
-a always,exit -F arch=b64 -S delete_module -k kernel_module

# ── Time changes ─────────────────────────────────────────────
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time_change
-w /etc/localtime -p wa -k time_change

# ── Crontab ───────────────────────────────────────────────────
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny  -p wa -k cron
-w /etc/cron.d/    -p wa -k cron
-w /etc/crontab    -p wa -k cron
-w /var/spool/cron/crontabs -p wa -k cron

# ── Startup scripts ───────────────────────────────────────────
-w /etc/init.d/ -p wa -k startup
-w /etc/rc.d/   -p wa -k startup
-w /etc/systemd/system/ -p wa -k startup

# ── Audit log tampering ───────────────────────────────────────
-w /var/log/audit/ -p wxa -k audit_log
-w /etc/audit/     -p wa  -k audit_config
-w /sbin/auditctl  -p x   -k audit_tools

# ── LD_PRELOAD injection ──────────────────────────────────────
-w /etc/ld.so.conf.d/ -p wa -k ld_preload
-w /etc/ld.so.preload -p wa -k ld_preload

# Make the config immutable (requires reboot to change)
# -e 2
RULES

log "Audit rules written to $RULES_FILE"

# ── Grant agent read access ───────────────────────────────────
AGENT_USER="siemagt"
if id "$AGENT_USER" &>/dev/null; then
  if command -v setfacl &>/dev/null; then
    setfacl -m u:"$AGENT_USER":r /var/log/audit/audit.log 2>/dev/null && \
      log "ACL granted to $AGENT_USER on /var/log/audit/audit.log" || \
      warn "setfacl failed — add $AGENT_USER to adm group manually"
  else
    usermod -aG adm "$AGENT_USER" 2>/dev/null && \
      log "$AGENT_USER added to adm group" || \
      warn "Could not add $AGENT_USER to adm group"
  fi
else
  warn "Agent user '$AGENT_USER' not found — run agent installer first"
fi

# ── Enable & reload auditd ────────────────────────────────────
systemctl enable auditd
augenrules --load 2>/dev/null || auditctl -R "$RULES_FILE" 2>/dev/null || true
systemctl restart auditd

log "auditd restarted with new rules"
echo
auditctl -l | tail -5
echo
echo -e "${GRN}Done! auditd is collecting system events.${RST}"
echo "  Rules : $RULES_FILE"
echo "  Log   : /var/log/audit/audit.log"
echo "  Test  : auditctl -l | wc -l  (should show 40+ rules)"
"""
