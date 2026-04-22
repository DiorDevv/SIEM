"""
Agent installer endpoint.

Serves:
  GET /api/installer/linux         bash installer script
  GET /api/installer/windows       PowerShell installer script
  GET /api/installer/docker        docker-compose snippet
  GET /api/installer/agent.tar.gz  agent source archive (requires agent vol-mount)
"""
import io
import os
import tarfile
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response, StreamingResponse

from routes.auth import get_current_user
from models.user import User

router = APIRouter(prefix="/api/installer", tags=["installer"])

# Agent directory: mounted into container as /app/agent, fallback for local dev
_AGENT_DIR = Path(os.getenv("AGENT_DIR", "/app/agent"))
if not _AGENT_DIR.exists():
    _AGENT_DIR = Path(__file__).resolve().parents[2] / "agent"


# ── helpers ───────────────────────────────────────────────────────────────────

def _ok(user: User = Depends(get_current_user)) -> User:
    return user


# ── Linux bash installer ──────────────────────────────────────────────────────

def _linux_script(manager_url: str, agent_name: str) -> str:
    return f"""\
#!/usr/bin/env bash
# ============================================================
#  SecureWatch SIEM — Agent Installer
#  Supports: Ubuntu 20+/22+, Debian 11+, CentOS/RHEL 8+,
#            Amazon Linux 2/2023, Fedora 36+
# ============================================================
set -euo pipefail

# ── config ───────────────────────────────────────────────────
MANAGER_URL="{manager_url}"
AGENT_NAME="{agent_name}"
INSTALL_DIR="/opt/siem-agent"
SERVICE_NAME="siem-agent"
SERVICE_USER="siemagt"
PYTHON_MIN_MAJOR=3
PYTHON_MIN_MINOR=8
LOG_FILE="/var/log/siem-agent-install.log"

# ── colours ──────────────────────────────────────────────────
RED="\\033[0;31m"; GRN="\\033[0;32m"; YLW="\\033[1;33m"
BLU="\\033[0;34m"; CYN="\\033[0;36m"; BLD="\\033[1m"; RST="\\033[0m"

log()  {{ echo -e "${{GRN}}[✓]${{RST}} $*"   | tee -a "$LOG_FILE"; }}
warn() {{ echo -e "${{YLW}}[!]${{RST}} $*"   | tee -a "$LOG_FILE"; }}
err()  {{ echo -e "${{RED}}[✗]${{RST}} $*" >&2 | tee -a "$LOG_FILE"; exit 1; }}
step() {{ echo -e "\\n${{BLU}}[${{BLD}}${{1}}${{RST}}${{BLU}}]${{RST}} ${{2:-}}"; }}

banner() {{
  echo -e "${{CYN}}"
  echo "  ╔══════════════════════════════════════════╗"
  echo "  ║   SecureWatch SIEM  ·  Agent Installer   ║"
  echo "  ╚══════════════════════════════════════════╝"
  echo -e "${{RST}}"
}}

# ── preflight ────────────────────────────────────────────────
preflight() {{
  step "1/6" "Pre-flight checks"
  [[ $EUID -eq 0 ]] || err "Run as root: sudo bash $0"

  # Connectivity
  if command -v curl &>/dev/null; then
    curl -sf --max-time 5 "$MANAGER_URL/api/health" -o /dev/null \
      || warn "Cannot reach $MANAGER_URL — check firewall/URL and re-run"
  fi

  # Disk space (200 MB minimum)
  local avail
  avail=$(df -m /opt 2>/dev/null | awk 'NR==2{{print $4}}' || echo 9999)
  (( avail >= 200 )) || err "Less than 200 MB free on /opt"

  log "Pre-flight OK"
}}

# ── OS detection & Python install ────────────────────────────
install_python() {{
  step "2/6" "Checking Python ${{PYTHON_MIN_MAJOR}}.${{PYTHON_MIN_MINOR}}+"

  local py_bin=""
  for cmd in python3.12 python3.11 python3.10 python3.9 python3.8 python3; do
    if command -v "$cmd" &>/dev/null; then
      local ver; ver=$($cmd -c 'import sys; print(sys.version_info[:2])' 2>/dev/null || true)
      # quick check: major.minor >= 3.8
      if $cmd -c \
        "import sys; sys.exit(0 if sys.version_info>=(3,8) else 1)" 2>/dev/null; then
        py_bin="$cmd"; break
      fi
    fi
  done

  if [[ -z "$py_bin" ]]; then
    warn "Python 3.8+ not found — installing..."

    if   command -v apt-get &>/dev/null; then
      apt-get update -qq
      apt-get install -y python3 python3-pip python3-venv curl tar
    elif command -v dnf &>/dev/null; then
      dnf install -y python3 python3-pip tar curl
    elif command -v yum &>/dev/null; then
      yum install -y python3 python3-pip tar curl
    elif command -v pacman &>/dev/null; then
      pacman -Sy --noconfirm python python-pip
    else
      err "Cannot install Python: unknown package manager"
    fi
    py_bin="python3"
  fi

  PYTHON="$py_bin"
  log "Using $($PYTHON --version)"
}}

# ── create system user ───────────────────────────────────────
create_user() {{
  if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null || true
    log "System user '$SERVICE_USER' created"
  fi
}}

# ── download & extract agent ─────────────────────────────────
install_agent() {{
  step "3/6" "Downloading agent"

  mkdir -p "$INSTALL_DIR"

  # Download archive
  local archive="/tmp/siem-agent.tar.gz"
  if command -v curl &>/dev/null; then
    curl -fsSL --max-time 60 \
      "$MANAGER_URL/api/installer/agent.tar.gz" \
      -o "$archive" || err "Download failed"
  else
    wget -q --timeout=60 -O "$archive" \
      "$MANAGER_URL/api/installer/agent.tar.gz" || err "Download failed (wget)"
  fi

  tar -xzf "$archive" -C "$INSTALL_DIR" --strip-components=0
  rm -f "$archive"
  log "Agent extracted to $INSTALL_DIR"
}}

# ── virtual environment & dependencies ───────────────────────
setup_venv() {{
  step "4/6" "Setting up virtual environment"

  if [[ ! -d "$INSTALL_DIR/venv" ]]; then
    $PYTHON -m venv "$INSTALL_DIR/venv"
  fi

  "$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
  "$INSTALL_DIR/venv/bin/pip" install --quiet \
    -r "$INSTALL_DIR/requirements.txt"

  log "Dependencies installed"
}}

# ── config file ──────────────────────────────────────────────
write_config() {{
  step "5/6" "Writing configuration"

  cat > "$INSTALL_DIR/config.yaml" <<YAML
manager_url: $MANAGER_URL
agent_name: $AGENT_NAME
check_interval: 60
heartbeat_interval: 30
fim_interval: 300
rootcheck_interval: 3600
process_interval: 30
network_interval: 30
auditd_interval: 30
vuln_interval: 3600
sca_interval: 3600
batch_size: 100
log_level: INFO

log_paths:
  - /var/log/syslog
  - /var/log/auth.log
  - /var/log/kern.log
  - /var/log/messages

fim_paths:
  - /etc/passwd
  - /etc/shadow
  - /etc/hosts
  - /etc/crontab
  - /etc/sudoers
  - /etc/ssh/sshd_config
YAML

  chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
  log "Config written to $INSTALL_DIR/config.yaml"
}}

# ── systemd service ──────────────────────────────────────────
setup_service() {{
  step "6/6" "Installing systemd service"

  cat > "/etc/systemd/system/$SERVICE_NAME.service" <<UNIT
[Unit]
Description=SecureWatch SIEM Agent
Documentation=https://github.com/securewatch/siem
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/agent.py
Restart=on-failure
RestartSec=10s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_NAME
Environment=PYTHONUNBUFFERED=1
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  systemctl enable  "$SERVICE_NAME"
  systemctl restart "$SERVICE_NAME"

  sleep 2
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    log "Service '$SERVICE_NAME' is running"
  else
    warn "Service did not start — check: journalctl -u $SERVICE_NAME -n 50"
  fi
}}

# ── uninstall helper ─────────────────────────────────────────
uninstall() {{
  echo -e "${{YLW}}Uninstalling SecureWatch agent...${{RST}}"
  systemctl stop    "$SERVICE_NAME" 2>/dev/null || true
  systemctl disable "$SERVICE_NAME" 2>/dev/null || true
  rm -f "/etc/systemd/system/$SERVICE_NAME.service"
  systemctl daemon-reload
  rm -rf "$INSTALL_DIR"
  userdel "$SERVICE_USER" 2>/dev/null || true
  echo "Done."
  exit 0
}}

# ── entrypoint ───────────────────────────────────────────────
main() {{
  [[ "${{1:-}}" == "--uninstall" ]] && uninstall

  exec > >(tee -a "$LOG_FILE") 2>&1
  banner
  echo "  Manager : $MANAGER_URL"
  echo "  Agent   : $AGENT_NAME"
  echo "  Dir     : $INSTALL_DIR"
  echo

  preflight
  install_python
  create_user
  install_agent
  setup_venv
  write_config
  setup_service

  echo
  echo -e "${{GRN}}${{BLD}}════════════════════════════════════════════${{RST}}"
  echo -e "${{GRN}}${{BLD}}  Agent installed successfully!              ${{RST}}"
  echo -e "${{GRN}}${{BLD}}════════════════════════════════════════════${{RST}}"
  echo
  echo "  Status : systemctl status $SERVICE_NAME"
  echo "  Logs   : journalctl -u $SERVICE_NAME -f"
  echo "  Config : $INSTALL_DIR/config.yaml"
  echo "  Remove : bash $0 --uninstall"
  echo
}}

main "$@"
"""


# ── Windows PowerShell installer ─────────────────────────────────────────────

def _windows_script(manager_url: str, agent_name: str) -> str:
    return f"""\
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SecureWatch SIEM Agent Installer for Windows
.DESCRIPTION
    Installs the SecureWatch SIEM agent as a Windows service.
    Supports Windows 10/11, Windows Server 2016/2019/2022.
.NOTES
    Run in an elevated PowerShell:
    Set-ExecutionPolicy Bypass -Scope Process -Force
    .\\install.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

# ── config ───────────────────────────────────────────────────
$ManagerUrl  = "{manager_url}"
$AgentName   = "{agent_name}"
$InstallDir  = "C:\\ProgramData\\SIEMAgent"
$ServiceName = "SIEMAgent"
$ServiceDesc = "SecureWatch SIEM Monitoring Agent"
$PythonMin   = [Version]"3.8"
$LogFile     = "$InstallDir\\install.log"

# ── helpers ──────────────────────────────────────────────────
function Write-Step   {{ param($n, $m) Write-Host "`n[$n] $m" -ForegroundColor Cyan }}
function Write-Ok     {{ param($m) Write-Host "  [+] $m" -ForegroundColor Green }}
function Write-Warn   {{ param($m) Write-Host "  [!] $m" -ForegroundColor Yellow }}
function Write-Fail   {{ param($m) throw "  [x] $m" }}

function Invoke-Step {{
    param([string]$Desc, [scriptblock]$Action)
    try   {{ & $Action; Write-Ok $Desc }}
    catch {{ Write-Fail "$Desc — $_" }}
}}

# ── banner ───────────────────────────────────────────────────
Clear-Host
Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║   SecureWatch SIEM  ·  Agent Installer   ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host "  Manager : $ManagerUrl"
Write-Host "  Agent   : $AgentName"
Write-Host "  Dir     : $InstallDir`n"

# ── pre-flight ───────────────────────────────────────────────
Write-Step "1/5" "Pre-flight checks"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{
    Write-Fail "Run as Administrator"
}}

try {{
    $health = Invoke-RestMethod -Uri "$ManagerUrl/api/health" -TimeoutSec 5
    Write-Ok "Manager reachable (status: $($health.status))"
}} catch {{
    Write-Warn "Cannot reach $ManagerUrl — check URL/firewall"
}}

# Ensure log dir
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Start-Transcript -Path $LogFile -Append | Out-Null

# ── Python ───────────────────────────────────────────────────
Write-Step "2/5" "Checking Python $PythonMin+"

$python = $null
foreach ($cmd in @('python', 'python3', 'py')) {{
    try {{
        $ver = & $cmd --version 2>&1
        if ($ver -match '(\\d+\\.\\d+\\.\\d+)') {{
            $v = [Version]$Matches[1]
            if ($v -ge $PythonMin) {{ $python = $cmd; break }}
        }}
    }} catch {{ }}
}}

if (-not $python) {{
    Write-Warn "Python $PythonMin+ not found. Attempting install via winget..."
    try {{
        winget install --id Python.Python.3.11 --silent --accept-package-agreements --accept-source-agreements
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("Path","User")
        $python = 'python'
        Write-Ok "Python installed via winget"
    }} catch {{
        Write-Fail "Could not install Python automatically.`nDownload from https://www.python.org/downloads/ and re-run."
    }}
}}
Write-Ok "Using $(& $python --version)"

# ── Download agent ───────────────────────────────────────────
Write-Step "3/5" "Downloading agent"

$archive = "$env:TEMP\\siem-agent.tar.gz"
Invoke-WebRequest -Uri "$ManagerUrl/api/installer/agent.tar.gz" `
    -OutFile $archive -UseBasicParsing -TimeoutSec 60

# Extract (requires tar.exe — available on Win 10 1803+)
Push-Location $InstallDir
try   {{ tar -xzf $archive --strip-components=0 2>&1 | Out-Null }}
catch {{ Write-Fail "Extraction failed. Requires Windows 10 1803+ or tar.exe in PATH." }}
Pop-Location
Remove-Item $archive -Force
Write-Ok "Agent extracted to $InstallDir"

# ── venv & deps ──────────────────────────────────────────────
Write-Step "4/5" "Setting up virtual environment"

if (-not (Test-Path "$InstallDir\\venv")) {{
    & $python -m venv "$InstallDir\\venv" | Out-Null
}}
& "$InstallDir\\venv\\Scripts\\pip.exe" install --quiet --upgrade pip
& "$InstallDir\\venv\\Scripts\\pip.exe" install --quiet -r "$InstallDir\\requirements.txt"
Write-Ok "Dependencies installed"

# ── config ───────────────────────────────────────────────────
$config = @"
manager_url: $ManagerUrl
agent_name: $AgentName
check_interval: 60
heartbeat_interval: 30
fim_interval: 300
rootcheck_interval: 3600
process_interval: 30
network_interval: 30
batch_size: 100
log_level: INFO

log_paths: []

fim_paths:
  - C:\\Windows\\System32\\drivers\\etc\\hosts
  - C:\\Windows\\System32\\drivers\\etc\\services

windows_event_logs:
  - Security
  - System
  - Application
windows_events_max: 500
"@
$config | Set-Content "$InstallDir\\config.yaml" -Encoding UTF8
Write-Ok "Config written to $InstallDir\\config.yaml"

# ── Windows Service ──────────────────────────────────────────
Write-Step "5/5" "Installing Windows service"

$exePath = "$InstallDir\\venv\\Scripts\\python.exe"
$agentScript = "$InstallDir\\agent.py"

# Remove old service if exists
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {{
    Stop-Service  -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}}

# Use sc.exe to create the service
# We wrap via cmd /c to handle the python script launch
$binPath = "`"$exePath`" `"$agentScript`""
sc.exe create $ServiceName binPath= $binPath `
    start= auto obj= "LocalSystem" DisplayName= $ServiceDesc | Out-Null

sc.exe description $ServiceName $ServiceDesc | Out-Null
sc.exe failure $ServiceName reset= 60 actions= restart/10000/restart/10000/restart/30000 | Out-Null

Start-Service -Name $ServiceName
Start-Sleep -Seconds 3

$svc = Get-Service -Name $ServiceName
if ($svc.Status -eq 'Running') {{
    Write-Ok "Service '$ServiceName' is running"
}} else {{
    Write-Warn "Service status: $($svc.Status) — check Event Viewer"
}}

Stop-Transcript | Out-Null

Write-Host "`n  ══════════════════════════════════════════" -ForegroundColor Green
Write-Host "    Agent installed successfully!" -ForegroundColor Green
Write-Host "  ══════════════════════════════════════════`n" -ForegroundColor Green
Write-Host "  Status : Get-Service $ServiceName"
Write-Host "  Logs   : Get-EventLog -LogName Application -Source $ServiceName -Newest 50"
Write-Host "  Config : $InstallDir\\config.yaml"
Write-Host "  Remove : sc.exe stop $ServiceName; sc.exe delete $ServiceName`n"
"""


# ── Docker compose snippet ────────────────────────────────────────────────────

def _docker_snippet(manager_url: str, agent_name: str) -> str:
    return f"""\
# Add this to your docker-compose.yml OR run standalone:
#
#   docker compose --profile agent up -d
#
# Standalone (no docker-compose):
#
#   docker run -d \\
#     --name siem-agent \\
#     --restart unless-stopped \\
#     -e MANAGER_URL={manager_url} \\
#     -e AGENT_NAME={agent_name} \\
#     -v /var/log:/var/log:ro \\
#     -v /etc:/etc:ro \\
#     -v /proc:/host/proc:ro \\
#     securewatch/siem-agent:latest

services:
  agent:
    build:
      context: ./agent
      dockerfile: Dockerfile
    container_name: {agent_name.replace(' ', '-').lower()}
    restart: unless-stopped
    environment:
      MANAGER_URL: {manager_url}
      AGENT_NAME: {agent_name}
    volumes:
      - /var/log:/var/log:ro
      - /etc:/etc:ro
    networks:
      - siem-net
    depends_on:
      backend:
        condition: service_healthy

networks:
  siem-net:
    external: true
"""


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/linux")
async def linux_installer(
    manager_url: str = Query(..., description="SIEM backend URL"),
    agent_name:  str = Query("my-agent", description="Agent hostname/name"),
    _: User = Depends(_ok),
):
    script = _linux_script(manager_url.rstrip("/"), agent_name)
    return Response(
        content=script,
        media_type="text/x-shellscript",
        headers={"Content-Disposition": 'attachment; filename="install-siem-agent.sh"'},
    )


@router.get("/windows")
async def windows_installer(
    manager_url: str = Query(...),
    agent_name:  str = Query("my-agent"),
    _: User = Depends(_ok),
):
    script = _windows_script(manager_url.rstrip("/"), agent_name)
    return Response(
        content=script,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="Install-SIEMAgent.ps1"'},
    )


@router.get("/docker")
async def docker_snippet(
    manager_url: str = Query(...),
    agent_name:  str = Query("my-agent"),
    _: User = Depends(_ok),
):
    return Response(content=_docker_snippet(manager_url.rstrip("/"), agent_name),
                    media_type="text/yaml")


@router.get("/agent.tar.gz")
async def agent_archive(_: User = Depends(_ok)):
    """Stream the agent directory as a gzipped tarball."""
    if not _AGENT_DIR.exists():
        from fastapi import HTTPException
        raise HTTPException(
            status_code=503,
            detail=f"Agent directory not found at {_AGENT_DIR}. "
                   "Mount ./agent into the container as /app/agent.",
        )

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path in sorted(_AGENT_DIR.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and not path.name.endswith(".pyc"):
                tar.add(path, arcname=path.relative_to(_AGENT_DIR))
    buf.seek(0)

    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="application/gzip",
        headers={"Content-Disposition": 'attachment; filename="siem-agent.tar.gz"'},
    )
