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

from fastapi import APIRouter, Query
from fastapi.responses import Response, StreamingResponse

router = APIRouter(prefix="/api/installer", tags=["installer"])

# Agent directory: mounted into container as /app/agent, fallback for local dev
_AGENT_DIR = Path(os.getenv("AGENT_DIR", "/app/agent"))
if not _AGENT_DIR.exists():
    _AGENT_DIR = Path(__file__).resolve().parents[2] / "agent"


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
    Installs the SecureWatch SIEM agent as a proper Windows service via pywin32.
    Supports Windows 10/11, Windows Server 2016/2019/2022.
.NOTES
    Run in an elevated PowerShell:
    Set-ExecutionPolicy Bypass -Scope Process -Force
    .\\Install-SIEMAgent.ps1
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
function Write-Step {{ param($n, $m) Write-Host "`n[$n] $m" -ForegroundColor Cyan }}
function Write-Ok   {{ param($m) Write-Host "  [+] $m" -ForegroundColor Green }}
function Write-Warn {{ param($m) Write-Host "  [!] $m" -ForegroundColor Yellow }}
function Write-Fail {{ param($m) throw "[x] $m" }}

# ── banner ───────────────────────────────────────────────────
Write-Host "`n  +==========================================+" -ForegroundColor Cyan
Write-Host "  |   SecureWatch SIEM  -  Agent Installer   |" -ForegroundColor Cyan
Write-Host "  +==========================================+`n" -ForegroundColor Cyan
Write-Host "  Manager : $ManagerUrl"
Write-Host "  Agent   : $AgentName"
Write-Host "  Dir     : $InstallDir`n"

# ── pre-flight ───────────────────────────────────────────────
Write-Step "1/5" "Pre-flight checks"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{
    Write-Fail "Script must run as Administrator. Right-click PowerShell -> Run as Administrator."
}}

try {{
    $health = Invoke-RestMethod -Uri "$ManagerUrl/api/health" -TimeoutSec 8 -UseBasicParsing
    Write-Ok "Manager reachable (status: $($health.status))"
}} catch {{
    Write-Warn "Cannot reach $ManagerUrl - continuing anyway. Check URL/firewall after install."
}}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Start-Transcript -Path $LogFile -Append -ErrorAction SilentlyContinue | Out-Null
Write-Ok "Pre-flight passed"

# ── Python ───────────────────────────────────────────────────
Write-Step "2/5" "Checking Python $PythonMin+"

$python = $null
foreach ($cmd in @('python', 'python3', 'py')) {{
    try {{
        $ver = & $cmd --version 2>&1
        if ($ver -match '(\\d+\\.\\d+\\.\\d+)') {{
            if ([Version]$Matches[1] -ge $PythonMin) {{ $python = $cmd; break }}
        }}
    }} catch {{ }}
}}

if (-not $python) {{
    Write-Warn "Python $PythonMin+ not found — installing via winget..."
    try {{
        winget install --id Python.Python.3.11 --silent --accept-package-agreements --accept-source-agreements
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("Path","User")
        $python = 'python'
        Write-Ok "Python installed via winget"
    }} catch {{
        Write-Fail "Cannot install Python automatically.`nInstall from https://www.python.org/downloads/ (check 'Add Python to PATH') then re-run."
    }}
}}
Write-Ok "Using $(& $python --version)"

# ── Download agent archive ────────────────────────────────────
Write-Step "3/5" "Downloading agent"

$archive = "$env:TEMP\\siem-agent.tar.gz"
try {{
    Invoke-WebRequest -Uri "$ManagerUrl/api/installer/agent.tar.gz" `
        -OutFile $archive -UseBasicParsing -TimeoutSec 90
}} catch {{
    Write-Fail "Download failed: $_`nEnsure the SIEM server is running and port 8000 is reachable."
}}

# tar.exe is built-in on Windows 10 1803+ (build 17063+)
try {{
    Push-Location $InstallDir
    tar -xzf $archive --strip-components=0 2>&1 | Out-Null
    Pop-Location
}} catch {{
    Pop-Location
    Write-Fail "Extraction failed. Requires Windows 10 build 17063+ (tar.exe). Error: $_"
}}
Remove-Item $archive -Force -ErrorAction SilentlyContinue
Write-Ok "Agent extracted to $InstallDir"

# ── Virtual environment + dependencies ───────────────────────
Write-Step "4/5" "Setting up virtual environment + dependencies"

$venvPython = "$InstallDir\\venv\\Scripts\\python.exe"
$venvPip    = "$InstallDir\\venv\\Scripts\\pip.exe"

if (-not (Test-Path "$InstallDir\\venv")) {{
    & $python -m venv "$InstallDir\\venv"
    Write-Ok "Virtual environment created"
}}

& $venvPython -m pip install --quiet --upgrade pip | Out-Null
& $venvPython -m pip install -r "$InstallDir\\requirements.txt"
if ($LASTEXITCODE -ne 0) {{
    Write-Fail "Dependency installation failed (exit $LASTEXITCODE). Check pip output above."
}}
Write-Ok "Python packages installed (including pywin32)"

# ── pywin32 DLL registration ─────────────────────────────────
# Windows SCM launches pythonservice.exe in a restricted environment.
# It needs pywintypes3XX.dll AND python3XX.dll in System32.
# We copy both sets explicitly since we have admin rights here.

# 1. pywin32 DLLs (pywintypes314.dll, pythoncom314.dll, etc.)
$pywin32DllSrc = "$InstallDir\\venv\\Lib\\site-packages\\pywin32_system32"
if (Test-Path $pywin32DllSrc) {{
    Get-ChildItem $pywin32DllSrc -Filter "*.dll" | ForEach-Object {{
        Copy-Item $_.FullName "$env:SystemRoot\\System32\\" -Force -ErrorAction SilentlyContinue
        Write-Ok "Registered: $($_.Name)"
    }}
}} else {{
    Write-Warn "pywin32_system32 dir not found — DLLs may be missing"
}}

# 2. Python runtime DLL (python314.dll) — per-user installs put this outside System32
$basePython = & $venvPython -c "import sys; print(sys.base_prefix)"
if ($basePython) {{
    Get-ChildItem $basePython -Filter "python*.dll" -ErrorAction SilentlyContinue | ForEach-Object {{
        Copy-Item $_.FullName "$env:SystemRoot\\System32\\" -Force -ErrorAction SilentlyContinue
        Write-Ok "Registered: $($_.Name)"
    }}
}}

# 3. Run pywin32_postinstall to register the Event Log source
$pw32Candidates = @(
    "$InstallDir\\venv\\Scripts\\pywin32_postinstall.py",
    "$InstallDir\\venv\\Lib\\site-packages\\pywin32_postinstall.py"
)
$pw32PostInstall = $pw32Candidates | Where-Object {{ Test-Path $_ }} | Select-Object -First 1
if ($pw32PostInstall) {{
    & $venvPython $pw32PostInstall -install 2>&1 | Out-Null
    Write-Ok "pywin32 post-install complete"
}} else {{
    & $venvPython -c "import pywin32_postinstall; pywin32_postinstall.install()" 2>&1 | Out-Null
    Write-Ok "pywin32 post-install complete (module mode)"
}}

# ── Write config.yaml ─────────────────────────────────────────
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

fim_realtime_paths:
  - C:\\Windows\\System32\\drivers\\etc
  - C:\\Users
  - C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup

windows_event_logs:
  - Security
  - System
  - Application
  - Microsoft-Windows-PowerShell/Operational

windows_events_max: 500
sysmon_enabled: true
registry_fim_interval: 120
service_monitor_interval: 120

buffer_max_batches: 2000
buffer_ttl_hours: 48
buffer_drain_interval: 30
dedup_window: 60
geoip_enabled: false

exclusions:
  message_contains: []
  source_ends_with: []
  event_types: []
  log_levels: []
"@
$config | Set-Content "$InstallDir\\config.yaml" -Encoding UTF8
Write-Ok "config.yaml written to $InstallDir"

# ── Register agent as Windows Scheduled Task (SYSTEM, auto-start) ─────────────────
Write-Step "5/5" "Registering agent as Windows Scheduled Task (SYSTEM)"

# Clean up any legacy service or task
$oldSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($oldSvc) {{
    Write-Warn "Existing service found — removing..."
    Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep 2
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep 1
    Write-Ok "Old service removed"
}}
Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false -ErrorAction SilentlyContinue

# Join-Path avoids Python f-string backslash-escape pitfalls entirely
$logFile = Join-Path $InstallDir "agent.log"
$agentPy = Join-Path $InstallDir "agent.py"
$cmdFile = Join-Path $InstallDir "run_agent.cmd"

# Write .cmd launcher — Set-Content adds CRLF; PowerShell expands $logFile etc.
@(
    "@echo off",
    "set DATA_DIR=$InstallDir",
    "set PYTHONUNBUFFERED=1",
    "cd /d `"$InstallDir`"",
    "echo [%DATE% %TIME%] SIEMAgent starting >> `"$logFile`"",
    "`"$venvPython`" `"$agentPy`" >> `"$logFile`" 2>&1",
    "echo [%DATE% %TIME%] SIEMAgent stopped exit=%ERRORLEVEL% >> `"$logFile`""
) | Set-Content $cmdFile -Encoding ASCII
Write-Ok "Launcher written: $cmdFile"

# ── Smoke test: run as current admin to verify Python can actually start ──────────
Write-Warn "Smoke-testing Python (5 s)..."
$testProc = Start-Process -FilePath $env:ComSpec `
    -ArgumentList ('/c "{0}"' -f $cmdFile) `
    -WorkingDirectory $InstallDir -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 5
if (Test-Path $logFile) {{
    Write-Ok "agent.log created — Python launched OK:"
    Get-Content $logFile -TotalCount 6 -ErrorAction SilentlyContinue |
        ForEach-Object {{ Write-Host "     $_" }}
}} else {{
    Write-Warn "agent.log missing — Python may have crashed on import"
    Write-Warn ('Debug: & "{0}" "{1}"' -f $venvPython, $agentPy)
}}
if ($testProc -and -not $testProc.HasExited) {{ $testProc.Kill() }}
Remove-Item $logFile -ErrorAction SilentlyContinue   # SYSTEM task will recreate it

# ── Register scheduled task ───────────────────────────────────────────────────────
$action = New-ScheduledTaskAction `
    -Execute $env:ComSpec `
    -Argument ('/c "{0}"' -f $cmdFile) `
    -WorkingDirectory $InstallDir

$trigger  = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 10 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew
$settings.DisallowStartIfOnBatteries = $false
$settings.StopIfGoingOnBatteries     = $false
$settings.RunOnlyIfNetworkAvailable  = $false
$settings.RunOnlyIfIdle              = $false

$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask `
    -TaskName $ServiceName -Description $ServiceDesc `
    -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal -Force | Out-Null
Write-Ok "Task registered: $ServiceName"

# ── Start the task now ────────────────────────────────────────────────────────────
Start-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue
Start-Sleep -Seconds 6

$task  = Get-ScheduledTask     -TaskName $ServiceName -ErrorAction SilentlyContinue
$tInfo = Get-ScheduledTaskInfo -TaskName $ServiceName -ErrorAction SilentlyContinue
$state = if ($task) {{ $task.State }} else {{ 'not found' }}

if ($state -eq 'Running') {{
    Write-Ok "Task '$ServiceName' is RUNNING"
}} else {{
    $code = if ($tInfo) {{ ' (0x{{0:X}})' -f [int]$tInfo.LastTaskResult }} else {{ '' }}
    Write-Warn "State: $state$code — trying once more..."
    Start-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 4
    $state2 = (Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue).State
    if ($state2 -eq 'Running') {{
        Write-Ok "Task '$ServiceName' is now RUNNING"
    }} else {{
        Write-Warn "State: $state2 — task will auto-start on next boot."
        Write-Warn ('Start now : Start-ScheduledTask {0}' -f $ServiceName)
        Write-Warn ('Test run  : & "{0}" "{1}"' -f $venvPython, $agentPy)
        Write-Warn ('Logs      : Get-Content "{0}" -Tail 30 -Wait' -f $logFile)
    }}
}}

Stop-Transcript -ErrorAction SilentlyContinue | Out-Null

Write-Host "`n  ===========================================" -ForegroundColor Green
Write-Host "    Agent installed successfully!" -ForegroundColor Green
Write-Host "  ===========================================`n" -ForegroundColor Green
Write-Host "  Status : Get-ScheduledTask $ServiceName"
Write-Host "  Logs   : Get-Content $InstallDir\\agent.log -Tail 50 -Wait"
Write-Host "  Config : $InstallDir\\config.yaml"
Write-Host "  Stop   : Stop-ScheduledTask $ServiceName"
Write-Host "  Remove : Unregister-ScheduledTask $ServiceName -Confirm:`$false`n"
"""


# ── macOS bash installer ──────────────────────────────────────────────────────

def _macos_script(manager_url: str, agent_name: str) -> str:
    return f"""\
#!/usr/bin/env bash
# ============================================================
#  SecureWatch SIEM — Agent Installer for macOS
#  Supports: macOS 12 (Monterey)+, Intel & Apple Silicon
# ============================================================
set -euo pipefail

# ── config ───────────────────────────────────────────────────
MANAGER_URL="{manager_url}"
AGENT_NAME="{agent_name}"
INSTALL_DIR="/Library/Application Support/SIEMAgent"
LABEL="com.securewatch.siem-agent"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
SERVICE_USER="_siemagt"
LOG_FILE="/var/log/siem-agent-install.log"

# ── colours ──────────────────────────────────────────────────
RED="\\033[0;31m"; GRN="\\033[0;32m"; YLW="\\033[1;33m"
BLU="\\033[0;34m"; CYN="\\033[0;36m"; BLD="\\033[1m"; RST="\\033[0m"

log()  {{ echo -e "${{GRN}}[✓]${{RST}} $*"   | tee -a "$LOG_FILE"; }}
warn() {{ echo -e "${{YLW}}[!]${{RST}} $*"   | tee -a "$LOG_FILE"; }}
err()  {{ echo -e "${{RED}}[✗]${{RST}} $*" >&2; exit 1; }}
step() {{ echo -e "\\n${{BLU}}[${{BLD}}${{1}}${{RST}}${{BLU}}]${{RST}} ${{2:-}}"; }}

banner() {{
  echo -e "${{CYN}}"
  echo "  ╔══════════════════════════════════════════╗"
  echo "  ║   SecureWatch SIEM  ·  macOS Installer   ║"
  echo "  ╚══════════════════════════════════════════╝"
  echo -e "${{RST}}"
}}

# ── preflight ────────────────────────────────────────────────
preflight() {{
  step "1/6" "Pre-flight checks"
  [[ $EUID -eq 0 ]] || err "Run as root: sudo bash $0"
  [[ "$(uname -s)" == "Darwin" ]] || err "This installer is for macOS only"

  local os_ver major
  os_ver=$(sw_vers -productVersion)
  major=$(echo "$os_ver" | cut -d. -f1)
  (( major >= 12 )) || warn "macOS $os_ver detected — 12+ recommended"

  if command -v curl &>/dev/null; then
    curl -sf --max-time 5 "$MANAGER_URL/api/health" -o /dev/null \
      || warn "Cannot reach $MANAGER_URL — check firewall/URL and re-run"
  fi
  log "Pre-flight OK (macOS $os_ver)"
}}

# ── Python ───────────────────────────────────────────────────
install_python() {{
  step "2/6" "Checking Python 3.8+"

  local py_bin=""
  for cmd in python3.12 python3.11 python3.10 python3.9 python3.8 python3; do
    if command -v "$cmd" &>/dev/null; then
      if $cmd -c "import sys; sys.exit(0 if sys.version_info>=(3,8) else 1)" 2>/dev/null; then
        py_bin="$cmd"; break
      fi
    fi
  done

  if [[ -z "$py_bin" ]]; then
    warn "Python 3.8+ not found — attempting install via Homebrew..."
    if command -v brew &>/dev/null; then
      brew install python@3.11
      py_bin="$(brew --prefix)/bin/python3.11"
    else
      warn "Homebrew not found. Install from https://brew.sh then re-run."
      warn "Or install Python from https://www.python.org/downloads/macos/"
      err "Python 3.8+ is required"
    fi
  fi

  PYTHON="$py_bin"
  log "Using $($PYTHON --version)"
}}

# ── create system account ────────────────────────────────────
create_user() {{
  step "3/6" "Creating service account"

  if ! id "$SERVICE_USER" &>/dev/null; then
    local uid=300
    while dscl . -list /Users UniqueID 2>/dev/null | awk '{{print $2}}' | grep -q "^${{uid}}$"; do
      (( uid++ ))
    done
    dscl . -create "/Users/$SERVICE_USER"
    dscl . -create "/Users/$SERVICE_USER" UserShell /usr/bin/false
    dscl . -create "/Users/$SERVICE_USER" RealName "SIEM Agent"
    dscl . -create "/Users/$SERVICE_USER" UniqueID "$uid"
    dscl . -create "/Users/$SERVICE_USER" PrimaryGroupID 20
    dscl . -create "/Users/$SERVICE_USER" NFSHomeDirectory /var/empty
    log "System account '$SERVICE_USER' created (UID $uid)"
  else
    log "System account '$SERVICE_USER' already exists"
  fi
}}

# ── download & extract ───────────────────────────────────────
install_agent() {{
  step "4/6" "Downloading agent"
  mkdir -p "$INSTALL_DIR"

  local archive="/tmp/siem-agent.tar.gz"
  curl -fsSL --max-time 60 \
    "$MANAGER_URL/api/installer/agent.tar.gz" \
    -o "$archive" || err "Download failed"

  tar -xzf "$archive" -C "$INSTALL_DIR" --strip-components=0
  rm -f "$archive"
  log "Agent extracted to $INSTALL_DIR"
}}

# ── venv & deps ──────────────────────────────────────────────
setup_venv() {{
  step "5/6" "Setting up virtual environment"

  if [[ ! -d "$INSTALL_DIR/venv" ]]; then
    $PYTHON -m venv "$INSTALL_DIR/venv"
  fi

  "$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
  "$INSTALL_DIR/venv/bin/pip" install --quiet \
    -r "$INSTALL_DIR/requirements.txt"

  chown -R "$SERVICE_USER":staff "$INSTALL_DIR"
  log "Dependencies installed"
}}

# ── config ───────────────────────────────────────────────────
write_config() {{
  cat > "$INSTALL_DIR/config.yaml" <<YAML
manager_url: $MANAGER_URL
agent_name: $AGENT_NAME
check_interval: 60
heartbeat_interval: 30
fim_interval: 300
rootcheck_interval: 3600
process_interval: 30
network_interval: 30
batch_size: 100
log_level: INFO

log_paths:
  - /var/log/system.log
  - /var/log/install.log
  - /Library/Logs/DiagnosticReports

fim_paths:
  - /etc/hosts
  - /etc/sudoers
  - /etc/ssh/sshd_config
  - /Library/LaunchDaemons
  - /Library/LaunchAgents
YAML
  log "Config written to $INSTALL_DIR/config.yaml"
}}

# ── LaunchDaemon ─────────────────────────────────────────────
setup_service() {{
  step "6/6" "Installing LaunchDaemon"

  if launchctl list 2>/dev/null | grep -q "$LABEL"; then
    launchctl unload "$PLIST" 2>/dev/null || true
  fi

  cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$INSTALL_DIR/venv/bin/python</string>
    <string>$INSTALL_DIR/agent.py</string>
  </array>
  <key>UserName</key>
  <string>$SERVICE_USER</string>
  <key>WorkingDirectory</key>
  <string>$INSTALL_DIR</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/var/log/siem-agent.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/siem-agent-error.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PYTHONUNBUFFERED</key>
    <string>1</string>
  </dict>
</dict>
</plist>
PLIST

  chmod 644 "$PLIST"
  chown root:wheel "$PLIST"
  launchctl load -w "$PLIST"
  sleep 2

  if launchctl list 2>/dev/null | grep -q "$LABEL"; then
    log "LaunchDaemon '$LABEL' is running"
  else
    warn "LaunchDaemon may not have started — check: tail -f /var/log/siem-agent.log"
  fi
}}

# ── uninstall ────────────────────────────────────────────────
uninstall() {{
  echo -e "${{YLW}}Uninstalling SecureWatch agent...${{RST}}"
  launchctl unload "$PLIST" 2>/dev/null || true
  rm -f "$PLIST"
  rm -rf "$INSTALL_DIR"
  dscl . -delete "/Users/$SERVICE_USER" 2>/dev/null || true
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
  echo "  Status : launchctl list | grep $LABEL"
  echo "  Logs   : tail -f /var/log/siem-agent.log"
  echo "  Config : $INSTALL_DIR/config.yaml"
  echo "  Remove : sudo bash $0 --uninstall"
  echo
}}

main "$@"
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
# Installer endpoints are intentionally public — they serve only installer scripts
# and agent source code (no secrets). The Windows/Linux scripts need to download
# agent.tar.gz during install without a browser session, so no auth is required.

@router.get("/linux")
async def linux_installer(
    manager_url: str = Query(..., description="SIEM backend URL"),
    agent_name:  str = Query("my-agent", description="Agent hostname/name"),
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
):
    script = _windows_script(manager_url.rstrip("/"), agent_name)
    # UTF-8 BOM tells PowerShell to read as UTF-8 (avoids cp1252 misreads)
    content = "﻿" + script
    return Response(
        content=content.encode("utf-8"),
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="Install-SIEMAgent.ps1"'},
    )


@router.get("/macos")
async def macos_installer(
    manager_url: str = Query(..., description="SIEM backend URL"),
    agent_name:  str = Query("my-agent", description="Agent hostname/name"),
):
    script = _macos_script(manager_url.rstrip("/"), agent_name)
    return Response(
        content=script,
        media_type="text/x-shellscript",
        headers={"Content-Disposition": 'attachment; filename="install-siem-agent-macos.sh"'},
    )


@router.get("/docker")
async def docker_snippet(
    manager_url: str = Query(...),
    agent_name:  str = Query("my-agent"),
):
    return Response(content=_docker_snippet(manager_url.rstrip("/"), agent_name),
                    media_type="text/yaml")


@router.get("/agent.tar.gz")
async def agent_archive():
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
