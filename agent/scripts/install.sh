#!/usr/bin/env bash
# SecureWatch SIEM Agent — Full Installer
# Usage: sudo bash install.sh [MANAGER_URL]
# Example: sudo bash install.sh http://192.168.1.100:8000
set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*"; exit 1; }
section() { echo -e "\n${BOLD}${BLUE}══ $* ══${NC}"; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash $0 [MANAGER_URL]"

MANAGER_URL="${1:-http://localhost:8000}"
INSTALL_DIR="/opt/securewatch-agent"
SERVICE_USER="securewatch"
LOG_DIR="/var/log/securewatch"
VENV_DIR="$INSTALL_DIR/venv"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_SRC="$(dirname "$SCRIPT_DIR")"   # parent of scripts/

# ── System info ───────────────────────────────────────────────────────────────
section "SecureWatch SIEM Agent Installer"
info "Manager URL : $MANAGER_URL"
info "Install dir : $INSTALL_DIR"
info "Agent source: $AGENT_SRC"
info "OS          : $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"' || uname -s)"
echo ""

# ── Dependencies ──────────────────────────────────────────────────────────────
section "Installing system dependencies"

if command -v apt-get &>/dev/null; then
    apt-get update -qq
    apt-get install -y -q python3 python3-pip python3-venv python3-dev \
        libssl-dev libffi-dev acl curl net-tools auditd audispd-plugins
elif command -v dnf &>/dev/null; then
    dnf install -y python3 python3-pip python3-devel openssl-devel libffi-devel \
        acl curl net-tools audit audit-libs
elif command -v yum &>/dev/null; then
    yum install -y python3 python3-pip python3-devel openssl-devel libffi-devel \
        acl curl net-tools audit audit-libs
else
    warn "Unknown package manager — skipping apt/yum install"
fi
info "System dependencies installed"

# ── Service user ──────────────────────────────────────────────────────────────
section "Creating service user"

if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        --comment "SecureWatch SIEM Agent" "$SERVICE_USER"
    info "User '$SERVICE_USER' created"
else
    info "User '$SERVICE_USER' already exists"
fi

# Add to groups for log/audit access
for grp in adm syslog systemd-journal audit; do
    if getent group "$grp" &>/dev/null; then
        usermod -aG "$grp" "$SERVICE_USER"
        info "Added $SERVICE_USER to group $grp"
    fi
done

# ── Directories ───────────────────────────────────────────────────────────────
section "Creating directories"

mkdir -p "$INSTALL_DIR" "$LOG_DIR"
chmod 750 "$INSTALL_DIR" "$LOG_DIR"

# ── Copy agent files ──────────────────────────────────────────────────────────
section "Copying agent files"

rsync -a --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
    --exclude='.pytest_cache' --exclude='venv' --exclude='scripts' \
    "$AGENT_SRC/" "$INSTALL_DIR/"

info "Agent files copied to $INSTALL_DIR"

# ── Python virtualenv ─────────────────────────────────────────────────────────
section "Setting up Python virtualenv"

python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip -q
"$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q
info "Virtualenv created at $VENV_DIR"

# ── config.yaml ───────────────────────────────────────────────────────────────
section "Writing config.yaml"

CONFIG_FILE="$INSTALL_DIR/config.yaml"
if [[ ! -f "$CONFIG_FILE" ]]; then
    cat > "$CONFIG_FILE" << EOF
manager_url: $MANAGER_URL
agent_name: $(hostname)
check_interval: 60
heartbeat_interval: 30
fim_interval: 300
rootcheck_interval: 3600
process_interval: 30
network_interval: 30
auditd_interval: 30
batch_size: 100
log_level: INFO

log_paths:
  - /var/log/syslog
  - /var/log/auth.log
  - /var/log/kern.log
  - /var/log/dpkg.log

fim_paths:
  - /etc/passwd
  - /etc/shadow
  - /etc/group
  - /etc/hosts
  - /etc/crontab
  - /etc/sudoers
  - /etc/ssh/sshd_config
  - /etc/hosts.allow
  - /etc/hosts.deny

fim_realtime_paths:
  - /etc
  - /usr/bin
  - /usr/sbin
  - /bin
  - /sbin

fim_interval: 300

vuln_interval: 3600
sca_interval: 3600
EOF
    info "Config written to $CONFIG_FILE"
else
    info "Config already exists — skipping (edit $CONFIG_FILE manually)"
fi

# ── auditd rules ──────────────────────────────────────────────────────────────
section "Configuring auditd"

if command -v auditd &>/dev/null || systemctl list-unit-files auditd.service &>/dev/null 2>&1; then
    bash "$SCRIPT_DIR/setup_auditd.sh" && info "auditd configured"
else
    warn "auditd not found — skipping (run setup_auditd.sh manually)"
fi

# ── Permissions ───────────────────────────────────────────────────────────────
section "Setting permissions"

chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR" "$LOG_DIR"
chmod 600 "$CONFIG_FILE"

# ACL: allow agent to read log files
for logfile in /var/log/syslog /var/log/auth.log /var/log/kern.log \
               /var/log/audit/audit.log /var/log/dpkg.log; do
    if [[ -f "$logfile" ]]; then
        setfacl -m u:"$SERVICE_USER":r "$logfile" 2>/dev/null && \
            info "ACL: $SERVICE_USER can read $logfile" || true
    fi
done

# ACL on log directories
for logdir in /var/log; do
    setfacl -m u:"$SERVICE_USER":rx "$logdir" 2>/dev/null || true
done

# ── systemd service ───────────────────────────────────────────────────────────
section "Installing systemd service"

SERVICE_DEST="/etc/systemd/system/securewatch-agent.service"
cp "$SCRIPT_DIR/securewatch-agent.service" "$SERVICE_DEST"

# Patch the service file with actual paths
sed -i "s|/opt/securewatch-agent|$INSTALL_DIR|g" "$SERVICE_DEST"
sed -i "s|User=securewatch|User=$SERVICE_USER|g"  "$SERVICE_DEST"
sed -i "s|Group=securewatch|Group=$SERVICE_USER|g" "$SERVICE_DEST"

systemctl daemon-reload
systemctl enable securewatch-agent
systemctl restart securewatch-agent

info "Service installed and started"

# ── Verify ────────────────────────────────────────────────────────────────────
section "Verifying installation"

sleep 3
if systemctl is-active --quiet securewatch-agent; then
    info "✓ securewatch-agent is RUNNING"
else
    warn "Service not running — check logs: journalctl -u securewatch-agent -n 50"
fi

echo ""
echo -e "${BOLD}Installation complete!${NC}"
echo ""
echo "  Status  : systemctl status securewatch-agent"
echo "  Logs    : journalctl -u securewatch-agent -f"
echo "  Config  : $CONFIG_FILE"
echo "  Stop    : systemctl stop securewatch-agent"
echo "  Uninstall: systemctl disable securewatch-agent && rm -rf $INSTALL_DIR"
echo ""
