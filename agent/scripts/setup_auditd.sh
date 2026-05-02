#!/usr/bin/env bash
# SecureWatch SIEM Agent — auditd setup
# Installs auditd and loads CIS/STIG-inspired audit rules.
# Run as root: sudo bash setup_auditd.sh
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
error()   { echo -e "${RED}[✗]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo bash $0"

# ── Install auditd ────────────────────────────────────────────────────────────

info "Detecting package manager..."
if   command -v apt-get &>/dev/null; then
    apt-get install -y -q auditd audispd-plugins
elif command -v dnf      &>/dev/null; then
    dnf install -y audit audit-libs
elif command -v yum      &>/dev/null; then
    yum install -y audit audit-libs
else
    error "Unsupported package manager. Install auditd manually."
fi

# ── Write audit rules ─────────────────────────────────────────────────────────

RULES_FILE="/etc/audit/rules.d/securewatch.rules"
info "Writing audit rules to $RULES_FILE..."

cat > "$RULES_FILE" << 'RULES'
## SecureWatch SIEM — Audit Rules
## Based on CIS Benchmark + STIG + MITRE ATT&CK coverage

# Buffer size & failure mode (2=panic on overflow)
-b 8192
-f 1

# ── Identity / authentication ─────────────────────────────────────────────────
-w /etc/passwd       -p wa -k identity
-w /etc/shadow       -p wa -k identity
-w /etc/group        -p wa -k identity
-w /etc/gshadow      -p wa -k identity
-w /etc/sudoers      -p wa -k identity
-w /etc/sudoers.d/   -p wa -k identity

# ── Login/logout events ───────────────────────────────────────────────────────
-w /var/log/faillog  -p wa -k logins
-w /var/log/lastlog  -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock -p wa -k logins

# ── SSH ───────────────────────────────────────────────────────────────────────
-w /etc/ssh/sshd_config -p wa -k sshd_config

# ── Sudo & su ─────────────────────────────────────────────────────────────────
-w /usr/bin/sudo -p x -k privilege_escalation
-w /usr/bin/su   -p x -k privilege_escalation
-w /bin/su       -p x -k privilege_escalation

# ── Privilege escalation syscalls ─────────────────────────────────────────────
-a always,exit -F arch=b64 -S setuid   -S setgid   -S setreuid -S setregid -k setuid
-a always,exit -F arch=b32 -S setuid   -S setgid   -S setreuid -S setregid -k setuid
-a always,exit -F arch=b64 -S setresuid -S setresgid -k setuid
-a always,exit -F arch=b32 -S setresuid -S setresgid -k setuid

# ── Process execution ─────────────────────────────────────────────────────────
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec

# ── Network connections ───────────────────────────────────────────────────────
-a always,exit -F arch=b64 -S connect -k network_connect
-a always,exit -F arch=b32 -S connect -k network_connect
-a always,exit -F arch=b64 -S bind    -k network_bind
-a always,exit -F arch=b32 -S bind    -k network_bind

# ── File deletion ─────────────────────────────────────────────────────────────
-a always,exit -F arch=b64 -S unlink  -S unlinkat -S rename -S renameat -k file_deletion
-a always,exit -F arch=b32 -S unlink  -S unlinkat -S rename -S renameat -k file_deletion

# ── Module loading (rootkit detection) ────────────────────────────────────────
-w /sbin/insmod  -p x -k kernel_modules
-w /sbin/rmmod   -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules
-a always,exit -F arch=b64 -S init_module -S finit_module -S delete_module -k kernel_modules
-a always,exit -F arch=b32 -S init_module -S finit_module -S delete_module -k kernel_modules

# ── Cron ─────────────────────────────────────────────────────────────────────
-w /etc/cron.allow  -p wa -k cron
-w /etc/cron.deny   -p wa -k cron
-w /etc/cron.d/     -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/  -p wa -k cron
-w /etc/crontab     -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# ── Time/date changes ─────────────────────────────────────────────────────────
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time_change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -k time_change
-w /etc/localtime -p wa -k time_change

# ── System locale ────────────────────────────────────────────────────────────
-w /etc/locale.conf  -p wa -k system_locale
-w /etc/timezone     -p wa -k system_locale

# ── Startup scripts / persistence ────────────────────────────────────────────
-w /etc/init.d/      -p wa -k init
-w /etc/rc.d/        -p wa -k init
-w /etc/rc.local     -p wa -k init
-w /etc/systemd/     -p wa -k systemd
-w /lib/systemd/     -p wa -k systemd
-w /usr/lib/systemd/ -p wa -k systemd

# ── LD_PRELOAD hijack ─────────────────────────────────────────────────────────
-w /etc/ld.so.conf     -p wa -k ld_preload
-w /etc/ld.so.conf.d/  -p wa -k ld_preload
-w /etc/ld.so.preload  -p wa -k ld_preload

# ── Audit log tampering ───────────────────────────────────────────────────────
-w /var/log/audit/   -p wa -k audit_logs
-w /etc/audit/       -p wa -k audit_config

# ── Immutable: lock rules until reboot ───────────────────────────────────────
# Uncomment in production:
# -e 2
RULES

# ── Apply rules ───────────────────────────────────────────────────────────────

info "Loading audit rules..."
augenrules --load 2>/dev/null || auditctl -R "$RULES_FILE"

# ── Enable & start auditd ─────────────────────────────────────────────────────

info "Enabling auditd service..."
systemctl enable auditd
systemctl restart auditd

# ── Permissions for agent to read audit.log ───────────────────────────────────

AGENT_USER="${SUDO_USER:-root}"
info "Granting $AGENT_USER read access to audit log..."

# Add user to adm group (Ubuntu) or audit group (RHEL)
if getent group adm &>/dev/null; then
    usermod -aG adm "$AGENT_USER" && info "Added $AGENT_USER to adm group"
fi
if getent group audit &>/dev/null; then
    usermod -aG audit "$AGENT_USER" && info "Added $AGENT_USER to audit group"
fi

chmod 640 /var/log/audit/audit.log 2>/dev/null || true
setfacl -m u:"$AGENT_USER":r /var/log/audit/audit.log 2>/dev/null && \
    info "ACL set: $AGENT_USER can read audit.log" || \
    warn "setfacl not available — agent may need root or adm group"

info "auditd setup complete. Rules loaded: $(auditctl -l | wc -l)"
echo ""
echo "  Test: sudo ausearch -k exec | tail -5"
echo "  Logs: /var/log/audit/audit.log"
