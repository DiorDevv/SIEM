"""
Security Configuration Assessment (SCA) — CIS Benchmark Level 1 + STIG.
50+ checks covering SSH, kernel, filesystem, auth, services, and networking.
result: "pass" | "fail" | "skip"
"""
import os
import sys
import re
import stat
import logging
import subprocess
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

IS_LINUX   = sys.platform.startswith("linux")
IS_WINDOWS = sys.platform == "win32"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _read(path: str) -> Optional[str]:
    try:
        with open(path) as f:
            return f.read()
    except (FileNotFoundError, PermissionError):
        return None


def _run(cmd: List[str], timeout: int = 10) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except Exception:
        return ""


def _sysctl(key: str) -> Optional[str]:
    out = _run(["sysctl", "-n", key])
    v = out.strip()
    return v if v else None


def _grep_conf(path: str, pattern: str, active_only: bool = True) -> Optional[str]:
    content = _read(path)
    if not content:
        return None
    if active_only:
        # Strip comment lines
        content = "\n".join(
            l for l in content.splitlines() if l.strip() and not l.strip().startswith("#")
        )
    m = re.search(pattern, content, re.MULTILINE | re.IGNORECASE)
    return m.group(0) if m else None


def _file_mode(path: str) -> Optional[str]:
    try:
        return oct(os.stat(path).st_mode)[-4:]
    except Exception:
        return None


def _file_owner(path: str) -> Optional[int]:
    try:
        return os.stat(path).st_uid
    except Exception:
        return None


def _service_active(name: str) -> bool:
    out = _run(["systemctl", "is-active", name])
    return out.strip() == "active"


def _pkg_installed(name: str) -> bool:
    out = _run(["dpkg", "-l", name])
    if "ii" in out:
        return True
    out2 = _run(["rpm", "-q", name])
    return "not installed" not in out2 and bool(out2.strip())


def _chk(id_: str, title: str, result: str, severity: str,
         rationale: str, remediation: str = "") -> Dict[str, Any]:
    return {
        "id":          id_,
        "title":       title,
        "result":      result,
        "severity":    severity,
        "rationale":   rationale,
        "remediation": remediation,
    }


def _pass(id_, title, sev, rationale, fix=""):
    return _chk(id_, title, "pass", sev, rationale, fix)


def _fail(id_, title, sev, rationale, fix=""):
    return _chk(id_, title, "fail", sev, rationale, fix)


def _skip(id_, title, sev, reason):
    return _chk(id_, title, "skip", sev, reason)


# ══════════════════════════════════════════════════════════════════════════════
# SSH Checks
# ══════════════════════════════════════════════════════════════════════════════

_SSHD = "/etc/ssh/sshd_config"


def _ssh(key: str) -> Optional[str]:
    return _grep_conf(_SSHD, rf"^\s*{key}\s+(\S+)")


def chk_ssh_permit_root() -> Dict:
    val = _ssh("PermitRootLogin")
    if val is None:
        return _skip("SSH-001", "SSH: PermitRootLogin disabled", "HIGH", "sshd_config unreadable")
    ok = bool(re.search(r"(no|prohibit-password|forced-commands-only)", val, re.I))
    return (_pass if ok else _fail)(
        "SSH-001", "SSH: PermitRootLogin must not be 'yes'", "HIGH",
        f"Current: '{val.split()[-1]}'. Root SSH login is a critical risk.",
        "PermitRootLogin no",
    )


def chk_ssh_password_auth() -> Dict:
    val = _ssh("PasswordAuthentication")
    if val is None:
        return _skip("SSH-002", "SSH: PasswordAuthentication", "HIGH", "sshd_config unreadable")
    ok = bool(re.search(r"\bno\b", val, re.I))
    return (_pass if ok else _fail)(
        "SSH-002", "SSH: PasswordAuthentication should be 'no'", "HIGH",
        "Key-based auth prevents password brute-force.",
        "PasswordAuthentication no",
    )


def chk_ssh_empty_passwords() -> Dict:
    val = _ssh("PermitEmptyPasswords")
    ok = val is None or bool(re.search(r"\bno\b", val, re.I))
    return (_pass if ok else _fail)(
        "SSH-003", "SSH: PermitEmptyPasswords must be 'no'", "CRITICAL",
        "Empty passwords allow login with no credentials.",
        "PermitEmptyPasswords no",
    )


def chk_ssh_protocol() -> Dict:
    val = _ssh("Protocol")
    ok = val is None or "2" in (val or "")
    return (_pass if ok else _fail)(
        "SSH-004", "SSH: Protocol must be 2", "HIGH",
        "SSHv1 has critical known vulnerabilities.",
        "Protocol 2",
    )


def chk_ssh_max_auth_tries() -> Dict:
    val = _ssh("MaxAuthTries")
    if val is None:
        return _skip("SSH-005", "SSH: MaxAuthTries <= 4", "MEDIUM", "Not set (default 6)")
    m = re.search(r"(\d+)", val)
    tries = int(m.group(1)) if m else 99
    ok = tries <= 4
    return (_pass if ok else _fail)(
        "SSH-005", "SSH: MaxAuthTries should be <= 4", "MEDIUM",
        f"Currently {tries}. Limits brute-force exposure.",
        "MaxAuthTries 4",
    )


def chk_ssh_x11_forwarding() -> Dict:
    val = _ssh("X11Forwarding")
    ok = val is None or bool(re.search(r"\bno\b", val, re.I))
    return (_pass if ok else _fail)(
        "SSH-006", "SSH: X11Forwarding should be disabled", "LOW",
        "X11 forwarding can be exploited to hijack display.",
        "X11Forwarding no",
    )


def chk_ssh_agent_forwarding() -> Dict:
    val = _ssh("AllowAgentForwarding")
    ok = val is None or bool(re.search(r"\bno\b", val, re.I))
    return (_pass if ok else _fail)(
        "SSH-007", "SSH: AllowAgentForwarding should be disabled", "MEDIUM",
        "Agent forwarding allows pivoting via compromised intermediate hosts.",
        "AllowAgentForwarding no",
    )


def chk_ssh_log_level() -> Dict:
    val = _ssh("LogLevel")
    ok = val is None or bool(re.search(r"(INFO|VERBOSE|DEBUG)", val, re.I))
    return (_pass if ok else _fail)(
        "SSH-008", "SSH: LogLevel should be INFO or higher", "LOW",
        "Adequate logging is essential for incident response.",
        "LogLevel INFO",
    )


def chk_ssh_max_sessions() -> Dict:
    val = _ssh("MaxSessions")
    if val is None:
        return _skip("SSH-009", "SSH: MaxSessions <= 10", "LOW", "Not configured")
    m = re.search(r"(\d+)", val)
    n = int(m.group(1)) if m else 10
    ok = n <= 10
    return (_pass if ok else _fail)(
        "SSH-009", f"SSH: MaxSessions should be <= 10 (current {n})", "LOW",
        "Unbounded sessions allow resource exhaustion.",
        "MaxSessions 10",
    )


def chk_ssh_use_pam() -> Dict:
    val = _ssh("UsePAM")
    ok = val is None or bool(re.search(r"\byes\b", val, re.I))
    return (_pass if ok else _fail)(
        "SSH-010", "SSH: UsePAM should be enabled", "MEDIUM",
        "PAM provides centralized auth control and account lockout.",
        "UsePAM yes",
    )


def chk_ssh_tcp_keepalive() -> Dict:
    val = _ssh("TCPKeepAlive")
    ok = val is None or bool(re.search(r"\byes\b", val, re.I))
    return (_pass if ok else _fail)(
        "SSH-011", "SSH: TCPKeepAlive should be yes", "LOW",
        "Prevents stale sessions from holding connections open.",
        "TCPKeepAlive yes",
    )


def chk_ssh_client_alive() -> Dict:
    val = _ssh("ClientAliveInterval")
    if val is None:
        return _skip("SSH-012", "SSH: ClientAliveInterval configured", "LOW", "Not set")
    m = re.search(r"(\d+)", val)
    n = int(m.group(1)) if m else 0
    ok = 0 < n <= 300
    return (_pass if ok else _fail)(
        "SSH-012", f"SSH: ClientAliveInterval should be 1-300 (current {n})", "LOW",
        "Idle session timeout reduces exposure.",
        "ClientAliveInterval 300\nClientAliveCountMax 3",
    )


# ══════════════════════════════════════════════════════════════════════════════
# File Permission Checks
# ══════════════════════════════════════════════════════════════════════════════

def chk_shadow_perms() -> Dict:
    mode = _file_mode("/etc/shadow")
    if mode is None:
        return _skip("FILE-001", "/etc/shadow permissions", "CRITICAL", "Cannot stat")
    ok = mode in ("0640", "0000", "0600")
    return (_pass if ok else _fail)(
        "FILE-001", f"/etc/shadow mode must be <= 640 (current {mode})", "CRITICAL",
        "World-readable shadow exposes password hashes.",
        "chmod 640 /etc/shadow && chown root:shadow /etc/shadow",
    )


def chk_passwd_perms() -> Dict:
    mode = _file_mode("/etc/passwd")
    if mode is None:
        return _skip("FILE-002", "/etc/passwd permissions", "MEDIUM", "Cannot stat")
    ok = mode == "0644"
    return (_pass if ok else _fail)(
        "FILE-002", f"/etc/passwd must be 644 (current {mode})", "MEDIUM",
        "Incorrect permissions can prevent user lookups.",
        "chmod 644 /etc/passwd",
    )


def chk_crontab_perms() -> Dict:
    mode = _file_mode("/etc/crontab")
    if mode is None:
        return _skip("FILE-003", "/etc/crontab permissions", "LOW", "File absent")
    ok = mode in ("0600", "0644")
    return (_pass if ok else _fail)(
        "FILE-003", f"/etc/crontab mode should be 600 (current {mode})", "MEDIUM",
        "World-writable crontab allows persistent backdoors.",
        "chmod 600 /etc/crontab",
    )


def chk_sshd_config_perms() -> Dict:
    mode = _file_mode(_SSHD)
    if mode is None:
        return _skip("FILE-004", "sshd_config permissions", "HIGH", "File absent")
    ok = int(mode, 8) & 0o022 == 0
    return (_pass if ok else _fail)(
        "FILE-004", f"sshd_config must not be group/world writable (current {mode})", "HIGH",
        "Writable sshd_config allows backdooring SSH.",
        "chmod 600 /etc/ssh/sshd_config",
    )


def chk_world_writable_etc() -> Dict:
    out = _run(["find", "/etc", "-maxdepth", "3", "-perm", "-o+w",
                "!", "-type", "l", "-type", "f"], timeout=15)
    found = [l for l in out.splitlines() if l.strip()]
    ok = not found
    detail = f"Found: {found[:5]}" if found else "None found in /etc"
    return (_pass if ok else _fail)(
        "FILE-005", "No world-writable files in /etc", "HIGH", detail,
        "chmod o-w <file> for each listed path",
    )


def chk_no_unowned_files() -> Dict:
    out = _run(["find", "/", "-xdev", "-nouser", "-o", "-nogroup"], timeout=20)
    found = [l for l in out.splitlines() if l.strip()]
    ok = not found
    detail = f"Unowned files: {found[:5]}" if found else "None found"
    return (_pass if ok else _fail)(
        "FILE-006", "No unowned files on filesystem", "MEDIUM", detail,
        "chown root:root <file> or investigate orphaned files",
    )


def chk_sticky_bit_tmp() -> Dict:
    try:
        mode = os.stat("/tmp").st_mode
        ok = bool(mode & stat.S_ISVTX)
    except Exception:
        return _skip("FILE-007", "/tmp has sticky bit", "MEDIUM", "Cannot stat /tmp")
    return (_pass if ok else _fail)(
        "FILE-007", "/tmp must have sticky bit set", "MEDIUM",
        "Without sticky bit, any user can delete others' files in /tmp.",
        "chmod +t /tmp",
    )


# ══════════════════════════════════════════════════════════════════════════════
# Kernel / sysctl Checks
# ══════════════════════════════════════════════════════════════════════════════

def _kern(key: str, want: str, id_: str, title: str, sev: str,
          rationale: str, fix: str) -> Dict:
    val = _sysctl(key)
    if val is None:
        return _skip(id_, title, sev, f"sysctl {key} unavailable")
    ok = val.strip() == want
    return (_pass if ok else _fail)(id_, f"{title} (current={val.strip()}, want={want})",
                                    sev, rationale, fix)


def chk_ip_forward()       : return _kern("net.ipv4.ip_forward", "0", "KERN-001", "IP forwarding disabled (non-router)", "MEDIUM", "Enabled IP forwarding allows packet routing attacks.", "sysctl -w net.ipv4.ip_forward=0")
def chk_icmp_redirects()   : return _kern("net.ipv4.conf.all.accept_redirects", "0", "KERN-002", "ICMP redirects disabled", "MEDIUM", "ICMP redirects can be used for routing attacks.", "sysctl -w net.ipv4.conf.all.accept_redirects=0")
def chk_syncookies()       : return _kern("net.ipv4.tcp_syncookies", "1", "KERN-003", "SYN cookies enabled (anti-SYN-flood)", "MEDIUM", "SYN cookies prevent SYN flood DoS.", "sysctl -w net.ipv4.tcp_syncookies=1")
def chk_suid_dumpable()    : return _kern("fs.suid_dumpable", "0", "KERN-004", "SUID core dumps disabled", "MEDIUM", "SUID dumps can leak sensitive process memory.", "sysctl -w fs.suid_dumpable=0")
def chk_aslr()             : return _kern("kernel.randomize_va_space", "2", "KERN-005", "ASLR fully enabled", "HIGH", "Full ASLR (2) makes memory exploitation harder.", "sysctl -w kernel.randomize_va_space=2")
def chk_log_martians()     : return _kern("net.ipv4.conf.all.log_martians", "1", "KERN-006", "Log martian packets enabled", "LOW", "Log packets with impossible source addresses.", "sysctl -w net.ipv4.conf.all.log_martians=1")
def chk_rp_filter()        : return _kern("net.ipv4.conf.all.rp_filter", "1", "KERN-007", "Reverse path filtering enabled", "MEDIUM", "Prevents IP spoofing attacks.", "sysctl -w net.ipv4.conf.all.rp_filter=1")
def chk_send_redirects()   : return _kern("net.ipv4.conf.all.send_redirects", "0", "KERN-008", "Sending ICMP redirects disabled", "MEDIUM", "Host should not send ICMP redirects unless it is a router.", "sysctl -w net.ipv4.conf.all.send_redirects=0")
def chk_secure_icmp()      : return _kern("net.ipv4.icmp_ignore_bogus_error_responses", "1", "KERN-009", "Ignore bogus ICMP error responses", "LOW", "Prevents log spam from malformed ICMP.", "sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1")
def chk_dmesg_restrict()   : return _kern("kernel.dmesg_restrict", "1", "KERN-010", "dmesg restricted to root", "LOW", "dmesg can leak kernel memory addresses.", "sysctl -w kernel.dmesg_restrict=1")
def chk_ptrace_scope()     : return _kern("kernel.yama.ptrace_scope", "1", "KERN-011", "ptrace scope restricted", "MEDIUM", "Unrestricted ptrace allows process memory inspection.", "sysctl -w kernel.yama.ptrace_scope=1")


# ══════════════════════════════════════════════════════════════════════════════
# Auth / Password Policy
# ══════════════════════════════════════════════════════════════════════════════

_LOGIN_DEFS = "/etc/login.defs"


def chk_pass_max_days() -> Dict:
    val = _grep_conf(_LOGIN_DEFS, r"^\s*PASS_MAX_DAYS\s+(\d+)")
    if val is None:
        return _skip("AUTH-001", "Password max age <= 90 days", "MEDIUM", "login.defs unreadable")
    m = re.search(r"(\d+)", val)
    n = int(m.group(1)) if m else 999
    ok = n <= 90
    return (_pass if ok else _fail)(
        "AUTH-001", f"PASS_MAX_DAYS should be <= 90 (current {n})", "MEDIUM",
        "Long password lifetime increases exposure window.",
        "Set PASS_MAX_DAYS 90 in /etc/login.defs",
    )


def chk_pass_min_days() -> Dict:
    val = _grep_conf(_LOGIN_DEFS, r"^\s*PASS_MIN_DAYS\s+(\d+)")
    if val is None:
        return _skip("AUTH-002", "Password min age >= 7 days", "LOW", "login.defs unreadable")
    m = re.search(r"(\d+)", val)
    n = int(m.group(1)) if m else 0
    ok = n >= 7
    return (_pass if ok else _fail)(
        "AUTH-002", f"PASS_MIN_DAYS should be >= 7 (current {n})", "LOW",
        "Prevents users from immediately reverting to old passwords.",
        "Set PASS_MIN_DAYS 7 in /etc/login.defs",
    )


def chk_pass_warn_age() -> Dict:
    val = _grep_conf(_LOGIN_DEFS, r"^\s*PASS_WARN_AGE\s+(\d+)")
    if val is None:
        return _skip("AUTH-003", "Password warning age >= 7 days", "LOW", "login.defs unreadable")
    m = re.search(r"(\d+)", val)
    n = int(m.group(1)) if m else 0
    ok = n >= 7
    return (_pass if ok else _fail)(
        "AUTH-003", f"PASS_WARN_AGE should be >= 7 (current {n})", "LOW",
        "Users should receive advance notice before password expires.",
        "Set PASS_WARN_AGE 7 in /etc/login.defs",
    )


def chk_empty_passwords() -> Dict:
    content = _read("/etc/shadow")
    if content is None:
        return _skip("AUTH-004", "No empty passwords in shadow", "CRITICAL", "Cannot read /etc/shadow")
    empty = [l.split(":")[0] for l in content.splitlines()
             if len(l.split(":")) >= 2 and l.split(":")[1] == ""]
    ok = not empty
    return (_pass if ok else _fail)(
        "AUTH-004", "No accounts with empty passwords", "CRITICAL",
        f"Empty-password accounts: {empty}" if empty else "None found",
        "passwd <username> to set a password",
    )


def chk_root_uid0() -> Dict:
    content = _read("/etc/passwd")
    if content is None:
        return _skip("AUTH-005", "Only root has UID 0", "CRITICAL", "Cannot read /etc/passwd")
    uid0 = [l.split(":")[0] for l in content.splitlines()
            if len(l.split(":")) >= 4 and l.split(":")[2] == "0"]
    ok = uid0 == ["root"]
    detail = f"UID 0 accounts: {uid0}" if not ok else "Only root has UID 0"
    return (_pass if ok else _fail)(
        "AUTH-005", "Only root should have UID 0", "CRITICAL", detail,
        "Review accounts with UID 0 and remove unauthorized ones",
    )


def chk_sudo_nopasswd() -> Dict:
    content = _read("/etc/sudoers")
    if content is None:
        return _skip("AUTH-006", "No unrestricted NOPASSWD in sudoers", "CRITICAL", "Cannot read sudoers")
    dangerous = bool(re.search(r"ALL\s*=\s*\(ALL\)\s*NOPASSWD\s*:\s*ALL", content))
    return (_fail if dangerous else _pass)(
        "AUTH-006", "No unrestricted NOPASSWD:ALL in sudoers", "CRITICAL",
        "NOPASSWD:ALL grants passwordless root to any user.",
        "Scope NOPASSWD grants in /etc/sudoers",
    )


def chk_su_restriction() -> Dict:
    content = _read("/etc/pam.d/su")
    if content is None:
        return _skip("AUTH-007", "su restricted to wheel/sudo group", "MEDIUM", "/etc/pam.d/su absent")
    ok = bool(re.search(r"pam_wheel", content, re.I))
    return (_pass if ok else _fail)(
        "AUTH-007", "su restricted via pam_wheel", "MEDIUM",
        "Without pam_wheel, any user can attempt su to root.",
        "Add 'auth required pam_wheel.so use_uid' to /etc/pam.d/su",
    )


# ══════════════════════════════════════════════════════════════════════════════
# Services / Packages
# ══════════════════════════════════════════════════════════════════════════════

def chk_telnet_disabled() -> Dict:
    active = _service_active("telnet") or _service_active("telnetd") or _pkg_installed("telnetd")
    return (_fail if active else _pass)(
        "SVC-001", "Telnet service is disabled", "CRITICAL",
        "Telnet transmits credentials in plaintext.",
        "systemctl disable telnet --now && apt-get remove telnetd",
    )


def chk_ftp_disabled() -> Dict:
    active = (_service_active("vsftpd") or _service_active("proftpd")
              or _service_active("pure-ftpd"))
    return (_fail if active else _pass)(
        "SVC-002", "FTP service is disabled (use SFTP)", "HIGH",
        "FTP transmits credentials in plaintext.",
        "systemctl disable vsftpd --now",
    )


def chk_rsh_disabled() -> Dict:
    installed = any(_pkg_installed(p) for p in ["rsh-server", "rsh-redone-server"])
    return (_fail if installed else _pass)(
        "SVC-003", "rsh/rlogin disabled", "CRITICAL",
        "rsh/rlogin are insecure legacy protocols.",
        "apt-get remove rsh-server",
    )


def chk_nfs_disabled() -> Dict:
    active = _service_active("nfs-server") or _service_active("nfsd")
    return (_fail if active else _pass)(
        "SVC-004", "NFS server disabled (if not needed)", "MEDIUM",
        "NFS can expose filesystem to network if misconfigured.",
        "systemctl disable nfs-server --now",
    )


def chk_auditd_running() -> Dict:
    ok = _service_active("auditd")
    return (_pass if ok else _fail)(
        "SVC-005", "auditd service is running", "HIGH",
        "auditd provides syscall-level audit trail.",
        "apt-get install auditd && systemctl enable auditd --now",
    )


def chk_syslog_running() -> Dict:
    ok = (_service_active("rsyslog") or _service_active("syslog")
          or _service_active("syslog-ng"))
    return (_pass if ok else _fail)(
        "SVC-006", "syslog/rsyslog service is running", "HIGH",
        "Syslog is required for log collection.",
        "systemctl enable rsyslog --now",
    )


def chk_aide_installed() -> Dict:
    ok = _pkg_installed("aide") or os.path.exists("/usr/bin/aide")
    return (_pass if ok else _fail)(
        "SVC-007", "AIDE (host-based IDS) installed", "MEDIUM",
        "AIDE provides additional file integrity verification.",
        "apt-get install aide && aide --init",
    )


def chk_ufw_or_iptables() -> Dict:
    ufw = _run(["ufw", "status"])
    if "active" in ufw.lower():
        return _pass("SVC-008", "Host firewall active (ufw)", "HIGH", "ufw is active")
    fw = _run(["firewall-cmd", "--state"])
    if "running" in fw.lower():
        return _pass("SVC-008", "Host firewall active (firewalld)", "HIGH", "firewalld running")
    ipt = _run(["iptables", "-S"])
    if ipt and "-P INPUT" in ipt:
        default_policy = re.search(r"-P INPUT (\w+)", ipt)
        if default_policy and default_policy.group(1) != "ACCEPT":
            return _pass("SVC-008", "Host firewall active (iptables)", "HIGH", "iptables rules present")
    return _fail(
        "SVC-008", "No active host firewall detected", "HIGH",
        "A host firewall is the last line of defense.",
        "ufw enable",
    )


def chk_fail2ban() -> Dict:
    ok = _service_active("fail2ban") or _pkg_installed("fail2ban")
    return (_pass if ok else _fail)(
        "SVC-009", "fail2ban installed and running", "MEDIUM",
        "fail2ban blocks IPs with repeated auth failures.",
        "apt-get install fail2ban && systemctl enable fail2ban --now",
    )


# ══════════════════════════════════════════════════════════════════════════════
# Networking
# ══════════════════════════════════════════════════════════════════════════════

def chk_ipv6_router_adv() -> Dict:
    v = _sysctl("net.ipv6.conf.all.accept_ra")
    if v is None:
        return _skip("NET-001", "IPv6 router advertisements disabled", "LOW", "IPv6 sysctl unavailable")
    ok = v.strip() == "0"
    return (_pass if ok else _fail)(
        "NET-001", f"IPv6 router advertisements disabled (current {v.strip()})", "LOW",
        "Accepting RA can allow IPv6 MITM attacks.",
        "sysctl -w net.ipv6.conf.all.accept_ra=0",
    )


def chk_source_routing() -> Dict:
    v = _sysctl("net.ipv4.conf.all.accept_source_route")
    if v is None:
        return _skip("NET-002", "IPv4 source routing disabled", "MEDIUM", "sysctl unavailable")
    ok = v.strip() == "0"
    return (_pass if ok else _fail)(
        "NET-002", f"Source routing disabled (current {v.strip()})", "MEDIUM",
        "Source routing can be used to bypass firewall rules.",
        "sysctl -w net.ipv4.conf.all.accept_source_route=0",
    )


def chk_hosts_allow() -> Dict:
    exists = os.path.exists("/etc/hosts.allow")
    return (_pass if exists else _fail)(
        "NET-003", "/etc/hosts.allow exists (TCP wrappers)", "LOW",
        "TCP wrappers provide a simple access control layer.",
        "touch /etc/hosts.allow /etc/hosts.deny",
    )


# ══════════════════════════════════════════════════════════════════════════════
# Windows-specific
# ══════════════════════════════════════════════════════════════════════════════

def chk_win_firewall() -> Dict:
    out = _run(["netsh", "advfirewall", "show", "allprofiles", "state"])
    ok = "ON" in out.upper()
    return (_pass if ok else _fail)(
        "WIN-001", "Windows Firewall enabled", "HIGH", out[:200],
        "netsh advfirewall set allprofiles state on",
    )


def chk_win_updates() -> Dict:
    out = _run(["powershell", "-Command",
                "(New-Object -ComObject Microsoft.Update.Session)"
                ".CreateUpdateSearcher().Search('IsInstalled=0').Updates.Count"],
               timeout=30)
    try:
        n = int(out.strip())
        ok = n == 0
        return (_pass if ok else _fail)(
            "WIN-002", f"Windows updates: {n} pending", "HIGH",
            f"{n} updates pending.", "Run Windows Update",
        )
    except Exception:
        return _skip("WIN-002", "Windows updates check", "HIGH", "Unable to query WUA")


def chk_win_uac() -> Dict:
    out = _run(["reg", "query",
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "/v", "EnableLUA"])
    ok = "0x1" in out.lower()
    return (_pass if ok else _fail)(
        "WIN-003", "UAC (User Account Control) enabled", "HIGH", out[:200],
        "Enable UAC: reg add HKLM\\...\\System /v EnableLUA /t REG_DWORD /d 1",
    )


# ══════════════════════════════════════════════════════════════════════════════
# Run all
# ══════════════════════════════════════════════════════════════════════════════

_LINUX_CHECKS = [
    # SSH (12 checks)
    chk_ssh_permit_root, chk_ssh_password_auth, chk_ssh_empty_passwords,
    chk_ssh_protocol, chk_ssh_max_auth_tries, chk_ssh_x11_forwarding,
    chk_ssh_agent_forwarding, chk_ssh_log_level, chk_ssh_max_sessions,
    chk_ssh_use_pam, chk_ssh_tcp_keepalive, chk_ssh_client_alive,
    # File permissions (7 checks)
    chk_shadow_perms, chk_passwd_perms, chk_crontab_perms,
    chk_sshd_config_perms, chk_world_writable_etc,
    chk_no_unowned_files, chk_sticky_bit_tmp,
    # Kernel / sysctl (11 checks)
    chk_ip_forward, chk_icmp_redirects, chk_syncookies, chk_suid_dumpable,
    chk_aslr, chk_log_martians, chk_rp_filter, chk_send_redirects,
    chk_secure_icmp, chk_dmesg_restrict, chk_ptrace_scope,
    # Auth / password policy (7 checks)
    chk_pass_max_days, chk_pass_min_days, chk_pass_warn_age,
    chk_empty_passwords, chk_root_uid0, chk_sudo_nopasswd, chk_su_restriction,
    # Services (9 checks)
    chk_telnet_disabled, chk_ftp_disabled, chk_rsh_disabled, chk_nfs_disabled,
    chk_auditd_running, chk_syslog_running, chk_aide_installed,
    chk_ufw_or_iptables, chk_fail2ban,
    # Networking (3 checks)
    chk_ipv6_router_adv, chk_source_routing, chk_hosts_allow,
]

_WIN_CHECKS = [chk_win_firewall, chk_win_updates, chk_win_uac]


def run_sca() -> List[Dict[str, Any]]:
    checks = []
    fns = _LINUX_CHECKS if IS_LINUX else (_WIN_CHECKS if IS_WINDOWS else [])

    for fn in fns:
        try:
            checks.append(fn())
        except Exception as e:
            logger.debug(f"SCA {fn.__name__}: {e}")

    passed  = sum(1 for c in checks if c["result"] == "pass")
    failed  = sum(1 for c in checks if c["result"] == "fail")
    skipped = sum(1 for c in checks if c["result"] == "skip")
    logger.info(f"SCA: {len(checks)} checks — {passed} pass / {failed} fail / {skipped} skip")
    return checks
