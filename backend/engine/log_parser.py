import re
from datetime import datetime
from typing import Optional, Dict, Any

# Standard syslog: "Apr 17 12:34:56 hostname proc[pid]: msg"
SYSLOG_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)

# ISO syslog (systemd/journald): "2026-04-24T00:44:15.426109+05:00 hostname proc[pid]: msg"
ISO_SYSLOG_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T[\d:.]+[+-]\d{2}:\d{2}\s+"
    r"(?P<host>\S+)\s+(?P<proc>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)

# ── SSH ───────────────────────────────────────────────────────────────────────
_SSH_FAIL      = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+)")
_SSH_ACCEPT    = re.compile(r"Accepted \w+ for (\S+) from (\S+)")
_SSH_INVALID   = re.compile(r"Invalid user (\S+) from (\S+)")
_SSH_DISC      = re.compile(r"Disconnected from (?:authenticating )?user (\S+) (\S+)")
_SSH_MAXAUTH   = re.compile(r"maximum authentication attempts exceeded.*from (\S+)")
_SSH_CONN      = re.compile(r"Connection from (\S+) port (\d+)")
_SSH_CLOSED    = re.compile(r"Connection closed by (?:authenticating )?(?:invalid )?user (\S+) (\S+)")
_SSH_MAXSTART  = re.compile(r"drop connection #\d+ from \[(\S+)\].*past MaxStartups")
_SSH_ROOTLOGIN = re.compile(r"ROOT LOGIN|Accepted \w+ for root from (\S+)")
_SSH_FORCED    = re.compile(r"forced command|ForceCommand")
_SSH_PREAUTH   = re.compile(r"Received disconnect from (\S+) port \d+:\d+: Bye Bye \[preauth\]")

# ── Sudo ──────────────────────────────────────────────────────────────────────
_SUDO        = re.compile(r"sudo(?:\[\d+\])?:\s+(\S+)\s+:.*COMMAND=(.*?)(?:\s*;|$)")
_SUDO_FAIL   = re.compile(r"sudo(?:\[\d+\])?:.*authentication failure|sudo(?:\[\d+\])?:.*incorrect password")
_SUDO_DENY   = re.compile(r"sudo(?:\[\d+\])?:\s+\S+\s+:.*command not allowed")

# ── su (switch user) ─────────────────────────────────────────────────────────
_SU_SUCCESS  = re.compile(r"Successful su for (\S+) by (\S+)|pam_unix\(su[^)]*:session\): session opened for user (\S+)")
_SU_FAIL     = re.compile(r"FAILED su for (\S+) by (\S+)|pam_unix\(su[^)]*:auth\): authentication failure")
_SU_ROOT     = re.compile(r"Successful su for root by (\S+)")

# ── Login / TTY ───────────────────────────────────────────────────────────────
_LOGIN_TTY   = re.compile(r"pam_unix\(login:session\): session opened for user (\S+)|NEW SESSION|new session \d+ of user (\S+)")
_LOGOUT_TTY  = re.compile(r"pam_unix\(login:session\): session closed for user (\S+)|Removed session \d+")
_FAILLOCK    = re.compile(r"pam_faillock.*FAILED.*for user (\S+)|Unblock of (\S+)")

# ── at / batch scheduled tasks ───────────────────────────────────────────────
_AT_CMD      = re.compile(r"atd\[.*?\]: (\S+) ran job|(?:atd|at)\[.*\]: Job \d+ run")

# ── PAM ───────────────────────────────────────────────────────────────────────
_PAM_FAIL    = re.compile(r"pam_unix\(([^)]+):auth\): authentication failure.*?user=(\S+)")
_PAM_SUCCESS = re.compile(r"pam_unix\(([^)]+):session\): session opened for user (\S+)")
_PAM_CLOSE   = re.compile(r"pam_unix\(([^)]+):session\): session closed for user (\S+)")
_PAM_LOCKED  = re.compile(r"pam_tally|account.*locked|pam_faillock.*locked")
_PAM_KEYRING = re.compile(r"gkr-pam: unlocked login keyring")

# ── Screen / Session ──────────────────────────────────────────────────────────
_SCREEN_LOCK   = re.compile(r"systemd-logind.*(?:Lid closed|Session.*locked|Lock of session)")
_SCREEN_UNLOCK = re.compile(r"systemd-logind.*(?:Lid opened|Session.*unlocked|Unlock of session)")
_SUSPEND       = re.compile(r"systemd-logind.*Suspending|Performing sleep operation")
_RESUME        = re.compile(r"systemd-logind.*Operation.*suspend.*finished|System returned from sleep")

# ── Systemd services ──────────────────────────────────────────────────────────
_SVC_FAIL    = re.compile(r"Failed to start .+\.(?:service|scope)|\.(?:service|scope): [Ff]ailed|start-limit-hit|failed with result")
_SVC_START   = re.compile(r"(?:Started|Starting) (.+\.(?:service|scope|mount|socket|timer))")
_SVC_STOP    = re.compile(r"(?:Stopped|Finished) (.+\.(?:service|scope|mount|socket|timer))|\.(?:service|scope|mount|timer): Deactivated successfully")
_SVC_RELOAD  = re.compile(r"Reloading (.+\.service)|Reloaded (.+\.service)")
_SVC_TIMEOUT = re.compile(r"\.service: Watchdog timeout|\.service: Timed out")
_SVC_CRASH   = re.compile(r"\.service: Main process exited|\.service: Control process exited")

# ── NetworkManager ────────────────────────────────────────────────────────────
_NM_CONNECTED    = re.compile(r"NetworkManager state is now CONNECTED")
_NM_DISCONNECTED = re.compile(r"NetworkManager state is now DISCONNECTED|NetworkManager state is now ASLEEP")
_NM_DHCP         = re.compile(r"dhcp4 \((\S+)\): state changed.*address=(\S+)")
_NM_IFACE_UP     = re.compile(r"device state change:.*activated|device state change: config -> ip-config")
_NM_IFACE_DOWN   = re.compile(r"device state change:.*deactivat|device state change: activated -> deactivat")
_NM_NEW_DEV      = re.compile(r"\((\S+)\): new (?:Veth|Ethernet|Wi-Fi|Bridge) device")
_NM_WIFI_CONNECT = re.compile(r"device state change: config -> ip-config|(?:Wi-Fi|wireless).*connect")

# ── WiFi (wpa_supplicant) ─────────────────────────────────────────────────────
_WIFI_CONNECTED = re.compile(r"CTRL-EVENT-CONNECTED.*SSID[= ]'?([^']+)'?")
_WIFI_DISCONN   = re.compile(r"CTRL-EVENT-DISCONNECTED bssid=(\S+)")
_WIFI_AUTH_FAIL = re.compile(r"CTRL-EVENT-AUTH-REJECT|CTRL-EVENT-ASSOC-REJECT|WPA: 4-Way Handshake failed")
_WIFI_SIGNAL    = re.compile(r"CTRL-EVENT-SIGNAL-CHANGE")  # noisy — skip with low priority

# ── Kernel / Audit ────────────────────────────────────────────────────────────
_APPARMOR_DENY  = re.compile(r'apparmor="DENIED".*operation="(\w+)".*profile="([^"]+)".*name="([^"]*)"')
_APPARMOR_ALLOW = re.compile(r'apparmor="ALLOWED"')
_AUDIT_SYSCALL  = re.compile(r"audit:.*type=(\d+).*SYSCALL|type=SYSCALL.*syscall=(\d+)")
_AUDIT_USER     = re.compile(r"audit:.*type=1(?:1(?:00|07|14|16|17|18|19)|326).*acct=\"([^\"]+)\"")
_KERNEL_PANIC   = re.compile(r"Kernel panic|BUG:|kernel BUG at|OOPS")
_OOM            = re.compile(r"Out of memory: Kill process (\d+) \(([^)]+)\)")
_OOM2           = re.compile(r"oom_kill_process|memory cgroup out of memory")
_SEG_FAULT      = re.compile(r"segfault at|core dumped|SIGSEGV")
_USB_ADD        = re.compile(r"usb [\d.-]+: new (?:high|full|low|super)-speed USB device|New USB device found")
_USB_REMOVE     = re.compile(r"usb [\d.-]+: USB disconnect")
_NET_IF_UP      = re.compile(r"(\S+): renamed from|entered forwarding state|link becomes ready")
_NET_IF_DOWN    = re.compile(r"\(unregistering\): left (?:allmulticast|promiscuous) mode|entered disabled state")
_IPTABLES       = re.compile(r"IN=(\S*) OUT=(\S*).*SRC=(\S+) DST=(\S+).*PROTO=(\S+).*DPT=(\d+)")

# ── Docker / Container ────────────────────────────────────────────────────────
_DOCKER_START   = re.compile(r'msg="(?:create|start|container start)"')
_DOCKER_STOP    = re.compile(r'msg="(?:stop|container stop|kill|container kill)"')
_DOCKER_ERR     = re.compile(r'level=error|level=fatal', re.IGNORECASE)
_CONTAINERD_DC  = re.compile(r'msg="(?:shim disconnected|cleaning up (?:dead|after) shim)')

# ── Package management ────────────────────────────────────────────────────────
_PKG_INSTALL = re.compile(r"Installed: |install (\S+:\S+)|dpkg.*installed|yum.*installed|Unpacking ")
_PKG_REMOVE  = re.compile(r"Removed: |remove (\S+)|dpkg.*removed|yum.*erased|Removing ")
_PKG_UPGRADE = re.compile(r"Upgraded?: |upgrade (\S+)|dpkg.*upgraded|Setting up ")

# ── User management ───────────────────────────────────────────────────────────
_USERADD     = re.compile(r"useradd\[|new user:|new group:|groupadd\[")
_USERDEL     = re.compile(r"userdel\[|delete user|deleting user")
_PASSWD      = re.compile(r"passwd\[|password changed|chpasswd")

# ── Cron ─────────────────────────────────────────────────────────────────────
_CRON        = re.compile(r"CRON\[|crond\[|cron:")
_CRON_CMD    = re.compile(r"CMD\s+\(([^)]+)\)")

# ── OOM / Kernel ─────────────────────────────────────────────────────────────
_KERNEL_OOM  = re.compile(r"kernel:.*oom|kernel:.*OOM", re.IGNORECASE)

# ── UFW / Firewall ────────────────────────────────────────────────────────────
_UFW         = re.compile(r"UFW (BLOCK|ALLOW).*SRC=(\S+).*DST=(\S+)")
_IPT         = re.compile(r"iptables.*(?:DROP|REJECT).*SRC=(\S+).*DST=(\S+)")

# ── FIM (agent format) ───────────────────────────────────────────────────────
_FIM_MODIFIED = re.compile(r"FIM \[MODIFIED\]\s+(\S+)")
_FIM_CREATED  = re.compile(r"FIM \[CREATED\]\s+(\S+)")
_FIM_DELETED  = re.compile(r"FIM \[DELETED\]\s+(\S+)")
_FIM_MOVED    = re.compile(r"FIM \[MOVED\]\s+(\S+)")
_FIM_ATTRIB   = re.compile(r"FIM \[ATTRIB\]\s+(\S+)")

# ── ROOTCHECK (agent format) ─────────────────────────────────────────────────
_RC_ROOTKIT   = re.compile(r"ROOTCHECK \[ROOTKIT_FILE\].*?:\s+(.+)")
_RC_HIDDEN    = re.compile(r"ROOTCHECK \[HIDDEN_(?:PROCESS|FILE)\].*?:\s+(.+)")
_RC_SUSP_CRON = re.compile(r"ROOTCHECK \[SUSPICIOUS_CRON\].*?:\s+(.+)")
_RC_KERNEL    = re.compile(r"ROOTCHECK \[KERNEL_MODULE\].*?:\s+(.+)")

# ── Bluetooth ─────────────────────────────────────────────────────────────────
_BT_CONNECT   = re.compile(r"bluetoothd.*Endpoint registered|bluetoothd.*Device.*Connected|hci.*connection (created|request)")
_BT_DISCONNECT= re.compile(r"bluetoothd.*Endpoint unregistered|bluetoothd.*Device.*Disconnected")

# ── Severity maps ─────────────────────────────────────────────────────────────
_CRITICAL_EVENTS = frozenset({
    "rootkit_detected", "hidden_process", "hidden_file", "kernel_module_loaded",
    "fim_modified", "fim_deleted", "oom_kill", "brute_force_ssh",
    "kernel_panic", "apparmor_denied",
})
_ERROR_EVENTS = frozenset({
    "ssh_failed", "authentication_failed", "sudo_auth_failure", "pam_auth_failed",
    "pam_account_locked", "max_auth_exceeded", "process_crash", "service_failed",
    "service_crashed", "service_timeout", "wifi_auth_failed", "docker_error",
})
_WARNING_EVENTS = frozenset({
    "sudo_command", "firewall_block", "ufw_block", "fim_created", "fim_moved",
    "fim_attrib_changed", "user_created", "group_created", "package_installed",
    "package_removed", "package_upgraded", "cron_job", "suspicious_cron",
    "screen_lock", "screen_unlock", "system_suspend", "system_resume",
    "pam_session_opened", "pam_session_closed", "usb_connected", "usb_disconnected",
    "network_disconnected", "wifi_disconnected", "bt_disconnected",
    "container_stopped", "container_killed",
})


# ── Level helpers ─────────────────────────────────────────────────────────────

def parse_log_level(message: str) -> str:
    msg = message.lower()
    if any(k in msg for k in ("segfault", "core dumped", "killed", "oom", "panic", "critical", "crit", "fatal")):
        return "CRITICAL"
    if any(k in msg for k in ("error", "err", "failed", "failure", "refused", "denied")):
        return "ERROR"
    if any(k in msg for k in ("warn", "warning")):
        return "WARNING"
    if "debug" in msg:
        return "DEBUG"
    return "INFO"


def _level_from_event(event_type: Optional[str], message: str) -> str:
    if event_type in _CRITICAL_EVENTS:
        return "CRITICAL"
    if event_type in _ERROR_EVENTS:
        return "ERROR"
    if event_type in _WARNING_EVENTS:
        return "WARNING"
    return parse_log_level(message)


# ── Main parser ───────────────────────────────────────────────────────────────

def parse_syslog_line(line: str) -> Dict[str, Any]:
    parsed: Dict[str, Any] = {}

    m = SYSLOG_PATTERN.match(line) or ISO_SYSLOG_PATTERN.match(line)
    if m:
        if m.group("proc"): parsed["process"]  = m.group("proc")
        if m.group("pid"):  parsed["pid"]      = m.group("pid")
        if m.group("host"): parsed["hostname"] = m.group("host")

    # Jarayon nomidan qidiruv osonlashtirish uchun
    proc = parsed.get("process", "")

    # ── SSH ───────────────────────────────────────────────────────────────────

    sm = _SSH_FAIL.search(line)
    if sm:
        parsed.update({"event_type": "ssh_failed", "ssh_user": sm.group(1),
                       "ssh_src_ip": sm.group(2), "src_ip": sm.group(2)})
        return parsed

    sm = _SSH_ACCEPT.search(line)
    if sm:
        parsed.update({"event_type": "authentication_success", "ssh_user": sm.group(1),
                       "ssh_src_ip": sm.group(2), "src_ip": sm.group(2)})
        return parsed

    sm = _SSH_INVALID.search(line)
    if sm:
        parsed.update({"event_type": "ssh_invalid_user", "ssh_user": sm.group(1),
                       "ssh_src_ip": sm.group(2), "src_ip": sm.group(2)})
        return parsed

    sm = _SSH_ROOTLOGIN.search(line)
    if sm:
        ip = sm.group(1) if sm.lastindex else None
        parsed.update({"event_type": "authentication_success", "ssh_user": "root",
                       "is_root_login": True})
        if ip:
            parsed["src_ip"] = ip
        return parsed

    sm = _SSH_MAXAUTH.search(line)
    if sm:
        parsed.update({"event_type": "max_auth_exceeded", "src_ip": sm.group(1)})
        return parsed

    sm = _SSH_MAXSTART.search(line)
    if sm:
        parsed.update({"event_type": "ssh_failed", "src_ip": sm.group(1), "reason": "MaxStartups"})
        return parsed

    if _SSH_FORCED.search(line):
        parsed["event_type"] = "ssh_accepted"
        return parsed

    sm = _SSH_PREAUTH.search(line)
    if sm:
        parsed.update({"event_type": "ssh_disconnect", "src_ip": sm.group(1)})
        return parsed

    sm = _SSH_CLOSED.search(line)
    if sm:
        parsed.update({"event_type": "ssh_disconnect", "ssh_user": sm.group(1),
                       "src_ip": sm.group(2)})
        return parsed

    # ── Sudo ──────────────────────────────────────────────────────────────────

    if _SUDO_FAIL.search(line):
        parsed["event_type"] = "sudo_auth_failure"
        return parsed

    if _SUDO_DENY.search(line):
        parsed["event_type"] = "sudo_denied"
        return parsed

    sm = _SUDO.search(line)
    if sm:
        parsed.update({"event_type": "sudo_command", "sudo_user": sm.group(1),
                       "sudo_command": sm.group(2).strip()[:200]})
        return parsed

    # ── PAM ───────────────────────────────────────────────────────────────────

    sm = _PAM_FAIL.search(line)
    if sm:
        parsed.update({"event_type": "pam_auth_failed", "pam_service": sm.group(1),
                       "pam_user": sm.group(2)})
        return parsed

    if _PAM_LOCKED.search(line):
        parsed["event_type"] = "pam_account_locked"
        return parsed

    sm = _PAM_SUCCESS.search(line)
    if sm:
        parsed.update({"event_type": "pam_session_opened", "pam_service": sm.group(1),
                       "pam_user": sm.group(2).split("(")[0]})
        return parsed

    sm = _PAM_CLOSE.search(line)
    if sm:
        parsed.update({"event_type": "pam_session_closed", "pam_service": sm.group(1),
                       "pam_user": sm.group(2).split("(")[0]})
        return parsed

    if _PAM_KEYRING.search(line):
        parsed["event_type"] = "screen_unlock"
        return parsed

    if _FAILLOCK.search(line):
        parsed["event_type"] = "pam_account_locked"
        return parsed

    # ── su (switch user) ──────────────────────────────────────────────────────

    sm = _SU_ROOT.search(line)
    if sm:
        parsed.update({"event_type": "sudo_command", "su_target": "root",
                       "su_by": sm.group(1), "is_root_switch": True})
        return parsed

    sm = _SU_SUCCESS.search(line)
    if sm:
        target = sm.group(1) or sm.group(3) or ""
        by     = sm.group(2) or ""
        parsed.update({"event_type": "authentication_success", "su_target": target.split("(")[0],
                       "su_by": by})
        return parsed

    if _SU_FAIL.search(line):
        parsed["event_type"] = "authentication_failed"
        return parsed

    # ── Login / TTY ───────────────────────────────────────────────────────────

    sm = _LOGIN_TTY.search(line)
    if sm:
        user = sm.group(1) or sm.group(2) or ""
        parsed.update({"event_type": "pam_session_opened", "pam_user": user.split("(")[0]})
        return parsed

    sm = _LOGOUT_TTY.search(line)
    if sm:
        user = sm.group(1) or ""
        parsed.update({"event_type": "pam_session_closed", "pam_user": user.split("(")[0]})
        return parsed

    # ── at / batch ────────────────────────────────────────────────────────────

    if _AT_CMD.search(line):
        sm = _AT_CMD.search(line)
        parsed.update({"event_type": "cron_job", "scheduler": "at",
                       "at_user": sm.group(1) if sm.lastindex else ""})
        return parsed

    # ── Screen / Session ──────────────────────────────────────────────────────

    if _SCREEN_LOCK.search(line):
        parsed["event_type"] = "screen_lock"
        return parsed

    if _SCREEN_UNLOCK.search(line):
        parsed["event_type"] = "screen_unlock"
        return parsed

    if _SUSPEND.search(line):
        parsed["event_type"] = "system_suspend"
        return parsed

    if _RESUME.search(line):
        parsed["event_type"] = "system_resume"
        return parsed

    # ── AppArmor / Audit ──────────────────────────────────────────────────────

    sm = _APPARMOR_DENY.search(line)
    if sm:
        parsed.update({"event_type": "apparmor_denied", "aa_operation": sm.group(1),
                       "aa_profile": sm.group(2)[:100], "aa_name": sm.group(3)[:100]})
        return parsed

    if _KERNEL_PANIC.search(line):
        parsed["event_type"] = "kernel_panic"
        return parsed

    # ── OOM ───────────────────────────────────────────────────────────────────

    sm = _OOM.search(line)
    if sm:
        parsed.update({"event_type": "oom_kill", "oom_pid": sm.group(1), "oom_proc": sm.group(2)})
        return parsed

    if _OOM2.search(line) or _KERNEL_OOM.search(line):
        parsed["event_type"] = "oom_kill"
        return parsed

    # ── Segfault ──────────────────────────────────────────────────────────────

    if _SEG_FAULT.search(line):
        parsed["event_type"] = "process_crash"
        return parsed

    # ── USB ───────────────────────────────────────────────────────────────────

    if _USB_ADD.search(line):
        parsed["event_type"] = "usb_connected"
        return parsed

    if _USB_REMOVE.search(line):
        parsed["event_type"] = "usb_disconnected"
        return parsed

    # ── NetworkManager ────────────────────────────────────────────────────────

    if proc == "NetworkManager":
        sm = _NM_DHCP.search(line)
        if sm:
            parsed.update({"event_type": "network_connection", "net_iface": sm.group(1),
                           "src_ip": sm.group(2)})
            return parsed

        if _NM_CONNECTED.search(line):
            parsed["event_type"] = "network_connected"
            return parsed

        if _NM_DISCONNECTED.search(line):
            parsed["event_type"] = "network_disconnected"
            return parsed

        sm = _NM_NEW_DEV.search(line)
        if sm:
            parsed.update({"event_type": "network_connection", "net_iface": sm.group(1)})
            return parsed

        # Qolgan NM loglar — INFO, aniqlanmaydi
        return parsed

    # ── WiFi (wpa_supplicant) ─────────────────────────────────────────────────

    if proc == "wpa_supplicant":
        if _WIFI_SIGNAL.search(line):
            # Signal o'zgarish — juda ko'p, event_type qo'ymaymiz
            return parsed

        sm = _WIFI_CONNECTED.search(line)
        if sm:
            parsed.update({"event_type": "wifi_connected", "wifi_ssid": sm.group(1)})
            return parsed

        sm = _WIFI_DISCONN.search(line)
        if sm:
            parsed.update({"event_type": "wifi_disconnected", "wifi_bssid": sm.group(1)})
            return parsed

        if _WIFI_AUTH_FAIL.search(line):
            parsed["event_type"] = "wifi_auth_failed"
            return parsed

        return parsed

    # ── Docker / containerd ───────────────────────────────────────────────────

    if proc in ("dockerd", "containerd", "docker"):
        if _DOCKER_STOP.search(line):
            parsed["event_type"] = "container_stopped"
            return parsed

        if _DOCKER_START.search(line):
            parsed["event_type"] = "container_started"
            return parsed

        if _CONTAINERD_DC.search(line):
            parsed["event_type"] = "container_stopped"
            return parsed

        if _DOCKER_ERR.search(line):
            parsed["event_type"] = "docker_error"
            return parsed

        return parsed

    # ── Bluetooth ─────────────────────────────────────────────────────────────

    if proc == "bluetoothd":
        if _BT_CONNECT.search(line):
            parsed["event_type"] = "bt_connected"
            return parsed

        if _BT_DISCONNECT.search(line):
            parsed["event_type"] = "bt_disconnected"
            return parsed

        return parsed

    # ── Network interface state ───────────────────────────────────────────────

    sm = _IPTABLES.search(line)
    if sm:
        parsed.update({
            "event_type": "firewall_block",
            "net_in": sm.group(1), "net_out": sm.group(2),
            "src_ip": sm.group(3), "dst_ip": sm.group(4),
            "proto": sm.group(5), "dst_port": sm.group(6),
        })
        return parsed

    if _NET_IF_UP.search(line):
        parsed["event_type"] = "network_connected"
        return parsed

    # ── UFW / Firewall ────────────────────────────────────────────────────────

    sm = _UFW.search(line)
    if sm:
        parsed.update({"event_type": "ufw_block", "fw_action": sm.group(1),
                       "src_ip": sm.group(2), "dst_ip": sm.group(3)})
        return parsed

    sm = _IPT.search(line)
    if sm:
        parsed.update({"event_type": "firewall_block", "src_ip": sm.group(1), "dst_ip": sm.group(2)})
        return parsed

    # ── User management ───────────────────────────────────────────────────────

    if _USERADD.search(line):
        parsed["event_type"] = "user_created"
        return parsed

    if _USERDEL.search(line):
        parsed["event_type"] = "user_deleted"
        return parsed

    if _PASSWD.search(line):
        parsed["event_type"] = "password_changed"
        return parsed

    # ── Package management ────────────────────────────────────────────────────

    if _PKG_UPGRADE.search(line):
        parsed["event_type"] = "package_upgraded"
        return parsed

    if _PKG_INSTALL.search(line):
        parsed["event_type"] = "package_installed"
        return parsed

    if _PKG_REMOVE.search(line):
        parsed["event_type"] = "package_removed"
        return parsed

    # ── Cron ─────────────────────────────────────────────────────────────────

    if _CRON.search(line):
        sm = _CRON_CMD.search(line)
        parsed["event_type"] = "cron_job"
        if sm:
            parsed["cron_cmd"] = sm.group(1)[:200]
        return parsed

    # ── Systemd services ──────────────────────────────────────────────────────

    if _SVC_FAIL.search(line):
        parsed["event_type"] = "service_failed"
        return parsed

    if _SVC_TIMEOUT.search(line):
        parsed["event_type"] = "service_timeout"
        return parsed

    if _SVC_CRASH.search(line):
        parsed["event_type"] = "service_crashed"
        return parsed

    sm = _SVC_STOP.search(line)
    if sm:
        name = sm.group(1) or ""
        parsed.update({"event_type": "service_stopped", "service_name": name[:80]})
        return parsed

    sm = _SVC_START.search(line)
    if sm:
        parsed.update({"event_type": "service_started", "service_name": sm.group(1)[:80]})
        return parsed

    sm = _SVC_RELOAD.search(line)
    if sm:
        parsed.update({"event_type": "service_reloaded", "service_name": (sm.group(1) or sm.group(2))[:80]})
        return parsed

    # ── FIM ───────────────────────────────────────────────────────────────────

    sm = _FIM_MODIFIED.search(line)
    if sm:
        parsed.update({"event_type": "fim_modified", "file_path": sm.group(1)})
        return parsed

    sm = _FIM_CREATED.search(line)
    if sm:
        parsed.update({"event_type": "fim_created", "file_path": sm.group(1)})
        return parsed

    sm = _FIM_DELETED.search(line)
    if sm:
        parsed.update({"event_type": "fim_deleted", "file_path": sm.group(1)})
        return parsed

    sm = _FIM_MOVED.search(line)
    if sm:
        parsed.update({"event_type": "fim_moved", "file_path": sm.group(1)})
        return parsed

    sm = _FIM_ATTRIB.search(line)
    if sm:
        parsed.update({"event_type": "fim_attrib_changed", "file_path": sm.group(1)})
        return parsed

    # ── ROOTCHECK ─────────────────────────────────────────────────────────────

    sm = _RC_ROOTKIT.search(line)
    if sm:
        parsed.update({"event_type": "hidden_file", "rootcheck_detail": sm.group(1)[:200]})
        return parsed

    sm = _RC_HIDDEN.search(line)
    if sm:
        parsed.update({"event_type": "hidden_process", "rootcheck_detail": sm.group(1)[:200]})
        return parsed

    sm = _RC_SUSP_CRON.search(line)
    if sm:
        parsed.update({"event_type": "suspicious_cron", "rootcheck_detail": sm.group(1)[:200]})
        return parsed

    sm = _RC_KERNEL.search(line)
    if sm:
        parsed.update({"event_type": "kernel_module_loaded", "rootcheck_detail": sm.group(1)[:200]})
        return parsed

    return parsed


def normalize_log(raw_log: dict) -> dict:
    message = raw_log.get("message", "")
    raw     = raw_log.get("raw", message)

    agent_pf: dict = dict(raw_log.get("parsed_fields") or {})
    server_pf = parse_syslog_line(raw or message)
    merged    = {**server_pf, **agent_pf}

    level = (
        raw_log.get("level")
        or _level_from_event(merged.get("event_type"), message)
    )

    ts = raw_log.get("timestamp") or datetime.utcnow().isoformat()

    return {
        "agent_id":      raw_log.get("agent_id", ""),
        "hostname":      raw_log.get("hostname", ""),
        "timestamp":     ts,
        "level":         level.upper(),
        "source":        (
            raw_log.get("source")
            or agent_pf.get("process")
            or server_pf.get("process")
            or "unknown"
        ),
        "message":       message,
        "raw":           raw,
        "parsed_fields": merged,
    }
