"""
macOS Collector — unified log (OSLog), audit trail, and security events.

Sources:
  - /usr/bin/log stream / show  (Unified Logging System)
  - /usr/sbin/praudit + /usr/sbin/auditreduce  (BSM audit trail)
  - /var/log/system.log, install.log, wifi.log
  - Security framework events: login/logout, keychain, authorization
  - launchd / XPC service events
  - Gatekeeper, SIP, TCC events
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── MITRE ATT&CK mapping for macOS event categories ──────────────────────────
_MITRE_MAP: Dict[str, str] = {
    "authentication_failure":  "T1110",   # Brute Force
    "sudo":                    "T1548.003",# Abuse Elevation Control Mechanism: Sudo
    "privilege_escalation":    "T1548",    # Abuse Elevation Control Mechanism
    "persistence_launchd":     "T1543.004",# Create or Modify System Process: Launch Daemon
    "persistence_cron":        "T1053.003",# Scheduled Task/Job: Cron
    "scripting":               "T1059.002",# Command and Scripting Interpreter: AppleScript
    "bash_history":            "T1552.003",# Unsecured Credentials: Bash History
    "network_connection":      "T1071",    # Application Layer Protocol
    "file_deletion":           "T1070.004",# Indicator Removal: File Deletion
    "keychain_access":         "T1555.001",# Credentials from Password Stores: Keychain
    "tcc_bypass":              "T1548",    # Abuse Elevation Control Mechanism
    "gatekeeper_bypass":       "T1553.001",# Subvert Trust Controls: Gatekeeper
    "sip_violation":           "T1562.002",# Impair Defenses: Disable Windows Event Logging
    "reverse_shell":           "T1059",    # Command and Scripting Interpreter
    "screencapture":           "T1113",    # Screen Capture
    "clipboard_access":        "T1115",    # Clipboard Data
    "location_services":       "T1430",    # Location Tracking
    "camera_mic_access":       "T1125",    # Video Capture
}

# ── Suspicious process names and patterns ────────────────────────────────────
_SUSPICIOUS_PROCS = re.compile(
    r"(python3?|ruby|perl|nc|ncat|netcat|socat|curl|wget|osascript"
    r"|screencapture|pbcopy|pbpaste|security|ditto|hdiutil"
    r"|diskutil|launchctl|plutil|defaults|xattr|codesign"
    r"|spctl|csrutil|dtrace|lldb|instruments|ktrace"
    r"|base64|xxd|od|hexdump|strings|nm|otool|lipo"
    r"|mdfind|mdls|spotlight|find|locate"
    r"|bash|zsh|sh|ksh|fish|csh|tcsh"
    r"|nmap|masscan|nikto|sqlmap|metasploit|msfconsole"
    r"|proxychains|tor|ssh|sshd|sftp|ftp|telnet"
    r"|crontab|launchd|launchdaemon|loginitems)",
    re.IGNORECASE,
)

_REVERSE_SHELL_PATTERNS = re.compile(
    r"(bash\s+-i\s+>&|/dev/tcp/|/dev/udp/"
    r"|nc\s+-e\s+/bin|ncat\s+--exec"
    r"|python.*socket.*connect|perl.*socket.*connect"
    r"|ruby.*TCPSocket|php.*fsockopen)",
    re.IGNORECASE,
)

_OSASCRIPT_SUSPICIOUS = re.compile(
    r'osascript.*(-e\s+["\']|do\s+shell\s+script)',
    re.IGNORECASE,
)

# ── Log categories to collect from Unified Logging ───────────────────────────
_LOG_PREDICATES = [
    # Authentication
    'subsystem == "com.apple.securityd"',
    'subsystem == "com.apple.authorization"',
    # Launch services
    'subsystem == "com.apple.launchservices"',
    'subsystem == "com.apple.xpc.launchd"',
    # Network
    'subsystem == "com.apple.network.connection"',
    # Gatekeeper / SIP
    'subsystem == "com.apple.security.syspolicy"',
    # TCC (Transparency, Consent, Control)
    'subsystem == "com.apple.TCC"',
    # Crashes
    'subsystem == "com.apple.CrashReporter"',
    # OpenSSH
    'processImagePath CONTAINS "sshd"',
    # Sudo
    'processImagePath CONTAINS "sudo"',
    # Generic errors and faults across all subsystems
    '(messageType == fault OR messageType == error) AND subsystem != ""',
]

# ── BSM Audit event codes ─────────────────────────────────────────────────────
_AUDIT_EVENTS: Dict[int, str] = {
    1:   "AUE_EXIT",
    2:   "AUE_FORK",
    23:  "AUE_SETUID",
    27:  "AUE_EXECVE",
    30:  "AUE_ACCESS",
    37:  "AUE_KILL",
    72:  "AUE_MMAP",
    85:  "AUE_TRUNCATE",
    128: "AUE_OPENAT",
    170: "AUE_SETGID",
    173: "AUE_CONNECT",
    180: "AUE_BIND",
    183: "AUE_ACCEPT",
    247: "AUE_SESSION_START",
    248: "AUE_SESSION_END",
    256: "AUE_IDENTITY",
    32800: "AUE_openssh",
    32812: "AUE_sudo",
    45014: "AUE_SCREEN_CAPTURE",
    45015: "AUE_KEYCHAIN_ACCESS",
}

_AUDIT_CRITICAL = {23, 27, 128, 173, 247, 248, 32812, 45014, 45015}

# ── Launchd persistence paths ─────────────────────────────────────────────────
_PERSISTENCE_PATHS = [
    "/Library/LaunchDaemons",
    "/Library/LaunchAgents",
    os.path.expanduser("~/Library/LaunchAgents"),
    "/System/Library/LaunchDaemons",
    "/System/Library/LaunchAgents",
    "/Library/StartupItems",
    "/etc/periodic",
    os.path.expanduser("~/Library/Application Support/com.apple.backgroundtaskmanagementagent"),
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run(cmd: List[str], timeout: int = 10) -> Optional[str]:
    """Run a command and return stdout, or None on error."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as e:
        logger.debug(f"Command {cmd[0]} failed: {e}")
        return None


def _severity_from_type(msg_type: str) -> str:
    mapping = {
        "fault":   "critical",
        "error":   "high",
        "default": "informational",
        "info":    "informational",
        "debug":   "low",
    }
    return mapping.get(msg_type.lower(), "informational")


# ── Unified Log parser ────────────────────────────────────────────────────────

def _parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a single line from `log show --style json` output.
    Expected JSON fields: timestamp, messageType, processID, processImagePath,
    subsystem, category, eventMessage.
    """
    line = line.strip()
    if not line or line in ("[", "]", ","):
        return None
    line = line.rstrip(",")
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None

    msg = obj.get("eventMessage", "")
    proc = obj.get("processImagePath", "")
    proc_name = os.path.basename(proc) if proc else ""
    subsystem = obj.get("subsystem", "")
    msg_type = obj.get("messageType", "default")
    timestamp = obj.get("timestamp", _now_iso())

    event: Dict[str, Any] = {
        "timestamp":    timestamp,
        "source":       "macos_unified_log",
        "platform":     "macos",
        "severity":     _severity_from_type(msg_type),
        "message":      msg,
        "process":      proc_name,
        "process_path": proc,
        "pid":          obj.get("processID"),
        "subsystem":    subsystem,
        "category":     obj.get("category", ""),
        "message_type": msg_type,
        "log_type":     "unified_log",
        "raw":          line,
        "threat_intel": {},
    }

    # Enrich with threat context
    _enrich_unified_log(event, msg, proc_name, subsystem)
    return event


def _enrich_unified_log(
    event: Dict[str, Any],
    msg: str,
    proc_name: str,
    subsystem: str,
) -> None:
    ti = event["threat_intel"]

    # Authentication events
    if subsystem in ("com.apple.securityd", "com.apple.authorization"):
        if any(k in msg.lower() for k in ("failed", "denied", "error", "invalid")):
            ti["category"]       = "authentication_failure"
            ti["mitre"]          = _MITRE_MAP["authentication_failure"]
            event["severity"]    = "medium"
            event["event_type"]  = "authentication_failure"
        elif any(k in msg.lower() for k in ("succeeded", "authenticated", "granted")):
            event["event_type"]  = "authentication_success"

    # Sudo events
    if "sudo" in proc_name.lower():
        if "incorrect password" in msg.lower():
            ti["category"]       = "authentication_failure"
            ti["mitre"]          = _MITRE_MAP["sudo"]
            event["severity"]    = "high"
            event["event_type"]  = "sudo_failure"
        elif "session opened" in msg.lower():
            ti["category"]       = "privilege_escalation"
            ti["mitre"]          = _MITRE_MAP["sudo"]
            event["severity"]    = "medium"
            event["event_type"]  = "sudo_success"

    # Keychain access
    if subsystem == "com.apple.TCC" or "keychain" in msg.lower():
        ti["category"]  = "keychain_access"
        ti["mitre"]     = _MITRE_MAP["keychain_access"]
        event["severity"] = "medium"

    # Gatekeeper
    if subsystem == "com.apple.security.syspolicy":
        if any(k in msg.lower() for k in ("denied", "blocked", "untrusted")):
            ti["category"]    = "gatekeeper_bypass" if "bypass" in msg.lower() else "gatekeeper_block"
            ti["mitre"]       = _MITRE_MAP["gatekeeper_bypass"]
            event["severity"] = "high"

    # LaunchD persistence
    if subsystem == "com.apple.xpc.launchd":
        if any(k in msg.lower() for k in ("registered", "loaded", "enable")):
            ti["category"]    = "persistence_launchd"
            ti["mitre"]       = _MITRE_MAP["persistence_launchd"]
            event["severity"] = "medium"

    # Reverse shell
    if _REVERSE_SHELL_PATTERNS.search(msg):
        ti["category"]    = "reverse_shell"
        ti["mitre"]       = _MITRE_MAP["reverse_shell"]
        event["severity"] = "critical"
        ti["alert"]       = "Potential reverse shell detected"

    # Suspicious osascript usage
    if _OSASCRIPT_SUSPICIOUS.search(msg) or ("osascript" in proc_name.lower() and "do shell script" in msg):
        ti["category"]    = "scripting"
        ti["mitre"]       = _MITRE_MAP["scripting"]
        event["severity"] = "high"
        ti["alert"]       = "Suspicious AppleScript execution"

    # Screencapture
    if "screencapture" in proc_name.lower() or "screen capture" in msg.lower():
        ti["category"]    = "screencapture"
        ti["mitre"]       = _MITRE_MAP["screencapture"]
        event["severity"] = "medium"

    # Suspicious process
    if _SUSPICIOUS_PROCS.search(proc_name) and event.get("severity") == "informational":
        ti["suspicious_process"] = True


# ── BSM Audit Trail parser ────────────────────────────────────────────────────

def _parse_praudit_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parse a single line from praudit -x (XML) output.
    Simplified: parse key fields from text output.
    """
    line = line.strip()
    if not line:
        return None

    # praudit text format: <event>,<modifier>,<subtype>,<event-type>
    # Example: execve(27),<no flags>,<no flag>,<no flag>
    event_type_match = re.search(r"event <event-type>(.*?)</event-type>", line)
    event_code_match = re.search(r"<event-id>(\d+)</event-id>", line)
    uid_match        = re.search(r"<uid>(\d+)</uid>", line)
    pid_match        = re.search(r"<pid>(\d+)</pid>", line)
    path_match       = re.search(r"<path>(.*?)</path>", line)
    time_match       = re.search(r"<time>(.*?)</time>", line)

    event_code = int(event_code_match.group(1)) if event_code_match else 0
    event_name = _AUDIT_EVENTS.get(event_code, f"AUE_{event_code}")

    return {
        "timestamp":   time_match.group(1) if time_match else _now_iso(),
        "source":      "macos_audit",
        "platform":    "macos",
        "log_type":    "bsm_audit",
        "event_code":  event_code,
        "event_name":  event_name,
        "severity":    "high" if event_code in _AUDIT_CRITICAL else "informational",
        "uid":         uid_match.group(1) if uid_match else None,
        "pid":         int(pid_match.group(1)) if pid_match else None,
        "path":        path_match.group(1) if path_match else None,
        "raw":         line,
        "threat_intel": {
            "category": "privilege_escalation" if event_code in {23, 170, 32812} else "process_execution",
            "mitre":    "T1548" if event_code in {23, 170, 32812} else "T1059",
        } if event_code in _AUDIT_CRITICAL else {},
    }


# ── Persistence scanner ───────────────────────────────────────────────────────

async def scan_persistence() -> List[Dict[str, Any]]:
    """Scan known macOS persistence locations for plist files."""
    results = []
    for path in _PERSISTENCE_PATHS:
        if not os.path.isdir(path):
            continue
        try:
            for fname in os.listdir(path):
                if not fname.endswith(".plist"):
                    continue
                full = os.path.join(path, fname)
                stat = os.stat(full)
                mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
                out = _run(["plutil", "-p", full], timeout=5)
                program_args = ""
                if out:
                    prog_match = re.search(r'"ProgramArguments".*?\((.*?)\)', out, re.DOTALL)
                    if prog_match:
                        program_args = prog_match.group(1).strip().replace("\n", " ")

                results.append({
                    "timestamp":     _now_iso(),
                    "source":        "macos_persistence",
                    "platform":      "macos",
                    "log_type":      "persistence_scan",
                    "severity":      "low",
                    "path":          full,
                    "modified":      mtime,
                    "program_args":  program_args,
                    "threat_intel": {
                        "category": "persistence_launchd",
                        "mitre":    _MITRE_MAP["persistence_launchd"],
                    } if "/Library/LaunchDaemons" in path else {},
                })
        except PermissionError:
            logger.debug(f"Permission denied scanning {path}")
        except Exception as e:
            logger.debug(f"Error scanning {path}: {e}")
    return results


# ── Network connection snapshot ───────────────────────────────────────────────

async def collect_network_connections() -> List[Dict[str, Any]]:
    """Collect active network connections via lsof or netstat."""
    results = []
    out = _run(["lsof", "-nPi", "-sTCP:ESTABLISHED", "+c0"], timeout=15)
    if not out:
        out = _run(["netstat", "-an"], timeout=10)
    if not out:
        return results

    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        cmd    = parts[0]
        pid    = parts[1] if parts[1].isdigit() else None
        proto  = parts[7] if len(parts) > 7 else "TCP"
        addrs  = parts[8] if len(parts) > 8 else ""
        state  = parts[9] if len(parts) > 9 else ""

        if "->" in addrs:
            src, dst = addrs.split("->", 1)
        else:
            src, dst = addrs, ""

        results.append({
            "timestamp":   _now_iso(),
            "source":      "macos_network",
            "platform":    "macos",
            "log_type":    "network_connection",
            "severity":    "informational",
            "process":     cmd,
            "pid":         pid,
            "protocol":    proto,
            "src_addr":    src,
            "dst_addr":    dst,
            "state":       state,
            "raw":         line,
            "threat_intel": {
                "category": "network_connection",
                "mitre":    _MITRE_MAP["network_connection"],
                "suspicious_process": True,
            } if _SUSPICIOUS_PROCS.search(cmd) else {},
        })
    return results


# ── System log file collector ─────────────────────────────────────────────────

async def collect_system_log(path: str = "/var/log/system.log", tail_lines: int = 500) -> List[Dict[str, Any]]:
    """Read last N lines from /var/log/system.log."""
    results = []
    if not os.path.exists(path):
        return results
    try:
        out = _run(["tail", "-n", str(tail_lines), path], timeout=10)
        if not out:
            return results
        syslog_re = re.compile(
            r"^(\w{3}\s+\d+\s[\d:]+)\s+(\S+)\s+(\S+)\[(\d+)\]:\s+(.*)$"
        )
        for line in out.splitlines():
            m = syslog_re.match(line)
            if not m:
                continue
            ts, host, proc, pid, msg = m.groups()
            sev = "high" if any(k in msg.lower() for k in ("error", "fail", "denied", "critical")) else "informational"
            results.append({
                "timestamp":   _now_iso(),
                "source":      "macos_syslog",
                "platform":    "macos",
                "log_type":    "syslog",
                "severity":    sev,
                "hostname":    host,
                "process":     proc,
                "pid":         pid,
                "message":     msg,
                "raw":         line,
                "threat_intel": {},
            })
    except Exception as e:
        logger.debug(f"system.log read error: {e}")
    return results


# ── Unified Log stream/show collector ────────────────────────────────────────

async def collect_unified_logs(
    since_seconds: int = 300,
    max_events: int = 2000,
) -> List[Dict[str, Any]]:
    """
    Use `log show` to collect recent Unified Log events.
    Requires macOS 10.12+.
    """
    if sys.platform != "darwin":
        return []

    results = []
    start_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    for predicate in _LOG_PREDICATES:
        cmd = [
            "/usr/bin/log", "show",
            "--style", "json",
            "--last", f"{since_seconds}s",
            "--predicate", predicate,
        ]
        out = _run(cmd, timeout=30)
        if not out:
            continue

        for line in out.splitlines():
            parsed = _parse_log_line(line)
            if parsed:
                results.append(parsed)
                if len(results) >= max_events:
                    break
        if len(results) >= max_events:
            break

    return results


# ── BSM Audit trail collector ─────────────────────────────────────────────────

async def collect_audit_trail(max_events: int = 500) -> List[Dict[str, Any]]:
    """
    Collect recent BSM audit trail events using praudit.
    Requires root/audit group membership.
    """
    if sys.platform != "darwin":
        return []

    results = []
    # Find the most recent audit log
    audit_dir = "/var/audit"
    if not os.path.isdir(audit_dir):
        return results

    try:
        files = sorted(
            [f for f in os.listdir(audit_dir) if re.match(r"\d{14}\.\d{14}", f)],
            reverse=True,
        )
        if not files:
            return results

        audit_file = os.path.join(audit_dir, files[0])
        cmd = ["praudit", "-x", audit_file]
        out = _run(cmd, timeout=30)
        if not out:
            return results

        for line in out.splitlines()[-max_events:]:
            parsed = _parse_praudit_line(line)
            if parsed:
                results.append(parsed)
    except PermissionError:
        logger.debug("Cannot read audit trail — need root or audit group")
    except Exception as e:
        logger.debug(f"Audit trail collection error: {e}")

    return results


# ── User login / session events ───────────────────────────────────────────────

async def collect_user_sessions() -> List[Dict[str, Any]]:
    """Parse /var/log/asl/* and `last` output for login/logout events."""
    results = []
    out = _run(["last", "-F", "-100"], timeout=10)
    if not out:
        return results

    last_re = re.compile(
        r"^(\S+)\s+(\S+)\s+(\S+)\s+(\w{3}\s+\w{3}\s+\d+\s[\d:]+\s\d{4})"
        r"(?:\s+-\s+(\w{3}\s+\w{3}\s+\d+\s[\d:]+\s\d{4}))?"
        r"(?:\s+\(([^)]+)\))?"
    )
    for line in out.splitlines():
        m = last_re.match(line)
        if not m:
            continue
        user, tty, host, login_time, logout_time, duration = m.groups()
        if user in ("reboot", "shutdown", "wtmp"):
            continue

        results.append({
            "timestamp":    _now_iso(),
            "source":       "macos_sessions",
            "platform":     "macos",
            "log_type":     "user_session",
            "severity":     "informational",
            "username":     user,
            "terminal":     tty,
            "remote_host":  host if host != "" else None,
            "login_time":   login_time,
            "logout_time":  logout_time,
            "duration":     duration,
            "event_type":   "session_end" if logout_time else "session_active",
            "raw":          line,
            "threat_intel": {
                "category": "authentication_success",
                "mitre":    "T1078",
                "note":     "Remote login detected",
            } if host and host not in ("console", "", "localhost") else {},
        })
    return results


# ── Main entry point ──────────────────────────────────────────────────────────

async def collect_macos_events(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Unified macOS event collector.

    Config keys:
      unified_log (bool, default True)   — collect Unified Log events
      audit_trail (bool, default True)   — collect BSM audit trail
      system_log  (bool, default True)   — collect /var/log/system.log
      persistence (bool, default True)   — scan persistence paths
      network     (bool, default True)   — collect network connections
      sessions    (bool, default True)   — collect user sessions
      look_back   (int,  default 300)    — seconds to look back for unified log
      max_events  (int,  default 5000)   — total event limit
    """
    if sys.platform != "darwin":
        logger.debug("macOS collector skipped — not running on macOS")
        return []

    look_back  = config.get("look_back", 300)
    max_events = config.get("max_events", 5000)
    all_events: List[Dict[str, Any]] = []

    tasks = []
    if config.get("unified_log", True):
        tasks.append(collect_unified_logs(look_back, max_events))
    if config.get("audit_trail", True):
        tasks.append(collect_audit_trail(max_events // 5))
    if config.get("system_log", True):
        tasks.append(collect_system_log())
    if config.get("persistence", True):
        tasks.append(scan_persistence())
    if config.get("network", True):
        tasks.append(collect_network_connections())
    if config.get("sessions", True):
        tasks.append(collect_user_sessions())

    gathered = await asyncio.gather(*tasks, return_exceptions=True)
    for result in gathered:
        if isinstance(result, Exception):
            logger.warning(f"macOS collector error: {result}")
        elif isinstance(result, list):
            all_events.extend(result)

    all_events = all_events[:max_events]
    logger.info(f"macOS collector: {len(all_events)} events collected")
    return all_events
