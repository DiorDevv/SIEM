"""
Process monitor — detects new process creation, suspicious processes,
privilege changes, and process injection indicators.
"""
import os
import re
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Set

logger = logging.getLogger(__name__)

_prev_pids: Set[int] = set()
_PIDS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '.prev_pids')


def _load_prev_pids() -> Set[int]:
    try:
        if os.path.exists(_PIDS_FILE):
            with open(_PIDS_FILE) as f:
                return {int(x) for x in f.read().split() if x.strip().isdigit()}
    except Exception:
        pass
    return set()


def _save_pids(pids: Set[int]):
    try:
        with open(_PIDS_FILE, 'w') as f:
            f.write('\n'.join(str(p) for p in pids))
    except Exception:
        pass

SUSPICIOUS_CMDS = re.compile(
    r'(nc\s+-[le]|ncat|netcat|/dev/tcp|/dev/udp'
    r'|wget\s+http|curl\s+http.*\|\s*(?:bash|sh|python|perl)'
    r'|base64\s+-d.*\|\s*(?:bash|sh)'
    r'|python.*-c.*(?:socket|subprocess|exec)'
    r'|perl\s+-e'
    r'|msfvenom|msfconsole|metasploit'
    r'|john\s|hashcat'
    r'|tcpdump\s+-i|wireshark'
    r'|nmap\s|masscan\s'
    r'|hydra\s|medusa\s|crowbar\s'
    r'|sqlmap|nikto|dirb|gobuster'
    r'|mimikatz|lazagne|secretsdump'
    r'|chmod\s+[0-7]*[67][0-7]{2}\s+/)',
    re.I,
)

PRIV_ESCALATION_CMDS = re.compile(
    r'(sudo\s+-s|sudo\s+su|su\s+-\s*$|sudo\s+bash|sudo\s+sh'
    r'|pkexec\s+bash|pkexec\s+sh'
    r'|/usr/bin/python.*os\.setuid\(0\)'
    r'|chmod\s+u\+s)',
    re.I,
)

PERSISTENCE_CMDS = re.compile(
    r'(crontab\s+-e|at\s+now|systemctl\s+enable'
    r'|update-rc\.d|chkconfig\s+.*\s+on'
    r'|echo.*>>\s*/etc/rc\.local'
    r'|cp.*\s+/etc/init\.d/'
    r'|ln.*\s+/etc/cron)',
    re.I,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_process_log(severity: str, event: str, detail: str, extra: dict = None) -> Dict[str, Any]:
    msg = f"PROCESS [{event.upper()}]: {detail}"
    fields = {"event_type": event, "detail": detail}
    if extra:
        fields.update(extra)
    return {
        "timestamp":     _now(),
        "level":         severity,
        "source":        "process_monitor",
        "message":       msg,
        "raw":           msg,
        "parsed_fields": fields,
    }


def collect_processes() -> List[Dict[str, Any]]:
    """Collect new processes and check for suspicious activity."""
    events = []
    if os.name == "nt":
        return events

    try:
        import psutil
    except ImportError:
        return events

    global _prev_pids
    if not _prev_pids:
        _prev_pids = _load_prev_pids()
    current_pids: Set[int] = set()

    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username',
                                      'ppid', 'status', 'cpu_percent', 'memory_percent']):
        try:
            info = proc.info
            pid  = info['pid']
            current_pids.add(pid)
            cmdline = " ".join(info.get('cmdline') or [])

            # ── New process ──────────────────────────────────────────────────
            if pid not in _prev_pids and _prev_pids:
                entry = {
                    "timestamp":     _now(),
                    "level":         "INFO",
                    "source":        "process_monitor",
                    "message":       f"New process: [{pid}] {info['name']} user={info.get('username','')}",
                    "raw":           cmdline[:512],
                    "parsed_fields": {
                        "event_type":  "process_execution",
                        "pid":         pid,
                        "process":     info['name'],
                        "cmdline":     cmdline[:512],
                        "user":        info.get('username', ''),
                        "ppid":        info.get('ppid'),
                    },
                }

                # Suspicious command check
                if cmdline and SUSPICIOUS_CMDS.search(cmdline):
                    entry["level"] = "CRITICAL"
                    entry["parsed_fields"]["event_type"] = "suspicious_process"
                    entry["message"] = f"SUSPICIOUS process: [{pid}] {cmdline[:200]}"
                    events.append(entry)

                elif cmdline and PRIV_ESCALATION_CMDS.search(cmdline):
                    entry["level"] = "HIGH"
                    entry["parsed_fields"]["event_type"] = "privilege_escalation"
                    entry["message"] = f"Privilege escalation attempt: [{pid}] {cmdline[:200]}"
                    events.append(entry)

                elif cmdline and PERSISTENCE_CMDS.search(cmdline):
                    entry["level"] = "MEDIUM"
                    entry["parsed_fields"]["event_type"] = "persistence_attempt"
                    entry["message"] = f"Persistence mechanism: [{pid}] {cmdline[:200]}"
                    events.append(entry)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
        except Exception as e:
            logger.debug(f"Process iter error: {e}")

    _prev_pids = current_pids
    _save_pids(current_pids)
    return events
