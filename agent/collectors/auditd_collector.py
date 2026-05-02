"""
Auditd log collector and parser.
Reads /var/log/audit/audit.log and parses structured audit records.
Supports: SYSCALL, USER_AUTH, USER_LOGIN, EXECVE, PATH, SOCKADDR events.
"""
import os
import re
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

AUDIT_LOG = "/var/log/audit/audit.log"
_POSITION_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '.audit_pos')

_TYPE_RE  = re.compile(r'^type=(\S+)')
_TIME_RE  = re.compile(r'msg=audit\((\d+\.\d+):(\d+)\)')
_KV_RE    = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')

INTERESTING_TYPES = {
    'USER_AUTH', 'USER_LOGIN', 'USER_LOGOUT', 'USER_CMD',
    'USER_ROLE_CHANGE', 'ADD_USER', 'DEL_USER', 'ADD_GROUP', 'DEL_GROUP',
    'SYSCALL', 'EXECVE', 'PATH', 'SOCKADDR',
    'ANOM_PROMISCUOUS', 'ANOM_ABEND', 'ANOM_LOGIN_FAILURES',
    'AVC', 'SELINUX_ERR',
    'KERN_MODULE', 'CRYPTO_KEY_USER',
}

SEVERITY_MAP = {
    'USER_AUTH':           'INFO',
    'USER_LOGIN':          'INFO',
    'USER_LOGOUT':         'INFO',
    'USER_CMD':            'WARNING',
    'ADD_USER':            'WARNING',
    'DEL_USER':            'WARNING',
    'ADD_GROUP':           'WARNING',
    'DEL_GROUP':           'WARNING',
    'ANOM_PROMISCUOUS':    'CRITICAL',
    'ANOM_ABEND':          'ERROR',
    'ANOM_LOGIN_FAILURES': 'WARNING',
    'AVC':                 'WARNING',
    'SELINUX_ERR':         'ERROR',
    'KERN_MODULE':         'HIGH',
    'SYSCALL':             'INFO',
    'EXECVE':              'INFO',
}

EVENT_TYPE_MAP = {
    'USER_AUTH':           'user_authentication',
    'USER_LOGIN':          'user_login',
    'USER_LOGOUT':         'user_logout',
    'USER_CMD':            'user_command',
    'ADD_USER':            'user_created',
    'DEL_USER':            'user_deleted',
    'ADD_GROUP':           'group_created',
    'DEL_GROUP':           'group_deleted',
    'ANOM_PROMISCUOUS':    'network_sniffing',
    'ANOM_ABEND':          'process_crash',
    'ANOM_LOGIN_FAILURES': 'authentication_failed',
    'AVC':                 'selinux_denial',
    'KERN_MODULE':         'kernel_module_loaded',
    'EXECVE':              'process_execution',
    'SYSCALL':             'system_call',
}

# MITRE ATT&CK technique per audit event type
MITRE_MAP = {
    'USER_AUTH':           'T1078',      # Valid Accounts
    'USER_LOGIN':          'T1078',      # Valid Accounts
    'ANOM_LOGIN_FAILURES': 'T1110',      # Brute Force
    'ADD_USER':            'T1136.001',  # Create Account: Local Account
    'DEL_USER':            'T1531',      # Account Access Removal
    'USER_CMD':            'T1548.003',  # Abuse Elevation: Sudo
    'ANOM_PROMISCUOUS':    'T1040',      # Network Sniffing
    'KERN_MODULE':         'T1215',      # Kernel Modules and Extensions
    'EXECVE':              'T1059',      # Command and Scripting Interpreter
    'AVC':                 'T1068',      # Exploitation for Privilege Escalation
    'SELINUX_ERR':         'T1068',      # Exploitation for Privilege Escalation
    'CRYPTO_KEY_USER':     'T1552',      # Unsecured Credentials
}


def _load_pos() -> int:
    try:
        if os.path.exists(_POSITION_FILE):
            with open(_POSITION_FILE) as f:
                return int(f.read().strip())
    except Exception:
        pass
    return 0


def _save_pos(pos: int):
    try:
        with open(_POSITION_FILE, 'w') as f:
            f.write(str(pos))
    except Exception:
        pass


def _parse_kv(text: str) -> Dict[str, str]:
    result = {}
    for m in _KV_RE.finditer(text):
        key = m.group(1)
        val = m.group(2) if m.group(2) is not None else m.group(3)
        result[key] = val
    return result


def _parse_audit_line(line: str) -> Dict[str, Any]:
    line = line.strip()
    if not line:
        return {}

    type_m = _TYPE_RE.match(line)
    if not type_m:
        return {}
    audit_type = type_m.group(1)

    if audit_type not in INTERESTING_TYPES:
        return {}

    time_m = _TIME_RE.search(line)
    ts = datetime.now(timezone.utc).isoformat()
    if time_m:
        try:
            ts = datetime.fromtimestamp(
                float(time_m.group(1)), tz=timezone.utc
            ).isoformat()
        except Exception:
            pass

    kv = _parse_kv(line)

    severity   = SEVERITY_MAP.get(audit_type, 'INFO')
    event_type = EVENT_TYPE_MAP.get(audit_type, audit_type.lower())

    # Build a human-readable message
    parts = [f"type={audit_type}"]
    for key in ('uid', 'auid', 'euid', 'user', 'acct', 'exe', 'comm', 'key', 'res'):
        if key in kv:
            parts.append(f"{key}={kv[key]}")

    # Check for failure
    if kv.get('res') in ('failed', 'no'):
        severity = 'WARNING' if severity == 'INFO' else severity

    message = " ".join(parts)

    mitre = MITRE_MAP.get(audit_type, '')
    parsed = {
        "event_type":   event_type,
        "audit_type":   audit_type,
        "decoder":      "auditd",
        **kv,
    }
    if mitre:
        parsed["mitre_technique"] = mitre

    return {
        "timestamp":     ts,
        "level":         severity,
        "source":        f"auditd/{audit_type}",
        "message":       message[:2048],
        "raw":           line[:4096],
        "parsed_fields": parsed,
    }


def collect_auditd_logs(max_lines: int = 500) -> List[Dict[str, Any]]:
    if not os.path.exists(AUDIT_LOG):
        return []

    results = []
    pos = _load_pos()

    try:
        size = os.path.getsize(AUDIT_LOG)
        if size < pos:
            pos = 0  # rotated

        with open(AUDIT_LOG, 'r', errors='replace') as f:
            f.seek(pos)
            count = 0
            while count < max_lines:
                line = f.readline()
                if not line:
                    break
                parsed = _parse_audit_line(line)
                if parsed:
                    results.append(parsed)
                count += 1
            _save_pos(f.tell())

    except PermissionError:
        logger.warning("Permission denied reading audit.log (run agent as root)")
    except Exception as e:
        logger.error(f"Auditd collection error: {e}", exc_info=True)

    return results
