"""
Professional log collector — Linux (file tailing) + Windows (Event Log).
Supports: syslog, auth.log, kern.log, nginx, apache, json logs.
"""
import os
import re
import sys
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)

IS_WINDOWS = sys.platform == "win32"

# ── Level detection ──────────────────────────────────────────────────────────

_LEVEL_RULES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r'\b(CRITICAL|CRIT|FATAL|EMERG|PANIC)\b',       re.I), 'CRITICAL'),
    (re.compile(r'\b(ERROR|ERR|FAILED|FAILURE|REFUSED|DENIED)\b', re.I), 'ERROR'),
    (re.compile(r'\b(WARN(?:ING)?)\b',                           re.I), 'WARNING'),
    (re.compile(r'\b(DEBUG|TRACE|VERBOSE)\b',                    re.I), 'DEBUG'),
    (re.compile(r'segfault|core\s+dumped|oom.killer|out of memory', re.I), 'CRITICAL'),
    (re.compile(r'UFW BLOCK|iptables.*DROP|REJECT',              re.I), 'WARNING'),
]

def detect_level(text: str) -> str:
    for pattern, level in _LEVEL_RULES:
        if pattern.search(text):
            return level
    return 'INFO'

# ── Log format parsers ───────────────────────────────────────────────────────

# Standard syslog: "Apr 17 12:34:56 hostname process[pid]: message"
_SYSLOG_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<proc>\S+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$'
)

# RFC 5424: "<PRI>VERSION TIMESTAMP HOST APP PROCID MSGID STRUCTURED-DATA MSG"
_RFC5424_RE = re.compile(
    r'^<\d+>\d+\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<pid>\S+)\s+\S+\s+\S+\s*(?P<msg>.*)$'
)

# Nginx/Apache access log
_NGINX_RE = re.compile(
    r'^(?P<client>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+)'
)

# SSH patterns
_SSH_FAIL_RE    = re.compile(r'Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port (\d+)')
_SSH_ACCEPT_RE  = re.compile(r'Accepted (\S+) for (\S+) from (\S+) port (\d+)')
_SSH_INVALID_RE = re.compile(r'Invalid user (\S+) from (\S+)')
_SSH_DISCONNECT = re.compile(r'Disconnected from (?:authenticating )?user (\S+) (\S+)')

# Sudo
_SUDO_RE = re.compile(r'sudo:\s+(?P<user>\S+)\s+:.*?COMMAND=(?P<cmd>.*?)(?:\s*;|$)')

# UFW / iptables
_UFW_RE = re.compile(r'UFW (?P<action>BLOCK|ALLOW|LIMIT).*?SRC=(?P<src>\S+).*?DST=(?P<dst>\S+).*?PROTO=(?P<proto>\S+)')
_IPT_RE = re.compile(r'iptables.*?(?:DROP|REJECT).*?SRC=(\S+).*?DST=(\S+)')

# OOM killer
_OOM_RE = re.compile(r'Out of memory: Kill process (\d+) \((\S+)\)')

# su / privilege changes
_SU_RE = re.compile(r"su:\s+(?:session opened|session closed|authentication failure)")

# Cron
_CRON_RE = re.compile(r'CRON\[\d+\]:.*?(?:CMD|session opened|session closed)')


# ── MITRE ATT&CK technique map for syslog events ─────────────────────────────
_SYSLOG_MITRE: Dict[str, str] = {
    'ssh_failed':       'T1110',      # Brute Force
    'ssh_invalid_user': 'T1110.001',  # Password Guessing
    'ssh_accepted':     'T1078',      # Valid Accounts
    'sudo_command':     'T1548.003',  # Abuse Elevation: Sudo
    'firewall_block':   'T1562.004',  # Impair Defenses: Disable or Modify System Firewall
    'oom_kill':         'T1499',      # Endpoint Denial of Service
}


def _parse_syslog(line: str) -> Dict[str, Any]:
    fields: Dict[str, Any] = {}

    m = _SYSLOG_RE.match(line)
    if m:
        fields['process']  = m.group('proc')
        fields['pid']      = m.group('pid')
        fields['hostname'] = m.group('host')
        body = m.group('msg')
    else:
        m2 = _RFC5424_RE.match(line)
        if m2:
            fields['process']  = m2.group('app')
            fields['pid']      = m2.group('pid')
            fields['hostname'] = m2.group('host')
            body = m2.group('msg')
        else:
            body = line

    # SSH events
    sm = _SSH_FAIL_RE.search(line)
    if sm:
        fields.update({
            'event_type':       'ssh_failed',
            'ssh_user':         sm.group(1),
            'ssh_src_ip':       sm.group(2),
            'src_ip':           sm.group(2),
            'ssh_port':         sm.group(3),
            'mitre_technique':  _SYSLOG_MITRE['ssh_failed'],
        })

    sm = _SSH_ACCEPT_RE.search(line)
    if sm:
        fields.update({
            'event_type':       'ssh_accepted',
            'ssh_method':       sm.group(1),
            'ssh_user':         sm.group(2),
            'ssh_src_ip':       sm.group(3),
            'src_ip':           sm.group(3),
            'ssh_port':         sm.group(4),
            'mitre_technique':  _SYSLOG_MITRE['ssh_accepted'],
        })

    sm = _SSH_INVALID_RE.search(line)
    if sm:
        fields.update({
            'event_type':       'ssh_invalid_user',
            'ssh_user':         sm.group(1),
            'ssh_src_ip':       sm.group(2),
            'src_ip':           sm.group(2),
            'mitre_technique':  _SYSLOG_MITRE['ssh_invalid_user'],
        })

    # Sudo
    sm = _SUDO_RE.search(line)
    if sm:
        fields.update({
            'event_type':       'sudo_command',
            'sudo_user':        sm.group('user'),
            'sudo_cmd':         sm.group('cmd').strip(),
            'mitre_technique':  _SYSLOG_MITRE['sudo_command'],
        })

    # UFW
    sm = _UFW_RE.search(line)
    if sm:
        fields.update({
            'event_type':       'firewall_block',
            'fw_action':        sm.group('action'),
            'src_ip':           sm.group('src'),
            'dst_ip':           sm.group('dst'),
            'protocol':         sm.group('proto'),
            'mitre_technique':  _SYSLOG_MITRE['firewall_block'],
        })

    # OOM
    sm = _OOM_RE.search(line)
    if sm:
        fields.update({
            'event_type':       'oom_kill',
            'oom_pid':          sm.group(1),
            'oom_proc':         sm.group(2),
            'mitre_technique':  _SYSLOG_MITRE['oom_kill'],
        })

    return fields


def _parse_nginx_access(line: str) -> Dict[str, Any]:
    m = _NGINX_RE.match(line)
    if not m:
        return {}
    status = int(m.group('status'))
    return {
        'event_type':  'http_request',
        'client_ip':   m.group('client'),
        'http_method': m.group('method'),
        'http_path':   m.group('path'),
        'http_status': status,
        'bytes_sent':  int(m.group('bytes')),
        'is_error':    status >= 400,
    }


def _try_json_log(line: str) -> Optional[Dict[str, Any]]:
    """Try to parse JSON-formatted log lines (e.g. from Docker, apps)."""
    line = line.strip()
    if not line.startswith('{'):
        return None
    try:
        data = json.loads(line)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return None


# ── File position tracker ────────────────────────────────────────────────────

class PositionTracker:
    """Persist read positions per log file to avoid duplicate entries."""

    def __init__(self, state_file: str = '.log_positions'):
        from collectors._paths import data_path as _dp
        self._file = _dp(state_file)
        self._pos: Dict[str, int] = {}
        self._inodes: Dict[str, int] = {}
        self._load()

    def _load(self):
        try:
            if os.path.exists(self._file):
                with open(self._file) as f:
                    for line in f:
                        line = line.strip()
                        if '=' in line:
                            path, rest = line.split('=', 1)
                            parts = rest.split(':')
                            self._pos[path] = int(parts[0])
                            if len(parts) > 1:
                                self._inodes[path] = int(parts[1])
        except Exception:
            pass

    def _save(self):
        try:
            with open(self._file, 'w') as f:
                for path, pos in self._pos.items():
                    inode = self._inodes.get(path, 0)
                    f.write(f"{path}={pos}:{inode}\n")
        except Exception:
            pass

    def get(self, path: str) -> int:
        try:
            inode = os.stat(path).st_ino
            if self._inodes.get(path) != inode:
                # File was rotated
                logger.info(f"Log rotation detected: {path}")
                self._pos[path] = 0
                self._inodes[path] = inode
        except Exception:
            pass
        return self._pos.get(path, 0)

    def set(self, path: str, pos: int):
        self._pos[path] = pos
        try:
            self._inodes[path] = os.stat(path).st_ino
        except Exception:
            pass
        self._save()


_tracker = PositionTracker()

# ── Detect source type ───────────────────────────────────────────────────────

def _detect_source_type(path: str) -> str:
    name = os.path.basename(path).lower()
    if 'nginx' in name or 'access' in name:
        return 'nginx'
    if 'apache' in name or 'httpd' in name:
        return 'apache'
    if 'auth' in name:
        return 'auth'
    if 'kern' in name:
        return 'kernel'
    if 'syslog' in name or 'messages' in name:
        return 'syslog'
    return 'syslog'

# ── Linux log collection ─────────────────────────────────────────────────────

def collect_linux_logs(log_paths: List[str], max_lines_per_file: int = 500) -> List[Dict[str, Any]]:
    results = []
    now = datetime.now(timezone.utc).isoformat()

    for path in log_paths:
        if not os.path.exists(path):
            continue

        source_type = _detect_source_type(path)
        source_name = os.path.basename(path)

        try:
            file_size = os.path.getsize(path)
            last_pos  = _tracker.get(path)

            # Handle truncation
            if file_size < last_pos:
                last_pos = 0

            # Skip if nothing new
            if file_size == last_pos:
                continue

            with open(path, 'r', errors='replace') as f:
                f.seek(last_pos)
                lines_read = []
                while len(lines_read) < max_lines_per_file:
                    raw_line = f.readline()
                    if not raw_line:
                        break
                    lines_read.append(raw_line)
                new_pos = f.tell()

            _tracker.set(path, new_pos)

            for raw_line in lines_read:
                line = raw_line.rstrip('\n').rstrip('\r')
                if not line.strip():
                    continue

                # Try JSON first
                json_data = _try_json_log(line)
                if json_data:
                    results.append({
                        'timestamp':     json_data.get('time', json_data.get('timestamp', now)),
                        'level':         json_data.get('level', json_data.get('severity', 'INFO')).upper(),
                        'source':        json_data.get('logger', source_name),
                        'message':       json_data.get('message', json_data.get('msg', line[:2048])),
                        'raw':           line[:4096],
                        'parsed_fields': {k: v for k, v in json_data.items()
                                          if k not in ('message', 'msg', 'time', 'timestamp', 'level')},
                    })
                    continue

                # Parse based on source type
                if source_type in ('nginx', 'apache'):
                    parsed = _parse_nginx_access(line)
                    status = parsed.get('http_status', 200)
                    level  = 'ERROR' if status >= 500 else 'WARNING' if status >= 400 else 'INFO'
                else:
                    parsed = _parse_syslog(line)
                    level  = detect_level(line)

                results.append({
                    'timestamp':     now,
                    'level':         level,
                    'source':        parsed.get('process', source_name),
                    'message':       line[:2048],
                    'raw':           line[:4096],
                    'parsed_fields': parsed,
                })

        except PermissionError:
            logger.warning(f"Permission denied: {path}")
        except Exception as e:
            logger.error(f"Error reading {path}: {e}", exc_info=True)

    return results

# ── Windows Event Log collection ─────────────────────────────────────────────

_WIN_LEVEL_MAP = {
    1: 'CRITICAL',   # Critical
    2: 'ERROR',      # Error
    3: 'WARNING',    # Warning
    4: 'INFO',       # Information
    5: 'DEBUG',      # Verbose
    0: 'INFO',       # LogAlways
}

# Track last record number per channel
_win_last_record: Dict[str, int] = {}


def collect_windows_logs(channels: List[str], max_events: int = 200) -> List[Dict[str, Any]]:
    results = []
    try:
        import win32evtlog
        import win32evtlogutil
        import win32con
        import pywintypes
    except ImportError:
        logger.warning("pywin32 not installed — Windows Event Log unavailable")
        return results

    for channel in channels:
        try:
            hand  = win32evtlog.OpenEventLog(None, channel)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            last  = _win_last_record.get(channel, 0)
            count = 0

            while count < max_events:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break
                for ev in events:
                    rec_num = ev.RecordNumber
                    if rec_num <= last:
                        continue
                    _win_last_record[channel] = max(_win_last_record.get(channel, 0), rec_num)

                    try:
                        msg = win32evtlogutil.SafeFormatMessage(ev, channel) or ''
                    except Exception:
                        msg = f"EventID={ev.EventID & 0xFFFF}"

                    level = _WIN_LEVEL_MAP.get(getattr(ev, 'EventType', 4), 'INFO')
                    ts    = datetime.utcnow().isoformat()

                    results.append({
                        'timestamp': ts,
                        'level':     level,
                        'source':    f"WinEvent/{channel}/{ev.SourceName}",
                        'message':   msg.strip()[:2048],
                        'raw':       msg.strip()[:4096],
                        'parsed_fields': {
                            'event_id':     ev.EventID & 0xFFFF,
                            'record_num':   rec_num,
                            'computer':     ev.ComputerName,
                            'source_name':  ev.SourceName,
                            'category':     ev.EventCategory,
                            'event_type':   'windows_event',
                        },
                    })
                    count += 1
                    if count >= max_events:
                        break

            win32evtlog.CloseEventLog(hand)

        except Exception as e:
            logger.error(f"Windows event log '{channel}' error: {e}")

    return results

# ── Public interface ─────────────────────────────────────────────────────────

def collect_logs(config: dict) -> List[Dict[str, Any]]:
    """Entry point — auto-selects OS collector."""
    if IS_WINDOWS:
        channels = config.get('windows_event_logs', ['Security', 'System', 'Application'])
        logs = collect_windows_logs(channels)
    else:
        paths = config.get('log_paths', ['/var/log/syslog', '/var/log/auth.log'])
        logs  = collect_linux_logs(paths)

    logger.debug(f"Collected {len(logs)} log entries")
    return logs
