"""
Journald collector — captures systemd journal events via journalctl.
Handles: screen lock/unlock, auth failures, session open/close,
         sudo commands, SSH, USB devices, network changes, process crashes.
"""
import json
import logging
import os
import subprocess
import re
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)

from collectors._paths import data_path as _data_path
_CURSOR_FILE = _data_path('.journald_cursor')

# ── Event classification ──────────────────────────────────────────────────────

_EVENT_PATTERNS: List[tuple] = [
    # Screen lock / unlock
    (re.compile(r'gkr-pam:.*unlocked login keyring',        re.I), 'screen_unlock',   'WARNING'),
    (re.compile(r'gkr-pam:.*locked login keyring',          re.I), 'screen_lock',     'INFO'),
    (re.compile(r'pam_unix\(gdm-(?:password|fingerprint):auth\).*authentication failure', re.I), 'screen_auth_failure', 'ERROR'),
    (re.compile(r'pam_unix\(gdm-(?:password|fingerprint):session\).*session opened',     re.I), 'screen_unlock',   'INFO'),
    (re.compile(r'pam_unix\(gdm-(?:password|fingerprint):session\).*session closed',     re.I), 'screen_lock',     'INFO'),

    # Login / logout
    (re.compile(r'pam_unix\(login:session\).*session opened for user (\S+)',   re.I), 'user_login',    'WARNING'),
    (re.compile(r'pam_unix\(login:session\).*session closed for user (\S+)',   re.I), 'user_logout',   'INFO'),
    (re.compile(r'pam_unix\(sshd:auth\).*authentication failure',              re.I), 'ssh_auth_failure', 'ERROR'),
    (re.compile(r'Accepted (?:password|publickey) for (\S+) from (\S+)',       re.I), 'ssh_login',     'WARNING'),
    (re.compile(r'Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+)', re.I), 'ssh_failed', 'ERROR'),
    (re.compile(r'Invalid user (\S+) from (\S+)',                              re.I), 'ssh_invalid_user', 'ERROR'),
    (re.compile(r'Disconnected from (?:authenticating )?user (\S+)',           re.I), 'ssh_disconnect', 'INFO'),

    # Sudo
    (re.compile(r'sudo:.*COMMAND=(.*)',                                        re.I), 'sudo_command',  'WARNING'),
    (re.compile(r'sudo:.*authentication failure',                              re.I), 'sudo_auth_failure', 'ERROR'),
    (re.compile(r'sudo:.*NOT in sudoers',                                      re.I), 'sudo_denied',   'CRITICAL'),

    # User / group management
    (re.compile(r'useradd.*new user.*name=(\S+)',                              re.I), 'user_created',  'WARNING'),
    (re.compile(r'userdel.*user (\S+)',                                        re.I), 'user_deleted',  'WARNING'),
    (re.compile(r'groupadd.*new group.*name=(\S+)',                            re.I), 'group_created', 'WARNING'),
    (re.compile(r'passwd.*password changed for (\S+)',                         re.I), 'password_changed', 'WARNING'),

    # USB / hardware
    (re.compile(r'USB.*(?:connect|attach|new.*device)',                        re.I), 'usb_connected',    'WARNING'),
    (re.compile(r'USB.*(?:disconnect|remove)',                                 re.I), 'usb_disconnected', 'INFO'),

    # Network
    (re.compile(r'NetworkManager.*device.*deactivated',                        re.I), 'network_down',   'WARNING'),
    (re.compile(r'NetworkManager.*connection.*activated',                      re.I), 'network_up',     'INFO'),
    (re.compile(r'NetworkManager.*new connection.*ssid.*["\'](.+)["\']',       re.I), 'wifi_connected', 'INFO'),

    # System
    (re.compile(r'Reached target.*(?:shutdown|reboot)',                        re.I), 'system_shutdown', 'CRITICAL'),
    (re.compile(r'systemd.*Starting.*(?:shutdown|reboot)',                     re.I), 'system_shutdown', 'CRITICAL'),
    (re.compile(r'kernel:.*segfault|core dumped|oom-kill',                     re.I), 'process_crash',  'ERROR'),
    (re.compile(r'kernel:.*Out of memory.*Kill process (\d+) \((\S+)\)',       re.I), 'oom_kill',       'CRITICAL'),

    # Package management
    (re.compile(r'apt.*install.*(?:ok|installed)',                             re.I), 'package_installed', 'WARNING'),
    (re.compile(r'apt.*remove|dpkg.*remove',                                  re.I), 'package_removed',  'WARNING'),

    # Cron
    (re.compile(r'CRON\[\d+\].*CMD\s+\((.+)\)',                               re.I), 'cron_exec',     'DEBUG'),

    # Firewall
    (re.compile(r'UFW BLOCK',                                                  re.I), 'firewall_block', 'WARNING'),
    (re.compile(r'UFW ALLOW',                                                  re.I), 'firewall_allow', 'DEBUG'),
]


def _classify(message: str) -> Tuple[str, str]:
    """Returns (event_type, level)."""
    for pattern, etype, level in _EVENT_PATTERNS:
        if pattern.search(message):
            return etype, level
    return 'system_log', 'INFO'


def _load_cursor() -> Optional[str]:
    try:
        with open(_CURSOR_FILE, 'r') as f:
            return f.read().strip() or None
    except FileNotFoundError:
        return None


def _save_cursor(cursor: str):
    try:
        with open(_CURSOR_FILE, 'w') as f:
            f.write(cursor)
    except Exception as e:
        logger.warning(f"Could not save journald cursor: {e}")


def collect_journald_events(max_lines: int = 500) -> List[Dict[str, Any]]:
    """
    Reads new journald entries since last cursor.
    Returns list of normalized log dicts.
    """
    cursor = _load_cursor()

    cmd = [
        'journalctl',
        '--no-pager',
        '-o', 'json',
        '-n', str(max_lines),
        '--output-fields=MESSAGE,_COMM,_PID,_UID,SYSLOG_IDENTIFIER,PRIORITY,__REALTIME_TIMESTAMP,__CURSOR,_HOSTNAME',
    ]
    if cursor:
        cmd += ['--after-cursor', cursor]
    else:
        # First run: only last 5 minutes to avoid log flood
        cmd += ['--since', '5 minutes ago']

    results: List[Dict[str, Any]] = []
    last_cursor: Optional[str] = None

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        lines = proc.stdout.strip().splitlines()
    except subprocess.TimeoutExpired:
        logger.warning("journalctl timed out")
        return results
    except FileNotFoundError:
        logger.debug("journalctl not available")
        return results
    except Exception as e:
        logger.error(f"journalctl error: {e}")
        return results

    for line in lines:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        msg = entry.get('MESSAGE', '')
        if isinstance(msg, list):
            msg = ' '.join(str(x) for x in msg)
        msg = str(msg).strip()

        if not msg or len(msg) < 4:
            continue

        # Skip noisy entries
        if any(skip in msg for skip in [
            'dbus-daemon', 'gnome-shell: DING', 'dconf-service',
            'wpa_supplicant: wlp', 'CTRL-EVENT-SIGNAL-CHANGE',
            'dbus-update-activation-environment', 'rtkit-daemon',
        ]):
            continue

        realtime = entry.get('__REALTIME_TIMESTAMP')
        if realtime:
            ts = datetime.fromtimestamp(int(realtime) / 1_000_000, tz=timezone.utc).isoformat()
        else:
            ts = datetime.now(timezone.utc).isoformat()

        ident = entry.get('SYSLOG_IDENTIFIER') or entry.get('_COMM') or 'kernel'
        pid   = entry.get('_PID', '')
        uid   = entry.get('_UID', '')

        event_type, level = _classify(msg)

        # Map journald PRIORITY to level (only if our classifier didn't find a specific type)
        if event_type == 'system_log':
            prio = str(entry.get('PRIORITY', '6'))
            level = {
                '0': 'CRITICAL', '1': 'CRITICAL', '2': 'CRITICAL',
                '3': 'ERROR', '4': 'WARNING', '5': 'WARNING',
                '6': 'INFO', '7': 'DEBUG',
            }.get(prio, 'INFO')

        last_cursor = entry.get('__CURSOR', last_cursor)

        results.append({
            'timestamp':     ts,
            'level':         level,
            'source':        f"journald/{ident}",
            'message':       msg[:2048],
            'raw':           msg[:4096],
            'parsed_fields': {
                'event_type': event_type,
                'pid':        pid,
                'uid':        uid,
                'ident':      ident,
                'hostname':   entry.get('_HOSTNAME', ''),
            },
        })

    if last_cursor:
        _save_cursor(last_cursor)

    logger.debug(f"Journald: collected {len(results)} events")
    return results
