"""
Correlation Engine — Wazuh-style multi-event attack pattern detection.

Maintains a sliding window of recent events and fires composite alerts
when defined attack patterns are detected across time.

Rules covered:
  - SSH brute force (5+ failures from same IP in 60s)         T1110.001
  - Login after brute force (success after 3+ failures)       T1078
  - Port scan → suspicious connection (same IP within 120s)   T1046,T1190
  - Privilege escalation → persistence (within 120s)         T1548,T1547
  - Credential dump → lateral movement (within 300s)         T1003,T1021
  - Multiple CRITICAL indicators from same source (4+ in 2m) T1071
  - File modified → executed as suspicious process            T1059,T1105
  - Privilege escalation → credential access                 T1548,T1003
  - New user → admin group add (within 60s)                  T1136.001,T1098
  - C2 beaconing + suspicious process (same host)            T1071.001
"""
import hashlib
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger_name = __name__
import logging
logger = logging.getLogger(logger_name)

_lock = threading.Lock()

# Sliding window: event_type → deque of (monotonic_ts, log_dict)
_window: Dict[str, deque] = defaultdict(deque)

_WINDOW_SEC = 300   # 5-minute correlation window
_FIRED: Dict[str, float] = {}  # rule_key → last fired ts


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now_ts() -> float:
    return time.monotonic()


def _iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _evict():
    cutoff = _now_ts() - _WINDOW_SEC
    for q in _window.values():
        while q and q[0][0] < cutoff:
            q.popleft()
    stale = [k for k, v in _FIRED.items() if _now_ts() - v > 3600]
    for k in stale:
        del _FIRED[k]


def _already_fired(key: str, cooldown: float) -> bool:
    return (_now_ts() - _FIRED.get(key, 0)) < cooldown


def _mark_fired(key: str):
    _FIRED[key] = _now_ts()


def _ip_of(log: Dict) -> str:
    pf = log.get('parsed_fields') or {}
    for f in ('src_ip', 'ssh_src_ip', 'attacker_ip', 'client_ip', 'remote_ip', 'dst_ip'):
        v = str(pf.get(f) or log.get(f) or '').strip()
        if v and v not in ('', 'None', '0.0.0.0', '::'):
            return v
    return ''


def _user_of(log: Dict) -> str:
    pf = log.get('parsed_fields') or {}
    for f in ('user', 'username', 'ssh_user'):
        v = str(pf.get(f) or '').strip()
        if v:
            return v
    return ''


def _get_logs(etype: str, since: float) -> List[Dict]:
    cutoff = _now_ts() - since
    return [log for ts, log in list(_window.get(etype, deque())) if ts >= cutoff]


def _count_by_ip(etypes: List[str], ip: str, window_sec: float) -> int:
    cutoff = _now_ts() - window_sec
    count = 0
    for etype in etypes:
        for ts, log in list(_window.get(etype, deque())):
            if ts >= cutoff and _ip_of(log) == ip:
                count += 1
    return count


def _unique_ips(etypes: List[str], window_sec: float) -> set:
    cutoff = _now_ts() - window_sec
    ips = set()
    for etype in etypes:
        for ts, log in list(_window.get(etype, deque())):
            if ts >= cutoff:
                ip = _ip_of(log)
                if ip:
                    ips.add(ip)
    return ips


def _make_alert(rule_id: str, severity: str, title: str, detail: str,
                mitre: str, extra: Dict = None) -> Dict[str, Any]:
    msg = f"CORR [{rule_id.upper()}]: {title} — {detail}"
    fields: Dict[str, Any] = {
        'event_type':      f'corr_{rule_id}',
        'rule_id':         rule_id,
        'title':           title,
        'detail':          detail,
        'mitre_technique': mitre,
    }
    if extra:
        fields.update(extra)
    return {
        'timestamp':     _iso(),
        'level':         severity,
        'source':        'correlation_engine',
        'message':       msg,
        'raw':           msg,
        'parsed_fields': fields,
    }


# ── Main entry point ──────────────────────────────────────────────────────────

def correlate(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Feed new events into the correlation window and return any triggered alerts.
    Call this inside send_logs() pipeline after dedup, before sending to server.
    """
    if not events:
        return []

    now = _now_ts()
    alerts: List[Dict[str, Any]] = []

    with _lock:
        _evict()

        # ── Ingest events ─────────────────────────────────────────────────────
        for log in events:
            pf = log.get('parsed_fields') or {}
            etype = str(pf.get('event_type') or '')
            if etype:
                _window[etype].append((now, log))

        # ── RULE 1: SSH Brute Force ───────────────────────────────────────────
        failure_types = ['ssh_auth_failure', 'ssh_failed', 'ssh_invalid_user']
        for ip in _unique_ips(failure_types, 60):
            count = _count_by_ip(failure_types, ip, 60)
            if count >= 5:
                key = f'brute_ssh_{ip}'
                if not _already_fired(key, 120):
                    a = _make_alert(
                        'brute_force_ssh', 'CRITICAL',
                        'SSH Brute Force Attack',
                        f'{count} failed SSH logins from {ip} in 60s',
                        'T1110.001',
                        {'attacker_ip': ip, 'attempt_count': count},
                    )
                    alerts.append(a)
                    _mark_fired(key)
                    logger.warning(f"Correlation: SSH brute force from {ip} ({count} attempts)")

        # ── RULE 2: Successful Login After Brute Force ────────────────────────
        for ip in _unique_ips(['ssh_login'], 300):
            fails = _count_by_ip(failure_types, ip, 300)
            if fails >= 3:
                key = f'login_after_brute_{ip}'
                if not _already_fired(key, 300):
                    a = _make_alert(
                        'login_after_brute', 'CRITICAL',
                        'Successful Login After Brute Force',
                        f'Login from {ip} succeeded after {fails} failures in 5min',
                        'T1078',
                        {'attacker_ip': ip, 'prior_failures': fails},
                    )
                    alerts.append(a)
                    _mark_fired(key)
                    logger.warning(f"Correlation: Login after brute from {ip}")

        # ── RULE 3: Port Scan → Suspicious Connection ─────────────────────────
        scan_logs  = _get_logs('port_scan_detected',   120)
        conn_logs  = _get_logs('suspicious_connection', 120)
        for scan_log in scan_logs[-5:]:
            scan_ip = _ip_of(scan_log)
            if not scan_ip:
                continue
            for conn_log in conn_logs:
                if _ip_of(conn_log) == scan_ip:
                    key = f'scan_then_connect_{scan_ip}'
                    if not _already_fired(key, 300):
                        a = _make_alert(
                            'scan_then_connect', 'HIGH',
                            'Port Scan Followed by Suspicious Connection',
                            f'Host {scan_ip} scanned then connected to suspicious port',
                            'T1046,T1190',
                            {'attacker_ip': scan_ip},
                        )
                        alerts.append(a)
                        _mark_fired(key)
                    break

        # ── RULE 4: Privilege Escalation → Persistence ───────────────────────
        priv_logs = _get_logs('privilege_escalation', 120)
        persist_logs = (
            _get_logs('persistence_attempt', 120) +
            _get_logs('reg_value_added',     120) +
            _get_logs('new_service',         120)
        )
        if priv_logs and persist_logs:
            user = _user_of(priv_logs[-1]) or 'unknown'
            key = f'priv_then_persist_{user}_{int(now/120)}'
            if not _already_fired(key, 300):
                a = _make_alert(
                    'priv_esc_then_persist', 'CRITICAL',
                    'Privilege Escalation Followed by Persistence',
                    f"User '{user}' escalated privileges then established persistence",
                    'T1548,T1547',
                    {'user': user},
                )
                alerts.append(a)
                _mark_fired(key)

        # ── RULE 5: Credential Dump → Lateral Movement ───────────────────────
        cred_logs    = _get_logs('credential_access', 300)
        lateral_logs = _get_logs('lateral_movement',  300)
        if cred_logs and lateral_logs:
            key = f'cred_then_lateral_{int(now/300)}'
            if not _already_fired(key, 600):
                a = _make_alert(
                    'cred_dump_lateral', 'CRITICAL',
                    'Credential Dump Followed by Lateral Movement',
                    'Credentials extracted then used for lateral movement within 5min',
                    'T1003,T1021',
                )
                alerts.append(a)
                _mark_fired(key)

        # ── RULE 6: Multiple CRITICAL Indicators from Same Source ─────────────
        threat_etypes = [
            'suspicious_connection', 'tor_connection', 'suspicious_process',
            'credential_access', 'lateral_movement', 'port_scan_detected',
        ]
        ip_counts: Dict[str, int] = defaultdict(int)
        cutoff_2m = now - 120
        for etype in threat_etypes:
            for ts, log in list(_window.get(etype, deque())):
                if ts >= cutoff_2m:
                    ip = _ip_of(log)
                    if ip:
                        ip_counts[ip] += 1
        for ip, cnt in ip_counts.items():
            if cnt >= 4:
                key = f'multi_indicator_{ip}'
                if not _already_fired(key, 300):
                    a = _make_alert(
                        'multi_attack_indicator', 'CRITICAL',
                        'Multiple Attack Indicators from Single Source',
                        f'IP {ip} triggered {cnt} distinct threat indicators in 2 minutes',
                        'T1071,T1059',
                        {'attacker_ip': ip, 'indicator_count': cnt},
                    )
                    alerts.append(a)
                    _mark_fired(key)

        # ── RULE 7: File Modified → Executed as Suspicious Process ────────────
        fim_logs  = _get_logs('fim_modified', 60) + _get_logs('fim_created', 60)
        proc_logs = _get_logs('suspicious_process', 60)
        for fim_log in fim_logs[-10:]:
            fim_path = (fim_log.get('parsed_fields') or {}).get('file_path', '')
            if not fim_path:
                continue
            for proc_log in proc_logs:
                cmdline = (proc_log.get('parsed_fields') or {}).get('cmdline', '')
                if fim_path and fim_path in cmdline:
                    fkey = hashlib.sha256(fim_path.encode()).hexdigest()[:12]
                    key = f'fim_then_exec_{fkey}'
                    if not _already_fired(key, 300):
                        a = _make_alert(
                            'fim_then_exec', 'CRITICAL',
                            'Modified File Executed as Suspicious Process',
                            f'File {fim_path[:120]} modified then run as suspicious process',
                            'T1059,T1105',
                            {'file_path': fim_path},
                        )
                        alerts.append(a)
                        _mark_fired(key)
                    break

        # ── RULE 8: Privilege Escalation → Credential Access ──────────────────
        if priv_logs and cred_logs:
            user = _user_of(priv_logs[-1]) or 'unknown'
            key = f'priv_then_cred_{user}_{int(now/300)}'
            if not _already_fired(key, 600):
                a = _make_alert(
                    'priv_esc_cred_access', 'CRITICAL',
                    'Privilege Escalation Followed by Credential Access',
                    f"User '{user}' escalated privileges then attempted credential theft",
                    'T1548,T1003',
                    {'user': user},
                )
                alerts.append(a)
                _mark_fired(key)

        # ── RULE 9: New User → Added to Admin Group ───────────────────────────
        newuser_logs = _get_logs('user_created', 60)
        admin_logs   = _get_logs('privilege_escalation', 60)  # net localgroup admins /add
        if newuser_logs and admin_logs:
            key = f'newuser_admin_{int(now/120)}'
            if not _already_fired(key, 300):
                a = _make_alert(
                    'new_admin_account', 'CRITICAL',
                    'New User Created and Added to Admin Group',
                    'A new user account was created and elevated to admin within 60s',
                    'T1136.001,T1098',
                )
                alerts.append(a)
                _mark_fired(key)

        # ── RULE 10: C2 Beaconing + Suspicious Process ────────────────────────
        beacon_logs = _get_logs('c2_beaconing',       180)
        if beacon_logs and proc_logs:
            key = f'c2_beacon_proc_{int(now/300)}'
            if not _already_fired(key, 600):
                beacon_ip = _ip_of(beacon_logs[-1])
                a = _make_alert(
                    'c2_beacon_confirmed', 'CRITICAL',
                    'C2 Beaconing Correlated with Suspicious Process',
                    f'Regular-interval C2 beacon to {beacon_ip} with concurrent suspicious process',
                    'T1071.001,T1059',
                    {'c2_ip': beacon_ip},
                )
                alerts.append(a)
                _mark_fired(key)

    return alerts
