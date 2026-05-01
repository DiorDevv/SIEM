"""
Network connection monitor.
Detects: suspicious connections, port scans, C2 beaconing,
         unusual DNS resolvers, and exposed sensitive services.
Every finding is tagged with a MITRE ATT&CK technique.
"""
import re
import os
import time
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Any, Set, Tuple

logger = logging.getLogger(__name__)

# ── MITRE ATT&CK mapping ──────────────────────────────────────────────────────
_MITRE = {
    'suspicious_connection':  'T1071',    # Application Layer Protocol (C2)
    'sensitive_port_exposed': 'T1210',    # Exploitation of Remote Services
    'high_port_connection':   'T1041',    # Exfiltration Over C2 Channel
    'port_scan':              'T1046',    # Network Service Discovery
    'beaconing':              'T1071.001',# Web Protocols (C2 beaconing)
    'unusual_dns':            'T1071.004',# DNS (unusual resolver = DNS C2)
    'tor_exit_port':          'T1090.003',# Proxy: Multi-hop Proxy (Tor)
}

# ── Known suspicious ports ────────────────────────────────────────────────────
SUSPICIOUS_PORTS = {
    4444, 4445, 5555, 6666, 7777, 8888, 9999,   # Metasploit defaults
    1234, 31337, 12345, 54321,                    # Classic backdoors
    6667, 6668, 6669,                             # IRC (common C2)
    1080, 3128,                                   # SOCKS proxies
}

TOR_PORTS = {9001, 9030, 9050, 9051, 9150, 9151}

# Sensitive local ports that should never have external connections
SENSITIVE_LOCAL_PORTS = {3306, 5432, 6379, 27017, 9200, 2181, 11211, 5984, 8086}

# Well-known public DNS resolvers (not suspicious if used)
_KNOWN_DNS = {'8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1', '9.9.9.9',
              '208.67.222.222', '208.67.220.220', '64.6.64.6'}

_PRIVATE_RE = re.compile(
    r'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|fe80:|0\.0\.0\.0)'
)

# ── State ─────────────────────────────────────────────────────────────────────
_prev_connections: Set[Tuple] = set()

# Port scan detection: src_ip → {ports: set, first_seen: float}
_scan_state: Dict[str, Dict] = {}
_SCAN_WINDOW    = 60     # seconds
_SCAN_THRESHOLD = 12     # distinct destination ports = port scan

# Beaconing detection: "dst_ip:dst_port" → [timestamps]
_beacon_state: Dict[str, List[float]] = defaultdict(list)
_BEACON_MIN_COUNT  = 6
_BEACON_PERIOD_MIN = 45    # shortest regular interval (seconds)
_BEACON_PERIOD_MAX = 1800  # longest regular interval (seconds)
_BEACON_JITTER_MAX = 0.25  # max coefficient of variation (25 % jitter)


def _is_private(ip: str) -> bool:
    return bool(_PRIVATE_RE.match(ip))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _conn_log(
    severity: str,
    event: str,
    detail: str,
    extra: dict = None,
    mitre: str = '',
) -> Dict[str, Any]:
    msg = f"NET [{event.upper()}]: {detail}"
    fields: Dict[str, Any] = {"event_type": event, "detail": detail}
    if mitre:
        fields["mitre_technique"] = mitre
    if extra:
        fields.update(extra)
    return {
        "timestamp":     _now(),
        "level":         severity,
        "source":        "network_monitor",
        "message":       msg,
        "raw":           msg,
        "parsed_fields": fields,
    }


# ── Port scan detection ───────────────────────────────────────────────────────

def _update_scan_state(src_ip: str, dst_port: int) -> bool:
    """Returns True if this connection triggers a port-scan alert."""
    now = time.monotonic()
    entry = _scan_state.get(src_ip)
    if entry is None or now - entry['first_seen'] > _SCAN_WINDOW:
        _scan_state[src_ip] = {'ports': {dst_port}, 'first_seen': now, 'alerted': False}
        return False
    entry['ports'].add(dst_port)
    if len(entry['ports']) >= _SCAN_THRESHOLD and not entry['alerted']:
        entry['alerted'] = True
        return True
    return False


# ── Beaconing detection ───────────────────────────────────────────────────────

def _update_beacon_state(dst_ip: str, dst_port: int) -> bool:
    """Returns True if regular-interval beaconing is detected."""
    if _is_private(dst_ip):
        return False
    key = f"{dst_ip}:{dst_port}"
    now = time.monotonic()
    ts_list = _beacon_state[key]
    ts_list.append(now)

    # Trim to last hour
    cutoff = now - 3600
    while ts_list and ts_list[0] < cutoff:
        ts_list.pop(0)

    if len(ts_list) < _BEACON_MIN_COUNT:
        return False

    intervals = [ts_list[i+1] - ts_list[i] for i in range(len(ts_list) - 1)]
    avg = sum(intervals) / len(intervals)
    if not (_BEACON_PERIOD_MIN <= avg <= _BEACON_PERIOD_MAX):
        return False

    std = (sum((x - avg) ** 2 for x in intervals) / len(intervals)) ** 0.5
    cv  = std / avg if avg else 1.0
    return cv <= _BEACON_JITTER_MAX


# ── Main collector ────────────────────────────────────────────────────────────

def _cleanup_state():
    """Evict stale entries from scan/beacon state to prevent unbounded growth."""
    now = time.monotonic()
    stale_scan = [ip for ip, e in _scan_state.items()
                  if now - e['first_seen'] > _SCAN_WINDOW * 10]
    for ip in stale_scan:
        del _scan_state[ip]

    cutoff = now - 7200  # 2-hour beacon window
    stale_beacon = [k for k, ts in _beacon_state.items()
                    if not ts or ts[-1] < cutoff]
    for k in stale_beacon:
        del _beacon_state[k]


_cleanup_counter = 0
_CLEANUP_EVERY   = 20   # calls


def collect_connections() -> List[Dict[str, Any]]:
    events = []
    try:
        import psutil
    except ImportError:
        return events

    global _prev_connections, _cleanup_counter
    _cleanup_counter += 1
    if _cleanup_counter >= _CLEANUP_EVERY:
        _cleanup_counter = 0
        _cleanup_state()

    current: Set[Tuple] = set()

    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status not in ('ESTABLISHED', 'LISTEN', 'SYN_SENT'):
                continue

            laddr = conn.laddr
            raddr = conn.raddr
            if not raddr:
                continue

            key = (
                f"{laddr.ip}:{laddr.port}" if laddr else "",
                f"{raddr.ip}:{raddr.port}" if raddr else "",
                conn.status,
            )
            current.add(key)

            if key in _prev_connections:
                # Update beaconing state for known connections too
                if raddr:
                    _update_beacon_state(raddr.ip, raddr.port)
                continue

            remote_ip   = raddr.ip
            remote_port = raddr.port
            local_port  = laddr.port if laddr else 0
            local_ip    = laddr.ip   if laddr else ''

            extra = {
                "src_ip":   local_ip,
                "src_port": local_port,
                "dst_ip":   remote_ip,
                "dst_port": remote_port,
                "status":   conn.status,
                "pid":      conn.pid,
            }

            # ── Tor exit port ─────────────────────────────────────────────────
            if remote_port in TOR_PORTS and not _is_private(remote_ip):
                events.append(_conn_log(
                    "HIGH", "tor_connection",
                    f"Connection to Tor port {remote_ip}:{remote_port}",
                    {**extra, "event_type": "network_connection"},
                    mitre=_MITRE['tor_exit_port'],
                ))

            # ── Known C2/backdoor port ────────────────────────────────────────
            elif remote_port in SUSPICIOUS_PORTS and not _is_private(remote_ip):
                events.append(_conn_log(
                    "CRITICAL", "suspicious_connection",
                    f"Connection to C2/backdoor port {remote_ip}:{remote_port}",
                    {**extra, "event_type": "network_connection"},
                    mitre=_MITRE['suspicious_connection'],
                ))

            # ── Sensitive local service exposed externally ────────────────────
            elif local_port in SENSITIVE_LOCAL_PORTS and not _is_private(remote_ip):
                events.append(_conn_log(
                    "HIGH", "sensitive_port_exposed",
                    f"Sensitive port {local_port} reached from external {remote_ip}",
                    {**extra, "event_type": "network_connection"},
                    mitre=_MITRE['sensitive_port_exposed'],
                ))

            # ── Unusual DNS resolver ──────────────────────────────────────────
            elif remote_port == 53 and remote_ip not in _KNOWN_DNS and not _is_private(remote_ip):
                events.append(_conn_log(
                    "MEDIUM", "unusual_dns_resolver",
                    f"DNS query to unusual resolver {remote_ip}",
                    {**extra, "event_type": "network_connection"},
                    mitre=_MITRE['unusual_dns'],
                ))

            # ── Outbound on unusual high port ─────────────────────────────────
            elif (conn.status == "ESTABLISHED"
                  and not _is_private(remote_ip)
                  and remote_port > 49000):
                events.append(_conn_log(
                    "WARNING", "high_port_connection",
                    f"Outbound to high port {remote_ip}:{remote_port}",
                    {**extra, "event_type": "network_connection"},
                    mitre=_MITRE['high_port_connection'],
                ))

            # ── Update port scan tracker ─────────────────────────────────────
            if not _is_private(remote_ip):
                if _update_scan_state(remote_ip, local_port):
                    events.append(_conn_log(
                        "HIGH", "port_scan_detected",
                        f"Port scan from {remote_ip} — "
                        f"{len(_scan_state.get(remote_ip, {}).get('ports', set()))} ports probed",
                        {**extra, "attacker_ip": remote_ip,
                         "event_type": "network_scan"},
                        mitre=_MITRE['port_scan'],
                    ))

            # ── Beaconing check ───────────────────────────────────────────────
            if _update_beacon_state(remote_ip, remote_port):
                events.append(_conn_log(
                    "HIGH", "c2_beaconing",
                    f"Regular-interval beaconing to {remote_ip}:{remote_port} "
                    f"(pid={conn.pid})",
                    {**extra, "event_type": "network_connection"},
                    mitre=_MITRE['beaconing'],
                ))

    except (psutil.AccessDenied, PermissionError):
        pass
    except Exception as e:
        logger.debug(f"Network monitor error: {e}")

    _prev_connections = current
    return events
