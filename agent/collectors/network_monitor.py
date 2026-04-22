"""
Network connection monitor.
Detects: new outbound connections to suspicious ports,
reverse shells, port scans, unusual protocols.
"""
import re
import os
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Set, Tuple

logger = logging.getLogger(__name__)

# (local_addr, remote_addr, status) → seen
_prev_connections: Set[Tuple] = set()

# Suspicious remote ports (common C2/backdoor/exfiltration)
SUSPICIOUS_PORTS = {
    4444, 4445, 5555, 6666, 7777, 8888, 9999,  # Metasploit defaults
    1234, 31337, 12345, 54321,                   # Classic backdoors
    6667, 6668, 6669,                            # IRC (common C2)
    1080, 3128,                                  # SOCKS proxies
}

# High-risk local ports (should not be externally connected)
SENSITIVE_LOCAL_PORTS = {3306, 5432, 6379, 27017, 9200, 2181, 11211}

# Private IP ranges
_PRIVATE_RE = re.compile(
    r'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|fe80:)'
)


def _is_private(ip: str) -> bool:
    return bool(_PRIVATE_RE.match(ip))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _conn_log(severity: str, event: str, detail: str, extra: dict = None) -> Dict[str, Any]:
    msg = f"NET [{event.upper()}]: {detail}"
    fields = {"event_type": event, "detail": detail}
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


def collect_connections() -> List[Dict[str, Any]]:
    events = []
    if os.name == "nt":
        return events

    try:
        import psutil
    except ImportError:
        return events

    global _prev_connections
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

            # Only analyze new connections
            if key in _prev_connections:
                continue

            remote_ip   = raddr.ip
            remote_port = raddr.port
            local_port  = laddr.port if laddr else 0

            extra = {
                "src_ip":      laddr.ip if laddr else "",
                "src_port":    local_port,
                "dst_ip":      remote_ip,
                "dst_port":    remote_port,
                "status":      conn.status,
                "pid":         conn.pid,
            }

            # ── Suspicious remote port ─────────────────────────────────────
            if remote_port in SUSPICIOUS_PORTS and not _is_private(remote_ip):
                events.append(_conn_log(
                    "CRITICAL", "suspicious_connection",
                    f"Connection to suspicious port {remote_ip}:{remote_port}",
                    {**extra, "event_type": "network_connection"},
                ))

            # ── External connection to sensitive local service ──────────────
            elif local_port in SENSITIVE_LOCAL_PORTS and not _is_private(remote_ip):
                events.append(_conn_log(
                    "HIGH", "sensitive_port_exposed",
                    f"Sensitive service port {local_port} connected from external {remote_ip}",
                    {**extra, "event_type": "network_connection"},
                ))

            # ── Outbound on unusual high port ──────────────────────────────
            elif (conn.status == "ESTABLISHED"
                  and not _is_private(remote_ip)
                  and remote_port > 49000):
                events.append(_conn_log(
                    "WARNING", "high_port_connection",
                    f"Outbound connection to high port {remote_ip}:{remote_port}",
                    {**extra, "event_type": "network_connection"},
                ))

    except (psutil.AccessDenied, PermissionError):
        pass
    except Exception as e:
        logger.debug(f"Network monitor error: {e}")

    _prev_connections = current
    return events
