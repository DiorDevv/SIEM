"""
Event deduplication filter.
Drops identical events within a rolling time window — like Wazuh's if_sid + same_srcip logic.
CRITICAL/ERROR events are never deduplicated.
"""
import hashlib
import time
import threading
from typing import List, Dict, Any

_lock   = threading.Lock()
_cache: Dict[str, float] = {}
_WINDOW = 300  # seconds; overridable via set_window()

_NEVER_DEDUP = frozenset({'CRITICAL', 'HIGH', 'ERROR'})


def set_window(seconds: int):
    global _WINDOW
    _WINDOW = max(10, int(seconds))


def _evict():
    now = time.monotonic()
    expired = [k for k, ts in _cache.items() if now - ts > _WINDOW]
    for k in expired:
        del _cache[k]


def dedup(logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Return logs with duplicates removed within the rolling window.
    Events at CRITICAL/HIGH/ERROR level always pass through.
    """
    if not logs:
        return logs

    result = []
    now    = time.monotonic()

    with _lock:
        _evict()
        for log in logs:
            level = (log.get('level') or log.get('severity') or '').upper()
            if level in _NEVER_DEDUP:
                result.append(log)
                continue

            pf  = log.get('parsed_fields') or {}
            ev  = str(pf.get('event_type') or log.get('event_type') or '')
            src = str(log.get('source') or '')
            msg = str(log.get('message') or '')[:256]

            raw = f"{src}|{ev}|{msg}"
            key = hashlib.sha256(raw.encode()).hexdigest()  # full 256-bit — no collision risk

            if key not in _cache:
                _cache[key] = now
                result.append(log)

    return result
