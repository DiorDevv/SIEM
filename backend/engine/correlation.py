"""
Correlation engine — Redis-backed frequency & composite rule matching.

Uses Redis sorted sets for frequency windows and Redis lists for event
sequences. Falls back to in-memory structures when Redis is unavailable,
which allows single-instance operation but prevents horizontal scaling.
"""
import json
import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, Deque, List, Tuple, Optional

import redis.asyncio as aioredis

from config import settings

logger = logging.getLogger(__name__)

_redis: Optional[aioredis.Redis] = None

# In-memory fallback (used when Redis is unavailable)
_windows_mem: Dict[Tuple, Deque[datetime]] = defaultdict(deque)
_sequences_mem: Dict[str, Deque[dict]] = defaultdict(lambda: deque(maxlen=100))


async def _get_redis() -> Optional[aioredis.Redis]:
    global _redis
    if _redis is None:
        try:
            _redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
            await _redis.ping()
        except Exception as e:
            logger.warning(f"Correlation Redis unavailable, using in-memory fallback: {e}")
            _redis = None
    return _redis


# ── Composite attack patterns ─────────────────────────────────────────────────

COMPOSITE_PATTERNS = [
    # ── Lateral Movement ─────────────────────────────────────────────────────
    {
        "name":            "Lateral Movement — SSH then Sudo",
        "description":     "SSH login followed by sudo escalation in the same session",
        "sequence":        ["authentication_success", "sudo_command"],
        "window_seconds":  300,
        "severity":        "HIGH",
        "level":           12,
        "mitre_tactic":    "Lateral Movement",
        "mitre_technique": "T1021.004",
    },
    {
        "name":            "Lateral Movement — SSH then Package Install",
        "description":     "Remote login followed by software installation (backdoor/tool drop)",
        "sequence":        ["authentication_success", "sudo_command", "package_installed"],
        "window_seconds":  600,
        "severity":        "HIGH",
        "level":           13,
        "mitre_tactic":    "Persistence",
        "mitre_technique": "T1072",
    },

    # ── Privilege Escalation ─────────────────────────────────────────────────
    {
        "name":            "Privilege Escalation — Multiple Sudo Failures then Success",
        "description":     "Multiple sudo failures followed by successful escalation",
        "sequence":        ["sudo_auth_failure", "sudo_auth_failure", "sudo_command"],
        "window_seconds":  120,
        "severity":        "HIGH",
        "level":           13,
        "mitre_tactic":    "Privilege Escalation",
        "mitre_technique": "T1548.003",
    },
    {
        "name":            "Privilege Escalation — su to Root",
        "description":     "User switched to root account using su command",
        "sequence":        ["authentication_success", "sudo_command"],
        "window_seconds":  60,
        "severity":        "HIGH",
        "level":           12,
        "mitre_tactic":    "Privilege Escalation",
        "mitre_technique": "T1548",
    },

    # ── Persistence ──────────────────────────────────────────────────────────
    {
        "name":            "Persistence — Cron Job After Login",
        "description":     "Scheduled task created shortly after user login",
        "sequence":        ["authentication_success", "cron_job"],
        "window_seconds":  600,
        "severity":        "MEDIUM",
        "level":           9,
        "mitre_tactic":    "Persistence",
        "mitre_technique": "T1053.003",
    },
    {
        "name":            "Persistence — New User Account Created",
        "description":     "New local account created after remote login (possible backdoor user)",
        "sequence":        ["authentication_success", "user_created"],
        "window_seconds":  300,
        "severity":        "HIGH",
        "level":           13,
        "mitre_tactic":    "Persistence",
        "mitre_technique": "T1136.001",
    },
    {
        "name":            "Persistence — Kernel Module Loaded After Login",
        "description":     "Kernel module loaded after remote authentication (rootkit indicator)",
        "sequence":        ["authentication_success", "kernel_module_loaded"],
        "window_seconds":  600,
        "severity":        "CRITICAL",
        "level":           15,
        "mitre_tactic":    "Persistence",
        "mitre_technique": "T1547.006",
    },

    # ── Defense Evasion ──────────────────────────────────────────────────────
    {
        "name":            "Defense Evasion — Log File Cleared",
        "description":     "Critical log file modified (possible log tampering)",
        "sequence":        ["fim_modified"],
        "window_seconds":  60,
        "severity":        "CRITICAL",
        "level":           15,
        "mitre_tactic":    "Defense Evasion",
        "mitre_technique": "T1070.002",
        "path_contains":   "/var/log",
    },
    {
        "name":            "Defense Evasion — AppArmor Bypass Attempt",
        "description":     "Repeated AppArmor denials followed by service modification",
        "sequence":        ["apparmor_denied", "apparmor_denied", "service_started"],
        "window_seconds":  300,
        "severity":        "HIGH",
        "level":           12,
        "mitre_tactic":    "Defense Evasion",
        "mitre_technique": "T1562.001",
    },

    # ── Credential Access ────────────────────────────────────────────────────
    {
        "name":            "Credential Access — Multi-Service Auth Failure",
        "description":     "Authentication failures across multiple services (credential stuffing)",
        "sequence":        ["authentication_failed", "pam_auth_failed"],
        "window_seconds":  60,
        "severity":        "HIGH",
        "level":           12,
        "mitre_tactic":    "Credential Access",
        "mitre_technique": "T1110",
    },
    {
        "name":            "Credential Access — Brute Force then Login",
        "description":     "Multiple SSH failures from same source followed by successful login",
        "sequence":        ["ssh_failed", "ssh_failed", "authentication_success"],
        "window_seconds":  120,
        "severity":        "CRITICAL",
        "level":           14,
        "mitre_tactic":    "Credential Access",
        "mitre_technique": "T1110.001",
    },

    # ── Impact ───────────────────────────────────────────────────────────────
    {
        "name":            "Impact — Multiple Service Failures",
        "description":     "Multiple service failures in short window (possible attack or misconfiguration)",
        "sequence":        ["service_failed", "service_failed", "service_failed"],
        "window_seconds":  120,
        "severity":        "HIGH",
        "level":           11,
        "mitre_tactic":    "Impact",
        "mitre_technique": "T1489",
    },
    {
        "name":            "Impact — Container Killed then Host File Modified",
        "description":     "Container terminated followed by host filesystem modification (container escape indicator)",
        "sequence":        ["container_stopped", "fim_modified"],
        "window_seconds":  120,
        "severity":        "CRITICAL",
        "level":           15,
        "mitre_tactic":    "Impact",
        "mitre_technique": "T1610",
    },

    # ── Exfiltration ─────────────────────────────────────────────────────────
    {
        "name":            "Exfiltration — USB Connected After Login",
        "description":     "USB device connected shortly after user authentication (data theft indicator)",
        "sequence":        ["authentication_success", "usb_connected"],
        "window_seconds":  300,
        "severity":        "MEDIUM",
        "level":           9,
        "mitre_tactic":    "Exfiltration",
        "mitre_technique": "T1052.001",
    },
    {
        "name":            "Exfiltration — FIM + Network Connection",
        "description":     "Sensitive file modified then network connection established (data staging)",
        "sequence":        ["fim_modified", "network_connected"],
        "window_seconds":  120,
        "severity":        "HIGH",
        "level":           12,
        "mitre_tactic":    "Exfiltration",
        "mitre_technique": "T1048",
    },
]


async def record_event(agent_id: str, event_type: str, parsed_fields: dict):
    if not event_type:
        return

    redis = await _get_redis()
    if redis:
        try:
            key = f"siem:seq:{agent_id}"
            # Serialize only JSON-safe scalar fields
            safe_fields = {
                k: v for k, v in parsed_fields.items()
                if isinstance(v, (str, int, float, bool, type(None)))
            }
            entry = json.dumps({
                "event":     event_type,
                "timestamp": datetime.utcnow().isoformat(),
                "fields":    safe_fields,
            })
            pipe = redis.pipeline()
            await pipe.rpush(key, entry)
            await pipe.ltrim(key, -100, -1)   # keep last 100 events
            await pipe.expire(key, 3600)       # 1-hour TTL
            await pipe.execute()
            return
        except Exception as e:
            logger.debug(f"record_event Redis error: {e}")

    # In-memory fallback
    _sequences_mem[agent_id].append({
        "event":     event_type,
        "timestamp": datetime.utcnow(),
        "fields":    parsed_fields,
    })


async def check_frequency(
    rule_id: int,
    agent_id: str,
    groupby_value: str,
    frequency: int,
    timeframe: int,
) -> Tuple[bool, int]:
    """Sliding window frequency check. Returns (triggered, current_count)."""
    redis = await _get_redis()

    if redis:
        try:
            key = f"siem:freq:{rule_id}:{agent_id}:{groupby_value}"
            now = time.time()
            cutoff = now - timeframe
            unique_member = f"{now}:{id(object())}"

            pipe = redis.pipeline()
            await pipe.zremrangebyscore(key, 0, cutoff)
            await pipe.zadd(key, {unique_member: now})
            await pipe.zcard(key)
            await pipe.expire(key, timeframe * 2)
            results = await pipe.execute()
            count = results[2]

            if count >= frequency:
                await redis.delete(key)  # reset after trigger
                return True, count
            return False, count
        except Exception as e:
            logger.debug(f"check_frequency Redis error: {e}")

    # In-memory fallback
    mem_key = (rule_id, agent_id, groupby_value)
    now_dt = datetime.utcnow()
    cutoff_dt = now_dt - timedelta(seconds=timeframe)
    window = _windows_mem[mem_key]

    while window and window[0] < cutoff_dt:
        window.popleft()

    window.append(now_dt)
    count = len(window)

    if count >= frequency:
        window.clear()
        return True, count
    return False, count


async def check_composite_patterns(
    agent_id: str,
    current_event: str,
    current_fields: dict,
) -> List[dict]:
    """Check if current event completes any composite attack pattern."""
    triggered = []
    now = datetime.utcnow()

    # Load history from Redis or fallback
    redis = await _get_redis()
    if redis:
        try:
            key = f"siem:seq:{agent_id}"
            raw_entries = await redis.lrange(key, 0, -1)
            history = []
            for raw in raw_entries:
                try:
                    entry = json.loads(raw)
                    entry["timestamp"] = datetime.fromisoformat(entry["timestamp"])
                    history.append(entry)
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"check_composite Redis error: {e}")
            history = list(_sequences_mem[agent_id])
    else:
        history = list(_sequences_mem[agent_id])

    for pattern in COMPOSITE_PATTERNS:
        sequence = pattern["sequence"]
        window   = pattern["window_seconds"]
        cutoff   = now - timedelta(seconds=window)

        if current_event != sequence[-1]:
            continue

        if "path_contains" in pattern:
            path = current_fields.get("file_path", "")
            if pattern["path_contains"] not in path:
                continue

        needed = list(sequence[:-1])
        if not needed:
            triggered.append(pattern)
            continue

        for entry in reversed(history):
            if entry["timestamp"] < cutoff:
                break
            if needed and entry["event"] == needed[-1]:
                needed.pop()
            if not needed:
                triggered.append(pattern)
                break

    return triggered


async def get_window_stats() -> dict:
    redis = await _get_redis()
    if redis:
        try:
            freq_keys = await redis.keys("siem:freq:*")
            seq_keys  = await redis.keys("siem:seq:*")
            return {
                "backend":           "redis",
                "tracked_windows":   len(freq_keys),
                "tracked_sequences": len(seq_keys),
            }
        except Exception:
            pass
    return {
        "backend":           "memory",
        "tracked_windows":   len(_windows_mem),
        "tracked_sequences": len(_sequences_mem),
        "total_events":      sum(len(v) for v in _sequences_mem.values()),
    }
