"""
Statistical Anomaly Detection Engine — Wazuh-equivalent implementation.

How it works (same algorithm Wazuh uses internally):
  1.  For every numeric metric (login hour, auth failures/hour, log volume…)
      we maintain a running mean and standard deviation using Welford's online
      algorithm.  No raw history is stored; O(1) memory per metric.

  2.  When a new observation arrives we compute the z-score:
          z = |x - mean| / std_dev
      If z > 3.0  → HIGH confidence anomaly  (false-positive rate ≈ 0.3 %)
      If z > 2.0  → MEDIUM confidence        (false-positive rate ≈ 5 %)

  3.  We require at least MIN_SAMPLES before alerting to avoid noise during
      the warm-up period.

  4.  For categorical metrics (e.g. "has this user ever logged in from this IP")
      we keep a known-values set.  A value never seen before is immediately
      anomalous, regardless of statistical thresholds.

  5.  Redis is the primary store (fast, sub-millisecond).  PostgreSQL is the
      durable backup synced every SYNC_INTERVAL seconds.

Metrics tracked per agent (same as Wazuh baseline checks):
  - login_hour:{username}          — hour-of-day for successful logins
  - auth_fail_rate                 — authentication failures per hour
  - log_volume                     — log events per minute
  - process_spawn_rate             — new unique processes per minute
  - sudo_rate:{username}           — sudo commands per hour
  - fim_rate                       — FIM changes per hour
  - net_conn_rate                  — outbound connections per hour
  known-sets:
  - known_src_ip:{username}        — IPs that have authenticated as this user
  - known_dst_ip                   — destination IPs this agent has connected to
"""
import json
import logging
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple

import redis.asyncio as aioredis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings

logger = logging.getLogger(__name__)

# ── Tuning constants ───────────────────────────────────────────────────────────

MIN_SAMPLES      = 30      # observations required before alerting (warm-up guard)
Z_HIGH           = 3.0     # >3σ → HIGH  (0.3 % false-positive)
Z_MED            = 2.0     # >2σ → MEDIUM (5 % false-positive)
BASELINE_TTL     = 86_400 * 30   # Redis key TTL: 30 days
ALERT_COOLDOWN   = 3_600         # suppress duplicate anomaly alerts for 1 h
SYNC_INTERVAL    = 300           # flush Redis → PostgreSQL every 5 min
RATE_WINDOW_SEC  = 3_600         # 1-hour sliding window for rate metrics


# ── Welford online statistics ─────────────────────────────────────────────────

@dataclass
class WelfordState:
    n:    int   = 0
    mean: float = 0.0
    m2:   float = 0.0    # sum of squared deviations (Welford accumulator)

    # ── Welford update — O(1), numerically stable ─────────────────────────────
    def update(self, x: float) -> None:
        self.n  += 1
        delta    = x - self.mean
        self.mean += delta / self.n
        delta2   = x - self.mean
        self.m2  += delta * delta2

    @property
    def variance(self) -> float:
        return self.m2 / self.n if self.n > 1 else 0.0

    @property
    def std_dev(self) -> float:
        return math.sqrt(self.variance)

    def z_score(self, x: float) -> float:
        std = self.std_dev
        return abs(x - self.mean) / std if std > 0 else 0.0

    def to_dict(self) -> dict:
        return {"n": self.n, "mean": self.mean, "m2": self.m2}

    @classmethod
    def from_dict(cls, d: dict) -> "WelfordState":
        return cls(n=int(d["n"]), mean=float(d["mean"]), m2=float(d["m2"]))


# ── Result type ───────────────────────────────────────────────────────────────

@dataclass
class AnomalyResult:
    is_anomaly:    bool
    confidence:    str     # "HIGH" | "MEDIUM" | ""
    z_score:       float
    metric_key:    str
    current_value: float
    baseline_mean: float
    baseline_std:  float
    sample_count:  int
    description:   str
    mitre_tactic:  str = "Discovery"
    mitre_tech:    str = "T1082"

    @property
    def level(self) -> int:
        return 12 if self.confidence == "HIGH" else 9

    @property
    def severity(self) -> str:
        return "HIGH" if self.confidence == "HIGH" else "MEDIUM"


# ── Redis helpers ─────────────────────────────────────────────────────────────

_redis_client: Optional[aioredis.Redis] = None


async def _get_redis() -> Optional[aioredis.Redis]:
    global _redis_client
    if _redis_client is None:
        try:
            _redis_client = aioredis.from_url(
                settings.REDIS_URL, decode_responses=True, socket_timeout=1.0
            )
            await _redis_client.ping()
        except Exception:
            _redis_client = None
    return _redis_client


# In-memory fallback (used when Redis is unavailable)
_mem_baselines: Dict[str, WelfordState] = {}
_mem_known_sets: Dict[str, set] = {}
_mem_cooldowns:  Dict[str, float] = {}


def _rkey_baseline(agent_id: str, metric: str) -> str:
    return f"anomaly:baseline:{agent_id}:{metric}"


def _rkey_set(agent_id: str, set_name: str) -> str:
    return f"anomaly:set:{agent_id}:{set_name}"


def _rkey_cooldown(agent_id: str, metric: str) -> str:
    return f"anomaly:cooldown:{agent_id}:{metric}"


def _rkey_rate(agent_id: str, metric: str) -> str:
    return f"anomaly:rate:{agent_id}:{metric}"


# ── Baseline read / write ─────────────────────────────────────────────────────

async def _load_state(agent_id: str, metric: str) -> WelfordState:
    r = await _get_redis()
    if r:
        try:
            raw = await r.get(_rkey_baseline(agent_id, metric))
            if raw:
                return WelfordState.from_dict(json.loads(raw))
        except Exception as exc:
            logger.debug("Redis baseline load error: %s", exc)
    # in-memory fallback
    return _mem_baselines.get(f"{agent_id}:{metric}", WelfordState())


async def _save_state(agent_id: str, metric: str, state: WelfordState) -> None:
    r = await _get_redis()
    key = _rkey_baseline(agent_id, metric)
    payload = json.dumps({**state.to_dict(), "agent_id": agent_id, "metric": metric})
    if r:
        try:
            await r.setex(key, BASELINE_TTL, payload)
            return
        except Exception as exc:
            logger.debug("Redis baseline save error: %s", exc)
    _mem_baselines[f"{agent_id}:{metric}"] = state


async def _on_cooldown(agent_id: str, metric: str) -> bool:
    """True if an anomaly alert was already emitted for this metric recently."""
    r = await _get_redis()
    key = _rkey_cooldown(agent_id, metric)
    if r:
        try:
            return bool(await r.exists(key))
        except Exception:
            pass
    now = datetime.now(timezone.utc).timestamp()
    cd = _mem_cooldowns.get(f"{agent_id}:{metric}", 0)
    return now - cd < ALERT_COOLDOWN


async def _set_cooldown(agent_id: str, metric: str) -> None:
    r = await _get_redis()
    key = _rkey_cooldown(agent_id, metric)
    if r:
        try:
            await r.setex(key, ALERT_COOLDOWN, "1")
            return
        except Exception:
            pass
    _mem_cooldowns[f"{agent_id}:{metric}"] = datetime.now(timezone.utc).timestamp()


# ── Core: observe + check (numeric) ──────────────────────────────────────────

async def observe_and_check(
    agent_id: str,
    metric:   str,
    value:    float,
    description_template: str,
) -> Optional[AnomalyResult]:
    """
    Record a new observation and return an AnomalyResult if it is anomalous.

    The caller decides whether to create an Alert from the result.
    Returns None if: within warm-up, not anomalous, or on cooldown.
    """
    state = await _load_state(agent_id, metric)
    state.update(value)
    await _save_state(agent_id, metric, state)

    if state.n < MIN_SAMPLES:
        return None   # still warming up

    z = state.z_score(value)

    if z >= Z_HIGH:
        confidence = "HIGH"
    elif z >= Z_MED:
        confidence = "MEDIUM"
    else:
        return None   # normal

    if await _on_cooldown(agent_id, metric):
        return None

    await _set_cooldown(agent_id, metric)
    return AnomalyResult(
        is_anomaly    = True,
        confidence    = confidence,
        z_score       = round(z, 2),
        metric_key    = metric,
        current_value = value,
        baseline_mean = round(state.mean, 3),
        baseline_std  = round(state.std_dev, 3),
        sample_count  = state.n,
        description   = description_template.format(
            value=value, mean=round(state.mean, 1),
            std=round(state.std_dev, 1), z=round(z, 1),
        ),
    )


# ── Core: observe + check (set membership) ───────────────────────────────────

async def check_new_value(
    agent_id:    str,
    set_name:    str,
    value:       str,
    description: str,
) -> Optional[AnomalyResult]:
    """
    Returns an AnomalyResult the first time `value` is seen for this set.
    Subsequent observations of the same value return None.
    """
    if not value:
        return None

    r = await _get_redis()
    rkey = _rkey_set(agent_id, set_name)
    mem_key = f"{agent_id}:{set_name}"

    is_new = False
    if r:
        try:
            is_new = bool(await r.sadd(rkey, value))
            if is_new:
                await r.expire(rkey, BASELINE_TTL)
        except Exception:
            is_new = value not in _mem_known_sets.get(mem_key, set())
            _mem_known_sets.setdefault(mem_key, set()).add(value)
    else:
        known = _mem_known_sets.setdefault(mem_key, set())
        is_new = value not in known
        known.add(value)

    if not is_new:
        return None
    if await _on_cooldown(agent_id, set_name):
        return None
    await _set_cooldown(agent_id, set_name)
    return AnomalyResult(
        is_anomaly    = True,
        confidence    = "HIGH",
        z_score       = 99.0,     # sentinel — set-based anomaly, not z-score
        metric_key    = set_name,
        current_value = 0,
        baseline_mean = 0,
        baseline_std  = 0,
        sample_count  = 0,
        description   = description,
        mitre_tactic  = "Initial Access",
        mitre_tech    = "T1078",
    )


# ── Sliding-window rate counter ───────────────────────────────────────────────

async def increment_rate(agent_id: str, metric: str, window_sec: int = RATE_WINDOW_SEC) -> float:
    """
    Increment a time-bucketed counter and return the total count in the window.
    Uses Redis sorted sets for O(log N) cleanup of expired buckets.
    Falls back to a simple in-memory counter on Redis failure.
    """
    r = await _get_redis()
    rkey = _rkey_rate(agent_id, metric)
    now  = datetime.now(timezone.utc).timestamp()

    if r:
        try:
            pipe = r.pipeline()
            pipe.zadd(rkey, {str(now): now})
            pipe.zremrangebyscore(rkey, 0, now - window_sec)
            pipe.zcard(rkey)
            pipe.expire(rkey, window_sec + 60)
            results = await pipe.execute()
            return float(results[2])
        except Exception as exc:
            logger.debug("Redis rate counter error: %s", exc)

    # In-memory fallback: just count this as 1 (no real window)
    return 1.0


# ── High-level detector functions (one per metric type) ──────────────────────

async def detect_login_time_anomaly(
    agent_id: str, username: str, hour_of_day: int,
) -> Optional[AnomalyResult]:
    """Alert when a user logs in at an hour not seen in their historical pattern."""
    metric = f"login_hour:{username}"
    return await observe_and_check(
        agent_id, metric, float(hour_of_day),
        "Login-time anomaly for user '{username}': "
        "hour {value} (baseline avg {mean}h ±{std}h, z={z})",
    )


async def detect_auth_failure_anomaly(
    agent_id: str,
) -> Optional[AnomalyResult]:
    """Alert when auth failure rate spikes above historical average."""
    count = await increment_rate(agent_id, "auth_fail_rate")
    return await observe_and_check(
        agent_id, "auth_fail_rate", count,
        "Auth failure rate anomaly: {value} failures/h "
        "(baseline avg {mean} ±{std}, z={z})",
    )


async def detect_log_volume_anomaly(
    agent_id: str,
) -> Optional[AnomalyResult]:
    """Alert when the agent's log throughput deviates from its baseline."""
    count = await increment_rate(agent_id, "log_volume", window_sec=60)
    result = await observe_and_check(
        agent_id, "log_volume", count,
        "Log volume anomaly: {value} events/min "
        "(baseline avg {mean} ±{std}, z={z})",
    )
    if result:
        result.mitre_tactic = "Defense Evasion"
        result.mitre_tech   = "T1562"
    return result


async def detect_process_spawn_anomaly(
    agent_id: str,
) -> Optional[AnomalyResult]:
    """Alert when new-process rate spikes (common during exploit/pivot activity)."""
    count = await increment_rate(agent_id, "process_spawn", window_sec=60)
    result = await observe_and_check(
        agent_id, "process_spawn", count,
        "Process spawn rate anomaly: {value} new processes/min "
        "(baseline avg {mean} ±{std}, z={z})",
    )
    if result:
        result.mitre_tactic = "Execution"
        result.mitre_tech   = "T1059"
    return result


async def detect_sudo_rate_anomaly(
    agent_id: str, username: str,
) -> Optional[AnomalyResult]:
    """Alert when a user runs sudo more than usual."""
    metric = f"sudo_rate:{username}"
    count  = await increment_rate(agent_id, metric)
    result = await observe_and_check(
        agent_id, metric, count,
        "Sudo usage anomaly for {username}: {value} commands/h "
        "(baseline avg {mean} ±{std}, z={z})",
    )
    if result:
        result.mitre_tactic = "Privilege Escalation"
        result.mitre_tech   = "T1548.003"
    return result


async def detect_fim_rate_anomaly(
    agent_id: str,
) -> Optional[AnomalyResult]:
    """Alert when the rate of file-integrity changes spikes."""
    count = await increment_rate(agent_id, "fim_rate")
    result = await observe_and_check(
        agent_id, "fim_rate", count,
        "FIM change rate anomaly: {value} changes/h "
        "(baseline avg {mean} ±{std}, z={z})",
    )
    if result:
        result.mitre_tactic = "Defense Evasion"
        result.mitre_tech   = "T1070"
    return result


async def detect_new_src_ip(
    agent_id: str, username: str, src_ip: str,
) -> Optional[AnomalyResult]:
    """Alert when a user authenticates from an IP address never seen before."""
    result = await check_new_value(
        agent_id,
        set_name    = f"known_src_ip:{username}",
        value       = src_ip,
        description = (
            f"First login from new IP {src_ip} for user '{username}' on agent {agent_id}"
        ),
    )
    if result:
        result.mitre_tactic = "Initial Access"
        result.mitre_tech   = "T1078"
    return result


async def detect_new_dst_ip(
    agent_id: str, dst_ip: str,
) -> Optional[AnomalyResult]:
    """Alert when the agent connects to a destination IP it has never contacted before."""
    # Skip private/loopback IPs — they're expected
    import ipaddress
    try:
        addr = ipaddress.ip_address(dst_ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return None
    except ValueError:
        return None

    result = await check_new_value(
        agent_id,
        set_name    = "known_dst_ip",
        value       = dst_ip,
        description = (
            f"First outbound connection to new IP {dst_ip} from agent {agent_id}"
        ),
    )
    if result:
        result.mitre_tactic = "Command and Control"
        result.mitre_tech   = "T1071"
    return result


async def detect_net_connection_rate_anomaly(
    agent_id: str,
) -> Optional[AnomalyResult]:
    """Alert when outbound connection rate spikes (potential C2 beaconing or exfil)."""
    count = await increment_rate(agent_id, "net_conn_rate")
    result = await observe_and_check(
        agent_id, "net_conn_rate", count,
        "Network connection rate anomaly: {value} connections/h "
        "(baseline avg {mean} ±{std}, z={z})",
    )
    if result:
        result.mitre_tactic = "Command and Control"
        result.mitre_tech   = "T1071"
    return result


# ── Entry point: run all applicable checks for one log event ─────────────────

async def run_anomaly_checks(
    agent_id:      str,
    event_type:    Optional[str],
    parsed_fields: dict,
) -> list[AnomalyResult]:
    """
    Evaluate all anomaly checks relevant to this log event.
    Returns a (possibly empty) list of AnomalyResult objects.
    The caller (rule_engine) converts these into Alert records.
    """
    results: list[AnomalyResult] = []
    pf = parsed_fields or {}

    username = (
        pf.get("username") or pf.get("user") or
        pf.get("ssh_user") or pf.get("sudo_user") or ""
    )
    src_ip   = pf.get("src_ip") or pf.get("ssh_src_ip") or pf.get("client_ip") or ""
    dst_ip   = pf.get("dst_ip") or pf.get("destination_ip") or ""
    hour     = datetime.now(timezone.utc).hour

    # ── Always track log volume ───────────────────────────────────────────────
    r = await detect_log_volume_anomaly(agent_id)
    if r:
        results.append(r)

    # ── Auth success → login-time + new-IP checks ─────────────────────────────
    if event_type in (
        "authentication_success", "ssh_accepted",
        "pam_session_opened", "sudo_command",
    ):
        if username:
            r = await detect_login_time_anomaly(agent_id, username, hour)
            if r:
                r.description = (
                    f"Off-hours login anomaly: user '{username}' logged in at "
                    f"{hour:02d}:00 UTC (baseline avg {r.baseline_mean:.1f}h "
                    f"±{r.baseline_std:.1f}h, z={r.z_score})"
                )
                results.append(r)

            if src_ip:
                r = await detect_new_src_ip(agent_id, username, src_ip)
                if r:
                    results.append(r)

    # ── Auth failure → failure-rate check ─────────────────────────────────────
    if event_type in (
        "authentication_failed", "ssh_failed", "pam_auth_failed",
        "ssh_invalid_user", "sudo_auth_failure",
    ):
        r = await detect_auth_failure_anomaly(agent_id)
        if r:
            results.append(r)

    # ── Sudo usage ────────────────────────────────────────────────────────────
    if event_type == "sudo_command" and username:
        r = await detect_sudo_rate_anomaly(agent_id, username)
        if r:
            results.append(r)

    # ── FIM event ─────────────────────────────────────────────────────────────
    if event_type in ("fim_modified", "fim_created", "fim_deleted", "fim_moved"):
        r = await detect_fim_rate_anomaly(agent_id)
        if r:
            results.append(r)

    # ── Process spawn ─────────────────────────────────────────────────────────
    if event_type in ("process_start", "process_exec", "auditd_execve"):
        r = await detect_process_spawn_anomaly(agent_id)
        if r:
            results.append(r)

    # ── Network connection ────────────────────────────────────────────────────
    if event_type in ("network_connection", "network_connected"):
        r = await detect_net_connection_rate_anomaly(agent_id)
        if r:
            results.append(r)
        if dst_ip:
            r = await detect_new_dst_ip(agent_id, dst_ip)
            if r:
                results.append(r)

    return results


# ── DB persistence: sync Redis baselines → PostgreSQL ────────────────────────

async def sync_baselines_to_db(db: AsyncSession) -> int:
    """
    Flush current Welford states from Redis into PostgreSQL for durability.
    Called by the background scheduler every SYNC_INTERVAL seconds.
    Returns the number of baselines written.
    """
    from models.baseline import AnomalyBaseline
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    r = await _get_redis()
    if not r:
        return 0

    try:
        keys = await r.keys("anomaly:baseline:*")
    except Exception as exc:
        logger.warning("sync_baselines_to_db: Redis scan failed: %s", exc)
        return 0

    written = 0
    for key in keys:
        try:
            raw = await r.get(key)
            if not raw:
                continue
            d = json.loads(raw)
            agent_id   = d.get("agent_id", "")
            metric_key = d.get("metric", "")
            if not agent_id or not metric_key:
                continue

            stmt = pg_insert(AnomalyBaseline).values(
                agent_id   = agent_id,
                metric_key = metric_key,
                n          = int(d.get("n", 0)),
                mean       = float(d.get("mean", 0.0)),
                m2         = float(d.get("m2", 0.0)),
                updated_at = datetime.now(timezone.utc),
            ).on_conflict_do_update(
                index_elements=["agent_id", "metric_key"],
                set_={
                    "n":          int(d.get("n", 0)),
                    "mean":       float(d.get("mean", 0.0)),
                    "m2":         float(d.get("m2", 0.0)),
                    "updated_at": datetime.now(timezone.utc),
                },
            )
            await db.execute(stmt)
            written += 1
        except Exception as exc:
            logger.debug("sync_baselines_to_db: key %s error: %s", key, exc)

    if written:
        await db.commit()
    return written


async def load_baselines_from_db(db: AsyncSession) -> int:
    """
    On startup: restore baselines from PostgreSQL into Redis so the engine
    has history immediately instead of re-warming from scratch.
    """
    from models.baseline import AnomalyBaseline

    r = await _get_redis()
    if not r:
        return 0

    rows = (await db.execute(select(AnomalyBaseline))).scalars().all()
    loaded = 0
    for row in rows:
        try:
            payload = json.dumps({
                "n":        row.n,
                "mean":     row.mean,
                "m2":       row.m2,
                "agent_id": row.agent_id,
                "metric":   row.metric_key,
            })
            await r.setex(
                _rkey_baseline(row.agent_id, row.metric_key),
                BASELINE_TTL,
                payload,
            )
            loaded += 1
        except Exception as exc:
            logger.debug("load_baselines_from_db error: %s", exc)
    return loaded
