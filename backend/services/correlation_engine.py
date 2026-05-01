"""
Correlation Engine — background evaluator.

Runs every EVAL_INTERVAL seconds, checks all enabled rules,
creates alerts when thresholds are exceeded.
Uses Redis for per-group cooldown to prevent alert storms.
"""
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

import redis.asyncio as aioredis
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import AsyncSessionLocal
from models.alert import Alert, AlertSeverity, AlertStatus
from models.correlation import CorrelationRule
from models.log import Log

logger = logging.getLogger(__name__)

EVAL_INTERVAL = 60   # seconds between evaluation cycles
_redis: aioredis.Redis | None = None


async def _get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = await aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis


# ── Severity mapping ───────────────────────────────────────────────────────────

_SEV_MAP = {
    "LOW":      AlertSeverity.LOW,
    "MEDIUM":   AlertSeverity.MEDIUM,
    "HIGH":     AlertSeverity.HIGH,
    "CRITICAL": AlertSeverity.CRITICAL,
}


# ── Threshold evaluation ───────────────────────────────────────────────────────

async def _eval_threshold(
    db: AsyncSession,
    redis: aioredis.Redis,
    rule: CorrelationRule,
) -> int:
    """
    Returns number of alerts fired for this rule.
    conditions = {
      "source": "logs" | "alerts",
      "filters": { <field>__<op>: <value>, ... },
      "group_by": "agent_id" | "src_ip" | "rule_name"
    }
    """
    conditions  = rule.conditions or {}
    source      = conditions.get("source", "logs")
    filters     = conditions.get("filters", {})
    group_field = conditions.get("group_by", "agent_id")
    window_start = datetime.utcnow() - timedelta(seconds=rule.time_window_seconds or 300)

    fired = 0

    if source == "logs":
        col_map = {
            "agent_id": Log.agent_id,
            "source":   Log.source,
            "level":    Log.level,
        }
        group_col = col_map.get(group_field, Log.agent_id)

        q = (
            select(group_col, func.count(Log.id).label("cnt"))
            .where(Log.timestamp >= window_start)
        )
        for fk, fv in filters.items():
            field, _, op = fk.partition("__")
            if field == "message":
                q = q.where(Log.message.ilike(f"%{fv}%") if op == "contains" else Log.message == fv)
            elif field == "level":
                q = q.where(Log.level == fv)
            elif field == "source":
                q = q.where(Log.source.ilike(f"%{fv}%") if op == "contains" else Log.source == fv)
            elif field == "agent_id":
                q = q.where(Log.agent_id == fv)

        q = q.group_by(group_col).having(
            func.count(Log.id) >= (rule.threshold_count or 5)
        )
        rows = (await db.execute(q)).all()

    else:  # alerts
        col_map = {
            "agent_id": Alert.agent_id,
            "src_ip":   Alert.src_ip,
            "rule_name": Alert.rule_name,
            "agent_hostname": Alert.agent_hostname,
        }
        group_col = col_map.get(group_field, Alert.agent_id)

        q = (
            select(group_col, func.count(Alert.id).label("cnt"))
            .where(Alert.created_at >= window_start.replace(tzinfo=timezone.utc))
        )
        for fk, fv in filters.items():
            field, _, op = fk.partition("__")
            if field == "severity":
                q = q.where(Alert.severity == fv.upper())
            elif field == "rule_name":
                q = q.where(Alert.rule_name.ilike(f"%{fv}%") if op == "contains" else Alert.rule_name == fv)
            elif field == "title":
                q = q.where(Alert.title.ilike(f"%{fv}%") if op == "contains" else Alert.title == fv)
            elif field == "agent_id":
                q = q.where(Alert.agent_id == fv)
            elif field == "status":
                q = q.where(Alert.status == fv)

        q = q.group_by(group_col).having(
            func.count(Alert.id) >= (rule.threshold_count or 5)
        )
        rows = (await db.execute(q)).all()

    for row in rows:
        group_val, count = row[0], row[1]
        if not group_val:
            continue

        cooldown_key = f"corr:cd:{rule.id}:{group_val}"
        if await redis.exists(cooldown_key):
            continue

        # Build alert title from template
        window_label = _fmt_window(rule.time_window_seconds or 300)
        title = (rule.alert_title_template or "{rule_name}: {count} events in {window}s from {group_value}").format(
            rule_name=rule.name,
            count=count,
            window=rule.time_window_seconds or 300,
            window_label=window_label,
            group_field=group_field,
            group_value=group_val,
        )

        sev = _SEV_MAP.get(rule.severity.upper(), AlertSeverity.HIGH)
        alert = Alert(
            agent_id        = group_val if group_field == "agent_id" else "correlation-engine",
            severity        = sev,
            level           = {"LOW": 3, "MEDIUM": 6, "HIGH": 9, "CRITICAL": 12}.get(rule.severity.upper(), 9),
            title           = title,
            description     = (
                f"Correlation rule '{rule.name}' triggered.\n"
                f"Detected {count} matching events within {window_label}.\n"
                f"Grouped by {group_field} = {group_val}"
            ),
            rule_name       = f"CORR:{rule.id}:{rule.name}",
            status          = AlertStatus.open,
            src_ip          = group_val if group_field == "src_ip" else None,
            agent_hostname  = group_val if group_field == "agent_hostname" else None,
            mitre_tactic    = rule.mitre_tactics[0]    if rule.mitre_tactics    else None,
            mitre_technique = rule.mitre_techniques[0] if rule.mitre_techniques else None,
        )
        db.add(alert)
        await db.flush()

        # Set cooldown
        await redis.setex(cooldown_key, rule.cooldown_seconds or 300, "1")

        # Update rule stats
        await db.execute(
            update(CorrelationRule)
            .where(CorrelationRule.id == rule.id)
            .values(
                trigger_count=CorrelationRule.trigger_count + 1,
                last_triggered=datetime.utcnow(),
            )
        )

        # Notify channels
        try:
            from services.notification_service import notify_alert_channels
            await notify_alert_channels(db, alert)
        except Exception as e:
            logger.debug(f"Notification dispatch failed: {e}")

        fired += 1
        logger.info(f"Correlation rule '{rule.name}' fired: {group_field}={group_val} count={count}")

    return fired


# ── Sequence evaluation ────────────────────────────────────────────────────────

async def _eval_sequence(
    db: AsyncSession,
    redis: aioredis.Redis,
    rule: CorrelationRule,
) -> int:
    """
    Two-step sequence: first event A, then event B within window.
    conditions = {
      "source": "alerts",
      "steps": [
        {"filters": {"title__contains": "Port Scan"}},
        {"filters": {"title__contains": "Brute Force"}}
      ],
      "group_by": "agent_id"
    }
    """
    conditions  = rule.conditions or {}
    steps       = conditions.get("steps", [])
    group_field = conditions.get("group_by", "agent_id")

    if len(steps) < 2:
        return 0

    window_start = datetime.utcnow() - timedelta(seconds=rule.time_window_seconds or 600)
    fired = 0

    col_map = {
        "agent_id":       Alert.agent_id,
        "src_ip":         Alert.src_ip,
        "agent_hostname": Alert.agent_hostname,
    }
    group_col = col_map.get(group_field, Alert.agent_id)

    # Step 1 — find groups that had event A
    def _build_step_q(step_filters, group_col):
        q = select(group_col, func.min(Alert.created_at).label("first_at")).where(
            Alert.created_at >= window_start.replace(tzinfo=timezone.utc)
        )
        for fk, fv in step_filters.items():
            field, _, op = fk.partition("__")
            if field == "title":
                q = q.where(Alert.title.ilike(f"%{fv}%") if op == "contains" else Alert.title == fv)
            elif field == "rule_name":
                q = q.where(Alert.rule_name.ilike(f"%{fv}%") if op == "contains" else Alert.rule_name == fv)
            elif field == "severity":
                q = q.where(Alert.severity == fv.upper())
        return q.group_by(group_col)

    step1_rows = (await db.execute(_build_step_q(steps[0].get("filters", {}), group_col))).all()
    if not step1_rows:
        return 0

    step1_groups = {row[0]: row[1] for row in step1_rows if row[0]}

    step2_rows = (await db.execute(_build_step_q(steps[1].get("filters", {}), group_col))).all()
    step2_groups = {row[0]: row[1] for row in step2_rows if row[0]}

    # Find groups where step1 happened BEFORE step2
    for group_val, step1_time in step1_groups.items():
        if group_val not in step2_groups:
            continue
        step2_time = step2_groups[group_val]
        if step2_time <= step1_time:
            continue

        cooldown_key = f"corr:cd:{rule.id}:{group_val}"
        if await redis.exists(cooldown_key):
            continue

        title = f"{rule.name}: attack sequence detected on {group_field}={group_val}"
        sev = _SEV_MAP.get(rule.severity.upper(), AlertSeverity.HIGH)

        alert = Alert(
            agent_id        = group_val if group_field == "agent_id" else "correlation-engine",
            severity        = sev,
            level           = 10,
            title           = title,
            description     = (
                f"Attack sequence detected by correlation rule '{rule.name}'.\n"
                f"Step 1 at {step1_time}, Step 2 at {step2_time}\n"
                f"Group: {group_field} = {group_val}"
            ),
            rule_name       = f"CORR:{rule.id}:{rule.name}",
            status          = AlertStatus.open,
            src_ip          = group_val if group_field == "src_ip" else None,
            agent_hostname  = group_val if group_field == "agent_hostname" else None,
            mitre_tactic    = rule.mitre_tactics[0]    if rule.mitre_tactics    else None,
            mitre_technique = rule.mitre_techniques[0] if rule.mitre_techniques else None,
        )
        db.add(alert)
        await db.flush()

        await redis.setex(cooldown_key, rule.cooldown_seconds or 300, "1")
        await db.execute(
            update(CorrelationRule)
            .where(CorrelationRule.id == rule.id)
            .values(trigger_count=CorrelationRule.trigger_count + 1, last_triggered=datetime.utcnow())
        )

        try:
            from services.notification_service import notify_alert_channels
            await notify_alert_channels(db, alert)
        except Exception:
            pass

        fired += 1

    return fired


# ── Main loop ──────────────────────────────────────────────────────────────────

def _fmt_window(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    return f"{seconds // 3600}h"


async def correlation_evaluator():
    """Background task — evaluate all enabled correlation rules periodically."""
    logger.info("Correlation engine started")
    redis = await _get_redis()

    while True:
        try:
            await asyncio.sleep(EVAL_INTERVAL)
            async with AsyncSessionLocal() as db:
                rules = (
                    await db.execute(
                        select(CorrelationRule).where(CorrelationRule.enabled == True)
                    )
                ).scalars().all()

                total_fired = 0
                for rule in rules:
                    try:
                        async with AsyncSessionLocal() as rule_db:
                            if rule.rule_type == "threshold":
                                fired = await _eval_threshold(rule_db, redis, rule)
                            elif rule.rule_type == "sequence":
                                fired = await _eval_sequence(rule_db, redis, rule)
                            else:
                                fired = await _eval_threshold(rule_db, redis, rule)
                            await rule_db.commit()
                        total_fired += fired
                    except Exception as e:
                        logger.error(f"Error evaluating correlation rule {rule.id}: {e}", exc_info=True)

                if total_fired:
                    logger.info(f"Correlation cycle complete: {total_fired} alert(s) fired from {len(rules)} rules")

        except asyncio.CancelledError:
            logger.info("Correlation engine stopped")
            break
        except Exception as e:
            logger.error(f"Correlation engine error: {e}", exc_info=True)
            await asyncio.sleep(10)
