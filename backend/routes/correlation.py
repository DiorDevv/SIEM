"""
Correlation Rules API routes.

GET    /api/correlation/rules
POST   /api/correlation/rules
GET    /api/correlation/rules/{id}
PUT    /api/correlation/rules/{id}
DELETE /api/correlation/rules/{id}
POST   /api/correlation/rules/{id}/toggle
POST   /api/correlation/rules/{id}/test   — dry-run evaluation
GET    /api/correlation/stats
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.alert import Alert
from models.correlation import CorrelationRule
from routes.auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/correlation", tags=["correlation"])


# ── Schemas ────────────────────────────────────────────────────────────────────

class RuleCreate(BaseModel):
    name:                  str
    description:           Optional[str] = None
    rule_type:             str = "threshold"
    severity:              str = "HIGH"
    threshold_count:       int = 5
    time_window_seconds:   int = 300
    conditions:            Dict[str, Any]
    alert_title_template:  Optional[str] = None
    mitre_tactics:         Optional[List[str]] = None
    mitre_techniques:      Optional[List[str]] = None
    cooldown_seconds:      int = 300
    enabled:               bool = True


class RuleUpdate(BaseModel):
    name:                  Optional[str] = None
    description:           Optional[str] = None
    rule_type:             Optional[str] = None
    severity:              Optional[str] = None
    threshold_count:       Optional[int] = None
    time_window_seconds:   Optional[int] = None
    conditions:            Optional[Dict[str, Any]] = None
    alert_title_template:  Optional[str] = None
    mitre_tactics:         Optional[List[str]] = None
    mitre_techniques:      Optional[List[str]] = None
    cooldown_seconds:      Optional[int] = None
    enabled:               Optional[bool] = None


# ── Stats ──────────────────────────────────────────────────────────────────────

@router.get("/stats")
async def get_stats(
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    total   = (await db.execute(select(func.count(CorrelationRule.id)))).scalar_one()
    enabled = (await db.execute(select(func.count(CorrelationRule.id)).where(CorrelationRule.enabled == True))).scalar_one()
    total_triggers = (await db.execute(
        select(func.coalesce(func.sum(CorrelationRule.trigger_count), 0))
    )).scalar_one()

    # By type
    type_rows = (await db.execute(
        select(CorrelationRule.rule_type, func.count(CorrelationRule.id))
        .group_by(CorrelationRule.rule_type)
    )).all()

    # Most active rules
    top_rules = (await db.execute(
        select(CorrelationRule)
        .where(CorrelationRule.trigger_count > 0)
        .order_by(CorrelationRule.trigger_count.desc())
        .limit(5)
    )).scalars().all()

    # Recent correlation alerts (from last 24h)
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    recent_alerts = (await db.execute(
        select(func.count(Alert.id))
        .where(
            Alert.rule_name.ilike("CORR:%"),
            Alert.created_at >= since,
        )
    )).scalar_one()

    return {
        "total": total,
        "enabled": enabled,
        "disabled": total - enabled,
        "total_triggers": int(total_triggers),
        "recent_alerts_24h": recent_alerts,
        "by_type": {r[0]: r[1] for r in type_rows},
        "top_rules": [
            {
                "id": r.id,
                "name": r.name,
                "rule_type": r.rule_type,
                "severity": r.severity,
                "trigger_count": r.trigger_count,
                "last_triggered": r.last_triggered.isoformat() if r.last_triggered else None,
            }
            for r in top_rules
        ],
    }


# ── List rules ─────────────────────────────────────────────────────────────────

@router.get("/rules")
async def list_rules(
    rule_type: Optional[str] = Query(None),
    enabled:   Optional[bool] = Query(None),
    search:    Optional[str]  = Query(None),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    q = select(CorrelationRule)
    if rule_type:
        q = q.where(CorrelationRule.rule_type == rule_type)
    if enabled is not None:
        q = q.where(CorrelationRule.enabled == enabled)
    if search:
        q = q.where(CorrelationRule.name.ilike(f"%{search}%"))
    rows = (await db.execute(q.order_by(CorrelationRule.created_at.desc()))).scalars().all()
    return [_rule_dict(r) for r in rows]


# ── Get single rule ────────────────────────────────────────────────────────────

@router.get("/rules/{rule_id}")
async def get_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    rule = await _get_or_404(db, rule_id)
    return _rule_dict(rule)


# ── Create rule ────────────────────────────────────────────────────────────────

@router.post("/rules", status_code=201)
async def create_rule(
    body: RuleCreate,
    db: AsyncSession  = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    rule = CorrelationRule(
        name                 = body.name,
        description          = body.description,
        rule_type            = body.rule_type,
        severity             = body.severity,
        threshold_count      = body.threshold_count,
        time_window_seconds  = body.time_window_seconds,
        conditions           = body.conditions,
        alert_title_template = body.alert_title_template,
        mitre_tactics        = body.mitre_tactics,
        mitre_techniques     = body.mitre_techniques,
        cooldown_seconds     = body.cooldown_seconds,
        enabled              = body.enabled,
        created_by           = user.get("username"),
    )
    db.add(rule)
    await db.flush()
    return _rule_dict(rule)


# ── Update rule ────────────────────────────────────────────────────────────────

@router.put("/rules/{rule_id}")
async def update_rule(
    rule_id: int,
    body: RuleUpdate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    rule = await _get_or_404(db, rule_id)

    for field in ("name", "description", "rule_type", "severity",
                  "threshold_count", "time_window_seconds", "conditions",
                  "alert_title_template", "mitre_tactics", "mitre_techniques",
                  "cooldown_seconds", "enabled"):
        val = getattr(body, field, None)
        if val is not None:
            setattr(rule, field, val)

    await db.flush()
    return _rule_dict(rule)


# ── Delete rule ────────────────────────────────────────────────────────────────

@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    rule = await _get_or_404(db, rule_id)
    await db.delete(rule)


# ── Toggle enabled ─────────────────────────────────────────────────────────────

@router.post("/rules/{rule_id}/toggle")
async def toggle_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    rule = await _get_or_404(db, rule_id)
    rule.enabled = not rule.enabled
    await db.flush()
    return {"id": rule.id, "enabled": rule.enabled}


# ── Dry-run test ───────────────────────────────────────────────────────────────

@router.post("/rules/{rule_id}/test")
async def test_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    """
    Simulate rule evaluation without creating alerts or setting cooldowns.
    Returns what would be fired.
    """
    from services.correlation_engine import _eval_threshold, _eval_sequence
    import redis.asyncio as aioredis

    rule = await _get_or_404(db, rule_id)

    class _FakeRedis:
        async def exists(self, key): return False
        async def setex(self, key, ttl, val): pass

    fake_redis = _FakeRedis()
    original_add = db.add
    fired_alerts = []

    # Monkey-patch db.add to capture instead of persist
    def _capture_add(obj):
        if isinstance(obj, Alert):
            fired_alerts.append({
                "title":       obj.title,
                "severity":    obj.severity.value if hasattr(obj.severity, "value") else str(obj.severity),
                "description": obj.description,
                "src_ip":      obj.src_ip,
                "agent_id":    obj.agent_id,
            })
        # Don't call original — test mode
    db.add = _capture_add

    try:
        if rule.rule_type == "sequence":
            await _eval_sequence(db, fake_redis, rule)
        else:
            await _eval_threshold(db, fake_redis, rule)
    except Exception as e:
        logger.warning(f"Test run error for rule {rule_id}: {e}")
    finally:
        db.add = original_add

    return {
        "rule_id":    rule.id,
        "rule_name":  rule.name,
        "would_fire": len(fired_alerts),
        "alerts":     fired_alerts,
    }


# ── Seed default rules ─────────────────────────────────────────────────────────

async def seed_default_correlation_rules(db: AsyncSession):
    """Add built-in correlation rules on first startup."""
    count = (await db.execute(select(func.count(CorrelationRule.id)))).scalar_one()
    if count > 0:
        return

    defaults = [
        {
            "name": "SSH Brute Force Detection",
            "description": "5+ authentication failures from same agent within 5 minutes",
            "rule_type": "threshold",
            "severity": "HIGH",
            "threshold_count": 5,
            "time_window_seconds": 300,
            "conditions": {
                "source": "logs",
                "filters": {"message__contains": "authentication failure"},
                "group_by": "agent_id",
            },
            "alert_title_template": "SSH Brute Force: {count} failures in {window}s on {group_value}",
            "mitre_tactics": ["Credential Access"],
            "mitre_techniques": ["T1110"],
            "cooldown_seconds": 600,
        },
        {
            "name": "Multiple Critical Alerts",
            "description": "3+ CRITICAL severity alerts from the same agent within 10 minutes",
            "rule_type": "threshold",
            "severity": "CRITICAL",
            "threshold_count": 3,
            "time_window_seconds": 600,
            "conditions": {
                "source": "alerts",
                "filters": {"severity": "critical"},
                "group_by": "agent_id",
            },
            "alert_title_template": "Alert Storm: {count} critical alerts in {window}s on {group_value}",
            "mitre_tactics": ["Impact"],
            "mitre_techniques": [],
            "cooldown_seconds": 900,
        },
        {
            "name": "Port Scan followed by Brute Force",
            "description": "Reconnaissance followed by credential attack — lateral movement pattern",
            "rule_type": "sequence",
            "severity": "CRITICAL",
            "threshold_count": 1,
            "time_window_seconds": 1800,
            "conditions": {
                "source": "alerts",
                "steps": [
                    {"filters": {"title__contains": "Port Scan"}},
                    {"filters": {"title__contains": "Brute Force"}},
                ],
                "group_by": "agent_id",
            },
            "alert_title_template": "Attack Sequence: Recon + Brute Force on {group_value}",
            "mitre_tactics": ["Discovery", "Credential Access"],
            "mitre_techniques": ["T1046", "T1110"],
            "cooldown_seconds": 3600,
        },
        {
            "name": "Repeated Log Errors",
            "description": "20+ ERROR level log entries from same agent within 5 minutes",
            "rule_type": "threshold",
            "severity": "MEDIUM",
            "threshold_count": 20,
            "time_window_seconds": 300,
            "conditions": {
                "source": "logs",
                "filters": {"level": "ERROR"},
                "group_by": "agent_id",
            },
            "alert_title_template": "Log Error Storm: {count} errors in {window}s on {group_value}",
            "mitre_tactics": [],
            "mitre_techniques": [],
            "cooldown_seconds": 600,
        },
    ]

    for d in defaults:
        db.add(CorrelationRule(**d, created_by="system"))
    await db.flush()
    logger.info(f"Seeded {len(defaults)} default correlation rules")


# ── Helpers ────────────────────────────────────────────────────────────────────

async def _get_or_404(db: AsyncSession, rule_id: int) -> CorrelationRule:
    rule = (await db.execute(select(CorrelationRule).where(CorrelationRule.id == rule_id))).scalar_one_or_none()
    if not rule:
        raise HTTPException(404, "Correlation rule not found")
    return rule


def _rule_dict(r: CorrelationRule) -> dict:
    return {
        "id":                   r.id,
        "name":                 r.name,
        "description":          r.description,
        "rule_type":            r.rule_type,
        "enabled":              r.enabled,
        "severity":             r.severity,
        "threshold_count":      r.threshold_count,
        "time_window_seconds":  r.time_window_seconds,
        "conditions":           r.conditions,
        "alert_title_template": r.alert_title_template,
        "mitre_tactics":        r.mitre_tactics,
        "mitre_techniques":     r.mitre_techniques,
        "cooldown_seconds":     r.cooldown_seconds,
        "trigger_count":        r.trigger_count,
        "last_triggered":       r.last_triggered.isoformat() if r.last_triggered else None,
        "created_by":           r.created_by,
        "created_at":           r.created_at.isoformat() if r.created_at else None,
        "updated_at":           r.updated_at.isoformat() if r.updated_at else None,
    }
