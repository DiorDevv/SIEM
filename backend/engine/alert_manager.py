import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from models.alert import Alert, AlertStatus, AlertSeverity
from models.rule import Rule
from services.notification_service import notify_new_alert

logger = logging.getLogger(__name__)


async def create_alert(
    db:             AsyncSession,
    rule:           Rule,
    agent_id:       str,
    description:    str,
    log_id:         Optional[str] = None,
    agent_hostname: Optional[str] = None,
    src_ip:         Optional[str] = None,
) -> Optional[Alert]:
    """
    Thin wrapper used by legacy callers.  Delegates to the aggregation-aware
    _upsert_alert in rule_engine to keep all creation logic in one place.
    """
    from engine.rule_engine import _upsert_alert
    from engine.mitre import level_to_severity

    agg_key = f"{rule.id}:{agent_id}:{src_ip or ''}"[:128]
    return await _upsert_alert(
        db,
        agent_id         = agent_id,
        agent_hostname   = agent_hostname or agent_id,
        title            = rule.name,
        description      = description,
        severity         = rule.severity,
        level            = rule.level,
        agg_key          = agg_key,
        rule_id          = rule.id,
        rule_name        = rule.name,
        groups           = rule.groups,
        category         = rule.category,
        mitre_tactic     = rule.mitre_tactic,
        mitre_tech       = rule.mitre_technique,
        src_ip           = src_ip,
        log_id           = log_id,
        cooldown_seconds = rule.cooldown_seconds,
    )


async def create_brute_force_alert(
    db:             AsyncSession,
    agent_id:       str,
    src_ip:         str,
    count:          int,
    agent_hostname: Optional[str] = None,
) -> Optional[Alert]:
    """Legacy helper kept for backward compatibility with older callers."""
    stmt = select(Rule).where(
        Rule.custom_logic == "brute_force_ssh",
        Rule.enabled      == True,
    ).limit(1)
    rule = (await db.execute(stmt)).scalar_one_or_none()
    if not rule:
        return None

    from engine.rule_engine import _upsert_alert

    agg_key = f"{rule.id}:{agent_id}:{src_ip}"[:128]
    return await _upsert_alert(
        db,
        agent_id         = agent_id,
        agent_hostname   = agent_hostname or agent_id,
        title            = "Brute Force SSH Attack Detected",
        description      = (
            f"IP {src_ip} made {count} failed login attempts in 60 s "
            f"on agent {agent_hostname or agent_id}"
        ),
        severity         = AlertSeverity.CRITICAL,
        level            = rule.level,
        agg_key          = agg_key,
        rule_id          = rule.id,
        rule_name        = rule.name,
        groups           = rule.groups,
        category         = rule.category,
        mitre_tactic     = "Credential Access",
        mitre_tech       = "T1110.001",
        src_ip           = src_ip,
        cooldown_seconds = rule.cooldown_seconds,
    )
