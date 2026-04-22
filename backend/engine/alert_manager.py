import logging
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
from models.alert import Alert, AlertStatus, AlertSeverity
from models.rule import Rule
from models.agent import Agent
from services.notification_service import notify_new_alert

logger = logging.getLogger(__name__)


async def create_alert(
    db: AsyncSession,
    rule: Rule,
    agent_id: str,
    description: str,
    log_id: Optional[str] = None,
    agent_hostname: Optional[str] = None,
) -> Optional[Alert]:
    # Check cooldown
    cutoff = datetime.utcnow() - timedelta(seconds=rule.cooldown_seconds)
    stmt = select(Alert).where(
        and_(
            Alert.rule_id == rule.id,
            Alert.agent_id == agent_id,
            Alert.created_at >= cutoff,
        )
    ).limit(1)
    result = await db.execute(stmt)
    existing = result.scalar_one_or_none()
    if existing:
        return None

    alert = Alert(
        rule_id=rule.id,
        agent_id=agent_id,
        severity=rule.severity,
        title=rule.name,
        description=description,
        log_id=log_id,
        status=AlertStatus.open,
        agent_hostname=agent_hostname or agent_id,
        rule_name=rule.name,
    )
    db.add(alert)
    await db.flush()
    await db.refresh(alert)

    alert_data = {
        "id": alert.id,
        "rule_id": alert.rule_id,
        "agent_id": alert.agent_id,
        "severity": alert.severity,
        "title": alert.title,
        "description": alert.description,
        "log_id": alert.log_id,
        "status": alert.status,
        "agent_hostname": alert.agent_hostname,
        "rule_name": alert.rule_name,
        "created_at": str(alert.created_at),
    }

    try:
        await notify_new_alert(alert_data)
    except Exception as e:
        logger.error(f"Notify failed: {e}")

    return alert


async def create_brute_force_alert(
    db: AsyncSession,
    agent_id: str,
    src_ip: str,
    count: int,
    agent_hostname: Optional[str] = None,
) -> Optional[Alert]:
    stmt = select(Rule).where(Rule.custom_logic == "brute_force_ssh", Rule.enabled == True).limit(1)
    result = await db.execute(stmt)
    rule = result.scalar_one_or_none()
    if not rule:
        return None

    cutoff = datetime.utcnow() - timedelta(seconds=rule.cooldown_seconds)
    stmt2 = select(Alert).where(
        and_(
            Alert.rule_id == rule.id,
            Alert.agent_id == agent_id,
            Alert.description.contains(src_ip),
            Alert.created_at >= cutoff,
        )
    ).limit(1)
    r2 = await db.execute(stmt2)
    if r2.scalar_one_or_none():
        return None

    alert = Alert(
        rule_id=rule.id,
        agent_id=agent_id,
        severity=AlertSeverity.CRITICAL,
        title="Brute Force SSH Attack Detected",
        description=f"IP {src_ip} made {count} failed login attempts in 60 seconds on agent {agent_hostname or agent_id}",
        status=AlertStatus.open,
        agent_hostname=agent_hostname or agent_id,
        rule_name=rule.name,
    )
    db.add(alert)
    await db.flush()
    await db.refresh(alert)

    alert_data = {
        "id": alert.id,
        "rule_id": alert.rule_id,
        "agent_id": alert.agent_id,
        "severity": alert.severity,
        "title": alert.title,
        "description": alert.description,
        "status": alert.status,
        "agent_hostname": alert.agent_hostname,
        "rule_name": alert.rule_name,
        "created_at": str(alert.created_at),
    }
    try:
        await notify_new_alert(alert_data)
    except Exception as e:
        logger.error(f"Notify failed: {e}")

    return alert
