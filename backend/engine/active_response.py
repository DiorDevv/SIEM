"""
Active Response engine.

On every new alert the engine:
  1. Loads enabled AR policies
  2. Evaluates each policy's trigger condition against the alert
  3. Checks cooldown per (policy_id, src_ip or agent_id)
  4. Creates ARExecution records (pending) for agent-side actions
  5. Executes server-side actions (email, Slack) immediately
"""
import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from models.active_response import (
    ARPolicy, ARExecution, ARTriggerOn, ARActionType, ARExecutionStatus,
)
from models.alert import Alert

logger = logging.getLogger(__name__)


def _policy_matches(policy: ARPolicy, alert: Alert) -> bool:
    t = policy.trigger_on

    if t == ARTriggerOn.any_alert:
        return True

    if t == ARTriggerOn.severity:
        if not policy.trigger_severity:
            return False
        allowed = {s.strip().upper() for s in policy.trigger_severity.split(",")}
        return str(alert.severity).upper() in allowed

    if t == ARTriggerOn.rule_name:
        if not policy.trigger_rule:
            return False
        return policy.trigger_rule.lower() in (alert.rule_name or "").lower()

    if t == ARTriggerOn.category:
        if not policy.trigger_category:
            return False
        return policy.trigger_category.lower() == (alert.category or "").lower()

    if t == ARTriggerOn.src_ip:
        return bool(alert.src_ip)

    return False


async def _cooldown_ok(db: AsyncSession, policy: ARPolicy, groupby: str) -> bool:
    cutoff = datetime.utcnow() - timedelta(seconds=policy.cooldown_seconds)
    stmt = select(ARExecution).where(
        and_(
            ARExecution.policy_id == policy.id,
            ARExecution.src_ip == groupby,
            ARExecution.created_at >= cutoff,
        )
    ).limit(1)
    result = await db.execute(stmt)
    return result.scalar_one_or_none() is None


_SERVER_SIDE_ACTIONS = {ARActionType.email_alert, ARActionType.slack_alert}


async def trigger_active_response(
    db:       AsyncSession,
    alert:    Alert,
) -> int:
    stmt = select(ARPolicy).where(ARPolicy.enabled == True)
    if alert.agent_id:
        stmt = stmt.where(
            (ARPolicy.target_agent == None) |
            (ARPolicy.target_agent == alert.agent_id)
        )
    policies = (await db.execute(stmt)).scalars().all()

    created = 0
    for policy in policies:
        if not _policy_matches(policy, alert):
            continue

        groupby = alert.src_ip or alert.agent_id or "unknown"
        if not await _cooldown_ok(db, policy, groupby):
            logger.debug(f"AR policy {policy.name} on cooldown for {groupby}")
            continue

        execution = ARExecution(
            policy_id    = policy.id,
            alert_id     = alert.id,
            agent_id     = alert.agent_id,
            action       = policy.action,
            action_params= _build_params(policy, alert),
            status       = ARExecutionStatus.pending,
            src_ip       = groupby,
            policy_name  = policy.name,
        )
        db.add(execution)
        await db.flush()
        await db.refresh(execution)
        created += 1
        logger.info(
            f"AR triggered: policy='{policy.name}' action={policy.action} "
            f"alert_id={alert.id} agent={alert.agent_id}"
        )

        # Server-side actions run immediately
        if policy.action in _SERVER_SIDE_ACTIONS:
            await _run_server_action(execution, alert)

    return created


def _build_params(policy: ARPolicy, alert: Alert) -> dict:
    base = dict(policy.action_params or {})
    # Inject alert context so agent can use it
    base.setdefault("src_ip",    alert.src_ip or "")
    base.setdefault("severity",  str(alert.severity))
    base.setdefault("alert_title", alert.title or "")
    return base


async def _run_server_action(execution: ARExecution, alert: Alert):
    """Email / Slack — fire-and-forget."""
    from services.notification_service import send_alert_email, send_slack_alert

    params = execution.action_params or {}
    try:
        if execution.action == ARActionType.email_alert:
            await send_alert_email(alert, params.get("recipients"))
        elif execution.action == ARActionType.slack_alert:
            await send_slack_alert(alert)
        execution.status       = ARExecutionStatus.success
        execution.completed_at = datetime.utcnow()
    except Exception as e:
        execution.status = ARExecutionStatus.failed
        execution.result = str(e)
        logger.error(f"Server-side AR action failed: {e}")
