"""
Active Response engine.

On every new alert the engine:
  1. Loads enabled AR policies (filtered by target_agent if set)
  2. Evaluates trigger condition + extra conditions (level, event_type)
  3. Checks IP whitelist — private/RFC1918 IPs are never auto-blocked
  4. Checks cooldown per (policy_id, groupby_key)
  5. Checks max_per_hour rate cap per policy
  6. Skips if identical pending/sent execution already exists (dedup guard)
  7. Creates ARExecution records (status=pending) for agent-side actions
  8. Executes server-side actions (email, Slack) immediately
"""
import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select, and_, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from models.active_response import (
    ARPolicy, ARExecution, ARTriggerOn, ARActionType, ARExecutionStatus,
    ARTriggeredBy,
)
from models.alert import Alert

logger = logging.getLogger(__name__)

# RFC1918 + loopback + link-local — never auto-block these
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
]

AR_EXECUTION_TIMEOUT_SECONDS = 600   # 10 min — sent→timeout transition


# ── IP helpers ────────────────────────────────────────────────────────────────

def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


# ── Policy matching ───────────────────────────────────────────────────────────

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


def _passes_extra_conditions(policy: ARPolicy, alert: Alert) -> bool:
    """Check optional filter conditions stored in action_params."""
    params = policy.action_params or {}

    min_level = params.get("trigger_min_level")
    if min_level is not None:
        try:
            if (alert.level or 0) < int(min_level):
                return False
        except (ValueError, TypeError):
            pass

    event_type_filter = params.get("trigger_event_type")
    if event_type_filter:
        pf = alert.parsed_fields or {}
        alert_event = pf.get("event") or pf.get("event_type") or ""
        if event_type_filter.lower() != alert_event.lower():
            return False

    return True


# ── Rate controls ─────────────────────────────────────────────────────────────

async def _cooldown_ok(db: AsyncSession, policy: ARPolicy, groupby: str) -> bool:
    """True if no execution for this policy+groupby in the last cooldown_seconds."""
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=policy.cooldown_seconds)
    stmt = (
        select(ARExecution.id)
        .where(
            and_(
                ARExecution.policy_id == policy.id,
                ARExecution.src_ip    == groupby,
                ARExecution.created_at >= cutoff,
                ARExecution.status.notin_([
                    ARExecutionStatus.cancelled,
                ]),
            )
        )
        .limit(1)
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none() is None


async def _within_hourly_cap(db: AsyncSession, policy: ARPolicy) -> bool:
    """True if policy has not yet hit max_per_hour in the last 60 minutes."""
    if not policy.max_per_hour:
        return True
    cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
    count = (await db.execute(
        select(func.count(ARExecution.id)).where(
            and_(
                ARExecution.policy_id  == policy.id,
                ARExecution.created_at >= cutoff,
                ARExecution.status.notin_([ARExecutionStatus.cancelled]),
            )
        )
    )).scalar_one()
    return count < policy.max_per_hour


async def _no_duplicate_in_flight(
    db: AsyncSession, policy: ARPolicy, groupby: str
) -> bool:
    """True if no pending/sent execution already exists for this policy+groupby.

    Prevents duplicate actions when two alerts arrive simultaneously and both
    pass the cooldown window check.
    """
    stmt = (
        select(ARExecution.id)
        .where(
            and_(
                ARExecution.policy_id == policy.id,
                ARExecution.src_ip    == groupby,
                ARExecution.status.in_([
                    ARExecutionStatus.pending,
                    ARExecutionStatus.sent,
                ]),
            )
        )
        .limit(1)
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none() is None


# ── Param builder ─────────────────────────────────────────────────────────────

def _build_params(policy: ARPolicy, alert: Alert) -> dict:
    base = dict(policy.action_params or {})
    base.setdefault("src_ip",      alert.src_ip or "")
    base.setdefault("severity",    str(alert.severity))
    base.setdefault("alert_title", alert.title or "")
    base.setdefault("alert_id",    alert.id)
    return base


# ── Server-side action dispatch ───────────────────────────────────────────────

_SERVER_SIDE_ACTIONS = {ARActionType.email_alert, ARActionType.slack_alert}


async def _run_server_action(execution: ARExecution, alert: Alert) -> None:
    """Email / Slack — marks execution complete or failed."""
    from services.notification_service import send_alert_email, send_slack_alert

    params = execution.action_params or {}
    try:
        if execution.action == ARActionType.email_alert:
            await send_alert_email(alert, params.get("recipients"))
        elif execution.action == ARActionType.slack_alert:
            await send_slack_alert(alert)
        execution.status       = ARExecutionStatus.success
        execution.completed_at = datetime.now(timezone.utc)
        execution.result       = "Sent successfully"
    except Exception as exc:
        execution.status       = ARExecutionStatus.failed
        execution.completed_at = datetime.now(timezone.utc)
        execution.result       = str(exc)[:500]
        logger.error(f"Server-side AR action failed: {exc}")


# ── Primary entry point ───────────────────────────────────────────────────────

async def trigger_active_response(db: AsyncSession, alert: Alert) -> int:
    """Evaluate all enabled policies against the alert and queue matching actions.

    Returns the number of new executions created.
    """
    stmt = select(ARPolicy).where(ARPolicy.enabled == True)  # noqa: E712
    if alert.agent_id:
        stmt = stmt.where(
            (ARPolicy.target_agent == None) |  # noqa: E711
            (ARPolicy.target_agent == alert.agent_id)
        )
    policies = (await db.execute(stmt)).scalars().all()

    created = 0
    for policy in policies:
        if not _policy_matches(policy, alert):
            continue

        if not _passes_extra_conditions(policy, alert):
            continue

        # Never auto-block internal addresses
        if policy.action == ARActionType.block_ip and alert.src_ip:
            if _is_private_ip(alert.src_ip):
                logger.debug("AR skip block_ip: private IP %s", alert.src_ip)
                continue

        groupby = alert.src_ip or alert.agent_id or "unknown"

        if not await _cooldown_ok(db, policy, groupby):
            logger.debug("AR cooldown active: policy='%s' groupby=%s", policy.name, groupby)
            continue

        if not await _within_hourly_cap(db, policy):
            logger.warning(
                "AR hourly cap reached: policy='%s' max_per_hour=%s",
                policy.name, policy.max_per_hour,
            )
            continue

        if not await _no_duplicate_in_flight(db, policy, groupby):
            logger.debug(
                "AR dedup skip: pending/sent already exists policy='%s' groupby=%s",
                policy.name, groupby,
            )
            continue

        execution = ARExecution(
            policy_id    = policy.id,
            alert_id     = alert.id,
            agent_id     = alert.agent_id if policy.action not in _SERVER_SIDE_ACTIONS else None,
            action       = policy.action,
            action_params= _build_params(policy, alert),
            status       = ARExecutionStatus.pending,
            src_ip       = groupby,
            policy_name  = policy.name,
            triggered_by = ARTriggeredBy.auto,
            retry_count  = 0,
        )
        db.add(execution)
        await db.flush()
        await db.refresh(execution)
        created += 1

        logger.info(
            "AR triggered: policy='%s' action=%s alert_id=%s agent=%s groupby=%s exec_id=%s",
            policy.name, policy.action, alert.id, alert.agent_id, groupby, execution.id,
        )

        if policy.action in _SERVER_SIDE_ACTIONS:
            await _run_server_action(execution, alert)

    return created


# ── Background maintenance ────────────────────────────────────────────────────

async def mark_timed_out_executions(db: AsyncSession) -> int:
    """Transition 'sent' executions that exceed the timeout to 'timeout' status."""
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=AR_EXECUTION_TIMEOUT_SECONDS)
    stmt = select(ARExecution).where(
        and_(
            ARExecution.status    == ARExecutionStatus.sent,
            ARExecution.created_at < cutoff,
        )
    )
    execs = (await db.execute(stmt)).scalars().all()
    now = datetime.now(timezone.utc)
    for ex in execs:
        ex.status       = ARExecutionStatus.timeout
        ex.completed_at = now
        ex.result       = (
            f"Timed out after {AR_EXECUTION_TIMEOUT_SECONDS}s — "
            "agent may be offline or unreachable"
        )
    if execs:
        await db.flush()
        logger.info("AR timeout: marked %d execution(s) as timed out", len(execs))
    return len(execs)


async def process_auto_unblocks(db: AsyncSession) -> int:
    """Schedule unblock_ip executions for block_ip actions whose unblock_after has elapsed.

    Uses an '_unblock_scheduled' flag in action_params to prevent duplicate scheduling.
    flag_modified() is required to mark the mutated JSON column as dirty in SQLAlchemy.
    """
    now = datetime.now(timezone.utc)
    stmt = select(ARExecution).where(
        and_(
            ARExecution.action    == ARActionType.block_ip,
            ARExecution.status    == ARExecutionStatus.success,
            ARExecution.completed_at != None,  # noqa: E711
        )
    )
    execs = (await db.execute(stmt)).scalars().all()

    created = 0
    for ex in execs:
        params = ex.action_params or {}

        # Already scheduled — skip
        if params.get("_unblock_scheduled"):
            continue

        unblock_after = params.get("unblock_after")
        if not unblock_after:
            continue

        try:
            unblock_after_secs = int(unblock_after)
        except (ValueError, TypeError):
            continue

        if not ex.completed_at:
            continue

        # Make completed_at timezone-aware if stored as naive
        completed = (
            ex.completed_at.replace(tzinfo=timezone.utc)
            if ex.completed_at.tzinfo is None
            else ex.completed_at
        )

        if (now - completed).total_seconds() < unblock_after_secs:
            continue

        unblock = ARExecution(
            policy_id           = ex.policy_id,
            alert_id            = ex.alert_id,
            agent_id            = ex.agent_id,
            action              = ARActionType.unblock_ip,
            action_params       = {
                "src_ip": ex.src_ip,
                "ip":     params.get("src_ip", ex.src_ip),
            },
            status              = ARExecutionStatus.pending,
            src_ip              = ex.src_ip,
            policy_name         = f"{ex.policy_name or ''} [auto-unblock]",
            triggered_by        = ARTriggeredBy.auto,
            retry_count         = 0,
            parent_execution_id = ex.id,
        )
        db.add(unblock)

        # Mark as scheduled — flag_modified is required for in-place JSON mutation
        params["_unblock_scheduled"] = True
        ex.action_params = params
        flag_modified(ex, "action_params")
        created += 1

    if created:
        await db.flush()
        logger.info("AR auto-unblock: scheduled %d unblock execution(s)", created)
    return created
