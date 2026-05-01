"""
Active Response routes — policies, executions, stats, templates.

Agent-facing endpoints (/pending, /complete) require X-Agent-Token when
AGENT_SECRET is configured in settings; otherwise they remain open for
backward compatibility with agents that have not yet been updated.
"""
import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, field_validator, model_validator
from sqlalchemy import select, and_, func, update, text
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db
from models.active_response import (
    ARPolicy, ARExecution, ARTriggerOn, ARActionType, ARExecutionStatus,
    ARTriggeredBy,
)
from routes.auth import get_current_user, require_analyst, require_admin
from models.user import User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/ar", tags=["active-response"])

# ── Private networks — never allow manual block ───────────────────────────────

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


# ── Agent authentication ──────────────────────────────────────────────────────

def verify_agent_token(x_agent_token: Optional[str] = Header(default=None)) -> None:
    """Validates X-Agent-Token when AGENT_SECRET is configured.

    If AGENT_SECRET is not set in settings the check is skipped so existing
    agents continue to work without modification.
    """
    secret = getattr(settings, "AGENT_SECRET", None)
    if not secret:
        return
    if x_agent_token != secret:
        raise HTTPException(status_code=401, detail="Invalid agent token")


# ── Serialisers ───────────────────────────────────────────────────────────────

def _policy_dict(p: ARPolicy) -> dict:
    return {
        "id":               p.id,
        "name":             p.name,
        "description":      p.description,
        "enabled":          p.enabled,
        "trigger_on":       p.trigger_on,
        "trigger_severity": p.trigger_severity,
        "trigger_rule":     p.trigger_rule,
        "trigger_category": p.trigger_category,
        "action":           p.action,
        "action_params":    p.action_params,
        "target_agent":     p.target_agent,
        "cooldown_seconds": p.cooldown_seconds,
        "max_per_hour":     p.max_per_hour,
        "created_at":       p.created_at,
        "updated_at":       p.updated_at,
    }


def _exec_dict(e: ARExecution) -> dict:
    return {
        "id":                  e.id,
        "policy_id":           e.policy_id,
        "alert_id":            e.alert_id,
        "agent_id":            e.agent_id,
        "action":              e.action,
        "action_params":       e.action_params,
        "status":              e.status,
        "result":              e.result,
        "src_ip":              e.src_ip,
        "policy_name":         e.policy_name,
        "triggered_by":        e.triggered_by,
        "retry_count":         e.retry_count,
        "parent_execution_id": e.parent_execution_id,
        "created_at":          e.created_at,
        "completed_at":        e.completed_at,
    }


# ── Schemas ───────────────────────────────────────────────────────────────────

class PolicyCreate(BaseModel):
    name:             str
    description:      Optional[str]  = None
    enabled:          bool           = True
    trigger_on:       ARTriggerOn    = ARTriggerOn.severity
    trigger_severity: Optional[str]  = "CRITICAL,HIGH"
    trigger_rule:     Optional[str]  = None
    trigger_category: Optional[str]  = None
    action:           ARActionType
    action_params:    Optional[dict] = None
    target_agent:     Optional[str]  = None
    cooldown_seconds: int            = 300
    max_per_hour:     Optional[int]  = None

    @field_validator("name")
    @classmethod
    def name_not_blank(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name must not be blank")
        if len(v) > 256:
            raise ValueError("name must be ≤ 256 characters")
        return v

    @field_validator("cooldown_seconds")
    @classmethod
    def cooldown_bounds(cls, v: int) -> int:
        if v < 0:
            raise ValueError("cooldown_seconds must be ≥ 0")
        if v > 86_400:
            raise ValueError("cooldown_seconds must be ≤ 86400 (24 h)")
        return v

    @field_validator("max_per_hour")
    @classmethod
    def max_per_hour_bounds(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and v < 1:
            raise ValueError("max_per_hour must be ≥ 1")
        return v

    @model_validator(mode="after")
    def trigger_field_required(self) -> "PolicyCreate":
        if self.trigger_on == ARTriggerOn.severity and not self.trigger_severity:
            raise ValueError("trigger_severity required when trigger_on=severity")
        if self.trigger_on == ARTriggerOn.rule_name and not self.trigger_rule:
            raise ValueError("trigger_rule required when trigger_on=rule_name")
        if self.trigger_on == ARTriggerOn.category and not self.trigger_category:
            raise ValueError("trigger_category required when trigger_on=category")
        return self


class PolicyUpdate(BaseModel):
    name:             Optional[str]           = None
    description:      Optional[str]           = None
    enabled:          Optional[bool]          = None
    trigger_on:       Optional[ARTriggerOn]   = None
    trigger_severity: Optional[str]           = None
    trigger_rule:     Optional[str]           = None
    trigger_category: Optional[str]           = None
    action:           Optional[ARActionType]  = None
    action_params:    Optional[dict]          = None
    target_agent:     Optional[str]           = None
    cooldown_seconds: Optional[int]           = None
    max_per_hour:     Optional[int]           = None


class ManualTriggerRequest(BaseModel):
    policy_id: int
    agent_id:  str
    src_ip:    Optional[str] = None
    alert_id:  Optional[int] = None

    @field_validator("src_ip")
    @classmethod
    def validate_src_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v!r}")
        return v


class ExecutionResultRequest(BaseModel):
    status: ARExecutionStatus
    result: Optional[str] = None


class BulkToggleRequest(BaseModel):
    policy_ids: List[int]
    enabled:    bool


# ── Policy CRUD ───────────────────────────────────────────────────────────────

@router.get("/policies")
async def list_policies(
    enabled: Optional[bool] = None,
    db:      AsyncSession   = Depends(get_db),
    _user:   User           = Depends(get_current_user),
):
    stmt = select(ARPolicy).order_by(ARPolicy.created_at.desc())
    if enabled is not None:
        stmt = stmt.where(ARPolicy.enabled == enabled)
    result = await db.execute(stmt)
    return [_policy_dict(p) for p in result.scalars().all()]


@router.post("/policies", status_code=201)
async def create_policy(
    body:  PolicyCreate,
    db:    AsyncSession = Depends(get_db),
    _user: User         = Depends(require_admin),
):
    existing = (await db.execute(
        select(ARPolicy).where(ARPolicy.name == body.name)
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(400, "Policy name already exists")

    policy = ARPolicy(**body.model_dump())
    db.add(policy)
    await db.flush()
    await db.refresh(policy)
    logger.info("AR policy created: id=%d name='%s' by user=%s", policy.id, policy.name, _user.username)
    return _policy_dict(policy)


@router.put("/policies/{policy_id}")
async def update_policy(
    policy_id: int,
    body:      PolicyUpdate,
    db:        AsyncSession = Depends(get_db),
    _user:     User         = Depends(require_admin),
):
    policy = (await db.execute(
        select(ARPolicy).where(ARPolicy.id == policy_id)
    )).scalar_one_or_none()
    if not policy:
        raise HTTPException(404, "Policy not found")

    updates = body.model_dump(exclude_none=True)

    # If the action type is changing, clear action_params unless explicitly provided
    if "action" in updates and updates["action"] != policy.action and "action_params" not in updates:
        updates["action_params"] = {}

    for field, value in updates.items():
        setattr(policy, field, value)
    policy.updated_at = datetime.now(timezone.utc)
    await db.flush()
    logger.info("AR policy updated: id=%d by user=%s", policy.id, _user.username)
    return _policy_dict(policy)


@router.delete("/policies/{policy_id}", status_code=204)
async def delete_policy(
    policy_id: int,
    db:        AsyncSession = Depends(get_db),
    _user:     User         = Depends(require_admin),
):
    policy = (await db.execute(
        select(ARPolicy).where(ARPolicy.id == policy_id)
    )).scalar_one_or_none()
    if not policy:
        raise HTTPException(404, "Policy not found")
    await db.delete(policy)
    logger.info("AR policy deleted: id=%d name='%s' by user=%s", policy_id, policy.name, _user.username)


@router.post("/policies/{policy_id}/clone", status_code=201)
async def clone_policy(
    policy_id: int,
    db:        AsyncSession = Depends(get_db),
    _user:     User         = Depends(require_admin),
):
    """Duplicate a policy with ' (copy)' appended to the name."""
    source = (await db.execute(
        select(ARPolicy).where(ARPolicy.id == policy_id)
    )).scalar_one_or_none()
    if not source:
        raise HTTPException(404, "Policy not found")

    # Find a unique name
    base_name  = f"{source.name} (copy)"
    clone_name = base_name
    suffix     = 1
    while (await db.execute(
        select(ARPolicy.id).where(ARPolicy.name == clone_name)
    )).scalar_one_or_none():
        suffix    += 1
        clone_name = f"{base_name} {suffix}"

    clone = ARPolicy(
        name             = clone_name,
        description      = source.description,
        enabled          = False,   # disabled by default to avoid accidental activation
        trigger_on       = source.trigger_on,
        trigger_severity = source.trigger_severity,
        trigger_rule     = source.trigger_rule,
        trigger_category = source.trigger_category,
        action           = source.action,
        action_params    = dict(source.action_params or {}),
        target_agent     = source.target_agent,
        cooldown_seconds = source.cooldown_seconds,
        max_per_hour     = source.max_per_hour,
    )
    db.add(clone)
    await db.flush()
    await db.refresh(clone)
    logger.info("AR policy cloned: source=%d clone=%d by user=%s", policy_id, clone.id, _user.username)
    return _policy_dict(clone)


@router.post("/policies/bulk-toggle")
async def bulk_toggle_policies(
    body:  BulkToggleRequest,
    db:    AsyncSession = Depends(get_db),
    _user: User         = Depends(require_admin),
):
    """Enable or disable multiple policies in a single call."""
    if not body.policy_ids:
        raise HTTPException(400, "policy_ids must not be empty")
    if len(body.policy_ids) > 100:
        raise HTTPException(400, "Cannot toggle more than 100 policies at once")

    await db.execute(
        update(ARPolicy)
        .where(ARPolicy.id.in_(body.policy_ids))
        .values(enabled=body.enabled, updated_at=datetime.now(timezone.utc))
    )
    logger.info(
        "AR bulk toggle: %d policies → enabled=%s by user=%s",
        len(body.policy_ids), body.enabled, _user.username,
    )
    return {"toggled": len(body.policy_ids), "enabled": body.enabled}


# ── Executions ────────────────────────────────────────────────────────────────

@router.get("/executions")
async def list_executions(
    agent_id:  Optional[str]           = None,
    policy_id: Optional[int]           = None,
    status:    Optional[str]           = None,
    action:    Optional[str]           = None,
    date_from: Optional[datetime]      = Query(default=None),
    date_to:   Optional[datetime]      = Query(default=None),
    page:      int                     = Query(default=1, ge=1),
    size:      int                     = Query(default=50, ge=1, le=200),
    db:        AsyncSession            = Depends(get_db),
    _user:     User                    = Depends(get_current_user),
):
    filters = []
    if agent_id:
        filters.append(ARExecution.agent_id == agent_id)
    if policy_id:
        filters.append(ARExecution.policy_id == policy_id)
    if status:
        filters.append(ARExecution.status == status)
    if action:
        filters.append(ARExecution.action == action)
    if date_from:
        df = date_from.replace(tzinfo=timezone.utc) if date_from.tzinfo is None else date_from
        filters.append(ARExecution.created_at >= df)
    if date_to:
        dt = date_to.replace(tzinfo=timezone.utc) if date_to.tzinfo is None else date_to
        filters.append(ARExecution.created_at <= dt)

    base = and_(*filters) if filters else True

    total = (await db.execute(
        select(func.count(ARExecution.id)).where(base)
    )).scalar_one()

    execs = (await db.execute(
        select(ARExecution)
        .where(base)
        .order_by(ARExecution.created_at.desc())
        .offset((page - 1) * size)
        .limit(size)
    )).scalars().all()

    return {
        "executions": [_exec_dict(e) for e in execs],
        "total":      total,
        "page":       page,
        "size":       size,
        "pages":      (total + size - 1) // size,
    }


@router.get("/executions/{execution_id}")
async def get_execution(
    execution_id: int,
    db:           AsyncSession = Depends(get_db),
    _user:        User         = Depends(get_current_user),
):
    ex = (await db.execute(
        select(ARExecution).where(ARExecution.id == execution_id)
    )).scalar_one_or_none()
    if not ex:
        raise HTTPException(404, "Execution not found")
    return _exec_dict(ex)


@router.delete("/executions/{execution_id}", status_code=204)
async def cancel_execution(
    execution_id: int,
    db:           AsyncSession = Depends(get_db),
    _user:        User         = Depends(require_analyst),
):
    """Cancel a pending execution before the agent picks it up."""
    ex = (await db.execute(
        select(ARExecution).where(ARExecution.id == execution_id)
    )).scalar_one_or_none()
    if not ex:
        raise HTTPException(404, "Execution not found")
    if ex.status != ARExecutionStatus.pending:
        raise HTTPException(
            400,
            f"Only pending executions can be cancelled (current: {ex.status})",
        )
    ex.status       = ARExecutionStatus.cancelled
    ex.completed_at = datetime.now(timezone.utc)
    ex.result       = f"Cancelled by {_user.username}"
    await db.flush()
    logger.info("AR execution cancelled: id=%d by user=%s", execution_id, _user.username)


@router.post("/executions/{execution_id}/retry")
async def retry_execution(
    execution_id: int,
    db:           AsyncSession = Depends(get_db),
    _user:        User         = Depends(require_analyst),
):
    """Re-queue a failed or timed-out execution."""
    ex = (await db.execute(
        select(ARExecution).where(ARExecution.id == execution_id)
    )).scalar_one_or_none()
    if not ex:
        raise HTTPException(404, "Execution not found")
    if ex.status not in (ARExecutionStatus.failed, ARExecutionStatus.timeout):
        raise HTTPException(
            400,
            f"Can only retry failed or timeout executions (current: {ex.status})",
        )

    new_ex = ARExecution(
        policy_id           = ex.policy_id,
        alert_id            = ex.alert_id,
        agent_id            = ex.agent_id,
        action              = ex.action,
        action_params       = ex.action_params,
        status              = ARExecutionStatus.pending,
        src_ip              = ex.src_ip,
        policy_name         = ex.policy_name,
        triggered_by        = ARTriggeredBy.manual,
        retry_count         = (ex.retry_count or 0) + 1,
        parent_execution_id = ex.id,
    )
    db.add(new_ex)
    await db.flush()
    await db.refresh(new_ex)
    logger.info(
        "AR execution retried: original=%d new=%d retry_count=%d by user=%s",
        execution_id, new_ex.id, new_ex.retry_count, _user.username,
    )
    return _exec_dict(new_ex)


# ── Manual trigger ────────────────────────────────────────────────────────────

@router.post("/trigger")
async def manual_trigger(
    body:  ManualTriggerRequest,
    db:    AsyncSession = Depends(get_db),
    _user: User         = Depends(require_analyst),
):
    """Queue a policy action against a specific agent, bypassing auto-trigger conditions."""
    policy = (await db.execute(
        select(ARPolicy).where(ARPolicy.id == body.policy_id)
    )).scalar_one_or_none()
    if not policy:
        raise HTTPException(404, "Policy not found")

    # Refuse to manually block private IPs
    if policy.action == ARActionType.block_ip and body.src_ip:
        if _is_private(body.src_ip):
            raise HTTPException(400, "Cannot block a private/internal IP address")

    params = dict(policy.action_params or {})
    if body.src_ip:
        params["src_ip"] = body.src_ip

    execution = ARExecution(
        policy_id    = policy.id,
        alert_id     = body.alert_id,
        agent_id     = body.agent_id,
        action       = policy.action,
        action_params= params,
        status       = ARExecutionStatus.pending,
        src_ip       = body.src_ip or body.agent_id,
        policy_name  = policy.name,
        triggered_by = ARTriggeredBy.manual,
        retry_count  = 0,
    )
    db.add(execution)
    await db.flush()
    await db.refresh(execution)
    logger.info(
        "AR manual trigger: policy='%s' action=%s agent=%s src_ip=%s exec_id=%d by user=%s",
        policy.name, policy.action, body.agent_id, body.src_ip, execution.id, _user.username,
    )
    return _exec_dict(execution)


# ── Agent-facing endpoints ────────────────────────────────────────────────────

@router.get("/pending/{agent_id}")
async def get_pending_actions(
    agent_id:    str,
    db:          AsyncSession = Depends(get_db),
    _token_check: None       = Depends(verify_agent_token),
):
    """Called by agents to pull their pending AR actions (transitions them to 'sent')."""
    stmt = (
        select(ARExecution)
        .where(
            and_(
                ARExecution.agent_id == agent_id,
                ARExecution.status   == ARExecutionStatus.pending,
            )
        )
        .order_by(ARExecution.created_at.asc())
        .limit(20)
    )
    execs = (await db.execute(stmt)).scalars().all()

    if execs:
        now = datetime.now(timezone.utc)
        for e in execs:
            e.status     = ARExecutionStatus.sent
            e.completed_at = None   # reset in case of requeue
        await db.flush()
        logger.debug("AR pending dispatch: agent=%s count=%d", agent_id, len(execs))

    return [_exec_dict(e) for e in execs]


@router.post("/complete/{execution_id}")
async def complete_execution(
    execution_id:  int,
    body:          ExecutionResultRequest,
    db:            AsyncSession = Depends(get_db),
    _token_check:  None        = Depends(verify_agent_token),
):
    """Called by the agent to report execution result."""
    execution = (await db.execute(
        select(ARExecution).where(ARExecution.id == execution_id)
    )).scalar_one_or_none()
    if not execution:
        raise HTTPException(404, "Execution not found")

    # Ignore stale reports for already-completed executions
    if execution.status in (ARExecutionStatus.success, ARExecutionStatus.cancelled):
        return _exec_dict(execution)

    execution.status       = body.status
    execution.result       = (body.result or "")[:2000]
    execution.completed_at = datetime.now(timezone.utc)
    await db.flush()

    level = logging.INFO if body.status == ARExecutionStatus.success else logging.WARNING
    logger.log(
        level,
        "AR complete: exec_id=%d status=%s result=%.120s",
        execution_id, body.status, execution.result,
    )
    return _exec_dict(execution)


# ── Stats ─────────────────────────────────────────────────────────────────────

@router.get("/stats")
async def get_ar_stats(
    db:    AsyncSession = Depends(get_db),
    _user: User         = Depends(get_current_user),
):
    now            = datetime.now(timezone.utc)
    today_cutoff   = now - timedelta(hours=24)
    week_cutoff    = now - timedelta(days=7)

    total_policies   = (await db.execute(select(func.count(ARPolicy.id)))).scalar_one()
    enabled_policies = (await db.execute(
        select(func.count(ARPolicy.id)).where(ARPolicy.enabled == True)  # noqa: E712
    )).scalar_one()
    total_executions = (await db.execute(select(func.count(ARExecution.id)))).scalar_one()
    executions_today = (await db.execute(
        select(func.count(ARExecution.id)).where(ARExecution.created_at >= today_cutoff)
    )).scalar_one()

    status_rows = (await db.execute(
        select(ARExecution.status, func.count(ARExecution.id))
        .group_by(ARExecution.status)
    )).all()
    by_status = {(row[0].value if hasattr(row[0], 'value') else str(row[0]).split('.')[-1]): row[1] for row in status_rows}

    action_rows = (await db.execute(
        select(ARExecution.action, func.count(ARExecution.id))
        .group_by(ARExecution.action)
    )).all()
    by_action = {(row[0].value if hasattr(row[0], 'value') else str(row[0]).split('.')[-1]): row[1] for row in action_rows}

    top_rows = (await db.execute(
        select(ARExecution.policy_name, func.count(ARExecution.id).label("cnt"))
        .where(ARExecution.created_at >= week_cutoff)
        .group_by(ARExecution.policy_name)
        .order_by(func.count(ARExecution.id).desc())
        .limit(5)
    )).all()
    top_policies = [{"name": row[0] or "Unknown", "count": row[1]} for row in top_rows]

    success_count = by_status.get("success", 0)
    fail_count    = by_status.get("failed", 0) + by_status.get("timeout", 0)
    total_done    = success_count + fail_count
    success_rate  = round(success_count / total_done * 100) if total_done else 0

    # Executions per day for the past 7 days
    daily_rows = (await db.execute(
        select(
            func.date_trunc(text("'day'"), ARExecution.created_at).label("day"),
            func.count(ARExecution.id).label("cnt"),
        )
        .where(ARExecution.created_at >= week_cutoff)
        .group_by(func.date_trunc(text("'day'"), ARExecution.created_at))
        .order_by(func.date_trunc(text("'day'"), ARExecution.created_at))
    )).all()
    daily_trend = [{"day": str(row[0])[:10], "count": row[1]} for row in daily_rows]

    return {
        "total_policies":    total_policies,
        "enabled_policies":  enabled_policies,
        "total_executions":  total_executions,
        "executions_today":  executions_today,
        "success_rate":      success_rate,
        "by_status":         by_status,
        "by_action":         by_action,
        "top_policies":      top_policies,
        "daily_trend":       daily_trend,
    }


# ── Templates ─────────────────────────────────────────────────────────────────

AR_TEMPLATES = [
    {
        "id":          "block_ssh_brute",
        "name":        "Block SSH Brute Force",
        "description": "Automatically block IPs that trigger SSH brute force detection",
        "icon":        "🚫",
        "category":    "Network Defense",
        "policy": {
            "name":             "Block SSH Brute Force",
            "description":      "Block source IP when SSH brute force rule fires",
            "trigger_on":       "rule_name",
            "trigger_rule":     "Brute Force SSH Attack",
            "action":           "block_ip",
            "action_params":    {"unblock_after": 3600},
            "cooldown_seconds": 600,
        },
    },
    {
        "id":          "block_web_attacker",
        "name":        "Block Web Application Attacker",
        "description": "Block IPs performing SQL injection or path traversal attacks",
        "icon":        "🌐",
        "category":    "Network Defense",
        "policy": {
            "name":             "Block Web Application Attacker",
            "description":      "Block IP on web attack detection",
            "trigger_on":       "rule_name",
            "trigger_rule":     "Web Application Attack",
            "action":           "block_ip",
            "action_params":    {"unblock_after": 7200},
            "cooldown_seconds": 1800,
        },
    },
    {
        "id":          "block_port_scanner",
        "name":        "Block Port Scanner",
        "description": "Block IPs that trigger port scan detection",
        "icon":        "🔍",
        "category":    "Network Defense",
        "policy": {
            "name":             "Block Port Scanner",
            "description":      "Block IP on port scan detection",
            "trigger_on":       "rule_name",
            "trigger_rule":     "Port Scan Detected",
            "action":           "block_ip",
            "action_params":    {"unblock_after": 86400},
            "cooldown_seconds": 3600,
        },
    },
    {
        "id":          "email_critical",
        "name":        "Email Alert — CRITICAL Severity",
        "description": "Send email notification for all CRITICAL severity alerts",
        "icon":        "📧",
        "category":    "Notification",
        "policy": {
            "name":             "Email — CRITICAL Alerts",
            "description":      "Email SOC team on CRITICAL alerts",
            "trigger_on":       "severity",
            "trigger_severity": "CRITICAL",
            "action":           "email_alert",
            "action_params":    {"recipients": "soc@company.com"},
            "cooldown_seconds": 300,
        },
    },
    {
        "id":          "email_high",
        "name":        "Email Alert — HIGH & CRITICAL",
        "description": "Email notification for HIGH and CRITICAL severity alerts",
        "icon":        "📬",
        "category":    "Notification",
        "policy": {
            "name":             "Email — HIGH/CRITICAL Alerts",
            "description":      "Email on HIGH or CRITICAL severity",
            "trigger_on":       "severity",
            "trigger_severity": "CRITICAL,HIGH",
            "action":           "email_alert",
            "action_params":    {"recipients": "soc@company.com"},
            "cooldown_seconds": 600,
        },
    },
    {
        "id":          "slack_critical",
        "name":        "Slack Alert — CRITICAL Severity",
        "description": "Post to Slack channel when CRITICAL alerts fire",
        "icon":        "💬",
        "category":    "Notification",
        "policy": {
            "name":             "Slack — CRITICAL Alerts",
            "description":      "Post to Slack on CRITICAL alerts",
            "trigger_on":       "severity",
            "trigger_severity": "CRITICAL",
            "action":           "slack_alert",
            "action_params":    {},
            "cooldown_seconds": 300,
        },
    },
    {
        "id":          "disable_user_priv_esc",
        "name":        "Disable User — Privilege Escalation",
        "description": "Lock the user account when privilege escalation is detected",
        "icon":        "🔒",
        "category":    "Account Response",
        "policy": {
            "name":             "Disable User — Privilege Escalation",
            "description":      "Lock user account on privilege escalation alert",
            "trigger_on":       "category",
            "trigger_category": "privilege_escalation",
            "action":           "disable_user",
            "action_params":    {"trigger_min_level": 12},
            "cooldown_seconds": 1800,
        },
    },
    {
        "id":          "kill_suspicious_process",
        "name":        "Kill Suspicious Process",
        "description": "Terminate processes flagged as suspicious (reverse shell, attack tools)",
        "icon":        "💀",
        "category":    "Process Response",
        "policy": {
            "name":             "Kill Suspicious Process",
            "description":      "Kill process matching suspicious execution pattern",
            "trigger_on":       "rule_name",
            "trigger_rule":     "Suspicious Process Execution",
            "action":           "kill_process",
            "action_params":    {},
            "cooldown_seconds": 300,
        },
    },
    {
        "id":          "block_rootkit",
        "name":        "Block & Alert — Rootkit Detected",
        "description": "Immediate email alert when rootkit indicators are found",
        "icon":        "☠️",
        "category":    "Malware Response",
        "policy": {
            "name":             "Alert — Rootkit Detected",
            "description":      "Email SOC immediately on rootkit detection",
            "trigger_on":       "category",
            "trigger_category": "rootcheck",
            "action":           "email_alert",
            "action_params":    {"recipients": "security@company.com", "trigger_min_level": 13},
            "cooldown_seconds": 3600,
        },
    },
    {
        "id":          "block_password_spray",
        "name":        "Block Password Spray Attack",
        "description": "Block IPs performing password spray attacks",
        "icon":        "🔐",
        "category":    "Network Defense",
        "policy": {
            "name":             "Block Password Spray",
            "description":      "Block IP performing password spray",
            "trigger_on":       "rule_name",
            "trigger_rule":     "Password Spray Attack",
            "action":           "block_ip",
            "action_params":    {"unblock_after": 7200},
            "cooldown_seconds": 900,
        },
    },
]


@router.get("/templates")
async def get_templates(
    _user: User = Depends(get_current_user),
):
    return AR_TEMPLATES
