from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, and_, func
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.active_response import (
    ARPolicy, ARExecution, ARTriggerOn, ARActionType, ARExecutionStatus,
)
from routes.auth import get_current_user, require_analyst, require_admin
from models.user import User

router = APIRouter(prefix="/api/ar", tags=["active-response"])


# ── Schemas ──────────────────────────────────────────────────────────────────

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


class PolicyUpdate(BaseModel):
    name:             Optional[str]        = None
    description:      Optional[str]        = None
    enabled:          Optional[bool]       = None
    trigger_on:       Optional[ARTriggerOn]= None
    trigger_severity: Optional[str]        = None
    trigger_rule:     Optional[str]        = None
    trigger_category: Optional[str]        = None
    action:           Optional[ARActionType]= None
    action_params:    Optional[dict]        = None
    target_agent:     Optional[str]        = None
    cooldown_seconds: Optional[int]        = None


class ManualTriggerRequest(BaseModel):
    policy_id:  int
    agent_id:   str
    src_ip:     Optional[str] = None
    alert_id:   Optional[int] = None


class ExecutionResultRequest(BaseModel):
    status:  ARExecutionStatus
    result:  Optional[str] = None


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
        "created_at":       p.created_at,
        "updated_at":       p.updated_at,
    }


def _exec_dict(e: ARExecution) -> dict:
    return {
        "id":           e.id,
        "policy_id":    e.policy_id,
        "alert_id":     e.alert_id,
        "agent_id":     e.agent_id,
        "action":       e.action,
        "action_params":e.action_params,
        "status":       e.status,
        "result":       e.result,
        "src_ip":       e.src_ip,
        "policy_name":  e.policy_name,
        "created_at":   e.created_at,
        "completed_at": e.completed_at,
    }


# ── Policy CRUD ───────────────────────────────────────────────────────────────

@router.get("/policies")
async def list_policies(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(ARPolicy).order_by(ARPolicy.created_at.desc()))
    return [_policy_dict(p) for p in result.scalars().all()]


@router.post("/policies", status_code=201)
async def create_policy(
    body: PolicyCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
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
    return _policy_dict(policy)


@router.put("/policies/{policy_id}")
async def update_policy(
    policy_id: int,
    body: PolicyUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    policy = (await db.execute(
        select(ARPolicy).where(ARPolicy.id == policy_id)
    )).scalar_one_or_none()
    if not policy:
        raise HTTPException(404, "Policy not found")

    for field, value in body.model_dump(exclude_none=True).items():
        setattr(policy, field, value)
    policy.updated_at = datetime.utcnow()
    await db.flush()
    return _policy_dict(policy)


@router.delete("/policies/{policy_id}", status_code=204)
async def delete_policy(
    policy_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    policy = (await db.execute(
        select(ARPolicy).where(ARPolicy.id == policy_id)
    )).scalar_one_or_none()
    if not policy:
        raise HTTPException(404, "Policy not found")
    await db.delete(policy)


# ── Executions ────────────────────────────────────────────────────────────────

@router.get("/executions")
async def list_executions(
    agent_id:  Optional[str] = None,
    policy_id: Optional[int] = None,
    status:    Optional[str] = None,
    page:      int = 1,
    size:      int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if size > 200:
        size = 200

    filters = []
    if agent_id:
        filters.append(ARExecution.agent_id == agent_id)
    if policy_id:
        filters.append(ARExecution.policy_id == policy_id)
    if status:
        filters.append(ARExecution.status == status)

    count_q = select(func.count(ARExecution.id))
    if filters:
        count_q = count_q.where(and_(*filters))
    total = (await db.execute(count_q)).scalar_one()

    stmt = select(ARExecution)
    if filters:
        stmt = stmt.where(and_(*filters))
    stmt = stmt.order_by(ARExecution.created_at.desc()).offset((page - 1) * size).limit(size)
    executions = (await db.execute(stmt)).scalars().all()

    return {
        "executions": [_exec_dict(e) for e in executions],
        "total": total,
        "page":  page,
        "size":  size,
    }


@router.post("/trigger")
async def manual_trigger(
    body: ManualTriggerRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    policy = (await db.execute(
        select(ARPolicy).where(ARPolicy.id == body.policy_id)
    )).scalar_one_or_none()
    if not policy:
        raise HTTPException(404, "Policy not found")

    execution = ARExecution(
        policy_id    = policy.id,
        alert_id     = body.alert_id,
        agent_id     = body.agent_id,
        action       = policy.action,
        action_params= dict(policy.action_params or {}),
        status       = ARExecutionStatus.pending,
        src_ip       = body.src_ip,
        policy_name  = policy.name,
    )
    if body.src_ip:
        execution.action_params["src_ip"] = body.src_ip

    db.add(execution)
    await db.flush()
    await db.refresh(execution)
    return _exec_dict(execution)


# ── Agent-facing endpoints ────────────────────────────────────────────────────

@router.get("/pending/{agent_id}")
async def get_pending_actions(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Called by agents to pull their pending AR actions."""
    stmt = select(ARExecution).where(
        and_(
            ARExecution.agent_id == agent_id,
            ARExecution.status   == ARExecutionStatus.pending,
        )
    ).order_by(ARExecution.created_at.asc()).limit(20)
    executions = (await db.execute(stmt)).scalars().all()

    # Mark as sent so they won't be returned twice
    for e in executions:
        e.status = ARExecutionStatus.sent
    if executions:
        await db.flush()

    return [_exec_dict(e) for e in executions]


@router.post("/complete/{execution_id}")
async def complete_execution(
    execution_id: int,
    body: ExecutionResultRequest,
    db: AsyncSession = Depends(get_db),
):
    """Called by agent to report execution result."""
    execution = (await db.execute(
        select(ARExecution).where(ARExecution.id == execution_id)
    )).scalar_one_or_none()
    if not execution:
        raise HTTPException(404, "Execution not found")

    execution.status       = body.status
    execution.result       = body.result
    execution.completed_at = datetime.utcnow()
    await db.flush()
    return _exec_dict(execution)
