import uuid
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_db
from models.agent import Agent, AgentStatus
from routes.auth import get_current_user
from models.user import User
from config import settings

router = APIRouter(prefix="/api/agents", tags=["agents"])


def verify_agent_secret(x_agent_token: Optional[str] = Header(None)):
    if settings.AGENT_SECRET and x_agent_token != settings.AGENT_SECRET:
        raise HTTPException(status_code=401, detail="Invalid agent secret")


class AgentRegisterRequest(BaseModel):
    hostname: str
    ip_address: str
    os: Optional[str] = None
    os_version: Optional[str] = None
    agent_version: Optional[str] = "1.0.0"
    agent_name: Optional[str] = None


class HeartbeatRequest(BaseModel):
    agent_id:      Optional[str]   = None
    agent_version: Optional[str]   = None
    agent_cpu_pct: Optional[float] = None
    agent_mem_mb:  Optional[float] = None
    buffer_batches: Optional[int]  = None
    buffer_logs:    Optional[int]  = None
    server_up:      Optional[bool] = None


@router.post("/register")
async def register_agent(request: AgentRegisterRequest, db: AsyncSession = Depends(get_db), _: None = Depends(verify_agent_secret)):
    stmt = select(Agent).where(Agent.hostname == request.hostname, Agent.ip_address == request.ip_address)
    result = await db.execute(stmt)
    existing = result.scalar_one_or_none()

    if existing:
        existing.os = request.os or existing.os
        existing.os_version = request.os_version or existing.os_version
        existing.agent_version = request.agent_version or existing.agent_version
        existing.last_seen = datetime.utcnow()
        existing.status = AgentStatus.online
        existing.is_active = True
        await db.flush()
        return {
            "agent_id": existing.agent_id,
            "message": "Agent re-registered",
            "id": existing.id,
        }

    agent_id = str(uuid.uuid4())
    agent = Agent(
        agent_id=agent_id,
        hostname=request.hostname,
        ip_address=request.ip_address,
        os=request.os,
        os_version=request.os_version,
        agent_version=request.agent_version,
        status=AgentStatus.online,
        last_seen=datetime.utcnow(),
    )
    db.add(agent)
    await db.flush()
    await db.refresh(agent)
    return {
        "agent_id": agent.agent_id,
        "message": "Agent registered successfully",
        "id": agent.id,
    }


@router.get("")
async def list_agents(
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(Agent).where(Agent.is_active == True)
    if status:
        stmt = stmt.where(Agent.status == status)
    stmt = stmt.order_by(Agent.registered_at.desc())
    result = await db.execute(stmt)
    agents = result.scalars().all()
    return [_agent_to_dict(a) for a in agents]


@router.get("/{agent_id}")
async def get_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(Agent).where(Agent.agent_id == agent_id, Agent.is_active == True)
    result = await db.execute(stmt)
    agent = result.scalar_one_or_none()
    if not agent:
        stmt2 = select(Agent).where(Agent.id == int(agent_id) if agent_id.isdigit() else -1)
        result2 = await db.execute(stmt2)
        agent = result2.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return _agent_to_dict(agent)


@router.delete("/{agent_id}")
async def delete_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(Agent).where(Agent.agent_id == agent_id)
    result = await db.execute(stmt)
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent.is_active = False
    await db.flush()
    return {"message": "Agent deleted"}


@router.post("/{agent_id}/heartbeat")
async def agent_heartbeat(
    agent_id: str,
    body: Optional[HeartbeatRequest] = None,
    db: AsyncSession = Depends(get_db),
):
    from models.active_response import ARExecution, ARExecutionStatus
    from sqlalchemy import and_

    stmt = select(Agent).where(Agent.agent_id == agent_id)
    result = await db.execute(stmt)
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent.last_seen = datetime.utcnow()
    agent.status    = AgentStatus.online

    # Store agent self-health metrics from heartbeat payload
    if body:
        if body.agent_version  is not None: agent.agent_version  = body.agent_version
        if body.agent_cpu_pct  is not None: agent.agent_cpu_pct  = body.agent_cpu_pct
        if body.agent_mem_mb   is not None: agent.agent_mem_mb   = body.agent_mem_mb
        if body.buffer_batches is not None: agent.buffer_batches = body.buffer_batches
        if body.buffer_logs    is not None: agent.buffer_logs    = body.buffer_logs

    await db.flush()

    # Return pending AR actions so the agent can execute them
    ar_stmt = select(ARExecution).where(
        and_(
            ARExecution.agent_id == agent_id,
            ARExecution.status   == ARExecutionStatus.pending,
        )
    ).order_by(ARExecution.created_at.asc()).limit(10)
    pending = (await db.execute(ar_stmt)).scalars().all()
    for ex in pending:
        ex.status = ARExecutionStatus.sent
    if pending:
        await db.flush()

    return {
        "message":   "Heartbeat received",
        "timestamp": agent.last_seen,
        "ar_actions": [
            {
                "id":     ex.id,
                "action": ex.action,
                "params": ex.action_params or {},
            }
            for ex in pending
        ],
    }


def _agent_to_dict(agent: Agent) -> dict:
    return {
        "id":             agent.id,
        "agent_id":       agent.agent_id,
        "hostname":       agent.hostname,
        "ip_address":     agent.ip_address,
        "os":             agent.os,
        "os_version":     agent.os_version,
        "agent_version":  agent.agent_version,
        "status":         agent.status,
        "last_seen":      agent.last_seen,
        "registered_at":  agent.registered_at,
        "is_active":      agent.is_active,
        # Self-health metrics
        "agent_cpu_pct":  agent.agent_cpu_pct,
        "agent_mem_mb":   agent.agent_mem_mb,
        "buffer_batches": agent.buffer_batches,
        "buffer_logs":    agent.buffer_logs,
    }
