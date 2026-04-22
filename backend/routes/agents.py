import uuid
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_db
from models.agent import Agent, AgentStatus
from routes.auth import get_current_user
from models.user import User

router = APIRouter(prefix="/api/agents", tags=["agents"])


class AgentRegisterRequest(BaseModel):
    hostname: str
    ip_address: str
    os: Optional[str] = None
    os_version: Optional[str] = None
    agent_version: Optional[str] = "1.0.0"
    agent_name: Optional[str] = None


class HeartbeatRequest(BaseModel):
    agent_id: str


@router.post("/register")
async def register_agent(request: AgentRegisterRequest, db: AsyncSession = Depends(get_db)):
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
async def agent_heartbeat(agent_id: str, db: AsyncSession = Depends(get_db)):
    from models.active_response import ARExecution, ARExecutionStatus
    from sqlalchemy import and_

    stmt = select(Agent).where(Agent.agent_id == agent_id)
    result = await db.execute(stmt)
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent.last_seen = datetime.utcnow()
    agent.status    = AgentStatus.online
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
        "id": agent.id,
        "agent_id": agent.agent_id,
        "hostname": agent.hostname,
        "ip_address": agent.ip_address,
        "os": agent.os,
        "os_version": agent.os_version,
        "agent_version": agent.agent_version,
        "status": agent.status,
        "last_seen": agent.last_seen,
        "registered_at": agent.registered_at,
        "is_active": agent.is_active,
    }
