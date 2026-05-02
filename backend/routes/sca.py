from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.sca_result import SCAScan
from routes.auth import get_current_user
from models.user import User

router = APIRouter(prefix="/api/sca", tags=["sca"])


class SCACheckItem(BaseModel):
    id:        str
    title:     str
    result:    str           # "pass" | "fail" | "skip"
    severity:  str = "MEDIUM"
    rationale: Optional[str] = None
    remediation: Optional[str] = None


class SCAScanRequest(BaseModel):
    agent_id: str
    hostname: Optional[str] = None
    checks:   List[SCACheckItem]


def _scan_dict(s: SCAScan) -> dict:
    return {
        "id":         s.id,
        "agent_id":   s.agent_id,
        "hostname":   s.hostname,
        "checks":     s.checks,
        "passed":     s.passed,
        "failed":     s.failed,
        "skipped":    s.skipped,
        "score_pct":  s.score_pct,
        "scanned_at": s.scanned_at,
    }


@router.post("/submit", status_code=201)
async def submit_sca(
    body: SCAScanRequest,
    db: AsyncSession = Depends(get_db),
):
    checks = [c.model_dump() for c in body.checks]
    passed  = sum(1 for c in checks if c["result"] == "pass")
    failed  = sum(1 for c in checks if c["result"] == "fail")
    skipped = sum(1 for c in checks if c["result"] == "skip")
    total   = passed + failed
    score   = int(passed / total * 100) if total > 0 else 0

    scan = SCAScan(
        agent_id  = body.agent_id,
        hostname  = body.hostname,
        checks    = checks,
        passed    = passed,
        failed    = failed,
        skipped   = skipped,
        score_pct = score,
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)
    return _scan_dict(scan)


@router.get("")
async def list_scans(
    agent_id: Optional[str] = None,
    page:     int = 1,
    size:     int = 20,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if size > 100:
        size = 100

    stmt = select(SCAScan)
    if agent_id:
        stmt = stmt.where(SCAScan.agent_id == agent_id)
    stmt = stmt.order_by(SCAScan.scanned_at.desc()).offset((page - 1) * size).limit(size)

    scans = (await db.execute(stmt)).scalars().all()

    total_stmt = select(func.count(SCAScan.id))
    if agent_id:
        total_stmt = total_stmt.where(SCAScan.agent_id == agent_id)
    total = (await db.execute(total_stmt)).scalar_one()

    return {"scans": [_scan_dict(s) for s in scans], "total": total, "page": page, "size": size}


@router.get("/latest")
async def latest_scans(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Latest scan per agent."""
    # Get max scanned_at per agent
    subq = (
        select(SCAScan.agent_id, func.max(SCAScan.scanned_at).label("max_ts"))
        .group_by(SCAScan.agent_id)
        .subquery()
    )
    stmt = (
        select(SCAScan)
        .join(subq, (SCAScan.agent_id == subq.c.agent_id) & (SCAScan.scanned_at == subq.c.max_ts))
        .order_by(SCAScan.score_pct.asc())
    )
    scans = (await db.execute(stmt)).scalars().all()
    return [_scan_dict(s) for s in scans]


@router.get("/summary")
async def sca_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    total_scans   = (await db.execute(select(func.count(SCAScan.id)))).scalar_one()
    avg_score     = (await db.execute(select(func.avg(SCAScan.score_pct)))).scalar_one()
    critical_agents = (await db.execute(
        select(func.count(SCAScan.id)).where(SCAScan.score_pct < 50)
    )).scalar_one()
    return {
        "total_scans":      total_scans,
        "avg_score_pct":    round(float(avg_score or 0), 1),
        "critical_agents":  critical_agents,
    }
