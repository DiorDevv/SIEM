from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, and_, func, delete
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_db
from models.alert import Alert, AlertStatus, AlertSeverity
from routes.auth import get_current_user, require_analyst
from models.user import User
from services.audit_service import audit

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


def _alert_to_dict(a: Alert) -> dict:
    return {
        "id": a.id,
        "rule_id": a.rule_id,
        "agent_id": a.agent_id,
        "severity": a.severity,
        "title": a.title,
        "description": a.description,
        "log_id": a.log_id,
        "status": a.status,
        "agent_hostname": a.agent_hostname,
        "rule_name": a.rule_name,
        "created_at": a.created_at,
        "updated_at": a.updated_at,
        "acknowledged_at": a.acknowledged_at,
        "resolved_at": a.resolved_at,
    }


@router.get("")
async def list_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    agent_id: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    keyword: Optional[str] = None,
    page: int = 1,
    size: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if size > 200:
        size = 200

    filters = []
    if severity:
        filters.append(Alert.severity == severity.upper())
    if status:
        filters.append(Alert.status == status.lower())
    if agent_id:
        filters.append(Alert.agent_id == agent_id)
    if start_time:
        filters.append(Alert.created_at >= start_time)
    if end_time:
        filters.append(Alert.created_at <= end_time)
    if keyword:
        filters.append(Alert.title.ilike(f"%{keyword}%"))

    count_stmt = select(func.count(Alert.id))
    if filters:
        count_stmt = count_stmt.where(and_(*filters))
    count_result = await db.execute(count_stmt)
    total = count_result.scalar_one()

    stmt = select(Alert)
    if filters:
        stmt = stmt.where(and_(*filters))
    stmt = stmt.order_by(Alert.created_at.desc())
    stmt = stmt.offset((page - 1) * size).limit(size)
    result = await db.execute(stmt)
    alerts = result.scalars().all()

    return {
        "alerts": [_alert_to_dict(a) for a in alerts],
        "total": total,
        "page": page,
        "size": size,
    }


@router.get("/{alert_id}")
async def get_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    stmt = select(Alert).where(Alert.id == alert_id)
    result = await db.execute(stmt)
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _alert_to_dict(alert)


@router.put("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    stmt = select(Alert).where(Alert.id == alert_id)
    result = await db.execute(stmt)
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = AlertStatus.acknowledged
    alert.acknowledged_at = datetime.utcnow()
    alert.updated_at = datetime.utcnow()
    await db.flush()
    await audit(db, current_user, "acknowledge_alert", "alert", alert.id, alert.title)
    return _alert_to_dict(alert)


@router.put("/{alert_id}/resolve")
async def resolve_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    stmt = select(Alert).where(Alert.id == alert_id)
    result = await db.execute(stmt)
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = AlertStatus.resolved
    alert.resolved_at = datetime.utcnow()
    alert.updated_at = datetime.utcnow()
    await db.flush()
    await audit(db, current_user, "resolve_alert", "alert", alert.id, alert.title)
    return _alert_to_dict(alert)


@router.delete("/{alert_id}")
async def delete_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    stmt = select(Alert).where(Alert.id == alert_id)
    result = await db.execute(stmt)
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    await audit(db, current_user, "delete_alert", "alert", alert.id, alert.title)
    await db.delete(alert)
    await db.flush()
    return {"message": "Alert deleted"}


class BulkAcknowledgeRequest(BaseModel):
    alert_ids: List[int]


@router.post("/bulk-acknowledge")
async def bulk_acknowledge(
    request: BulkAcknowledgeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    now = datetime.utcnow()
    stmt = select(Alert).where(Alert.id.in_(request.alert_ids))
    result = await db.execute(stmt)
    alerts = result.scalars().all()
    for alert in alerts:
        alert.status = AlertStatus.acknowledged
        alert.acknowledged_at = now
        alert.updated_at = now
    await db.flush()
    return {"message": f"Acknowledged {len(alerts)} alerts"}
