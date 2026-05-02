"""
Audit log API — read-only, admin only.
"""
import json
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
import csv, io
from sqlalchemy import select, and_, func
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.audit_log import AuditLog
from routes.auth import require_admin
from models.user import User

router = APIRouter(prefix="/api/audit", tags=["audit"])


def _log_dict(e: AuditLog) -> dict:
    return {
        "id":            e.id,
        "timestamp":     e.timestamp,
        "username":      e.username,
        "action":        e.action,
        "resource_type": e.resource_type,
        "resource_id":   e.resource_id,
        "resource_name": e.resource_name,
        "details":       json.loads(e.details) if e.details else None,
        "ip_address":    e.ip_address,
        "status":        e.status,
    }


@router.get("")
async def list_audit_logs(
    username:      Optional[str] = None,
    action:        Optional[str] = None,
    resource_type: Optional[str] = None,
    status:        Optional[str] = None,
    days:          int           = Query(7, ge=1, le=90),
    page:          int           = Query(1, ge=1),
    size:          int           = Query(50, ge=1, le=200),
    db: AsyncSession             = Depends(get_db),
    _admin: User                 = Depends(require_admin),
):
    since = datetime.utcnow() - timedelta(days=days)
    filters = [AuditLog.timestamp >= since]

    if username:      filters.append(AuditLog.username.ilike(f"%{username}%"))
    if action:        filters.append(AuditLog.action == action)
    if resource_type: filters.append(AuditLog.resource_type == resource_type)
    if status:        filters.append(AuditLog.status == status)

    total = (await db.execute(
        select(func.count(AuditLog.id)).where(and_(*filters))
    )).scalar_one()

    rows = (await db.execute(
        select(AuditLog)
        .where(and_(*filters))
        .order_by(AuditLog.timestamp.desc())
        .offset((page - 1) * size)
        .limit(size)
    )).scalars().all()

    return {"logs": [_log_dict(r) for r in rows], "total": total, "page": page, "size": size}


@router.get("/stats")
async def audit_stats(
    days: int        = Query(7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
    _admin: User     = Depends(require_admin),
):
    """Summary stats: top users, top actions, events per hour, success/fail counts."""
    since = datetime.utcnow() - timedelta(days=days)

    total = (await db.execute(
        select(func.count(AuditLog.id)).where(AuditLog.timestamp >= since)
    )).scalar_one() or 0

    failed = (await db.execute(
        select(func.count(AuditLog.id)).where(
            and_(AuditLog.timestamp >= since, AuditLog.status == "failed")
        )
    )).scalar_one() or 0

    unique_users = (await db.execute(
        select(func.count(func.distinct(AuditLog.username))).where(AuditLog.timestamp >= since)
    )).scalar_one() or 0

    # Top users
    top_users_rows = (await db.execute(
        select(AuditLog.username, func.count(AuditLog.id).label("n"))
        .where(AuditLog.timestamp >= since)
        .group_by(AuditLog.username)
        .order_by(func.count(AuditLog.id).desc())
        .limit(8)
    )).all()
    top_users = [{"username": r[0] or "system", "count": r[1]} for r in top_users_rows]

    # Top actions
    top_actions_rows = (await db.execute(
        select(AuditLog.action, func.count(AuditLog.id).label("n"))
        .where(AuditLog.timestamp >= since)
        .group_by(AuditLog.action)
        .order_by(func.count(AuditLog.id).desc())
        .limit(10)
    )).all()
    top_actions = [{"action": r[0], "count": r[1]} for r in top_actions_rows]

    # Hourly trend (last 24h)
    cutoff_24h = datetime.utcnow() - timedelta(hours=24)
    hourly_rows = (await db.execute(
        select(
            func.date_trunc("hour", AuditLog.timestamp).label("h"),
            func.count(AuditLog.id).label("n"),
        )
        .where(AuditLog.timestamp >= cutoff_24h)
        .group_by("h")
    )).all()
    base_hour = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
    h_map = {row.h: row.n for row in hourly_rows}
    hourly_trend = [
        {
            "hour":  (base_hour - timedelta(hours=i)).strftime("%H:00"),
            "count": h_map.get(base_hour - timedelta(hours=i), 0),
        }
        for i in range(23, -1, -1)
    ]

    # Resource type breakdown
    rtype_rows = (await db.execute(
        select(AuditLog.resource_type, func.count(AuditLog.id).label("n"))
        .where(AuditLog.timestamp >= since, AuditLog.resource_type.isnot(None))
        .group_by(AuditLog.resource_type)
        .order_by(func.count(AuditLog.id).desc())
    )).all()
    by_resource = [{"resource_type": r[0], "count": r[1]} for r in rtype_rows]

    return {
        "total":        total,
        "failed":       failed,
        "unique_users": unique_users,
        "top_users":    top_users,
        "top_actions":  top_actions,
        "hourly_trend": hourly_trend,
        "by_resource":  by_resource,
    }


@router.get("/actions")
async def list_action_types(
    db: AsyncSession = Depends(get_db),
    _admin: User     = Depends(require_admin),
):
    rows = (await db.execute(
        select(AuditLog.action).distinct().order_by(AuditLog.action)
    )).scalars().all()
    return rows


@router.get("/csv")
async def export_audit_csv(
    days: int        = Query(7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
    _admin: User     = Depends(require_admin),
):
    since = datetime.utcnow() - timedelta(days=days)
    rows = (await db.execute(
        select(AuditLog)
        .where(AuditLog.timestamp >= since)
        .order_by(AuditLog.timestamp.desc())
        .limit(10000)
    )).scalars().all()

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ID", "Timestamp", "Username", "Action", "Resource Type",
                "Resource ID", "Resource Name", "Status", "IP", "Details"])
    for r in rows:
        w.writerow([r.id, r.timestamp, r.username, r.action, r.resource_type or "",
                    r.resource_id or "", r.resource_name or "", r.status,
                    r.ip_address or "", r.details or ""])
    buf.seek(0)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="audit_{ts}.csv"'},
    )
