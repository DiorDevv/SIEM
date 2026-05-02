"""
Alert lifecycle routes — Wazuh-style alert management.

Lifecycle:
    open → investigating → acknowledged → resolved → closed
                        ↘ false_positive

Aggregation: multiple raw events that share the same (rule, agent, src_ip)
are collapsed into one alert.  event_count tracks how many were absorbed so
analysts see "Brute Force ×47" instead of 47 individual rows.
"""
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy import select, and_, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.alert import Alert, AlertStatus, AlertSeverity, AlertNote
from routes.auth import get_current_user, require_analyst
from models.user import User
from services.audit_service import audit

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


# ── Allowed status transitions ────────────────────────────────────────────────

_TRANSITIONS: dict[AlertStatus, set[AlertStatus]] = {
    AlertStatus.open: {
        AlertStatus.investigating, AlertStatus.acknowledged,
        AlertStatus.resolved, AlertStatus.false_positive, AlertStatus.closed,
    },
    AlertStatus.investigating: {
        AlertStatus.open, AlertStatus.acknowledged,
        AlertStatus.resolved, AlertStatus.false_positive, AlertStatus.closed,
    },
    AlertStatus.acknowledged: {
        AlertStatus.investigating, AlertStatus.resolved,
        AlertStatus.false_positive, AlertStatus.closed,
    },
    AlertStatus.resolved: {
        AlertStatus.open, AlertStatus.closed,   # re-open allowed
    },
    AlertStatus.false_positive: {
        AlertStatus.open, AlertStatus.closed,
    },
    AlertStatus.closed: {
        AlertStatus.open,                        # re-open allowed
    },
}


# ── Serialisers ───────────────────────────────────────────────────────────────

def _note_to_dict(n: AlertNote) -> dict:
    return {
        "id":         n.id,
        "author":     n.author or "system",
        "body":       n.body,
        "created_at": n.created_at.isoformat() if n.created_at else None,
    }


def _alert_to_dict(a: Alert, notes: list | None = None) -> dict:
    now = datetime.now(timezone.utc)

    def _ts(dt):
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()

    def _age_min(dt):
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int((now - dt).total_seconds() / 60)

    tta = ttr = None
    if a.acknowledged_at and a.created_at:
        ca = a.created_at if a.created_at.tzinfo else a.created_at.replace(tzinfo=timezone.utc)
        aa = a.acknowledged_at if a.acknowledged_at.tzinfo else a.acknowledged_at.replace(tzinfo=timezone.utc)
        tta = max(0, int((aa - ca).total_seconds() / 60))
    if a.resolved_at and a.created_at:
        ca = a.created_at if a.created_at.tzinfo else a.created_at.replace(tzinfo=timezone.utc)
        ra = a.resolved_at if a.resolved_at.tzinfo else a.resolved_at.replace(tzinfo=timezone.utc)
        ttr = max(0, int((ra - ca).total_seconds() / 60))

    return {
        "id":               a.id,
        "rule_id":          a.rule_id,
        "agent_id":         a.agent_id,
        "severity":         a.severity,
        "level":            a.level,
        "title":            a.title,
        "description":      a.description,
        "log_id":           a.log_id,
        "status":           a.status,
        "agent_hostname":   a.agent_hostname,
        "rule_name":        a.rule_name,
        "groups":           a.groups,
        "category":         a.category,
        "mitre_tactic":     a.mitre_tactic,
        "mitre_technique":  a.mitre_technique,
        "src_ip":           a.src_ip,
        "threat_intel":     a.threat_intel,
        "raw_log":          a.raw_log,
        "parsed_fields":    a.parsed_fields,
        "risk_score":       a.risk_score,
        "indicators":       a.indicators,
        # aggregation
        "agg_key":          a.agg_key,
        "event_count":      a.event_count or 1,
        "first_seen_at":    _ts(a.first_seen_at),
        "last_seen_at":     _ts(a.last_seen_at),
        # lifecycle
        "assigned_to":      a.assigned_to,
        "assigned_to_name": a.assigned_to_name,
        "acknowledged_by":  a.acknowledged_by,
        "resolved_by":      a.resolved_by,
        "closed_by":        a.closed_by,
        "fp_by":            a.fp_by,
        # timestamps
        "created_at":       _ts(a.created_at),
        "updated_at":       _ts(a.updated_at),
        "acknowledged_at":  _ts(a.acknowledged_at),
        "resolved_at":      _ts(a.resolved_at),
        "closed_at":        _ts(a.closed_at),
        # computed SLA
        "sla_minutes":         _age_min(a.created_at),
        "time_to_ack_min":     tta,
        "time_to_resolve_min": ttr,
        # notes (only populated on single-alert GET)
        "notes": [_note_to_dict(n) for n in (notes or [])],
    }


# ── List ──────────────────────────────────────────────────────────────────────

@router.get("")
async def list_alerts(
    severity:    Optional[str]      = None,
    status:      Optional[str]      = None,
    agent_id:    Optional[str]      = None,
    category:    Optional[str]      = None,
    src_ip:      Optional[str]      = None,
    assigned_to: Optional[int]      = None,
    start_time:  Optional[datetime] = None,
    end_time:    Optional[datetime] = None,
    keyword:     Optional[str]      = None,
    min_count:   Optional[int]      = None,   # event_count >= N (aggregated only)
    sort:        str  = "created_at",
    order:       str  = "desc",
    page:        int  = 1,
    size:        int  = 50,
    db: AsyncSession  = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    size = min(size, 200)
    page = max(page, 1)

    filters = []
    if severity:    filters.append(Alert.severity   == severity.upper())
    if status:      filters.append(Alert.status     == status.lower())
    if agent_id:    filters.append(Alert.agent_id   == agent_id)
    if category:    filters.append(Alert.category   == category)
    if src_ip:      filters.append(Alert.src_ip     == src_ip)
    if assigned_to is not None:
                    filters.append(Alert.assigned_to == assigned_to)
    if start_time:  filters.append(Alert.created_at >= start_time)
    if end_time:    filters.append(Alert.created_at <= end_time)
    if min_count:   filters.append(Alert.event_count >= min_count)
    if keyword:
        filters.append(or_(
            Alert.title.ilike(f"%{keyword}%"),
            Alert.description.ilike(f"%{keyword}%"),
            Alert.src_ip.ilike(f"%{keyword}%"),
            Alert.agent_hostname.ilike(f"%{keyword}%"),
        ))

    where = and_(*filters) if filters else None

    count_q = select(func.count(Alert.id))
    if where is not None:
        count_q = count_q.where(where)
    total = (await db.execute(count_q)).scalar_one()

    sort_col = {
        "created_at":   Alert.created_at,
        "last_seen_at": Alert.last_seen_at,
        "severity":     Alert.level,
        "event_count":  Alert.event_count,
        "status":       Alert.status,
    }.get(sort, Alert.created_at)
    order_fn = sort_col.desc() if order != "asc" else sort_col.asc()

    stmt = select(Alert)
    if where is not None:
        stmt = stmt.where(where)
    stmt = stmt.order_by(order_fn).offset((page - 1) * size).limit(size)
    alerts = (await db.execute(stmt)).scalars().all()

    return {
        "alerts": [_alert_to_dict(a) for a in alerts],
        "total":  total,
        "page":   page,
        "size":   size,
        "pages":  max(1, (total + size - 1) // size),
    }


# ── Single alert (with notes) ─────────────────────────────────────────────────

@router.get("/stats/summary")
async def alert_stats(
    days: int = 7,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """SLA / distribution metrics for the dashboard."""
    since = datetime.now(timezone.utc) - timedelta(days=days)

    by_status = {}
    for st in AlertStatus:
        n = (await db.execute(
            select(func.count(Alert.id)).where(
                and_(Alert.status == st, Alert.created_at >= since)
            )
        )).scalar_one()
        by_status[st.value] = n

    by_severity = {}
    for sv in AlertSeverity:
        n = (await db.execute(
            select(func.count(Alert.id)).where(
                and_(Alert.severity == sv, Alert.created_at >= since)
            )
        )).scalar_one()
        by_severity[sv.value] = n

    top_rules = (await db.execute(
        select(Alert.rule_name, func.count(Alert.id).label("n"))
        .where(Alert.created_at >= since)
        .group_by(Alert.rule_name)
        .order_by(func.count(Alert.id).desc())
        .limit(5)
    )).all()

    top_ips = (await db.execute(
        select(Alert.src_ip, func.count(Alert.id).label("n"))
        .where(and_(Alert.created_at >= since, Alert.src_ip.isnot(None)))
        .group_by(Alert.src_ip)
        .order_by(func.count(Alert.id).desc())
        .limit(5)
    )).all()

    daily_trend = []
    for i in range(days):
        day_start = since + timedelta(days=i)
        day_end   = day_start + timedelta(days=1)
        n = (await db.execute(
            select(func.count(Alert.id)).where(
                and_(Alert.created_at >= day_start, Alert.created_at < day_end)
            )
        )).scalar_one()
        daily_trend.append({"date": day_start.date().isoformat(), "count": n})

    return {
        "period_days": days,
        "by_status":   by_status,
        "by_severity": by_severity,
        "top_rules":   [{"rule": r, "count": n} for r, n in top_rules],
        "top_src_ips": [{"ip": ip, "count": n} for ip, n in top_ips],
        "daily_trend": daily_trend,
    }


@router.get("/{alert_id}")
async def get_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    alert = (await db.execute(
        select(Alert).where(Alert.id == alert_id)
    )).scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    notes = (await db.execute(
        select(AlertNote)
        .where(AlertNote.alert_id == alert_id)
        .order_by(AlertNote.created_at)
    )).scalars().all()
    return _alert_to_dict(alert, notes=notes)


# ── Status transition ─────────────────────────────────────────────────────────

class StatusUpdate(BaseModel):
    status: str
    note: Optional[str] = None

    @field_validator("status")
    @classmethod
    def validate_status(cls, v: str) -> str:
        try:
            AlertStatus(v.lower())
        except ValueError:
            raise ValueError(f"Invalid status. Valid: {[s.value for s in AlertStatus]}")
        return v.lower()


@router.put("/{alert_id}/status")
async def update_alert_status(
    alert_id: int,
    body: StatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    alert = (await db.execute(
        select(Alert).where(Alert.id == alert_id)
    )).scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    new_status = AlertStatus(body.status)
    allowed    = _TRANSITIONS.get(alert.status, set())
    if new_status not in allowed:
        raise HTTPException(
            status_code=422,
            detail=f"Transition {alert.status.value} → {new_status.value} is not allowed",
        )

    now  = datetime.now(timezone.utc)
    name = current_user.username

    alert.status     = new_status
    alert.updated_at = now

    if new_status == AlertStatus.acknowledged:
        alert.acknowledged_at = now
        alert.acknowledged_by = name
    elif new_status == AlertStatus.resolved:
        alert.resolved_at = now
        alert.resolved_by = name
    elif new_status == AlertStatus.closed:
        alert.closed_at = now
        alert.closed_by = name
    elif new_status == AlertStatus.false_positive:
        alert.fp_by = name

    if body.note and body.note.strip():
        db.add(AlertNote(
            alert_id  = alert.id,
            author_id = current_user.id,
            author    = name,
            body      = body.note.strip()[:2000],
        ))

    await db.flush()
    await audit(db, current_user, f"alert_{new_status.value}", "alert", alert.id, alert.title)
    return _alert_to_dict(alert)


# ── Assign alert to analyst ───────────────────────────────────────────────────

class AssignRequest(BaseModel):
    user_id: Optional[int] = None   # None = unassign


@router.put("/{alert_id}/assign")
async def assign_alert(
    alert_id: int,
    body: AssignRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    alert = (await db.execute(
        select(Alert).where(Alert.id == alert_id)
    )).scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if body.user_id is None:
        alert.assigned_to      = None
        alert.assigned_to_name = None
        detail_msg = "Alert unassigned"
    else:
        target = (await db.execute(
            select(User).where(User.id == body.user_id)
        )).scalar_one_or_none()
        if not target:
            raise HTTPException(status_code=404, detail="User not found")
        alert.assigned_to      = target.id
        alert.assigned_to_name = target.username
        detail_msg = f"Assigned to {target.username}"

    alert.updated_at = datetime.now(timezone.utc)
    db.add(AlertNote(
        alert_id  = alert.id,
        author_id = current_user.id,
        author    = current_user.username,
        body      = f"{detail_msg} by {current_user.username}",
    ))
    await db.flush()
    await audit(db, current_user, "alert_assign", "alert", alert.id, alert.title)
    return _alert_to_dict(alert)


# ── Notes / analyst timeline ──────────────────────────────────────────────────

class NoteCreate(BaseModel):
    body: str

    @field_validator("body")
    @classmethod
    def body_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Note body cannot be empty")
        return v[:2000]


@router.get("/{alert_id}/notes")
async def list_notes(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    exists = (await db.execute(
        select(Alert.id).where(Alert.id == alert_id)
    )).scalar_one_or_none()
    if not exists:
        raise HTTPException(status_code=404, detail="Alert not found")

    notes = (await db.execute(
        select(AlertNote)
        .where(AlertNote.alert_id == alert_id)
        .order_by(AlertNote.created_at)
    )).scalars().all()
    return {"notes": [_note_to_dict(n) for n in notes]}


@router.post("/{alert_id}/notes")
async def add_note(
    alert_id: int,
    body: NoteCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    exists = (await db.execute(
        select(Alert.id).where(Alert.id == alert_id)
    )).scalar_one_or_none()
    if not exists:
        raise HTTPException(status_code=404, detail="Alert not found")

    note = AlertNote(
        alert_id  = alert_id,
        author_id = current_user.id,
        author    = current_user.username,
        body      = body.body,
    )
    db.add(note)
    await db.flush()
    await db.refresh(note)
    return _note_to_dict(note)


# ── Bulk action ───────────────────────────────────────────────────────────────

class BulkActionRequest(BaseModel):
    alert_ids: List[int]
    action:    str
    user_id:   Optional[int] = None   # required only for "assign"
    note:      Optional[str] = None

    @field_validator("alert_ids")
    @classmethod
    def limit_ids(cls, v: List[int]) -> List[int]:
        if not v:
            raise ValueError("alert_ids cannot be empty")
        if len(v) > 500:
            raise ValueError("Cannot bulk-action more than 500 alerts at once")
        return v

    @field_validator("action")
    @classmethod
    def valid_action(cls, v: str) -> str:
        allowed = {"investigate", "acknowledge", "resolve", "close",
                   "false_positive", "assign", "delete"}
        if v not in allowed:
            raise ValueError(f"Invalid action. Valid: {sorted(allowed)}")
        return v


@router.post("/bulk-action")
async def bulk_action(
    body: BulkActionRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    alerts = (await db.execute(
        select(Alert).where(Alert.id.in_(body.alert_ids))
    )).scalars().all()

    now    = datetime.now(timezone.utc)
    name   = current_user.username
    count  = 0

    # Resolve assign target once to avoid N queries
    assign_target = None
    if body.action == "assign" and body.user_id is not None:
        assign_target = (await db.execute(
            select(User).where(User.id == body.user_id)
        )).scalar_one_or_none()
        if not assign_target:
            raise HTTPException(status_code=404, detail="Assign target user not found")

    action_to_status = {
        "investigate":   AlertStatus.investigating,
        "acknowledge":   AlertStatus.acknowledged,
        "resolve":       AlertStatus.resolved,
        "close":         AlertStatus.closed,
        "false_positive": AlertStatus.false_positive,
    }

    for alert in alerts:
        if body.action == "delete":
            await db.delete(alert)
            count += 1
            continue

        if body.action == "assign":
            if assign_target:
                alert.assigned_to      = assign_target.id
                alert.assigned_to_name = assign_target.username
            else:
                alert.assigned_to      = None
                alert.assigned_to_name = None
            alert.updated_at = now
            count += 1
            continue

        new_status = action_to_status[body.action]
        if new_status not in _TRANSITIONS.get(alert.status, set()):
            continue   # skip invalid transitions silently in bulk

        alert.status     = new_status
        alert.updated_at = now

        if new_status == AlertStatus.acknowledged:
            alert.acknowledged_at = now
            alert.acknowledged_by = name
        elif new_status == AlertStatus.resolved:
            alert.resolved_at = now
            alert.resolved_by = name
        elif new_status == AlertStatus.closed:
            alert.closed_at = now
            alert.closed_by = name
        elif new_status == AlertStatus.false_positive:
            alert.fp_by = name

        if body.note and body.note.strip():
            db.add(AlertNote(
                alert_id  = alert.id,
                author_id = current_user.id,
                author    = name,
                body      = body.note.strip()[:2000],
            ))
        count += 1

    await db.flush()
    await audit(db, current_user, f"bulk_{body.action}", "alert", None,
                f"{count} alert(s)")
    return {"updated": count}


# ── Delete single ─────────────────────────────────────────────────────────────

@router.delete("/{alert_id}")
async def delete_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    alert = (await db.execute(
        select(Alert).where(Alert.id == alert_id)
    )).scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    await audit(db, current_user, "delete_alert", "alert", alert.id, alert.title)
    await db.delete(alert)
    await db.flush()
    return {"message": "Alert deleted"}


# ── Backward-compat shims ─────────────────────────────────────────────────────

@router.put("/{alert_id}/acknowledge")
async def acknowledge_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    return await update_alert_status(
        alert_id, StatusUpdate(status="acknowledged"), db, current_user
    )


@router.put("/{alert_id}/resolve")
async def resolve_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    return await update_alert_status(
        alert_id, StatusUpdate(status="resolved"), db, current_user
    )


class BulkAcknowledgeRequest(BaseModel):
    alert_ids: List[int]


@router.post("/bulk-acknowledge")
async def bulk_acknowledge(
    request: BulkAcknowledgeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    return await bulk_action(
        BulkActionRequest(alert_ids=request.alert_ids, action="acknowledge"),
        db, current_user,
    )
