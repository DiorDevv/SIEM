"""
Case Management API — full incident lifecycle.
"""
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, and_, update
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.case import Case, CaseAlert, CaseNote, CaseTimeline, CaseStatus, CaseSeverity, NoteType
from models.alert import Alert
from models.user import User
from routes.auth import get_current_user

router = APIRouter(prefix="/api/cases", tags=["cases"])


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _next_case_number(db: AsyncSession) -> str:
    last = (await db.execute(
        select(func.max(Case.id))
    )).scalar_one() or 0
    return f"CASE-{(last + 1):04d}"


async def _add_timeline(db: AsyncSession, case_id: int, username: str, action: str,
                         old_value: str = None, new_value: str = None):
    db.add(CaseTimeline(
        case_id=case_id, username=username, action=action,
        old_value=old_value, new_value=new_value,
    ))


def _case_dict(c: Case) -> dict:
    sla_ok = None
    if c.sla_deadline:
        sla_ok = c.sla_deadline > datetime.utcnow()
    return {
        "id":               c.id,
        "case_number":      c.case_number,
        "title":            c.title,
        "description":      c.description,
        "status":           c.status,
        "severity":         c.severity,
        "tlp":              c.tlp,
        "assigned_to":      c.assigned_to,
        "assigned_to_name": c.assigned_to_name,
        "created_by":       c.created_by,
        "created_by_name":  c.created_by_name,
        "tags":             c.tags or [],
        "mitre_tactics":    c.mitre_tactics or [],
        "mitre_techniques": c.mitre_techniques or [],
        "sla_hours":        c.sla_hours,
        "sla_deadline":     c.sla_deadline.isoformat() if c.sla_deadline else None,
        "sla_ok":           sla_ok,
        "alert_count":      c.alert_count or 0,
        "note_count":       c.note_count or 0,
        "created_at":       c.created_at.isoformat() if c.created_at else None,
        "updated_at":       c.updated_at.isoformat() if c.updated_at else None,
        "resolved_at":      c.resolved_at.isoformat() if c.resolved_at else None,
        "closed_at":        c.closed_at.isoformat() if c.closed_at else None,
    }


# ── Schemas ───────────────────────────────────────────────────────────────────

class CaseIn(BaseModel):
    title:            str
    description:      Optional[str]      = None
    severity:         str                = "MEDIUM"
    tlp:              str                = "AMBER"
    tags:             Optional[List[str]] = None
    mitre_tactics:    Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    sla_hours:        Optional[int]      = None
    alert_ids:        Optional[List[int]] = None  # pre-link alerts on creation


class CaseUpdate(BaseModel):
    title:            Optional[str]      = None
    description:      Optional[str]      = None
    severity:         Optional[str]      = None
    tlp:              Optional[str]      = None
    tags:             Optional[List[str]] = None
    mitre_tactics:    Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    sla_hours:        Optional[int]      = None


class NoteIn(BaseModel):
    content:   str
    note_type: str = "note"   # note | action | evidence | ioc


class AssignIn(BaseModel):
    user_id:   Optional[int]  = None
    username:  Optional[str]  = None


class StatusIn(BaseModel):
    status: str


# ── Stats ─────────────────────────────────────────────────────────────────────

@router.get("/stats")
async def case_stats(
    db: AsyncSession          = Depends(get_db),
    current_user: User        = Depends(get_current_user),
):
    total  = (await db.execute(select(func.count(Case.id)))).scalar_one() or 0
    open_  = (await db.execute(select(func.count(Case.id)).where(Case.status == CaseStatus.open))).scalar_one() or 0
    inp    = (await db.execute(select(func.count(Case.id)).where(Case.status == CaseStatus.in_progress))).scalar_one() or 0
    resolved = (await db.execute(select(func.count(Case.id)).where(Case.status == CaseStatus.resolved))).scalar_one() or 0
    closed_  = (await db.execute(select(func.count(Case.id)).where(Case.status == CaseStatus.closed))).scalar_one() or 0

    crit = (await db.execute(
        select(func.count(Case.id)).where(
            and_(Case.severity == CaseSeverity.critical,
                 Case.status.in_([CaseStatus.open, CaseStatus.in_progress]))
        )
    )).scalar_one() or 0

    # SLA breached (deadline passed, not resolved)
    sla_breached = (await db.execute(
        select(func.count(Case.id)).where(
            and_(Case.sla_deadline < datetime.utcnow(),
                 Case.status.in_([CaseStatus.open, CaseStatus.in_progress, CaseStatus.pending]))
        )
    )).scalar_one() or 0

    # By severity
    sev_rows = (await db.execute(
        select(Case.severity, func.count(Case.id).label("n"))
        .group_by(Case.severity)
    )).all()
    by_severity = {r[0]: r[1] for r in sev_rows}

    # Avg resolution time (hours)
    avg_res_row = (await db.execute(
        select(func.avg(
            func.extract("epoch", Case.resolved_at) -
            func.extract("epoch", Case.created_at)
        )).where(Case.resolved_at.isnot(None))
    )).scalar_one()
    avg_resolution_hours = round(float(avg_res_row) / 3600, 1) if avg_res_row else None

    return {
        "total":               total,
        "open":                open_,
        "in_progress":         inp,
        "resolved":            resolved,
        "closed":              closed_,
        "critical_open":       crit,
        "sla_breached":        sla_breached,
        "by_severity":         by_severity,
        "avg_resolution_hours": avg_resolution_hours,
    }


# ── List ──────────────────────────────────────────────────────────────────────

@router.get("")
async def list_cases(
    status:      Optional[str] = None,
    severity:    Optional[str] = None,
    assigned_to: Optional[int] = None,
    search:      Optional[str] = None,
    days:        Optional[int] = None,
    page:        int           = Query(1, ge=1),
    size:        int           = Query(20, ge=1, le=100),
    db: AsyncSession           = Depends(get_db),
    current_user: User         = Depends(get_current_user),
):
    filters = []
    if status:      filters.append(Case.status == status)
    if severity:    filters.append(Case.severity == severity.upper())
    if assigned_to: filters.append(Case.assigned_to == assigned_to)
    if days:        filters.append(Case.created_at >= datetime.utcnow() - timedelta(days=days))
    if search:
        filters.append(
            Case.title.ilike(f"%{search}%") |
            Case.case_number.ilike(f"%{search}%") |
            Case.description.ilike(f"%{search}%")
        )

    where = and_(*filters) if filters else True

    total = (await db.execute(select(func.count(Case.id)).where(where))).scalar_one() or 0
    rows  = (await db.execute(
        select(Case).where(where)
        .order_by(Case.updated_at.desc())
        .offset((page - 1) * size).limit(size)
    )).scalars().all()

    return {
        "cases": [_case_dict(c) for c in rows],
        "total": total, "page": page, "size": size,
    }


# ── Create ────────────────────────────────────────────────────────────────────

@router.post("", status_code=201)
async def create_case(
    body: CaseIn,
    db: AsyncSession      = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    case_number = await _next_case_number(db)
    sla_deadline = None
    if body.sla_hours:
        sla_deadline = datetime.utcnow() + timedelta(hours=body.sla_hours)

    case = Case(
        case_number      = case_number,
        title            = body.title,
        description      = body.description,
        severity         = body.severity.upper(),
        tlp              = body.tlp.upper(),
        tags             = body.tags or [],
        mitre_tactics    = body.mitre_tactics or [],
        mitre_techniques = body.mitre_techniques or [],
        sla_hours        = body.sla_hours,
        sla_deadline     = sla_deadline,
        created_by       = current_user.id,
        created_by_name  = current_user.username,
        status           = CaseStatus.open,
    )
    db.add(case)
    await db.flush()

    # Link alerts if provided
    if body.alert_ids:
        for aid in body.alert_ids:
            db.add(CaseAlert(case_id=case.id, alert_id=aid, linked_by=current_user.username))
        case.alert_count = len(body.alert_ids)

    await _add_timeline(db, case.id, current_user.username, "Case created",
                         new_value=f"Severity: {case.severity}, TLP: {case.tlp}")
    await db.commit()
    await db.refresh(case)
    return _case_dict(case)


# ── Get single ────────────────────────────────────────────────────────────────

@router.get("/{case_id}")
async def get_case(
    case_id: int,
    db: AsyncSession   = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    case = await db.get(Case, case_id)
    if not case:
        raise HTTPException(404, "Case not found")

    # Notes
    notes = (await db.execute(
        select(CaseNote).where(CaseNote.case_id == case_id)
        .order_by(CaseNote.created_at.asc())
    )).scalars().all()

    # Timeline
    timeline = (await db.execute(
        select(CaseTimeline).where(CaseTimeline.case_id == case_id)
        .order_by(CaseTimeline.created_at.desc())
    )).scalars().all()

    # Linked alerts
    alert_links = (await db.execute(
        select(CaseAlert).where(CaseAlert.case_id == case_id)
    )).scalars().all()
    alert_ids = [l.alert_id for l in alert_links]

    alerts = []
    if alert_ids:
        alert_rows = (await db.execute(
            select(Alert).where(Alert.id.in_(alert_ids))
            .order_by(Alert.created_at.desc())
        )).scalars().all()
        alerts = [{
            "id":           a.id,
            "severity":     a.severity,
            "title":        a.title,
            "status":       a.status,
            "agent_hostname": a.agent_hostname,
            "mitre_tactic": a.mitre_tactic,
            "src_ip":       a.src_ip,
            "rule_name":    a.rule_name,
            "created_at":   a.created_at.isoformat() if a.created_at else None,
            "linked_at":    next((l.linked_at.isoformat() for l in alert_links if l.alert_id == a.id), None),
            "linked_by":    next((l.linked_by for l in alert_links if l.alert_id == a.id), None),
        } for a in alert_rows]

    result = _case_dict(case)
    result["notes"] = [{
        "id":         n.id,
        "username":   n.username,
        "content":    n.content,
        "note_type":  n.note_type,
        "created_at": n.created_at.isoformat() if n.created_at else None,
    } for n in notes]
    result["timeline"] = [{
        "id":         t.id,
        "username":   t.username,
        "action":     t.action,
        "old_value":  t.old_value,
        "new_value":  t.new_value,
        "created_at": t.created_at.isoformat() if t.created_at else None,
    } for t in timeline]
    result["alerts"] = alerts
    return result


# ── Update ────────────────────────────────────────────────────────────────────

@router.put("/{case_id}")
async def update_case(
    case_id: int,
    body: CaseUpdate,
    db: AsyncSession   = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    case = await db.get(Case, case_id)
    if not case:
        raise HTTPException(404, "Case not found")

    changes = []
    if body.title is not None and body.title != case.title:
        changes.append(f"Title updated")
        case.title = body.title
    if body.description is not None:
        case.description = body.description
    if body.severity is not None:
        old = case.severity
        case.severity = body.severity.upper()
        if old != case.severity:
            changes.append(f"Severity: {old} → {case.severity}")
    if body.tlp is not None:
        case.tlp = body.tlp.upper()
    if body.tags is not None:
        case.tags = body.tags
    if body.mitre_tactics is not None:
        case.mitre_tactics = body.mitre_tactics
    if body.mitre_techniques is not None:
        case.mitre_techniques = body.mitre_techniques
    if body.sla_hours is not None:
        case.sla_hours    = body.sla_hours
        case.sla_deadline = datetime.utcnow() + timedelta(hours=body.sla_hours)

    if changes:
        await _add_timeline(db, case_id, current_user.username, "; ".join(changes))

    await db.commit()
    await db.refresh(case)
    return _case_dict(case)


# ── Status change ─────────────────────────────────────────────────────────────

@router.post("/{case_id}/status")
async def change_status(
    case_id: int,
    body: StatusIn,
    db: AsyncSession   = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    case = await db.get(Case, case_id)
    if not case:
        raise HTTPException(404, "Case not found")

    valid = {s.value for s in CaseStatus}
    if body.status not in valid:
        raise HTTPException(400, f"Invalid status. Must be one of: {valid}")

    old_status = case.status
    case.status = body.status
    if body.status == CaseStatus.resolved and not case.resolved_at:
        case.resolved_at = datetime.utcnow()
    if body.status == CaseStatus.closed and not case.closed_at:
        case.closed_at = datetime.utcnow()

    await _add_timeline(db, case_id, current_user.username,
                         f"Status changed: {old_status} → {body.status}",
                         old_value=old_status, new_value=body.status)
    await db.commit()
    await db.refresh(case)
    return _case_dict(case)


# ── Assign ────────────────────────────────────────────────────────────────────

@router.post("/{case_id}/assign")
async def assign_case(
    case_id: int,
    body: AssignIn,
    db: AsyncSession   = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    case = await db.get(Case, case_id)
    if not case:
        raise HTTPException(404, "Case not found")

    old_name = case.assigned_to_name or "unassigned"
    case.assigned_to      = body.user_id
    case.assigned_to_name = body.username

    # Auto-move to in_progress if was open
    if case.status == CaseStatus.open and body.user_id:
        case.status = CaseStatus.in_progress
        await _add_timeline(db, case_id, current_user.username, "Status changed: open → in_progress")

    await _add_timeline(db, case_id, current_user.username,
                         f"Assigned to {body.username or 'nobody'}",
                         old_value=old_name, new_value=body.username or "unassigned")
    await db.commit()
    await db.refresh(case)
    return _case_dict(case)


# ── Notes ─────────────────────────────────────────────────────────────────────

@router.post("/{case_id}/notes", status_code=201)
async def add_note(
    case_id: int,
    body: NoteIn,
    db: AsyncSession   = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    case = await db.get(Case, case_id)
    if not case:
        raise HTTPException(404, "Case not found")

    note = CaseNote(
        case_id   = case_id,
        user_id   = current_user.id,
        username  = current_user.username,
        content   = body.content,
        note_type = body.note_type,
    )
    db.add(note)
    case.note_count = (case.note_count or 0) + 1

    type_labels = {"note": "Note added", "action": "Action logged",
                   "evidence": "Evidence added", "ioc": "IOC added"}
    await _add_timeline(db, case_id, current_user.username,
                         type_labels.get(body.note_type, "Note added"))
    await db.commit()
    await db.refresh(note)
    return {
        "id":         note.id,
        "username":   note.username,
        "content":    note.content,
        "note_type":  note.note_type,
        "created_at": note.created_at.isoformat() if note.created_at else None,
    }


@router.delete("/{case_id}/notes/{note_id}", status_code=204)
async def delete_note(
    case_id: int,
    note_id: int,
    db: AsyncSession   = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    note = await db.get(CaseNote, note_id)
    if not note or note.case_id != case_id:
        raise HTTPException(404, "Note not found")
    if note.user_id != current_user.id and current_user.role != "admin":
        raise HTTPException(403, "Cannot delete another user's note")
    await db.delete(note)
    case = await db.get(Case, case_id)
    if case:
        case.note_count = max(0, (case.note_count or 1) - 1)
    await db.commit()


# ── Alert linking ─────────────────────────────────────────────────────────────

@router.post("/{case_id}/alerts/{alert_id}", status_code=201)
async def link_alert(
    case_id:  int,
    alert_id: int,
    db: AsyncSession   = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    case  = await db.get(Case, case_id)
    alert = await db.get(Alert, alert_id)
    if not case:  raise HTTPException(404, "Case not found")
    if not alert: raise HTTPException(404, "Alert not found")

    existing = (await db.execute(
        select(CaseAlert).where(
            and_(CaseAlert.case_id == case_id, CaseAlert.alert_id == alert_id)
        )
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "Alert already linked to this case")

    db.add(CaseAlert(case_id=case_id, alert_id=alert_id, linked_by=current_user.username))
    case.alert_count = (case.alert_count or 0) + 1

    await _add_timeline(db, case_id, current_user.username,
                         f"Alert #{alert_id} linked: {alert.title[:80]}")
    await db.commit()
    return {"ok": True}


@router.delete("/{case_id}/alerts/{alert_id}", status_code=204)
async def unlink_alert(
    case_id:  int,
    alert_id: int,
    db: AsyncSession   = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    link = (await db.execute(
        select(CaseAlert).where(
            and_(CaseAlert.case_id == case_id, CaseAlert.alert_id == alert_id)
        )
    )).scalar_one_or_none()
    if not link:
        raise HTTPException(404, "Link not found")
    await db.delete(link)
    case = await db.get(Case, case_id)
    if case:
        case.alert_count = max(0, (case.alert_count or 1) - 1)
    await _add_timeline(db, case_id, current_user.username, f"Alert #{alert_id} unlinked")
    await db.commit()


# ── Delete case ───────────────────────────────────────────────────────────────

@router.delete("/{case_id}", status_code=204)
async def delete_case(
    case_id: int,
    db: AsyncSession   = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role != "admin":
        raise HTTPException(403, "Admin only")
    case = await db.get(Case, case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    await db.delete(case)
    await db.commit()
