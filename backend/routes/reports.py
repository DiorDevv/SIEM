"""
Reports / Export API.
Supports CSV and JSON export for alerts, logs summary, and vulnerability findings.
"""
import csv
import json
import io
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse, JSONResponse
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.alert import Alert, AlertStatus, AlertSeverity
from models.vulnerability import Vulnerability, VulnStatus
from models.sca_result import SCAScan
from routes.auth import get_current_user
from models.user import User

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _now_str() -> str:
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")


# ── Alerts export ─────────────────────────────────────────────────────────────

@router.get("/alerts/csv")
async def export_alerts_csv(
    severity:   Optional[str]      = None,
    status:     Optional[str]      = None,
    agent_id:   Optional[str]      = None,
    days:       int                 = Query(7, ge=1, le=365),
    db: AsyncSession                = Depends(get_db),
    current_user: User              = Depends(get_current_user),
):
    since = datetime.utcnow() - timedelta(days=days)
    filters = [Alert.created_at >= since]
    if severity: filters.append(Alert.severity == severity.upper())
    if status:   filters.append(Alert.status   == status)
    if agent_id: filters.append(Alert.agent_id == agent_id)

    stmt = select(Alert).where(and_(*filters)).order_by(Alert.created_at.desc()).limit(10000)
    alerts = (await db.execute(stmt)).scalars().all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "ID", "Severity", "Level", "Title", "Rule", "Agent", "Source IP",
        "MITRE Tactic", "MITRE Technique", "Status", "Category",
        "Created At", "Resolved At", "Description",
    ])
    for a in alerts:
        writer.writerow([
            a.id, a.severity, a.level, a.title, a.rule_name or "",
            a.agent_hostname or "", a.src_ip or "",
            a.mitre_tactic or "", a.mitre_technique or "",
            a.status, a.category or "",
            a.created_at.isoformat() if a.created_at else "",
            a.resolved_at.isoformat() if a.resolved_at else "",
            (a.description or "").replace("\n", " ")[:500],
        ])

    buf.seek(0)
    fname = f"siem_alerts_{_now_str()}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@router.get("/alerts/json")
async def export_alerts_json(
    severity:   Optional[str]  = None,
    status:     Optional[str]  = None,
    agent_id:   Optional[str]  = None,
    days:       int             = Query(7, ge=1, le=365),
    db: AsyncSession            = Depends(get_db),
    current_user: User          = Depends(get_current_user),
):
    since = datetime.utcnow() - timedelta(days=days)
    filters = [Alert.created_at >= since]
    if severity: filters.append(Alert.severity == severity.upper())
    if status:   filters.append(Alert.status   == status)
    if agent_id: filters.append(Alert.agent_id == agent_id)

    stmt = select(Alert).where(and_(*filters)).order_by(Alert.created_at.desc()).limit(10000)
    alerts = (await db.execute(stmt)).scalars().all()

    data = [{
        "id":               a.id,
        "severity":         a.severity,
        "level":            a.level,
        "title":            a.title,
        "rule_name":        a.rule_name,
        "agent_hostname":   a.agent_hostname,
        "src_ip":           a.src_ip,
        "mitre_tactic":     a.mitre_tactic,
        "mitre_technique":  a.mitre_technique,
        "status":           a.status,
        "category":         a.category,
        "created_at":       a.created_at.isoformat() if a.created_at else None,
        "description":      a.description,
    } for a in alerts]

    fname = f"siem_alerts_{_now_str()}.json"
    content = json.dumps({"generated_at": datetime.utcnow().isoformat(), "count": len(data), "alerts": data}, indent=2)
    return StreamingResponse(
        iter([content]),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ── Vulnerabilities export ────────────────────────────────────────────────────

@router.get("/vulns/csv")
async def export_vulns_csv(
    agent_id:  Optional[str] = None,
    severity:  Optional[str] = None,
    db: AsyncSession          = Depends(get_db),
    current_user: User        = Depends(get_current_user),
):
    filters = [Vulnerability.status == VulnStatus.open]
    if agent_id: filters.append(Vulnerability.agent_id == agent_id)
    if severity: filters.append(Vulnerability.severity == severity.upper())

    stmt = select(Vulnerability).where(and_(*filters)).order_by(
        Vulnerability.severity.desc(), Vulnerability.cvss_score.desc()
    ).limit(10000)
    vulns = (await db.execute(stmt)).scalars().all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "ID", "Agent", "Package", "Version", "Ecosystem",
        "CVE/VULN ID", "Severity", "CVSS Score", "Title", "Fixed Version", "First Seen",
    ])
    for v in vulns:
        writer.writerow([
            v.id, v.hostname or v.agent_id, v.package_name, v.package_version, v.ecosystem or "",
            v.vuln_id, v.severity, v.cvss_score or "",
            (v.title or "").replace("\n", " ")[:200],
            v.fixed_version or "No fix available",
            v.first_seen.isoformat() if v.first_seen else "",
        ])

    buf.seek(0)
    fname = f"siem_vulns_{_now_str()}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ── SCA export ────────────────────────────────────────────────────────────────

@router.get("/sca/csv")
async def export_sca_csv(
    agent_id:  Optional[str] = None,
    db: AsyncSession          = Depends(get_db),
    current_user: User        = Depends(get_current_user),
):
    stmt = select(SCAScan)
    if agent_id:
        stmt = stmt.where(SCAScan.agent_id == agent_id)
    stmt = stmt.order_by(SCAScan.scanned_at.desc()).limit(500)
    scans = (await db.execute(stmt)).scalars().all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Agent", "Hostname", "Score %", "Passed", "Failed", "Skipped", "Scanned At"])
    for s in scans:
        writer.writerow([s.agent_id, s.hostname or "", s.score_pct, s.passed, s.failed, s.skipped,
                         s.scanned_at.isoformat() if s.scanned_at else ""])

    buf.seek(0)
    fname = f"siem_sca_{_now_str()}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ── Executive summary (JSON) ──────────────────────────────────────────────────

@router.get("/summary")
async def executive_summary(
    days: int = Query(7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from sqlalchemy import func
    from models.agent import Agent, AgentStatus

    since = datetime.utcnow() - timedelta(days=days)

    total_alerts = (await db.execute(
        select(func.count(Alert.id)).where(Alert.created_at >= since)
    )).scalar_one()

    by_sev = {}
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        cnt = (await db.execute(
            select(func.count(Alert.id)).where(
                and_(Alert.created_at >= since, Alert.severity == sev)
            )
        )).scalar_one()
        by_sev[sev] = cnt

    open_vulns = (await db.execute(
        select(func.count(Vulnerability.id)).where(Vulnerability.status == VulnStatus.open)
    )).scalar_one()

    critical_vulns = (await db.execute(
        select(func.count(Vulnerability.id)).where(
            and_(Vulnerability.status == VulnStatus.open, Vulnerability.severity == "CRITICAL")
        )
    )).scalar_one()

    online_agents = (await db.execute(
        select(func.count(Agent.id)).where(
            and_(Agent.is_active == True, Agent.status == AgentStatus.online)
        )
    )).scalar_one()

    return {
        "generated_at":    datetime.utcnow().isoformat(),
        "period_days":     days,
        "alerts": {
            "total":       total_alerts,
            "by_severity": by_sev,
        },
        "vulnerabilities": {
            "open":        open_vulns,
            "critical":    critical_vulns,
        },
        "agents": {
            "online":      online_agents,
        },
    }
