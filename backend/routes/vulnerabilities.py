import asyncio
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy import select, func, and_, delete
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.vulnerability import PackageScan, Vulnerability, VulnStatus
from routes.auth import get_current_user, require_analyst
from models.user import User
from engine.vuln_checker import check_all_packages

router = APIRouter(prefix="/api/vulns", tags=["vulnerabilities"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class PackageItem(BaseModel):
    name:      str
    version:   str
    ecosystem: str = "unknown"


class PackageScanRequest(BaseModel):
    agent_id:  str
    hostname:  Optional[str] = None
    packages:  List[PackageItem]


class VulnStatusUpdate(BaseModel):
    status: VulnStatus


# ── Helpers ───────────────────────────────────────────────────────────────────

def _vuln_dict(v: Vulnerability) -> dict:
    return {
        "id":               v.id,
        "agent_id":         v.agent_id,
        "hostname":         v.hostname,
        "package_name":     v.package_name,
        "package_version":  v.package_version,
        "ecosystem":        v.ecosystem,
        "vuln_id":          v.vuln_id,
        "title":            v.title,
        "description":      v.description,
        "severity":         v.severity,
        "cvss_score":       v.cvss_score,
        "fixed_version":    v.fixed_version,
        "references":       v.references,
        "status":           v.status,
        "first_seen":       v.first_seen,
        "last_seen":        v.last_seen,
    }


async def _run_scan_bg(db_url: str, agent_id: str, hostname: str, packages: list):
    """Background task: check packages against OSV.dev and persist results."""
    from database import AsyncSessionLocal
    # Detect distro from package ecosystem hints
    distro = "ubuntu"
    if any(p.get("ecosystem", "").lower() in ("rpm", "yum", "dnf") for p in packages):
        distro = "rhel"
    findings = await check_all_packages(packages, distro=distro)

    async with AsyncSessionLocal() as db:
        try:
            for f in findings:
                # Upsert: match by agent + package + version + vuln_id
                stmt = select(Vulnerability).where(
                    and_(
                        Vulnerability.agent_id        == agent_id,
                        Vulnerability.package_name    == f["package_name"],
                        Vulnerability.package_version == f["package_version"],
                        Vulnerability.vuln_id         == f["vuln_id"],
                    )
                )
                existing = (await db.execute(stmt)).scalar_one_or_none()
                if existing:
                    existing.last_seen    = datetime.utcnow()
                    existing.severity     = f["severity"]
                    existing.cvss_score   = f["cvss_score"]
                    existing.fixed_version = f["fixed_version"]
                else:
                    vuln = Vulnerability(
                        agent_id        = agent_id,
                        hostname        = hostname,
                        package_name    = f["package_name"],
                        package_version = f["package_version"],
                        ecosystem       = f["ecosystem"],
                        vuln_id         = f["vuln_id"],
                        title           = f["title"],
                        description     = f["description"],
                        severity        = f["severity"],
                        cvss_score      = f["cvss_score"],
                        fixed_version   = f["fixed_version"],
                        references      = f["references"],
                        status          = VulnStatus.open,
                    )
                    db.add(vuln)
            await db.commit()
        except Exception as e:
            await db.rollback()
            import logging
            logging.getLogger(__name__).error(f"Vuln persist error: {e}")


# ── Ingest (called by agent) ──────────────────────────────────────────────────

@router.post("/scan", status_code=202)
async def submit_package_scan(
    body: PackageScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Agent submits installed packages; vulnerability check runs in background."""
    scan = PackageScan(
        agent_id   = body.agent_id,
        hostname   = body.hostname,
        packages   = [p.model_dump() for p in body.packages],
    )
    db.add(scan)
    await db.flush()

    pkgs = [p.model_dump() for p in body.packages]
    from config import settings
    background_tasks.add_task(_run_scan_bg, settings.DATABASE_URL, body.agent_id, body.hostname or "", pkgs)

    return {"message": f"Scan queued for {len(pkgs)} packages", "scan_id": scan.id}


# ── Query APIs ────────────────────────────────────────────────────────────────

@router.get("")
async def list_vulns(
    agent_id:  Optional[str] = None,
    severity:  Optional[str] = None,
    status:    Optional[str] = None,
    ecosystem: Optional[str] = None,
    page:      int = 1,
    size:      int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if size > 200:
        size = 200

    filters = []
    if agent_id:  filters.append(Vulnerability.agent_id == agent_id)
    if severity:  filters.append(Vulnerability.severity == severity.upper())
    if status:    filters.append(Vulnerability.status == status)
    if ecosystem: filters.append(Vulnerability.ecosystem.ilike(f"%{ecosystem}%"))

    total = (await db.execute(
        select(func.count(Vulnerability.id)).where(and_(*filters)) if filters
        else select(func.count(Vulnerability.id))
    )).scalar_one()

    stmt = select(Vulnerability)
    if filters:
        stmt = stmt.where(and_(*filters))
    stmt = stmt.order_by(Vulnerability.severity.desc(), Vulnerability.first_seen.desc())
    stmt = stmt.offset((page - 1) * size).limit(size)
    vulns = (await db.execute(stmt)).scalars().all()

    return {"vulnerabilities": [_vuln_dict(v) for v in vulns], "total": total, "page": page, "size": size}


@router.get("/summary")
async def vuln_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Per-severity counts and per-agent breakdown."""
    sev_counts = {}
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        cnt = (await db.execute(
            select(func.count(Vulnerability.id)).where(
                and_(Vulnerability.severity == sev, Vulnerability.status == VulnStatus.open)
            )
        )).scalar_one()
        sev_counts[sev] = cnt

    # Top 5 agents by vuln count
    top = (await db.execute(
        select(Vulnerability.hostname, func.count(Vulnerability.id).label("cnt"))
        .where(Vulnerability.status == VulnStatus.open)
        .group_by(Vulnerability.hostname)
        .order_by(func.count(Vulnerability.id).desc())
        .limit(5)
    )).all()

    return {
        "by_severity": sev_counts,
        "total_open":  sum(sev_counts.values()),
        "top_agents":  [{"hostname": r[0] or "unknown", "count": r[1]} for r in top],
    }


@router.put("/{vuln_id}/status")
async def update_vuln_status(
    vuln_id: int,
    body: VulnStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    vuln = (await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))).scalar_one_or_none()
    if not vuln:
        raise HTTPException(404, "Vulnerability not found")
    vuln.status = body.status
    await db.flush()
    return _vuln_dict(vuln)
