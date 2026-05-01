"""
Threat Intelligence API routes.

GET  /api/threat-intel/stats
GET  /api/threat-intel/iocs
POST /api/threat-intel/iocs
PUT  /api/threat-intel/iocs/{id}
DELETE /api/threat-intel/iocs/{id}
POST /api/threat-intel/lookup          — real-time VT + AbuseIPDB + DB check
POST /api/threat-intel/iocs/{id}/enrich — re-enrich existing IOC from VT
POST /api/threat-intel/scan-alerts      — scan last N alerts for IOC hits
POST /api/threat-intel/import-feed      — bulk import from plain-text
"""
import logging
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from pydantic import BaseModel
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db
from models.alert import Alert
from models.threat_intel import ThreatIntelIOC
from routes.auth import get_current_user
from services.threat_intel_service import (
    lookup_virustotal,
    extract_observables,
    match_iocs_in_db,
    import_plaintext_feed,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/threat-intel", tags=["threat-intel"])


# ── Pydantic schemas ───────────────────────────────────────────────────────────

class IOCCreate(BaseModel):
    ioc_type: str
    value: str
    severity: str = "MEDIUM"
    confidence: int = 50
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    malware_family: Optional[str] = None
    source: str = "manual"
    expires_days: Optional[int] = None


class IOCUpdate(BaseModel):
    severity: Optional[str] = None
    confidence: Optional[int] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    malware_family: Optional[str] = None
    is_active: Optional[bool] = None
    expires_days: Optional[int] = None


class LookupRequest(BaseModel):
    ioc_type: str
    value: str
    enrich: bool = True   # hit VirusTotal if available


# ── Stats ──────────────────────────────────────────────────────────────────────

@router.get("/stats")
async def get_stats(
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    total      = (await db.execute(select(func.count(ThreatIntelIOC.id)))).scalar_one()
    active     = (await db.execute(select(func.count(ThreatIntelIOC.id)).where(ThreatIntelIOC.is_active == True))).scalar_one()
    critical   = (await db.execute(select(func.count(ThreatIntelIOC.id)).where(ThreatIntelIOC.severity == "CRITICAL", ThreatIntelIOC.is_active == True))).scalar_one()
    high       = (await db.execute(select(func.count(ThreatIntelIOC.id)).where(ThreatIntelIOC.severity == "HIGH",     ThreatIntelIOC.is_active == True))).scalar_one()
    hit_total  = (await db.execute(select(func.coalesce(func.sum(ThreatIntelIOC.hit_count), 0)))).scalar_one()

    # By type
    type_rows = (await db.execute(
        select(ThreatIntelIOC.ioc_type, func.count(ThreatIntelIOC.id))
        .where(ThreatIntelIOC.is_active == True)
        .group_by(ThreatIntelIOC.ioc_type)
    )).all()

    # Top hits
    top_hits = (await db.execute(
        select(ThreatIntelIOC)
        .where(ThreatIntelIOC.hit_count > 0)
        .order_by(ThreatIntelIOC.hit_count.desc())
        .limit(5)
    )).scalars().all()

    return {
        "total": total,
        "active": active,
        "critical": critical,
        "high": high,
        "total_hits": int(hit_total),
        "vt_enabled": bool(getattr(settings, "VT_API_KEY", "")),
        "abuseipdb_enabled": settings.ABUSEIPDB_ENABLED,
        "by_type": {r[0]: r[1] for r in type_rows},
        "top_hits": [
            {
                "id": r.id, "ioc_type": r.ioc_type, "value": r.value,
                "hit_count": r.hit_count, "severity": r.severity,
            }
            for r in top_hits
        ],
    }


# ── List IOCs ──────────────────────────────────────────────────────────────────

@router.get("/iocs")
async def list_iocs(
    ioc_type:  Optional[str] = Query(None),
    severity:  Optional[str] = Query(None),
    source:    Optional[str] = Query(None),
    search:    Optional[str] = Query(None),
    is_active: Optional[bool] = Query(True),
    limit: int  = Query(100, le=500),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    q = select(ThreatIntelIOC)
    if is_active is not None:
        q = q.where(ThreatIntelIOC.is_active == is_active)
    if ioc_type:
        q = q.where(ThreatIntelIOC.ioc_type == ioc_type)
    if severity:
        q = q.where(ThreatIntelIOC.severity == severity)
    if source:
        q = q.where(ThreatIntelIOC.source == source)
    if search:
        q = q.where(ThreatIntelIOC.value.ilike(f"%{search}%"))

    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    rows  = (await db.execute(q.order_by(ThreatIntelIOC.created_at.desc()).limit(limit).offset(offset))).scalars().all()

    return {
        "total": total,
        "items": [_ioc_dict(r) for r in rows],
    }


# ── Create IOC ─────────────────────────────────────────────────────────────────

@router.post("/iocs", status_code=201)
async def create_ioc(
    body: IOCCreate,
    db: AsyncSession  = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    existing = (await db.execute(
        select(ThreatIntelIOC).where(
            ThreatIntelIOC.ioc_type == body.ioc_type,
            ThreatIntelIOC.value    == body.value,
        )
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(409, f"IOC {body.ioc_type}:{body.value} already exists")

    expires_at = None
    if body.expires_days:
        expires_at = datetime.utcnow() + timedelta(days=body.expires_days)

    ioc = ThreatIntelIOC(
        ioc_type=body.ioc_type,
        value=body.value,
        source=body.source,
        severity=body.severity,
        confidence=body.confidence,
        description=body.description,
        tags=body.tags,
        malware_family=body.malware_family,
        expires_at=expires_at,
        created_by=user.username if hasattr(user, 'username') else str(user),
    )
    db.add(ioc)
    await db.flush()

    # Auto-enrich with VirusTotal if key is set
    vt_key = getattr(settings, "VT_API_KEY", "")
    if vt_key and body.ioc_type in ("ip", "domain", "md5", "sha1", "sha256", "url"):
        try:
            vt = await lookup_virustotal(body.ioc_type, body.value, vt_key)
            if vt:
                ioc.vt_malicious = vt.get("vt_malicious")
                ioc.vt_total     = vt.get("vt_total")
                ioc.vt_permalink = vt.get("vt_permalink")
                ioc.vt_raw       = vt.get("vt_raw")
        except Exception as e:
            logger.debug(f"VT enrichment failed: {e}")

    await db.flush()
    return _ioc_dict(ioc)


# ── Update IOC ─────────────────────────────────────────────────────────────────

@router.put("/iocs/{ioc_id}")
async def update_ioc(
    ioc_id: int,
    body: IOCUpdate,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    ioc = (await db.execute(select(ThreatIntelIOC).where(ThreatIntelIOC.id == ioc_id))).scalar_one_or_none()
    if not ioc:
        raise HTTPException(404, "IOC not found")

    if body.severity    is not None: ioc.severity    = body.severity
    if body.confidence  is not None: ioc.confidence  = body.confidence
    if body.description is not None: ioc.description = body.description
    if body.tags        is not None: ioc.tags        = body.tags
    if body.malware_family is not None: ioc.malware_family = body.malware_family
    if body.is_active   is not None: ioc.is_active   = body.is_active
    if body.expires_days is not None:
        ioc.expires_at = datetime.utcnow() + timedelta(days=body.expires_days)

    await db.flush()
    return _ioc_dict(ioc)


# ── Delete IOC ─────────────────────────────────────────────────────────────────

@router.delete("/iocs/{ioc_id}", status_code=204)
async def delete_ioc(
    ioc_id: int,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    ioc = (await db.execute(select(ThreatIntelIOC).where(ThreatIntelIOC.id == ioc_id))).scalar_one_or_none()
    if not ioc:
        raise HTTPException(404, "IOC not found")
    await db.delete(ioc)


# ── Real-time Lookup ───────────────────────────────────────────────────────────

@router.post("/lookup")
async def lookup_ioc(
    body: LookupRequest,
    db: AsyncSession  = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    result: dict = {
        "ioc_type": body.ioc_type,
        "value": body.value,
        "db_match": None,
        "virustotal": None,
        "abuseipdb": None,
        "verdict": "unknown",
    }

    # 1. Check local IOC DB
    db_row = (await db.execute(
        select(ThreatIntelIOC).where(
            ThreatIntelIOC.ioc_type == body.ioc_type,
            ThreatIntelIOC.value    == body.value,
            ThreatIntelIOC.is_active == True,
        )
    )).scalar_one_or_none()
    if db_row:
        result["db_match"] = _ioc_dict(db_row)
        result["verdict"]  = db_row.severity.lower()

    if not body.enrich:
        return result

    # 2. VirusTotal
    vt_key = getattr(settings, "VT_API_KEY", "")
    if vt_key and body.ioc_type in ("ip", "domain", "md5", "sha1", "sha256", "url"):
        try:
            vt = await lookup_virustotal(body.ioc_type, body.value, vt_key)
            if vt:
                result["virustotal"] = {
                    "malicious": vt.get("vt_malicious", 0),
                    "total":     vt.get("vt_total", 0),
                    "permalink": vt.get("vt_permalink"),
                }
                if (vt.get("vt_malicious") or 0) > 0 and result["verdict"] == "unknown":
                    result["verdict"] = "malicious"
        except Exception as e:
            logger.debug(f"VT lookup failed: {e}")

    # 3. AbuseIPDB (IPs only)
    if body.ioc_type == "ip" and settings.ABUSEIPDB_ENABLED:
        try:
            from engine.threat_intel import _check_abuseipdb
            abuse = await _check_abuseipdb(body.value)
            if abuse:
                result["abuseipdb"] = abuse
                if abuse.get("abuse_score", 0) >= settings.ABUSEIPDB_MIN_SCORE:
                    if result["verdict"] == "unknown":
                        result["verdict"] = "suspicious"
        except Exception as e:
            logger.debug(f"AbuseIPDB lookup failed: {e}")

    return result


# ── Re-enrich existing IOC ─────────────────────────────────────────────────────

@router.post("/iocs/{ioc_id}/enrich")
async def enrich_ioc(
    ioc_id: int,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    ioc = (await db.execute(select(ThreatIntelIOC).where(ThreatIntelIOC.id == ioc_id))).scalar_one_or_none()
    if not ioc:
        raise HTTPException(404, "IOC not found")

    vt_key = getattr(settings, "VT_API_KEY", "")
    if not vt_key:
        raise HTTPException(400, "VirusTotal API key not configured")

    vt = await lookup_virustotal(ioc.ioc_type, ioc.value, vt_key)
    if vt:
        ioc.vt_malicious = vt.get("vt_malicious")
        ioc.vt_total     = vt.get("vt_total")
        ioc.vt_permalink = vt.get("vt_permalink")
        ioc.vt_raw       = vt.get("vt_raw")
        ioc.last_seen    = datetime.utcnow()
    await db.flush()
    return _ioc_dict(ioc)


# ── Scan recent alerts for IOC matches ────────────────────────────────────────

@router.post("/scan-alerts")
async def scan_alerts(
    days: int = Query(1, le=30),
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(get_current_user),
):
    from services.threat_intel_service import enrich_alert_with_ti

    since = datetime.utcnow() - timedelta(days=days)
    # Only scan alerts that haven't been TI-enriched yet
    alerts = (await db.execute(
        select(Alert)
        .where(Alert.created_at >= since.replace(tzinfo=None))
        .order_by(Alert.created_at.desc())
        .limit(500)
    )).scalars().all()

    enriched = 0
    hits_total = 0
    for alert in alerts:
        try:
            hits = await enrich_alert_with_ti(db, alert)
            if hits:
                alert.threat_intel = hits
                enriched += 1
                hits_total += len(hits)
        except Exception as e:
            logger.debug(f"Alert {alert.id} TI scan failed: {e}")

    await db.flush()
    return {
        "scanned": len(alerts),
        "enriched": enriched,
        "total_hits": hits_total,
    }


# ── Import feed ────────────────────────────────────────────────────────────────

@router.post("/import-feed")
async def import_feed(
    ioc_type: str = Query(...),
    source:   str = Query("feed"),
    severity: str = Query("MEDIUM"),
    tags:     str = Query(""),     # comma-separated
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    content = (await file.read()).decode("utf-8", errors="ignore")
    lines = content.splitlines()
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []

    result = await import_plaintext_feed(
        db=db,
        lines=lines,
        ioc_type=ioc_type,
        source=source,
        severity=severity,
        tags=tag_list,
        created_by=user.username if hasattr(user, 'username') else "admin",
    )
    return result


# ── Helpers ────────────────────────────────────────────────────────────────────

def _ioc_dict(r: ThreatIntelIOC) -> dict:
    return {
        "id":             r.id,
        "ioc_type":       r.ioc_type,
        "value":          r.value,
        "source":         r.source,
        "severity":       r.severity,
        "confidence":     r.confidence,
        "description":    r.description,
        "tags":           r.tags,
        "malware_family": r.malware_family,
        "vt_malicious":   r.vt_malicious,
        "vt_total":       r.vt_total,
        "vt_permalink":   r.vt_permalink,
        "abuse_score":    r.abuse_score,
        "country":        r.country,
        "asn":            r.asn,
        "hit_count":      r.hit_count,
        "is_active":      r.is_active,
        "first_seen":     r.first_seen.isoformat() if r.first_seen else None,
        "last_seen":      r.last_seen.isoformat()  if r.last_seen  else None,
        "expires_at":     r.expires_at.isoformat() if r.expires_at else None,
        "created_by":     r.created_by,
        "created_at":     r.created_at.isoformat() if r.created_at else None,
    }
