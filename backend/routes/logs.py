import csv
import io
import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.agent import Agent
from engine.log_parser import normalize_log
from engine.rule_engine import run_rules_against_logs
from engine.threat_intel import enrich_log, extract_ips_from_log
from services.elasticsearch_service import (
    bulk_index_logs,
    search_logs,
    get_log_sources,
    get_log_stats,
    get_dynamic_event_types,
)
from services.notification_service import notify_critical_log
from routes.auth import get_current_user
from models.user import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/logs", tags=["logs"])

# Static fallback — merged with dynamic event types from ES
_STATIC_EVENT_TYPES = sorted({
    # Auth / Session
    "screen_lock", "screen_unlock", "screen_auth_failure",
    "authentication_success", "authentication_failed",
    "pam_auth_failed", "pam_account_locked", "pam_session_opened", "pam_session_closed",
    # SSH
    "ssh_failed", "ssh_invalid_user", "ssh_disconnect", "ssh_accepted", "max_auth_exceeded",
    # Sudo
    "sudo_command", "sudo_auth_failure", "sudo_denied",
    # User / Group
    "user_created", "user_deleted", "group_created", "password_changed",
    # Network
    "network_connected", "network_disconnected", "network_connection",
    "wifi_connected", "wifi_disconnected", "wifi_auth_failed",
    "firewall_block", "firewall_allow", "ufw_block",
    # USB / Bluetooth
    "usb_connected", "usb_disconnected", "bt_connected", "bt_disconnected",
    # System
    "system_suspend", "system_resume", "system_shutdown", "kernel_panic",
    "oom_kill", "process_crash",
    # Services
    "service_started", "service_stopped", "service_failed",
    "service_crashed", "service_timeout", "service_reloaded",
    # Containers
    "container_started", "container_stopped", "container_killed", "docker_error",
    # Packages
    "package_installed", "package_removed", "package_upgraded",
    # Cron
    "cron_job", "suspicious_cron",
    # Kernel / AppArmor
    "apparmor_denied",
    # FIM
    "fim_created", "fim_modified", "fim_deleted", "fim_moved", "fim_attrib_changed",
    # Rootcheck
    "rootkit_detected", "hidden_process", "hidden_file", "kernel_module_loaded",
    # Other
    "system_metrics", "windows_event", "auditd_event",
})


class LogEntry(BaseModel):
    timestamp:     Optional[str]  = None
    level:         Optional[str]  = None
    source:        Optional[str]  = None
    message:       str
    raw:           Optional[str]  = None
    parsed_fields: Optional[dict] = None


class LogIngestRequest(BaseModel):
    agent_id: str
    logs:     List[LogEntry]


# ── Ingest ────────────────────────────────────────────────────────────────────

@router.post("/ingest")
async def ingest_logs(
    request:          LogIngestRequest,
    background_tasks: BackgroundTasks,
    db:               AsyncSession = Depends(get_db),
):
    stmt = select(Agent).where(Agent.agent_id == request.agent_id, Agent.is_active == True)
    agent = (await db.execute(stmt)).scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not registered")

    agent.last_seen    = datetime.utcnow()
    agent_id_str       = request.agent_id
    agent_hostname     = agent.hostname

    # Normalize — inject agent_id + hostname into each log
    normalized: list = []
    for entry in request.logs:
        raw_dict = entry.dict()
        raw_dict["agent_id"] = agent_id_str
        raw_dict["hostname"] = agent_hostname
        normalized.append(normalize_log(raw_dict))

    # Enrich with threat intel BEFORE indexing so GeoIP/AbuseIPDB land in ES
    enriched: list = []
    for log in normalized:
        if extract_ips_from_log(log):
            try:
                log = await enrich_log(log)
            except Exception as exc:
                logger.debug(f"Threat intel enrichment skipped: {exc}")
        enriched.append(log)

    # Bulk index to Elasticsearch
    try:
        es_ids = await bulk_index_logs(enriched)
        for i, es_id in enumerate(es_ids):
            if i < len(enriched):
                enriched[i]["id"] = es_id
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Elasticsearch error: {e}")

    # Notify on critical/error logs (background)
    for log in enriched:
        if log.get("level") in ("CRITICAL", "ERROR"):
            background_tasks.add_task(notify_critical_log, log)

    # Rule engine (already has threat intel since we enriched before)
    try:
        await run_rules_against_logs(db, enriched, agent_id_str, agent_hostname)
    except Exception as e:
        logger.error(f"Rule engine error: {e}", exc_info=True)

    return {"message": f"Ingested {len(enriched)} logs", "count": len(enriched)}


# ── Query ─────────────────────────────────────────────────────────────────────

@router.get("")
async def get_logs(
    agent_id:    Optional[str]      = None,
    hostname:    Optional[str]      = None,
    level:       Optional[str]      = None,
    start_time:  Optional[datetime] = None,
    end_time:    Optional[datetime] = None,
    keyword:     Optional[str]      = None,
    event_type:  Optional[str]      = None,   # comma-separated
    source:      Optional[str]      = None,
    sort_by:     str                = Query("timestamp", regex="^(timestamp|level)$"),
    sort_order:  str                = Query("desc",      regex="^(asc|desc)$"),
    page:        int                = Query(1,   ge=1),
    size:        int                = Query(50,  ge=1, le=200),
    current_user: User = Depends(get_current_user),
):
    event_types = (
        [e.strip() for e in event_type.split(",") if e.strip()]
        if event_type else None
    )
    return await search_logs(
        agent_id=agent_id,
        hostname=hostname,
        level=level,
        start_time=start_time,
        end_time=end_time,
        keyword=keyword,
        event_types=event_types,
        source=source,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        size=size,
    )


# ── Metadata endpoints ────────────────────────────────────────────────────────

@router.get("/event-types")
async def list_event_types(current_user: User = Depends(get_current_user)):
    dynamic = await get_dynamic_event_types()
    combined = sorted(set(dynamic) | set(_STATIC_EVENT_TYPES))
    return {"event_types": combined}


@router.get("/sources")
async def list_sources(current_user: User = Depends(get_current_user)):
    sources = await get_log_sources()
    return {"sources": sources}


@router.get("/stats")
async def log_stats(
    hours:        int  = Query(24, ge=1, le=168),
    current_user: User = Depends(get_current_user),
):
    return await get_log_stats(hours=hours)


# ── Export ────────────────────────────────────────────────────────────────────

@router.get("/timeline")
async def log_timeline(
    hours: int = Query(24, ge=1, le=168),
    current_user: User = Depends(get_current_user),
):
    from services.elasticsearch_service import count_logs_per_hour
    buckets = await count_logs_per_hour(hours)
    return {"buckets": buckets, "hours": hours}


@router.get("/export/csv")
async def export_logs_csv(
    agent_id:    Optional[str]      = None,
    hostname:    Optional[str]      = None,
    level:       Optional[str]      = None,
    start_time:  Optional[datetime] = None,
    end_time:    Optional[datetime] = None,
    keyword:     Optional[str]      = None,
    event_type:  Optional[str]      = None,
    source:      Optional[str]      = None,
    current_user: User = Depends(get_current_user),
):
    event_types = (
        [e.strip() for e in event_type.split(",") if e.strip()]
        if event_type else None
    )
    result = await search_logs(
        agent_id=agent_id,
        hostname=hostname,
        level=level,
        start_time=start_time,
        end_time=end_time,
        keyword=keyword,
        event_types=event_types,
        source=source,
        sort_by="timestamp",
        sort_order="desc",
        page=1,
        size=5000,
    )

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "Timestamp", "Level", "Source", "Agent ID", "Hostname",
        "Event Type", "Src IP", "Geo Country", "Message",
    ])
    for log in result["logs"]:
        pf = log.get("parsed_fields") or {}
        writer.writerow([
            log.get("timestamp", ""),
            log.get("level", ""),
            log.get("source", ""),
            log.get("agent_id", ""),
            log.get("hostname", ""),
            pf.get("event_type", ""),
            pf.get("src_ip") or pf.get("ssh_src_ip", ""),
            pf.get("geo_country", ""),
            (log.get("message") or "").replace("\n", " ")[:500],
        ])

    buf.seek(0)
    fname = f"siem_logs_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )
