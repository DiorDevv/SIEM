import logging
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_db
from models.agent import Agent
from engine.log_parser import normalize_log
from engine.rule_engine import run_rules_against_logs
from services.elasticsearch_service import bulk_index_logs, search_logs
from services.notification_service import notify_critical_log
from routes.auth import get_current_user
from models.user import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/logs", tags=["logs"])

EVENT_TYPES = [
    "screen_lock", "screen_unlock", "screen_auth_failure",
    "user_login", "user_logout",
    "ssh_login", "ssh_failed", "ssh_auth_failure", "ssh_invalid_user", "ssh_disconnect",
    "sudo_command", "sudo_auth_failure", "sudo_denied",
    "user_created", "user_deleted", "group_created", "password_changed",
    "usb_connected", "usb_disconnected",
    "network_up", "network_down", "wifi_connected",
    "system_shutdown", "process_crash", "oom_kill",
    "package_installed", "package_removed",
    "cron_exec", "firewall_block", "firewall_allow",
    "ssh_accepted", "ssh_invalid_user",
    "windows_event", "auditd_event",
    "system_log",
]


@router.get("/event-types")
async def list_event_types(current_user: User = Depends(get_current_user)):
    return {"event_types": sorted(set(EVENT_TYPES))}


class LogEntry(BaseModel):
    timestamp: Optional[str] = None
    level: Optional[str] = None
    source: Optional[str] = None
    message: str
    raw: Optional[str] = None
    parsed_fields: Optional[dict] = None


class LogIngestRequest(BaseModel):
    agent_id: str
    logs: List[LogEntry]


@router.post("/ingest")
async def ingest_logs(
    request: LogIngestRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Agent).where(Agent.agent_id == request.agent_id, Agent.is_active == True)
    result = await db.execute(stmt)
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not registered")

    agent.last_seen = datetime.utcnow()
    agent_id_str   = request.agent_id
    agent_hostname = agent.hostname

    normalized_logs = []
    for entry in request.logs:
        raw_dict = entry.dict()
        raw_dict["agent_id"] = request.agent_id
        normalized = normalize_log(raw_dict)
        normalized_logs.append(normalized)

    try:
        es_ids = await bulk_index_logs(normalized_logs)
        for i, es_id in enumerate(es_ids):
            if i < len(normalized_logs):
                normalized_logs[i]["id"] = es_id
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Elasticsearch error: {str(e)}")

    for log in normalized_logs:
        if log.get("level") in ("CRITICAL", "ERROR"):
            background_tasks.add_task(notify_critical_log, log)

    try:
        await run_rules_against_logs(db, normalized_logs, agent_id_str, agent_hostname)
    except Exception as e:
        logger.error(f"Rule engine error: {e}", exc_info=True)

    return {"message": f"Ingested {len(normalized_logs)} logs", "count": len(normalized_logs)}


@router.get("")
async def get_logs(
    agent_id: Optional[str] = None,
    level: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    keyword: Optional[str] = None,
    event_type: Optional[str] = None,
    source: Optional[str] = None,
    page: int = 1,
    size: int = 50,
    current_user: User = Depends(get_current_user),
):
    if size > 200:
        size = 200
    result = await search_logs(
        agent_id=agent_id,
        level=level,
        start_time=start_time,
        end_time=end_time,
        keyword=keyword,
        event_type=event_type,
        source=source,
        page=page,
        size=size,
    )
    return result
