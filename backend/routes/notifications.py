"""
Notification channels — CRUD + test endpoint.
Admin only.
"""
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.notification import NotificationChannel
from routes.auth import require_admin
from models.user import User

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class ChannelIn(BaseModel):
    name:         str
    type:         str                   # email | telegram | slack | discord | webhook
    config:       Dict[str, Any]
    enabled:      bool = True
    min_severity: str  = "HIGH"         # LOW | MEDIUM | HIGH | CRITICAL


class ChannelOut(BaseModel):
    id:           int
    name:         str
    type:         str
    config:       Dict[str, Any]
    enabled:      bool
    min_severity: str
    created_at:   Optional[datetime]
    updated_at:   Optional[datetime]

    class Config:
        from_attributes = True


# ── Helpers ───────────────────────────────────────────────────────────────────

def _mask(ch: NotificationChannel) -> dict:
    """Return channel dict with sensitive fields masked for display."""
    cfg = dict(ch.config or {})
    for sensitive in ("smtp_password", "bot_token", "api_key"):
        if sensitive in cfg and cfg[sensitive]:
            cfg[sensitive] = "••••••••"
    return {
        "id":           ch.id,
        "name":         ch.name,
        "type":         ch.type,
        "config":       cfg,
        "enabled":      ch.enabled,
        "min_severity": ch.min_severity,
        "created_at":   ch.created_at.isoformat() if ch.created_at else None,
        "updated_at":   ch.updated_at.isoformat() if ch.updated_at else None,
    }


# ── CRUD ──────────────────────────────────────────────────────────────────────

@router.get("")
async def list_channels(
    db: AsyncSession = Depends(get_db),
    _: User          = Depends(require_admin),
):
    rows = (await db.execute(
        select(NotificationChannel).order_by(NotificationChannel.id)
    )).scalars().all()
    return [_mask(r) for r in rows]


@router.post("", status_code=201)
async def create_channel(
    body: ChannelIn,
    db: AsyncSession = Depends(get_db),
    _: User          = Depends(require_admin),
):
    allowed = {"email", "telegram", "slack", "discord", "webhook"}
    if body.type not in allowed:
        raise HTTPException(400, f"type must be one of {allowed}")

    ch = NotificationChannel(
        name=body.name, type=body.type, config=body.config,
        enabled=body.enabled, min_severity=body.min_severity.upper(),
    )
    db.add(ch)
    await db.commit()
    await db.refresh(ch)
    return _mask(ch)


@router.put("/{channel_id}")
async def update_channel(
    channel_id: int,
    body: ChannelIn,
    db: AsyncSession = Depends(get_db),
    _: User          = Depends(require_admin),
):
    ch = (await db.get(NotificationChannel, channel_id))
    if not ch:
        raise HTTPException(404, "Channel not found")

    ch.name         = body.name
    ch.type         = body.type
    ch.enabled      = body.enabled
    ch.min_severity = body.min_severity.upper()

    # Merge config: keep existing passwords if masked value sent
    new_cfg = dict(body.config)
    for sensitive in ("smtp_password", "bot_token", "api_key"):
        if new_cfg.get(sensitive) == "••••••••":
            new_cfg[sensitive] = (ch.config or {}).get(sensitive, "")
    ch.config = new_cfg

    await db.commit()
    await db.refresh(ch)
    return _mask(ch)


@router.delete("/{channel_id}", status_code=204)
async def delete_channel(
    channel_id: int,
    db: AsyncSession = Depends(get_db),
    _: User          = Depends(require_admin),
):
    ch = await db.get(NotificationChannel, channel_id)
    if not ch:
        raise HTTPException(404, "Channel not found")
    await db.delete(ch)
    await db.commit()


# ── Test ──────────────────────────────────────────────────────────────────────

@router.post("/{channel_id}/test")
async def test_channel(
    channel_id: int,
    db: AsyncSession = Depends(get_db),
    admin: User      = Depends(require_admin),
):
    ch = await db.get(NotificationChannel, channel_id)
    if not ch:
        raise HTTPException(404, "Channel not found")

    # Build a fake alert object
    class FakeAlert:
        id             = 0
        severity       = "HIGH"
        title          = "Test Notification — SecureWatch SIEM"
        agent_hostname = "test-agent"
        src_ip         = "192.168.1.1"
        mitre_tactic   = "Initial Access"
        mitre_technique = "T1078"
        rule_name      = "Test Rule"
        description    = "This is a test notification from SecureWatch SIEM."
        status         = "open"

    result = "ok"
    cfg = ch.config or {}
    try:
        from services.notification_service import (
            send_telegram_alert, send_webhook_alert, _send_channel_email
        )
        if ch.type == "email":
            await _send_channel_email(FakeAlert(), cfg)
        elif ch.type == "telegram":
            await send_telegram_alert(FakeAlert(), cfg.get("bot_token", ""), cfg.get("chat_id", ""))
        elif ch.type in ("slack", "discord", "webhook"):
            url = cfg.get("webhook_url", "")
            if url:
                await send_webhook_alert(FakeAlert(), url)
            else:
                result = "missing webhook_url"
        else:
            result = f"unknown type: {ch.type}"
    except Exception as e:
        result = str(e)

    return {"success": result == "ok", "message": result}
