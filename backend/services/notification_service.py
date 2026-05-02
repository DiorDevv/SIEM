"""
Notification service — WebSocket, Email (SMTP), Slack webhook.
All channels are non-blocking: failures are logged, never raised.
"""
import logging
import json
from typing import Optional, List

from config import settings
from services.websocket_manager import ws_manager

logger = logging.getLogger(__name__)


# ── WebSocket ─────────────────────────────────────────────────────────────────

async def notify_new_alert(alert_data: dict):
    try:
        await ws_manager.send_new_alert(alert_data)
    except Exception as e:
        logger.error(f"WS new_alert broadcast failed: {e}")


async def notify_agent_offline(agent_id: str, hostname: str):
    try:
        await ws_manager.send_agent_offline(agent_id, hostname)
    except Exception as e:
        logger.error(f"WS agent_offline broadcast failed: {e}")


async def notify_critical_log(log_data: dict):
    try:
        await ws_manager.send_critical_log(log_data)
    except Exception as e:
        logger.error(f"WS critical_log broadcast failed: {e}")


# ── Email ─────────────────────────────────────────────────────────────────────

def _severity_emoji(severity: str) -> str:
    return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(
        str(severity).upper(), "⚪"
    )


def _build_email_html(alert) -> str:
    sev   = str(getattr(alert, "severity", "")).upper()
    emoji = _severity_emoji(sev)
    colors = {
        "CRITICAL": "#ef4444", "HIGH": "#f97316",
        "MEDIUM":   "#f59e0b", "LOW":  "#3b82f6",
    }
    color = colors.get(sev, "#6b7280")

    return f"""
<html><body style="font-family:Arial,sans-serif;background:#0f1117;color:#e5e7eb;padding:24px;">
  <div style="max-width:600px;margin:auto;background:#161b2e;border-radius:12px;
              border:1px solid {color}40;overflow:hidden;">
    <div style="background:linear-gradient(135deg,{color}20,#161b2e);
                padding:20px 24px;border-bottom:1px solid {color}40;">
      <h2 style="margin:0;color:{color};">{emoji} SecureWatch SIEM Alert</h2>
      <p style="margin:4px 0 0;color:#94a3b8;font-size:13px;">
        Severity: <strong style="color:{color};">{sev}</strong>
      </p>
    </div>
    <div style="padding:24px;">
      <table style="width:100%;border-collapse:collapse;font-size:14px;">
        <tr><td style="padding:8px 0;color:#94a3b8;width:140px;">Title</td>
            <td style="padding:8px 0;color:#fff;font-weight:bold;">{getattr(alert,'title','')}</td></tr>
        <tr><td style="padding:8px 0;color:#94a3b8;">Agent</td>
            <td style="padding:8px 0;color:#e5e7eb;">{getattr(alert,'agent_hostname','')}</td></tr>
        <tr><td style="padding:8px 0;color:#94a3b8;">Source IP</td>
            <td style="padding:8px 0;color:#e5e7eb;">{getattr(alert,'src_ip','') or '—'}</td></tr>
        <tr><td style="padding:8px 0;color:#94a3b8;">MITRE Tactic</td>
            <td style="padding:8px 0;color:#e5e7eb;">{getattr(alert,'mitre_tactic','') or '—'}</td></tr>
        <tr><td style="padding:8px 0;color:#94a3b8;">MITRE Tech</td>
            <td style="padding:8px 0;color:#e5e7eb;">{getattr(alert,'mitre_technique','') or '—'}</td></tr>
        <tr><td style="padding:8px 0;color:#94a3b8;">Description</td>
            <td style="padding:8px 0;color:#e5e7eb;">{(getattr(alert,'description','') or '')[:400]}</td></tr>
      </table>
    </div>
  </div>
</body></html>
""".strip()


async def send_alert_email(alert, extra_recipients: Optional[str] = None):
    if not settings.SMTP_ENABLED:
        return

    try:
        import aiosmtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
    except ImportError:
        logger.warning("aiosmtplib not installed — email disabled")
        return

    recipients: List[str] = []
    if settings.SMTP_TO:
        recipients += [r.strip() for r in settings.SMTP_TO.split(",") if r.strip()]
    if extra_recipients:
        recipients += [r.strip() for r in extra_recipients.split(",") if r.strip()]
    if not recipients:
        logger.warning("Email: no recipients configured")
        return

    sev   = str(getattr(alert, "severity", "")).upper()
    emoji = _severity_emoji(sev)
    title = getattr(alert, "title", "Alert")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"{emoji} [{sev}] {title} — SecureWatch SIEM"
    msg["From"]    = settings.SMTP_FROM
    msg["To"]      = ", ".join(recipients)
    msg.attach(MIMEText(_build_email_html(alert), "html"))

    try:
        await aiosmtplib.send(
            msg,
            hostname  = settings.SMTP_HOST,
            port      = settings.SMTP_PORT,
            username  = settings.SMTP_USERNAME or None,
            password  = settings.SMTP_PASSWORD or None,
            start_tls = settings.SMTP_USE_TLS,
        )
        logger.info(f"Email sent for alert '{title}' → {recipients}")
    except Exception as e:
        logger.error(f"SMTP send failed: {e}")


# ── Slack ─────────────────────────────────────────────────────────────────────

def _build_slack_payload(alert) -> dict:
    sev   = str(getattr(alert, "severity", "")).upper()
    emoji = _severity_emoji(sev)
    colors = {
        "CRITICAL": "#ef4444", "HIGH": "#f97316",
        "MEDIUM":   "#f59e0b", "LOW":  "#3b82f6",
    }
    color = colors.get(sev, "#6b7280")
    title = getattr(alert, "title", "Alert")
    agent = getattr(alert, "agent_hostname", "unknown")
    src   = getattr(alert, "src_ip", "") or "—"
    desc  = (getattr(alert, "description", "") or "")[:300]
    tactic = getattr(alert, "mitre_tactic", "") or ""
    tech   = getattr(alert, "mitre_technique", "") or ""

    return {
        "channel": settings.SLACK_CHANNEL,
        "text":    f"{emoji} *[{sev}]* {title}",
        "attachments": [{
            "color": color,
            "fields": [
                {"title": "Agent",        "value": agent,  "short": True},
                {"title": "Source IP",    "value": src,    "short": True},
                {"title": "MITRE Tactic", "value": tactic or "—", "short": True},
                {"title": "MITRE Tech",   "value": tech   or "—", "short": True},
                {"title": "Description",  "value": desc,   "short": False},
            ],
            "footer": "SecureWatch SIEM",
            "ts": int(__import__("time").time()),
        }],
    }


async def send_slack_alert(alert):
    if not settings.SLACK_ENABLED or not settings.SLACK_WEBHOOK_URL:
        return

    import aiohttp

    payload = _build_slack_payload(alert)
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                settings.SLACK_WEBHOOK_URL,
                json    = payload,
                timeout = aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    logger.error(f"Slack webhook {resp.status}: {body}")
                else:
                    logger.info(f"Slack alert sent: {getattr(alert,'title','')}")
    except Exception as e:
        logger.error(f"Slack send failed: {e}")


# ── Telegram ──────────────────────────────────────────────────────────────────

async def send_telegram_alert(alert, bot_token: str, chat_id: str):
    sev   = str(getattr(alert, "severity", "")).upper()
    emoji = _severity_emoji(sev)
    title = getattr(alert, "title", "Alert")
    agent = getattr(alert, "agent_hostname", "unknown")
    src   = getattr(alert, "src_ip", "") or "—"
    tactic = getattr(alert, "mitre_tactic", "") or "—"

    text = (
        f"{emoji} *\\[{sev}\\] {title}*\n"
        f"Agent: `{agent}`  |  IP: `{src}`\n"
        f"MITRE: {tactic}\n"
        f"Rule: {getattr(alert, 'rule_name', '') or '—'}"
    )

    import httpx
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(url, json={
                "chat_id": chat_id, "text": text, "parse_mode": "MarkdownV2"
            })
            if r.status_code != 200:
                logger.error(f"Telegram {r.status_code}: {r.text[:200]}")
            else:
                logger.info(f"Telegram alert sent: {title}")
    except Exception as e:
        logger.error(f"Telegram send failed: {e}")


# ── Generic webhook ───────────────────────────────────────────────────────────

async def send_webhook_alert(alert, webhook_url: str):
    sev = str(getattr(alert, "severity", "")).upper()
    import httpx, time
    payload = {
        "severity":     sev,
        "title":        getattr(alert, "title", ""),
        "agent":        getattr(alert, "agent_hostname", ""),
        "src_ip":       getattr(alert, "src_ip", ""),
        "mitre_tactic": getattr(alert, "mitre_tactic", ""),
        "rule_name":    getattr(alert, "rule_name", ""),
        "alert_id":     getattr(alert, "id", None),
        "timestamp":    time.time(),
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(webhook_url, json=payload)
            if r.status_code not in (200, 201, 204):
                logger.error(f"Webhook {r.status_code}: {r.text[:200]}")
    except Exception as e:
        logger.error(f"Webhook send failed: {e}")


# ── DB-backed channel dispatch ────────────────────────────────────────────────

_SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


async def notify_alert_channels(db, alert) -> None:
    """
    Dispatch alert to all enabled DB-backed notification channels
    if alert severity >= channel.min_severity.
    Called from rule_engine after alert upsert.
    """
    try:
        from sqlalchemy import select
        from models.notification import NotificationChannel

        channels = (await db.execute(
            select(NotificationChannel).where(NotificationChannel.enabled == True)
        )).scalars().all()

        if not channels:
            return

        sev = str(getattr(alert, "severity", "LOW")).upper().replace("ALERTSEVERITY.", "")
        sev_val = _SEV_ORDER.get(sev, 0)

        for ch in channels:
            min_sev = (ch.min_severity or "HIGH").upper()
            if sev_val < _SEV_ORDER.get(min_sev, 2):
                continue
            cfg = ch.config or {}
            try:
                if ch.type == "email":
                    # Reuse existing send_alert_email but with channel config
                    await _send_channel_email(alert, cfg)
                elif ch.type == "telegram":
                    await send_telegram_alert(alert, cfg.get("bot_token", ""), cfg.get("chat_id", ""))
                elif ch.type in ("slack", "discord", "webhook"):
                    url = cfg.get("webhook_url", "")
                    if url:
                        await send_webhook_alert(alert, url)
            except Exception as exc:
                logger.error(f"Channel {ch.name} ({ch.type}) dispatch error: {exc}")
    except Exception as e:
        logger.error(f"notify_alert_channels failed: {e}")


async def _send_channel_email(alert, cfg: dict):
    """Send email using per-channel SMTP config."""
    host     = cfg.get("smtp_host", settings.SMTP_HOST)
    port     = int(cfg.get("smtp_port", settings.SMTP_PORT))
    username = cfg.get("smtp_user", settings.SMTP_USERNAME)
    password = cfg.get("smtp_password", settings.SMTP_PASSWORD)
    to       = cfg.get("to_email", settings.SMTP_TO)
    use_tls  = cfg.get("use_tls", settings.SMTP_USE_TLS)

    if not (host and to):
        return

    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    import aiosmtplib

    sev   = str(getattr(alert, "severity", "")).upper()
    emoji = _severity_emoji(sev)
    title = getattr(alert, "title", "Alert")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"{emoji} [{sev}] {title} — SecureWatch SIEM"
    msg["From"]    = username or f"siem@{host}"
    msg["To"]      = to
    msg.attach(MIMEText(_build_email_html(alert), "html"))

    await aiosmtplib.send(
        msg,
        hostname=host, port=port,
        username=username or None, password=password or None,
        start_tls=use_tls,
    )
