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
