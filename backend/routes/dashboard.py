from datetime import datetime, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_db
from models.agent import Agent, AgentStatus
from models.alert import Alert, AlertSeverity, AlertStatus
from services.elasticsearch_service import count_logs_per_hour, count_logs_in_range
from routes.auth import get_current_user
from models.user import User

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

# MITRE ATT&CK tactic ordering for the radar chart
MITRE_TACTICS = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Command and Control",
    "Impact",
    "Reconnaissance",
]


@router.get("/stats")
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    now = datetime.utcnow()
    base_hour    = now.replace(minute=0, second=0, microsecond=0)
    today_start  = now.replace(hour=0, minute=0, second=0, microsecond=0)
    cutoff_24h   = now - timedelta(hours=24)
    week_start   = now - timedelta(days=7)

    # ── Agent counts ──────────────────────────────────────────────────────────
    r = await db.execute(
        select(
            func.count(Agent.id).label("total"),
            func.count(Agent.id).filter(Agent.status == AgentStatus.online).label("online"),
            func.count(Agent.id).filter(Agent.status == AgentStatus.offline).label("offline"),
        ).where(Agent.is_active == True)
    )
    agent_row    = r.one()
    total_agents  = agent_row.total   or 0
    online_agents = agent_row.online  or 0
    offline_agents= agent_row.offline or 0

    # ── Log counts ────────────────────────────────────────────────────────────
    total_logs_today = await count_logs_in_range(today_start, now)
    total_logs_week  = await count_logs_in_range(week_start, now)

    # ── Alert counts (scalar aggregates — one query) ──────────────────────────
    r = await db.execute(
        select(
            func.count(Alert.id).label("today"),
            func.count(Alert.id).filter(
                Alert.created_at >= today_start,
                Alert.severity == AlertSeverity.CRITICAL,
            ).label("critical_today"),
            func.count(Alert.id).filter(Alert.status == AlertStatus.open).label("open"),
        ).where(Alert.created_at >= today_start)
    )
    alert_row           = r.one()
    total_alerts_today  = alert_row.today          or 0
    critical_alerts_today = alert_row.critical_today or 0

    open_r = await db.execute(
        select(func.count(Alert.id)).where(Alert.status == AlertStatus.open)
    )
    open_alerts = open_r.scalar_one() or 0

    # ── Alerts by severity (all-time totals) ──────────────────────────────────
    sev_r = await db.execute(
        select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    )
    alerts_by_severity = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for sev, cnt in sev_r.all():
        if sev:
            alerts_by_severity[str(sev).upper()] = cnt

    # ── Alerts per hour — last 24 h (single query, not 24 loops) ─────────────
    aph_r = await db.execute(
        select(
            func.date_trunc("hour", Alert.created_at).label("h"),
            func.count(Alert.id).label("cnt"),
        )
        .where(Alert.created_at >= cutoff_24h)
        .group_by("h")
    )
    aph_map = {row.h: row.cnt for row in aph_r.all()}
    alerts_per_hour = [
        {
            "hour": (base_hour - timedelta(hours=i)).strftime("%H:00"),
            "count": aph_map.get(base_hour - timedelta(hours=i), 0),
        }
        for i in range(23, -1, -1)
    ]

    # ── Severity trend — last 24 h × 4 levels (single query) ─────────────────
    trend_r = await db.execute(
        select(
            func.date_trunc("hour", Alert.created_at).label("h"),
            Alert.severity,
            func.count(Alert.id).label("cnt"),
        )
        .where(Alert.created_at >= cutoff_24h)
        .group_by("h", Alert.severity)
    )
    # skeleton: all 24 h pre-filled with zeros
    trend_map: dict[datetime, dict] = {}
    for i in range(23, -1, -1):
        hdt = base_hour - timedelta(hours=i)
        trend_map[hdt] = {"hour": hdt.strftime("%H:00"),
                          "critical": 0, "high": 0, "medium": 0, "low": 0}
    for row in trend_r.all():
        bucket = row.h
        if bucket in trend_map and row.severity:
            key = str(row.severity).lower()
            if key in trend_map[bucket]:
                trend_map[bucket][key] = row.cnt
    severity_trend = [trend_map[k] for k in sorted(trend_map)]

    # ── MITRE ATT&CK tactic distribution (all-time) ───────────────────────────
    mitre_r = await db.execute(
        select(Alert.mitre_tactic, func.count(Alert.id).label("cnt"))
        .where(Alert.mitre_tactic.isnot(None), Alert.mitre_tactic != "")
        .group_by(Alert.mitre_tactic)
    )
    mitre_raw = {row[0]: row[1] for row in mitre_r.all()}
    # Ensure all known tactics present (zeros for unseen ones)
    alerts_by_tactic = {tactic: mitre_raw.get(tactic, 0) for tactic in MITRE_TACTICS}
    # Also include any unknown tactics captured in the DB
    for tactic, cnt in mitre_raw.items():
        if tactic not in alerts_by_tactic:
            alerts_by_tactic[tactic] = cnt

    # ── Logs per hour — last 24 h ─────────────────────────────────────────────
    logs_per_hour = await count_logs_per_hour(24)

    # ── Top agents by alert count ─────────────────────────────────────────────
    top_r = await db.execute(
        select(Alert.agent_hostname, func.count(Alert.id).label("cnt"))
        .group_by(Alert.agent_hostname)
        .order_by(func.count(Alert.id).desc())
        .limit(5)
    )
    top_agents_by_alerts = [
        {"agent_hostname": row[0] or "unknown", "count": row[1]}
        for row in top_r.all()
    ]

    # ── Recent alerts ─────────────────────────────────────────────────────────
    recent_r = await db.execute(
        select(Alert).order_by(Alert.created_at.desc()).limit(10)
    )
    recent_alerts = [
        {
            "id":             a.id,
            "rule_id":        a.rule_id,
            "agent_id":       a.agent_id,
            "severity":       a.severity,
            "level":          a.level,
            "title":          a.title,
            "description":    a.description,
            "status":         a.status,
            "agent_hostname": a.agent_hostname,
            "rule_name":      a.rule_name,
            "mitre_tactic":   a.mitre_tactic,
            "mitre_technique":a.mitre_technique,
            "src_ip":         a.src_ip,
            "created_at":     a.created_at,
        }
        for a in recent_r.scalars().all()
    ]

    return {
        "total_agents":        total_agents,
        "online_agents":       online_agents,
        "offline_agents":      offline_agents,
        "total_logs_today":    total_logs_today,
        "total_logs_week":     total_logs_week,
        "total_alerts_today":  total_alerts_today,
        "critical_alerts_today": critical_alerts_today,
        "open_alerts":         open_alerts,
        "alerts_by_severity":  alerts_by_severity,
        "alerts_per_hour":     alerts_per_hour,
        "logs_per_hour":       logs_per_hour,
        "severity_trend":      severity_trend,
        "alerts_by_tactic":    alerts_by_tactic,
        "top_agents_by_alerts":top_agents_by_alerts,
        "recent_alerts":       recent_alerts,
    }


@router.get("/system-info")
async def get_system_info(current_user: User = Depends(get_current_user)):
    import platform
    import time
    start = time.time()
    return {
        "version":        "1.0.0",
        "platform":       platform.system(),
        "python_version": platform.python_version(),
        "uptime":         platform.node(),
    }
