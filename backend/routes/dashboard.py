"""
Dashboard API — SOC-grade metrics for SecureWatch SIEM.

Metrics returned:
  • Agent status summary
  • Alert volume + severity distribution
  • SOC KPIs: MTTD, MTTR, SLA breach buckets, closure rate
  • Alert lifecycle funnel (open → investigating → resolved)
  • Top attackers (src_ip enriched with threat intel + geo)
  • Geo / country distribution
  • MITRE ATT&CK tactic distribution
  • 24-hour severity trend + alerts per hour
  • 7-day weekly trend
  • Recent alerts (ordered by last activity)
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import select, func, and_, extract
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.agent import Agent, AgentStatus
from models.alert import Alert, AlertSeverity, AlertStatus
from services.elasticsearch_service import count_logs_per_hour, count_logs_in_range
from routes.auth import get_current_user
from models.user import User

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

MITRE_TACTICS = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Exfiltration", "Command and Control", "Impact", "Reconnaissance",
]

_FLAGS: dict[str, str] = {
    "CN": "🇨🇳", "RU": "🇷🇺", "US": "🇺🇸", "DE": "🇩🇪", "NL": "🇳🇱",
    "FR": "🇫🇷", "GB": "🇬🇧", "KR": "🇰🇷", "BR": "🇧🇷", "IN": "🇮🇳",
    "TR": "🇹🇷", "UA": "🇺🇦", "VN": "🇻🇳", "ID": "🇮🇩", "IR": "🇮🇷",
    "PK": "🇵🇰", "MX": "🇲🇽", "TH": "🇹🇭", "PL": "🇵🇱", "RO": "🇷🇴",
    "JP": "🇯🇵", "IT": "🇮🇹", "ES": "🇪🇸", "CA": "🇨🇦", "AU": "🇦🇺",
}


@router.get("/stats")
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    now         = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    base_hour   = now.replace(minute=0, second=0, microsecond=0)
    cutoff_24h  = now - timedelta(hours=24)
    week_start  = now - timedelta(days=7)

    # ── 1. Agents ─────────────────────────────────────────────────────────────
    agent_row = (await db.execute(
        select(
            func.count(Agent.id).label("total"),
            func.count(Agent.id).filter(Agent.status == AgentStatus.online).label("online"),
            func.count(Agent.id).filter(Agent.status == AgentStatus.offline).label("offline"),
        ).where(Agent.is_active == True)
    )).one()
    total_agents   = agent_row.total   or 0
    online_agents  = agent_row.online  or 0
    offline_agents = agent_row.offline or 0

    # ── 2. Log counts ─────────────────────────────────────────────────────────
    total_logs_today = await count_logs_in_range(today_start, now)
    total_logs_week  = await count_logs_in_range(week_start,  now)

    # ── 3. Alert volume ───────────────────────────────────────────────────────
    alert_today_row = (await db.execute(
        select(
            func.count(Alert.id).label("today"),
            func.count(Alert.id).filter(
                Alert.severity == AlertSeverity.CRITICAL
            ).label("critical_today"),
        ).where(Alert.created_at >= today_start)
    )).one()
    total_alerts_today    = alert_today_row.today          or 0
    critical_alerts_today = alert_today_row.critical_today or 0

    open_alerts = (await db.execute(
        select(func.count(Alert.id)).where(Alert.status == AlertStatus.open)
    )).scalar_one() or 0

    # ── 4. Severity distribution ──────────────────────────────────────────────
    sev_rows = (await db.execute(
        select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
    )).all()
    alerts_by_severity = {s: 0 for s in ("LOW", "MEDIUM", "HIGH", "CRITICAL")}
    for sev, cnt in sev_rows:
        if sev:
            key = sev.value if hasattr(sev, 'value') else str(sev).upper().split('.')[-1]
            alerts_by_severity[key] = cnt

    # ── 5. Alert lifecycle funnel ─────────────────────────────────────────────
    status_rows = (await db.execute(
        select(Alert.status, func.count(Alert.id).label("n"))
        .group_by(Alert.status)
    )).all()
    status_distribution = {s.value: 0 for s in AlertStatus}
    for st, cnt in status_rows:
        if st:
            # str(enum) returns "AlertStatus.open" — use .value to get "open"
            key = st.value if hasattr(st, 'value') else str(st)
            if key in status_distribution:
                status_distribution[key] = cnt

    # ── 6. SOC KPIs — MTTD ───────────────────────────────────────────────────
    mttd_sec = (await db.execute(
        select(func.avg(
            extract("epoch", Alert.acknowledged_at) -
            extract("epoch", Alert.created_at)
        )).where(
            Alert.acknowledged_at.isnot(None),
            Alert.created_at >= week_start,
        )
    )).scalar_one()
    mttd_minutes = round(float(mttd_sec) / 60, 1) if mttd_sec else None

    # ── 7. SOC KPIs — MTTR ───────────────────────────────────────────────────
    mttr_sec = (await db.execute(
        select(func.avg(
            extract("epoch", Alert.resolved_at) -
            extract("epoch", Alert.created_at)
        )).where(
            Alert.resolved_at.isnot(None),
            Alert.created_at >= week_start,
        )
    )).scalar_one()
    mttr_minutes = round(float(mttr_sec) / 60, 1) if mttr_sec else None

    # ── 8. SLA breach buckets ─────────────────────────────────────────────────
    _active = [AlertStatus.open, AlertStatus.investigating]

    sla_1h = (await db.execute(
        select(func.count(Alert.id)).where(
            and_(Alert.status.in_(_active),
                 Alert.created_at < now - timedelta(hours=1))
        )
    )).scalar_one() or 0

    sla_4h = (await db.execute(
        select(func.count(Alert.id)).where(
            and_(Alert.status.in_(_active),
                 Alert.created_at < now - timedelta(hours=4))
        )
    )).scalar_one() or 0

    sla_24h = (await db.execute(
        select(func.count(Alert.id)).where(
            and_(Alert.status.in_(_active),
                 Alert.created_at < now - timedelta(hours=24))
        )
    )).scalar_one() or 0

    # ── 9. Top attackers ──────────────────────────────────────────────────────
    top_ip_rows = (await db.execute(
        select(Alert.src_ip, func.count(Alert.id).label("n"))
        .where(Alert.src_ip.isnot(None), Alert.created_at >= week_start)
        .group_by(Alert.src_ip)
        .order_by(func.count(Alert.id).desc())
        .limit(10)
    )).all()

    top_attackers = []
    for ip, count in top_ip_rows:
        ti = (await db.execute(
            select(Alert.threat_intel)
            .where(Alert.src_ip == ip, Alert.threat_intel.isnot(None))
            .order_by(Alert.created_at.desc())
            .limit(1)
        )).scalar_one_or_none()
        country = (ti or {}).get("country_code")
        top_attackers.append({
            "src_ip":      ip,
            "count":       count,
            "country":     country,
            "flag":        _FLAGS.get(country or "", "🌐"),
            "abuse_score": (ti or {}).get("abuse_score"),
            "is_tor":      (ti or {}).get("is_tor", False),
            "isp":         (ti or {}).get("isp"),
        })

    # ── 10. Geo distribution ──────────────────────────────────────────────────
    geo_raw: dict[str, int] = {}
    for a in top_attackers:
        c = a["country"] or "Unknown"
        geo_raw[c] = geo_raw.get(c, 0) + a["count"]
    geo_distribution = [
        {"country": k, "count": v, "flag": _FLAGS.get(k, "🌐")}
        for k, v in sorted(geo_raw.items(), key=lambda x: -x[1])
    ][:10]

    # ── 11. Alerts per hour — last 24 h ──────────────────────────────────────
    aph_rows = (await db.execute(
        select(
            func.date_trunc("hour", Alert.created_at).label("h"),
            func.count(Alert.id).label("cnt"),
        )
        .where(Alert.created_at >= cutoff_24h)
        .group_by("h")
    )).all()
    aph_map = {row.h: row.cnt for row in aph_rows}
    alerts_per_hour = [
        {
            "hour":  (base_hour - timedelta(hours=i)).strftime("%H:00"),
            "count": aph_map.get(base_hour - timedelta(hours=i), 0),
        }
        for i in range(23, -1, -1)
    ]

    # ── 12. Severity trend — last 24 h ───────────────────────────────────────
    trend_rows = (await db.execute(
        select(
            func.date_trunc("hour", Alert.created_at).label("h"),
            Alert.severity,
            func.count(Alert.id).label("cnt"),
        )
        .where(Alert.created_at >= cutoff_24h)
        .group_by("h", Alert.severity)
    )).all()
    trend_map: dict = {}
    for i in range(23, -1, -1):
        hdt = base_hour - timedelta(hours=i)
        trend_map[hdt] = {"hour": hdt.strftime("%H:00"),
                          "critical": 0, "high": 0, "medium": 0, "low": 0}
    for row in trend_rows:
        if row.h in trend_map and row.severity:
            key = (row.severity.value if hasattr(row.severity, 'value') else str(row.severity).split('.')[-1]).lower()
            if key in trend_map[row.h]:
                trend_map[row.h][key] = row.cnt
    severity_trend = [trend_map[k] for k in sorted(trend_map)]

    # ── 13. Weekly trend — last 7 days ───────────────────────────────────────
    weekly_trend = []
    for i in range(6, -1, -1):
        ds = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
        de = ds + timedelta(days=1)
        n  = (await db.execute(
            select(func.count(Alert.id)).where(
                and_(Alert.created_at >= ds, Alert.created_at < de)
            )
        )).scalar_one() or 0
        weekly_trend.append({
            "date":      ds.strftime("%a"),
            "full_date": ds.date().isoformat(),
            "count":     n,
        })

    # ── 14. MITRE distribution ────────────────────────────────────────────────
    mitre_rows = (await db.execute(
        select(Alert.mitre_tactic, func.count(Alert.id).label("cnt"))
        .where(Alert.mitre_tactic.isnot(None), Alert.mitre_tactic != "")
        .group_by(Alert.mitre_tactic)
    )).all()
    mitre_raw = {row[0]: row[1] for row in mitre_rows}
    alerts_by_tactic = {t: mitre_raw.get(t, 0) for t in MITRE_TACTICS}
    for t, cnt in mitre_raw.items():
        if t not in alerts_by_tactic:
            alerts_by_tactic[t] = cnt

    # ── 15. Logs per hour ─────────────────────────────────────────────────────
    logs_per_hour = await count_logs_per_hour(24)

    # ── 16. Top agents by alert count ────────────────────────────────────────
    top_agent_rows = (await db.execute(
        select(Alert.agent_hostname, func.count(Alert.id).label("cnt"))
        .group_by(Alert.agent_hostname)
        .order_by(func.count(Alert.id).desc())
        .limit(5)
    )).all()
    top_agents_by_alerts = [
        {"agent_hostname": row[0] or "unknown", "count": row[1]}
        for row in top_agent_rows
    ]

    # ── 17. Recent alerts (ordered by last activity) ─────────────────────────
    recent_rows = (await db.execute(
        select(Alert).order_by(Alert.last_seen_at.desc()).limit(10)
    )).scalars().all()
    recent_alerts = [
        {
            "id":              a.id,
            "severity":        a.severity,
            "level":           a.level,
            "title":           a.title,
            "status":          a.status,
            "agent_hostname":  a.agent_hostname,
            "rule_name":       a.rule_name,
            "mitre_tactic":    a.mitre_tactic,
            "mitre_technique": a.mitre_technique,
            "src_ip":          a.src_ip,
            "event_count":     a.event_count or 1,
            "created_at":      a.created_at.isoformat() if a.created_at else None,
            "last_seen_at":    a.last_seen_at.isoformat() if a.last_seen_at else None,
        }
        for a in recent_rows
    ]

    return {
        # Agents
        "total_agents":          total_agents,
        "online_agents":         online_agents,
        "offline_agents":        offline_agents,
        # Logs
        "total_logs_today":      total_logs_today,
        "total_logs_week":       total_logs_week,
        # Alerts
        "total_alerts_today":    total_alerts_today,
        "critical_alerts_today": critical_alerts_today,
        "open_alerts":           open_alerts,
        "alerts_by_severity":    alerts_by_severity,
        # Lifecycle
        "status_distribution":   status_distribution,
        # SOC KPIs
        "mttd_minutes":          mttd_minutes,
        "mttr_minutes":          mttr_minutes,
        "sla_breach":            {"gt_1h": sla_1h, "gt_4h": sla_4h, "gt_24h": sla_24h},
        # Threat intel
        "top_attackers":         top_attackers,
        "geo_distribution":      geo_distribution,
        # Charts
        "alerts_per_hour":       alerts_per_hour,
        "severity_trend":        severity_trend,
        "weekly_trend":          weekly_trend,
        "alerts_by_tactic":      alerts_by_tactic,
        "logs_per_hour":         logs_per_hour,
        # Tables
        "top_agents_by_alerts":  top_agents_by_alerts,
        "recent_alerts":         recent_alerts,
    }


@router.get("/system-info")
async def get_system_info(current_user: User = Depends(get_current_user)):
    import platform
    return {
        "version":        "2.0.0",
        "platform":       platform.system(),
        "python_version": platform.python_version(),
        "node":           platform.node(),
    }
