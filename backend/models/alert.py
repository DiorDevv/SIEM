from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, Enum, Text, ForeignKey, JSON, Index
import enum
from database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class AlertStatus(str, enum.Enum):
    open           = "open"
    investigating  = "investigating"
    acknowledged   = "acknowledged"
    resolved       = "resolved"
    false_positive = "false_positive"
    closed         = "closed"


class AlertSeverity(str, enum.Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class AlertNote(Base):
    """Analyst timeline notes attached to an alert."""
    __tablename__ = "alert_notes"

    id         = Column(Integer, primary_key=True, index=True)
    alert_id   = Column(Integer, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True)
    author_id  = Column(Integer, ForeignKey("users.id",  ondelete="SET NULL"), nullable=True)
    author     = Column(String(128), nullable=True)   # denormalized for speed
    body       = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)


class Alert(Base):
    __tablename__ = "alerts"

    id              = Column(Integer, primary_key=True, index=True)
    rule_id         = Column(Integer, ForeignKey("rules.id", ondelete="SET NULL"), nullable=True)
    agent_id        = Column(String(64),  nullable=False, index=True)
    severity        = Column(Enum(AlertSeverity), nullable=False)
    level           = Column(Integer, default=5)
    title           = Column(String(512), nullable=False)
    description     = Column(Text, nullable=True)
    log_id          = Column(String(128), nullable=True)
    status          = Column(Enum(AlertStatus), default=AlertStatus.open, nullable=False, index=True)
    agent_hostname  = Column(String(256), nullable=True)
    rule_name       = Column(String(256), nullable=True)

    # MITRE ATT&CK
    mitre_tactic    = Column(String(128), nullable=True)
    mitre_technique = Column(String(64),  nullable=True)

    # Groups / category
    groups          = Column(String(512), nullable=True)
    category        = Column(String(64),  nullable=True)

    # Threat intelligence enrichment
    src_ip          = Column(String(45),  nullable=True, index=True)
    threat_intel    = Column(JSON,        nullable=True)

    # Raw event data
    raw_log         = Column(Text,        nullable=True)
    parsed_fields   = Column(JSON,        nullable=True)

    # Risk & IOC enrichment
    risk_score      = Column(Integer, nullable=True)
    indicators      = Column(JSON,    nullable=True)

    # ── Aggregation ──────────────────────────────────────────────────────────
    # Multiple events sharing the same (rule, agent, src_ip) are collapsed into
    # one alert instead of creating N identical rows.  event_count tracks how
    # many raw events were absorbed.  first_seen_at / last_seen_at bound the
    # aggregation window.
    agg_key         = Column(String(128), nullable=True, index=True)
    event_count     = Column(Integer, default=1, nullable=False)
    first_seen_at   = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    last_seen_at    = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    assigned_to      = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    assigned_to_name = Column(String(128), nullable=True)   # denormalized display name
    acknowledged_by  = Column(String(128), nullable=True)
    resolved_by      = Column(String(128), nullable=True)
    closed_by        = Column(String(128), nullable=True)
    fp_by            = Column(String(128), nullable=True)   # false_positive marked by

    created_at      = Column(DateTime(timezone=True), default=_utcnow, index=True)
    updated_at      = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    resolved_at     = Column(DateTime(timezone=True), nullable=True)
    closed_at       = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_alert_agg_status",   "agg_key",  "status"),
        Index("ix_alert_agent_status", "agent_id", "status"),
        Index("ix_alert_created_sev",  "created_at", "severity"),
    )
