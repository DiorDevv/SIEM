"""
Correlation Engine — multi-event detection rules.

Rule types:
  threshold   — N events matching criteria within T seconds (brute-force, port-scan)
  sequence    — event A followed by event B within T seconds (lateral movement)
  aggregation — aggregate field reaches a threshold (high data volume)
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON, Index
from database import Base


def _utcnow():
    return datetime.utcnow()


class CorrelationRule(Base):
    __tablename__ = "correlation_rules"

    id          = Column(Integer, primary_key=True, index=True)
    name        = Column(String(256), nullable=False)
    description = Column(Text,        nullable=True)
    rule_type   = Column(String(32),  default="threshold", nullable=False)
    # threshold | sequence | aggregation

    enabled     = Column(Boolean, default=True, nullable=False, index=True)
    severity    = Column(String(16), default="HIGH", nullable=False)

    # Threshold / aggregation config
    threshold_count      = Column(Integer, default=5)
    time_window_seconds  = Column(Integer, default=300)

    # Conditions JSON — defines what to match and how to group
    # threshold example:
    # {
    #   "source": "logs",           # "logs" | "alerts"
    #   "filters": {
    #     "message__contains": "authentication failure",
    #     "level": "WARNING"
    #   },
    #   "group_by": "agent_id"      # agent_id | src_ip | hostname | rule_name
    # }
    # sequence example:
    # {
    #   "source": "alerts",
    #   "steps": [
    #     {"filters": {"title__contains": "Port Scan"}},
    #     {"filters": {"title__contains": "Brute Force"}}
    #   ],
    #   "group_by": "agent_id"
    # }
    conditions = Column(JSON, nullable=True)

    alert_title_template = Column(
        String(512),
        default="{rule_name}: {count} events in {window}s from {group_value}"
    )
    mitre_tactics    = Column(JSON, nullable=True)
    mitre_techniques = Column(JSON, nullable=True)

    # Anti-flood — don't re-fire same rule for same group within cooldown
    cooldown_seconds = Column(Integer, default=300)

    # Stats
    trigger_count  = Column(Integer,  default=0)
    last_triggered = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=_utcnow, nullable=False)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
    created_by = Column(String(128), nullable=True)

    __table_args__ = (
        Index("ix_corr_enabled_type", "enabled", "rule_type"),
    )
