from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Enum, Text, ForeignKey, JSON
import enum
from database import Base


class AlertStatus(str, enum.Enum):
    open           = "open"
    acknowledged   = "acknowledged"
    resolved       = "resolved"
    false_positive = "false_positive"


class AlertSeverity(str, enum.Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class Alert(Base):
    __tablename__ = "alerts"

    id              = Column(Integer, primary_key=True, index=True)
    rule_id         = Column(Integer, ForeignKey("rules.id", ondelete="SET NULL"), nullable=True)
    agent_id        = Column(String(64),  nullable=False, index=True)
    severity        = Column(Enum(AlertSeverity), nullable=False)
    level           = Column(Integer, default=5)          # 0-15 Wazuh-style
    title           = Column(String(512), nullable=False)
    description     = Column(Text, nullable=True)
    log_id          = Column(String(128), nullable=True)
    status          = Column(Enum(AlertStatus), default=AlertStatus.open, nullable=False)
    agent_hostname  = Column(String(256), nullable=True)
    rule_name       = Column(String(256), nullable=True)

    # MITRE ATT&CK
    mitre_tactic    = Column(String(128), nullable=True)
    mitre_technique = Column(String(64),  nullable=True)

    # Groups / category
    groups          = Column(String(512), nullable=True)
    category        = Column(String(64),  nullable=True)

    # Threat intelligence enrichment
    src_ip          = Column(String(45),  nullable=True)
    threat_intel    = Column(JSON,        nullable=True)  # {score, country, isp, malicious}

    # Raw event data
    raw_log         = Column(Text,        nullable=True)
    parsed_fields   = Column(JSON,        nullable=True)

    created_at      = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at      = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at     = Column(DateTime, nullable=True)
