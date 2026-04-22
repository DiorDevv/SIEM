from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum, Text, Float
import enum
from database import Base


class RuleSeverity(str, enum.Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class Rule(Base):
    __tablename__ = "rules"

    id               = Column(Integer, primary_key=True, index=True)
    name             = Column(String(256), nullable=False, unique=True)
    description      = Column(Text, nullable=True)
    pattern          = Column(Text, nullable=True)
    severity         = Column(Enum(RuleSeverity), default=RuleSeverity.MEDIUM, nullable=False)
    level            = Column(Integer, default=5)          # Wazuh-style 0-15
    category         = Column(String(64), nullable=True, default="general")
    groups           = Column(String(512), nullable=True)  # comma-separated: "authentication,ssh"
    enabled          = Column(Boolean, default=True)
    cooldown_seconds = Column(Integer, default=300)
    custom_logic     = Column(String(64), nullable=True)

    # Frequency rule (N events in T seconds → alert)
    frequency        = Column(Integer, nullable=True)      # min occurrences
    timeframe        = Column(Integer, nullable=True)      # seconds window

    # MITRE ATT&CK
    mitre_tactic     = Column(String(128), nullable=True)
    mitre_technique  = Column(String(64),  nullable=True)

    # Field-level matching (decoded field conditions)
    field_name       = Column(String(64),  nullable=True)  # e.g. "http_status"
    field_value      = Column(String(256), nullable=True)  # e.g. ">=400"

    created_at       = Column(DateTime, default=datetime.utcnow)
    updated_at       = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
