from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum, Text, JSON
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
    level            = Column(Integer, default=5)           # Wazuh-style 0-15
    category         = Column(String(64), nullable=True, default="general")
    groups           = Column(String(512), nullable=True)   # comma-separated: "authentication,ssh"
    enabled          = Column(Boolean, default=True)
    cooldown_seconds = Column(Integer, default=300)
    custom_logic     = Column(String(64), nullable=True)

    # Frequency rule (N events in T seconds → alert)
    frequency        = Column(Integer, nullable=True)       # min occurrences
    timeframe        = Column(Integer, nullable=True)       # seconds window

    # MITRE ATT&CK
    mitre_tactic     = Column(String(128), nullable=True)
    mitre_technique  = Column(String(64),  nullable=True)

    # Field-level matching — supports: >=N, ==N, ~regex, in:a,b,c, contains:x, exists, !exists
    field_name       = Column(String(64),  nullable=True)
    field_value      = Column(String(256), nullable=True)

    # If this regex matches, suppress the alert (allowlisting / false-positive reduction)
    exclusion_pattern = Column(Text, nullable=True)

    # Extra conditions JSON: {min_level, required_fields, not_fields, src_ip_not_private}
    metadata_        = Column(JSON, nullable=True)

    created_at       = Column(DateTime, default=datetime.utcnow)
    updated_at       = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
