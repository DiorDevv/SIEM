"""
Case Management — Incident Response tracking.

Tables:
  cases           — main case record
  case_alerts     — alerts linked to a case (many-to-many)
  case_notes      — analyst notes, actions, IOCs per case
  case_timeline   — auto-generated audit trail of case changes
"""
import enum
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime,
    Text, JSON, ForeignKey, Index,
)
from database import Base


def _utcnow():
    return datetime.utcnow()


class CaseStatus(str, enum.Enum):
    open        = "open"
    in_progress = "in_progress"
    pending     = "pending"
    resolved    = "resolved"
    closed      = "closed"


class CaseSeverity(str, enum.Enum):
    low      = "LOW"
    medium   = "MEDIUM"
    high     = "HIGH"
    critical = "CRITICAL"


class CaseTLP(str, enum.Enum):
    white = "WHITE"   # unrestricted
    green = "GREEN"   # community
    amber = "AMBER"   # limited distribution
    red   = "RED"     # restricted


class NoteType(str, enum.Enum):
    note     = "note"
    action   = "action"
    evidence = "evidence"
    ioc      = "ioc"


class Case(Base):
    __tablename__ = "cases"

    id              = Column(Integer, primary_key=True, index=True)
    case_number     = Column(String(16),  nullable=False, unique=True, index=True)  # CASE-0001
    title           = Column(String(512), nullable=False)
    description     = Column(Text,        nullable=True)
    status          = Column(String(32),  default=CaseStatus.open,     nullable=False, index=True)
    severity        = Column(String(16),  default=CaseSeverity.medium, nullable=False, index=True)
    tlp             = Column(String(8),   default=CaseTLP.amber,       nullable=False)

    # Assignment
    assigned_to      = Column(Integer,     ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    assigned_to_name = Column(String(128), nullable=True)

    # Creator
    created_by       = Column(Integer,     ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_by_name  = Column(String(128), nullable=True)

    # Categorisation
    tags             = Column(JSON, nullable=True)          # ["ransomware", "lateral-movement"]
    mitre_tactics    = Column(JSON, nullable=True)          # ["Initial Access", "Execution"]
    mitre_techniques = Column(JSON, nullable=True)          # ["T1078", "T1059"]

    # SLA
    sla_hours    = Column(Integer, nullable=True)           # target resolution hours
    sla_deadline = Column(DateTime, nullable=True)

    # Counts (denormalised for speed)
    alert_count = Column(Integer, default=0)
    note_count  = Column(Integer, default=0)

    created_at  = Column(DateTime, default=_utcnow, nullable=False, index=True)
    updated_at  = Column(DateTime, default=_utcnow, onupdate=_utcnow)
    resolved_at = Column(DateTime, nullable=True)
    closed_at   = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_case_status_sev", "status", "severity"),
    )


class CaseAlert(Base):
    __tablename__ = "case_alerts"

    id         = Column(Integer, primary_key=True, index=True)
    case_id    = Column(Integer, ForeignKey("cases.id",  ondelete="CASCADE"), nullable=False, index=True)
    alert_id   = Column(Integer, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)
    linked_at  = Column(DateTime, default=_utcnow)
    linked_by  = Column(String(128), nullable=True)

    __table_args__ = (
        Index("ix_ca_case_alert", "case_id", "alert_id", unique=True),
    )


class CaseNote(Base):
    __tablename__ = "case_notes"

    id        = Column(Integer, primary_key=True, index=True)
    case_id   = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id   = Column(Integer, nullable=True)
    username  = Column(String(128), nullable=True)
    content   = Column(Text, nullable=False)
    note_type = Column(String(16), default=NoteType.note, nullable=False)  # note|action|evidence|ioc
    created_at = Column(DateTime, default=_utcnow, nullable=False)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


class CaseTimeline(Base):
    __tablename__ = "case_timeline"

    id         = Column(Integer, primary_key=True, index=True)
    case_id    = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    username   = Column(String(128), nullable=True)
    action     = Column(String(256), nullable=False)   # "Status changed: open → in_progress"
    old_value  = Column(String(512), nullable=True)
    new_value  = Column(String(512), nullable=True)
    created_at = Column(DateTime, default=_utcnow, nullable=False, index=True)
