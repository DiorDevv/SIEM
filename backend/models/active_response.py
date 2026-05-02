from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Enum, Text, JSON,
    ForeignKey, Index,
)
import enum
from database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class ARTriggerOn(str, enum.Enum):
    any_alert   = "any_alert"
    severity    = "severity"
    rule_name   = "rule_name"
    category    = "category"
    src_ip      = "src_ip"


class ARActionType(str, enum.Enum):
    block_ip      = "block_ip"
    unblock_ip    = "unblock_ip"
    kill_process  = "kill_process"
    disable_user  = "disable_user"
    enable_user   = "enable_user"
    run_script    = "run_script"
    email_alert   = "email_alert"
    slack_alert   = "slack_alert"


class ARExecutionStatus(str, enum.Enum):
    pending    = "pending"
    sent       = "sent"
    success    = "success"
    failed     = "failed"
    timeout    = "timeout"
    cancelled  = "cancelled"


class ARTriggeredBy(str, enum.Enum):
    auto   = "auto"
    manual = "manual"


class ARPolicy(Base):
    __tablename__ = "ar_policies"

    id               = Column(Integer, primary_key=True, index=True)
    name             = Column(String(256), nullable=False, unique=True)
    description      = Column(Text, nullable=True)
    enabled          = Column(Boolean, default=True)

    trigger_on       = Column(Enum(ARTriggerOn), default=ARTriggerOn.severity)
    trigger_severity = Column(String(64), nullable=True)   # "CRITICAL,HIGH"
    trigger_rule     = Column(String(256), nullable=True)  # substring match on rule_name
    trigger_category = Column(String(64), nullable=True)

    action           = Column(Enum(ARActionType), nullable=False)
    action_params    = Column(JSON, nullable=True)

    target_agent     = Column(String(64), nullable=True)   # NULL = all agents
    cooldown_seconds = Column(Integer, default=300)
    max_per_hour     = Column(Integer, nullable=True)       # hard rate cap, NULL = unlimited

    created_at       = Column(DateTime(timezone=True), default=_utcnow)
    updated_at       = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class ARExecution(Base):
    __tablename__ = "ar_executions"

    id                  = Column(Integer, primary_key=True, index=True)
    policy_id           = Column(Integer, ForeignKey("ar_policies.id", ondelete="SET NULL"), nullable=True)
    alert_id            = Column(Integer, ForeignKey("alerts.id",      ondelete="SET NULL"), nullable=True)
    # nullable: server-side actions (email/slack) have no target agent
    agent_id            = Column(String(64), nullable=True, index=True)
    action              = Column(Enum(ARActionType), nullable=False)
    action_params       = Column(JSON, nullable=True)
    status              = Column(Enum(ARExecutionStatus), default=ARExecutionStatus.pending, index=True)
    result              = Column(Text, nullable=True)
    # groupby key — stores src_ip or agent_id (whichever is used as cooldown key)
    src_ip              = Column(String(64), nullable=True)
    policy_name         = Column(String(256), nullable=True)
    triggered_by        = Column(Enum(ARTriggeredBy), default=ARTriggeredBy.auto, nullable=False)
    retry_count         = Column(Integer, default=0, nullable=False)
    parent_execution_id = Column(
        Integer, ForeignKey("ar_executions.id", ondelete="SET NULL"), nullable=True
    )
    created_at          = Column(DateTime(timezone=True), default=_utcnow, index=True)
    completed_at        = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        # Covers the cooldown query: WHERE policy_id=? AND src_ip=? AND created_at>=?
        Index("ix_ar_exec_cooldown", "policy_id", "src_ip", "created_at"),
        # Covers the per-hour rate cap query
        Index("ix_ar_exec_policy_created", "policy_id", "created_at"),
    )
