from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum, Text, JSON, ForeignKey
import enum
from database import Base


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
    pending   = "pending"
    sent      = "sent"
    success   = "success"
    failed    = "failed"
    timeout   = "timeout"


class ARPolicy(Base):
    __tablename__ = "ar_policies"

    id               = Column(Integer, primary_key=True, index=True)
    name             = Column(String(256), nullable=False, unique=True)
    description      = Column(Text, nullable=True)
    enabled          = Column(Boolean, default=True)

    # Trigger conditions
    trigger_on       = Column(Enum(ARTriggerOn), default=ARTriggerOn.severity)
    trigger_severity = Column(String(32), nullable=True)   # CRITICAL,HIGH,...
    trigger_rule     = Column(String(256), nullable=True)  # rule name pattern
    trigger_category = Column(String(64), nullable=True)

    # Action to execute
    action           = Column(Enum(ARActionType), nullable=False)
    action_params    = Column(JSON, nullable=True)          # {timeout, script, ...}

    # Targeting
    target_agent     = Column(String(64), nullable=True)    # null = all agents

    # Throttle: max once per N seconds per src_ip
    cooldown_seconds = Column(Integer, default=300)

    created_at       = Column(DateTime, default=datetime.utcnow)
    updated_at       = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ARExecution(Base):
    __tablename__ = "ar_executions"

    id           = Column(Integer, primary_key=True, index=True)
    policy_id    = Column(Integer, ForeignKey("ar_policies.id", ondelete="SET NULL"), nullable=True)
    alert_id     = Column(Integer, ForeignKey("alerts.id",     ondelete="SET NULL"), nullable=True)
    agent_id     = Column(String(64),  nullable=False, index=True)
    action       = Column(Enum(ARActionType), nullable=False)
    action_params= Column(JSON, nullable=True)
    status       = Column(Enum(ARExecutionStatus), default=ARExecutionStatus.pending)
    result       = Column(Text, nullable=True)
    src_ip       = Column(String(45), nullable=True)
    policy_name  = Column(String(256), nullable=True)
    created_at   = Column(DateTime, default=datetime.utcnow, index=True)
    completed_at = Column(DateTime, nullable=True)
