from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Enum, Float
import enum
from database import Base


class AgentStatus(str, enum.Enum):
    online = "online"
    offline = "offline"
    unknown = "unknown"


class Agent(Base):
    __tablename__ = "agents"

    id            = Column(Integer,      primary_key=True, index=True)
    agent_id      = Column(String(64),   unique=True, nullable=False, index=True)
    hostname      = Column(String(256),  nullable=False)
    ip_address    = Column(String(45),   nullable=False)
    os            = Column(String(64),   nullable=True)
    os_version    = Column(String(128),  nullable=True)
    agent_version = Column(String(32),   nullable=True, default="1.0.0")
    status        = Column(Enum(AgentStatus), default=AgentStatus.unknown)
    is_active     = Column(Boolean,      default=True)
    last_seen     = Column(DateTime,     nullable=True)
    registered_at = Column(DateTime,     default=datetime.utcnow)
    updated_at    = Column(DateTime,     default=datetime.utcnow, onupdate=datetime.utcnow)

    # Agent self-health (updated on each heartbeat)
    agent_cpu_pct    = Column(Float,   nullable=True)   # agent process CPU %
    agent_mem_mb     = Column(Float,   nullable=True)   # agent process RSS MB
    buffer_batches   = Column(Integer, nullable=True, default=0)  # offline queue depth
    buffer_logs      = Column(Integer, nullable=True, default=0)  # total buffered logs
