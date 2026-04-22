from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Enum
import enum
from database import Base


class AgentStatus(str, enum.Enum):
    online = "online"
    offline = "offline"
    unknown = "unknown"


class Agent(Base):
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(64), unique=True, nullable=False, index=True)
    hostname = Column(String(256), nullable=False)
    ip_address = Column(String(45), nullable=False)
    os = Column(String(64), nullable=True)
    os_version = Column(String(128), nullable=True)
    agent_version = Column(String(32), nullable=True, default="1.0.0")
    status = Column(Enum(AgentStatus), default=AgentStatus.unknown)
    is_active = Column(Boolean, default=True)
    last_seen = Column(DateTime, nullable=True)
    registered_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
