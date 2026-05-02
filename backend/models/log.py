from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text
from database import Base


class Log(Base):
    __tablename__ = "logs_meta"

    id = Column(Integer, primary_key=True, index=True)
    es_id = Column(String(128), nullable=True, index=True)
    agent_id = Column(String(64), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    level = Column(String(16), nullable=True, default="INFO")
    source = Column(String(256), nullable=True)
    message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
