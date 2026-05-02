from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text
from database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id            = Column(Integer, primary_key=True, index=True)
    timestamp     = Column(DateTime, default=datetime.utcnow, index=True)
    user_id       = Column(Integer, nullable=True, index=True)
    username      = Column(String(64), nullable=True)
    action        = Column(String(64), nullable=False, index=True)
    resource_type = Column(String(64), nullable=True)
    resource_id   = Column(String(64), nullable=True)
    resource_name = Column(String(256), nullable=True)
    details       = Column(Text, nullable=True)
    ip_address    = Column(String(64), nullable=True)
    status        = Column(String(16), default="success")
