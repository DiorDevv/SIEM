"""
Notification channels — email, Telegram, Slack/Discord webhooks.
"""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON
from database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class NotificationChannel(Base):
    __tablename__ = "notification_channels"

    id         = Column(Integer, primary_key=True, index=True)
    name       = Column(String(128), nullable=False)
    type       = Column(String(32),  nullable=False)   # email | telegram | slack | webhook
    config     = Column(JSON,        nullable=False)   # type-specific config
    enabled    = Column(Boolean,     default=True)
    # Trigger config
    min_severity = Column(String(16), default="HIGH")  # LOW | MEDIUM | HIGH | CRITICAL
    created_at   = Column(DateTime(timezone=True), default=_utcnow)
    updated_at   = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
