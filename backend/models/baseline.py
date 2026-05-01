from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, Index, Text
from database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class AnomalyBaseline(Base):
    """
    Persists Welford online-statistics per (agent_id, metric_key).
    Redis is the primary store; this table is the durable backup so
    baselines survive Redis restarts.
    """
    __tablename__ = "anomaly_baselines"

    id          = Column(Integer, primary_key=True, index=True)
    agent_id    = Column(String(64),  nullable=False)
    metric_key  = Column(String(128), nullable=False)
    n           = Column(Integer,     default=0,   nullable=False)
    mean        = Column(Float,       default=0.0, nullable=False)
    m2          = Column(Float,       default=0.0, nullable=False)  # sum of squared devs
    last_value  = Column(Float,       nullable=True)
    updated_at  = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        Index("ix_baseline_agent_metric", "agent_id", "metric_key", unique=True),
    )


class AnomalyKnownSet(Base):
    """
    Tracks known values for set-membership anomalies (e.g. known src IPs per user).
    Each row represents one known value; new values trigger a one-time alert.
    """
    __tablename__ = "anomaly_known_sets"

    id         = Column(Integer, primary_key=True, index=True)
    agent_id   = Column(String(64),  nullable=False)
    set_key    = Column(String(128), nullable=False)   # e.g. "known_ip:alice"
    value      = Column(String(256), nullable=False)   # the known value
    first_seen = Column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (
        Index("ix_known_set_lookup", "agent_id", "set_key", "value", unique=True),
    )
