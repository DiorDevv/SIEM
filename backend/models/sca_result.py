from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Boolean
from database import Base


class SCAScan(Base):
    """SCA scan result from an agent."""
    __tablename__ = "sca_scans"

    id         = Column(Integer, primary_key=True, index=True)
    agent_id   = Column(String(64), nullable=False, index=True)
    hostname   = Column(String(256), nullable=True)
    checks     = Column(JSON, nullable=False)   # [{id, title, result, severity, rationale}]
    passed     = Column(Integer, default=0)
    failed     = Column(Integer, default=0)
    skipped    = Column(Integer, default=0)
    score_pct  = Column(Integer, default=0)     # passed / (passed+failed) * 100
    scanned_at = Column(DateTime, default=datetime.utcnow, index=True)
