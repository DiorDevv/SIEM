"""
Threat Intelligence — IOC database.
Stores Indicators of Compromise (IPs, domains, hashes, URLs, emails)
enriched from VirusTotal, AbuseIPDB, or imported from threat feeds.
"""
import enum
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime,
    Text, JSON, Index,
)
from database import Base


def _utcnow():
    return datetime.utcnow()


class ThreatIntelIOC(Base):
    __tablename__ = "threat_intel_iocs"

    id             = Column(Integer, primary_key=True, index=True)

    ioc_type       = Column(String(16),  nullable=False, index=True)
    # ip | domain | md5 | sha256 | sha1 | url | email | cve

    value          = Column(String(512), nullable=False, index=True)
    source         = Column(String(32),  default="manual", nullable=False)
    # manual | virustotal | abuseipdb | feed | misp | otx

    severity       = Column(String(16),  default="MEDIUM", nullable=False, index=True)
    confidence     = Column(Integer,     default=50)    # 0-100
    description    = Column(Text,        nullable=True)
    tags           = Column(JSON,        nullable=True)  # ["ransomware", "c2"]
    malware_family = Column(String(128), nullable=True)

    # VirusTotal enrichment
    vt_malicious   = Column(Integer,     nullable=True)  # engines that flagged
    vt_total       = Column(Integer,     nullable=True)  # total engines
    vt_permalink   = Column(String(512), nullable=True)
    vt_raw         = Column(JSON,        nullable=True)  # full VT response

    # AbuseIPDB enrichment
    abuse_score    = Column(Integer,     nullable=True)  # 0-100
    abuse_reports  = Column(Integer,     nullable=True)

    # GeoIP (for IPs)
    country        = Column(String(4),   nullable=True)
    asn            = Column(String(128), nullable=True)

    first_seen     = Column(DateTime, default=_utcnow, nullable=False)
    last_seen      = Column(DateTime, default=_utcnow, onupdate=_utcnow)
    expires_at     = Column(DateTime, nullable=True)
    is_active      = Column(Boolean,  default=True,  nullable=False)
    hit_count      = Column(Integer,  default=0)       # alerts matched

    created_by     = Column(String(128), nullable=True)
    created_at     = Column(DateTime, default=_utcnow, nullable=False)
    updated_at     = Column(DateTime, default=_utcnow, onupdate=_utcnow)

    __table_args__ = (
        Index("ix_ioc_type_value", "ioc_type", "value", unique=True),
        Index("ix_ioc_active_sev", "is_active", "severity"),
    )
