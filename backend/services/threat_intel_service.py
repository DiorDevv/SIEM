"""
Threat Intelligence service.
- VirusTotal v3 API lookups (IP, domain, file hash, URL)
- IOC database match checking
- Alert enrichment pipeline
- Feed import (CSV / plain-text)
"""
import asyncio
import hashlib
import logging
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import aiohttp
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from models.threat_intel import ThreatIntelIOC

logger = logging.getLogger(__name__)

# ── VirusTotal ─────────────────────────────────────────────────────────────────

_VT_BASE = "https://www.virustotal.com/api/v3"
_vt_cache: Dict[str, tuple] = {}   # value → (result, expiry)
_VT_CACHE_TTL = 3600 * 6           # 6 hours


async def _vt_request(endpoint: str, api_key: str) -> Optional[Dict]:
    if not api_key:
        return None
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    timeout = aiohttp.ClientTimeout(total=10)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as s:
            async with s.get(f"{_VT_BASE}/{endpoint}", headers=headers) as r:
                if r.status == 200:
                    return await r.json()
                if r.status == 404:
                    return {"not_found": True}
                logger.debug(f"VT {endpoint} → HTTP {r.status}")
                return None
    except Exception as e:
        logger.debug(f"VT request failed: {e}")
        return None


def _vt_stats(data: dict) -> Dict[str, Any]:
    """Extract malicious/total from VT last_analysis_stats."""
    if not data or data.get("not_found"):
        return {}
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
    total = sum(stats.values()) or 1
    return {
        "vt_malicious": malicious,
        "vt_total": total,
        "vt_permalink": f"https://www.virustotal.com/gui/{'file' if 'meaningful_name' in attrs else 'ip-address'}/{data.get('data',{}).get('id','')}",
        "vt_raw": stats,
    }


async def lookup_virustotal(ioc_type: str, value: str, api_key: str) -> Dict[str, Any]:
    """Query VirusTotal for an IOC. Returns enrichment dict."""
    if not api_key:
        return {}

    cache_key = f"{ioc_type}:{value}"
    if cache_key in _vt_cache:
        result, expiry = _vt_cache[cache_key]
        if datetime.utcnow() < expiry:
            return result

    endpoint_map = {
        "ip":     f"ip_addresses/{value}",
        "domain": f"domains/{value}",
        "md5":    f"files/{value}",
        "sha1":   f"files/{value}",
        "sha256": f"files/{value}",
        "url":    f"urls/{hashlib.sha256(value.encode()).hexdigest()}",
    }
    endpoint = endpoint_map.get(ioc_type)
    if not endpoint:
        return {}

    data = await _vt_request(endpoint, api_key)
    result = _vt_stats(data) if data else {}
    _vt_cache[cache_key] = (result, datetime.utcnow() + timedelta(seconds=_VT_CACHE_TTL))
    return result


# ── IOC Database matching ──────────────────────────────────────────────────────

_IOC_PATTERNS = {
    "ip":     re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "domain": re.compile(r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', re.I),
    "md5":    re.compile(r'\b[0-9a-fA-F]{32}\b'),
    "sha1":   re.compile(r'\b[0-9a-fA-F]{40}\b'),
    "sha256": re.compile(r'\b[0-9a-fA-F]{64}\b'),
    "url":    re.compile(r'https?://[^\s\'"]+'),
}

_PRIVATE_RANGES = re.compile(
    r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1|fe80:)'
)


def extract_observables(text: str) -> Dict[str, List[str]]:
    """Extract IOC observables from a text string."""
    if not text:
        return {}
    result: Dict[str, List[str]] = {}
    for ioc_type, pattern in _IOC_PATTERNS.items():
        matches = pattern.findall(text)
        # Filter private IPs
        if ioc_type == "ip":
            matches = [m for m in matches if not _PRIVATE_RANGES.match(m)]
        if matches:
            result[ioc_type] = list(set(matches))
    return result


async def match_iocs_in_db(
    db: AsyncSession,
    observables: Dict[str, List[str]],
) -> List[Dict[str, Any]]:
    """Check extracted observables against the IOC database."""
    hits = []
    for ioc_type, values in observables.items():
        for value in values:
            row = (
                await db.execute(
                    select(ThreatIntelIOC).where(
                        ThreatIntelIOC.ioc_type == ioc_type,
                        ThreatIntelIOC.value == value,
                        ThreatIntelIOC.is_active == True,
                    )
                )
            ).scalar_one_or_none()
            if row:
                hits.append({
                    "ioc_type": row.ioc_type,
                    "value": row.value,
                    "severity": row.severity,
                    "confidence": row.confidence,
                    "source": row.source,
                    "malware_family": row.malware_family,
                    "tags": row.tags,
                    "vt_malicious": row.vt_malicious,
                    "vt_total": row.vt_total,
                })
                # Increment hit counter
                await db.execute(
                    update(ThreatIntelIOC)
                    .where(ThreatIntelIOC.id == row.id)
                    .values(hit_count=ThreatIntelIOC.hit_count + 1, last_seen=datetime.utcnow())
                )
    return hits


async def enrich_alert_with_ti(db: AsyncSession, alert) -> List[Dict[str, Any]]:
    """
    Extract observables from an alert and match against IOC DB.
    Returns list of IOC hits to store in alert.threat_intel.
    """
    text_fields = []
    if alert.title:
        text_fields.append(alert.title)
    if alert.description:
        text_fields.append(alert.description)
    if alert.raw_log:
        text_fields.append(alert.raw_log)
    if alert.src_ip:
        text_fields.append(alert.src_ip)

    combined = " ".join(text_fields)
    observables = extract_observables(combined)

    # Always include explicit src_ip if present
    if alert.src_ip and not _PRIVATE_RANGES.match(alert.src_ip):
        observables.setdefault("ip", [])
        if alert.src_ip not in observables["ip"]:
            observables["ip"].append(alert.src_ip)

    if not observables:
        return []

    hits = await match_iocs_in_db(db, observables)
    return hits


# ── Feed import ────────────────────────────────────────────────────────────────

async def import_plaintext_feed(
    db: AsyncSession,
    lines: List[str],
    ioc_type: str,
    source: str = "feed",
    severity: str = "MEDIUM",
    tags: Optional[List[str]] = None,
    created_by: str = "system",
) -> Dict[str, int]:
    """Import IOCs from a plain-text list (one IOC per line)."""
    added = 0
    skipped = 0
    for raw in lines:
        value = raw.strip()
        if not value or value.startswith("#"):
            continue
        # Check if already exists
        existing = (
            await db.execute(
                select(ThreatIntelIOC).where(
                    ThreatIntelIOC.ioc_type == ioc_type,
                    ThreatIntelIOC.value == value,
                )
            )
        ).scalar_one_or_none()
        if existing:
            skipped += 1
            continue
        db.add(ThreatIntelIOC(
            ioc_type=ioc_type,
            value=value,
            source=source,
            severity=severity,
            tags=tags or [],
            is_active=True,
            created_by=created_by,
        ))
        added += 1

    await db.commit()
    logger.info(f"Feed import: {added} added, {skipped} skipped")
    return {"added": added, "skipped": skipped}
