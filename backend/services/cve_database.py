"""
Offline CVE Database — downloads NVD JSON feeds and stores in PostgreSQL.

Features:
  - Downloads NVD feeds for current year and previous years on demand.
  - Fast lookup: package name + version → list of CVEs with CVSS scores.
  - Background auto-refresh every 24 hours.
  - No internet dependency after initial download.
"""
from __future__ import annotations

import asyncio
import gzip
import json
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

import httpx
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Index, select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from database import Base, AsyncSessionLocal

logger = logging.getLogger(__name__)

NVD_FEED_BASE   = "https://nvd.nist.gov/feeds/json/cve/1.1"
FEED_YEARS      = list(range(datetime.utcnow().year - 4, datetime.utcnow().year + 1))
FEED_RECENT     = "recent"          # last 8 days
REFRESH_HOURS   = 24
CVSS_SEVERITY   = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


# ── Model ─────────────────────────────────────────────────────────────────────

class CVERecord(Base):
    __tablename__ = "cve_records"

    id           = Column(Integer, primary_key=True, index=True)
    cve_id       = Column(String(20), unique=True, nullable=False, index=True)
    description  = Column(Text, nullable=True)
    cvss_v3      = Column(Float, nullable=True)
    cvss_v2      = Column(Float, nullable=True)
    severity     = Column(String(10), nullable=True)
    cwe          = Column(String(50), nullable=True)
    published    = Column(DateTime, nullable=True)
    modified     = Column(DateTime, nullable=True)
    # Affected CPEs stored as a comma-separated list for fast LIKE queries
    cpe_list     = Column(Text, nullable=True)
    references   = Column(Text, nullable=True)   # JSON list
    vendor_fix   = Column(String(256), nullable=True)

__table_args__ = (
    Index("ix_cve_cpe", "cpe_list"),
)


class CVEFeedMeta(Base):
    __tablename__ = "cve_feed_meta"

    id          = Column(Integer, primary_key=True)
    feed_name   = Column(String(50), unique=True, nullable=False)
    last_updated= Column(DateTime, default=datetime.utcnow)
    record_count= Column(Integer, default=0)


# ── Parser ────────────────────────────────────────────────────────────────────

def _parse_cvss(metrics: dict) -> tuple[Optional[float], Optional[float], str]:
    """Returns (cvss_v3, cvss_v2, severity)."""
    v3, v2, sev = None, None, "UNKNOWN"
    v3_data = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
    v2_data = metrics.get("cvssMetricV2") or []

    if v3_data:
        v3  = v3_data[0].get("cvssData", {}).get("baseScore")
        sev = v3_data[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
    if v2_data:
        v2 = v2_data[0].get("cvssData", {}).get("baseScore")
        if sev == "UNKNOWN":
            score2 = float(v2 or 0)
            sev = ("CRITICAL" if score2 >= 9 else "HIGH" if score2 >= 7
                   else "MEDIUM" if score2 >= 4 else "LOW")
    return v3, v2, sev


def _parse_entry_v2(item: dict) -> Optional[dict]:
    """Parse NVD 1.1 feed entry."""
    try:
        cve_obj  = item.get("cve", {})
        cve_id   = cve_obj.get("CVE_data_meta", {}).get("ID", "")
        if not cve_id: return None

        descs = cve_obj.get("description", {}).get("description_data", [])
        desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "")

        impact   = item.get("impact", {})
        v3_data  = impact.get("baseMetricV3", {}).get("cvssV3", {})
        v2_data  = impact.get("baseMetricV2", {}).get("cvssV2", {})
        cvss_v3  = v3_data.get("baseScore")
        cvss_v2  = v2_data.get("baseScore")
        sev      = (impact.get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity")
                    or impact.get("baseMetricV2", {}).get("severity", "UNKNOWN"))

        # Extract CPEs
        cpe_nodes = cve_obj.get("affects", {})
        cpe_list  = []
        configs   = item.get("configurations", {}).get("nodes", [])
        for node in configs:
            for match in node.get("cpe_match", []):
                cpe = match.get("cpe23Uri", "")
                if cpe: cpe_list.append(cpe)

        # CWE
        prob = cve_obj.get("problemtype", {}).get("problemtype_data", [])
        cwe  = next(
            (d["value"] for p in prob for d in p.get("description", []) if d.get("value","").startswith("CWE")),
            None,
        )

        # References
        refs     = cve_obj.get("references", {}).get("reference_data", [])
        fix_urls = [r["url"] for r in refs if "patch" in r.get("tags", []) or "Vendor Advisory" in r.get("tags", [])]

        pub = item.get("publishedDate")
        mod = item.get("lastModifiedDate")

        return {
            "cve_id":      cve_id,
            "description": desc[:2000],
            "cvss_v3":     float(cvss_v3) if cvss_v3 else None,
            "cvss_v2":     float(cvss_v2) if cvss_v2 else None,
            "severity":    sev.upper() if sev else "UNKNOWN",
            "cwe":         cwe,
            "published":   datetime.fromisoformat(pub.rstrip("Z")) if pub else None,
            "modified":    datetime.fromisoformat(mod.rstrip("Z")) if mod else None,
            "cpe_list":    ",".join(cpe_list)[:4096],
            "references":  json.dumps(fix_urls[:10]),
            "vendor_fix":  fix_urls[0] if fix_urls else None,
        }
    except Exception as e:
        logger.debug(f"CVE parse error: {e}")
        return None


# ── Downloader ────────────────────────────────────────────────────────────────

async def _download_feed(feed_name: str) -> List[dict]:
    """Download and decompress a single NVD feed. Returns list of parsed entries."""
    url = f"{NVD_FEED_BASE}/nvdcve-1.1-{feed_name}.json.gz"
    entries = []
    try:
        async with httpx.AsyncClient(timeout=120) as client:
            logger.info(f"Downloading CVE feed: {feed_name} from {url}")
            resp = await client.get(url)
            resp.raise_for_status()
            raw  = gzip.decompress(resp.content)
            data = json.loads(raw)
            items = data.get("CVE_Items", [])
            for item in items:
                parsed = _parse_entry_v2(item)
                if parsed:
                    entries.append(parsed)
            logger.info(f"Parsed {len(entries)} CVEs from feed '{feed_name}'")
    except Exception as e:
        logger.error(f"Failed to download CVE feed '{feed_name}': {e}")
    return entries


async def _upsert_feed(session: AsyncSession, entries: List[dict], feed_name: str):
    """Insert or update CVE records in bulk."""
    count = 0
    for entry in entries:
        try:
            stmt = select(CVERecord).where(CVERecord.cve_id == entry["cve_id"])
            result = await session.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing:
                for k, v in entry.items():
                    setattr(existing, k, v)
            else:
                session.add(CVERecord(**entry))
            count += 1

            if count % 500 == 0:
                await session.flush()
                logger.debug(f"Upserted {count} CVEs from feed '{feed_name}'")
        except Exception as e:
            logger.debug(f"CVE upsert error for {entry.get('cve_id')}: {e}")

    # Update meta
    stmt = select(CVEFeedMeta).where(CVEFeedMeta.feed_name == feed_name)
    meta = (await session.execute(stmt)).scalar_one_or_none()
    if meta:
        meta.last_updated = datetime.utcnow()
        meta.record_count = count
    else:
        session.add(CVEFeedMeta(feed_name=feed_name, last_updated=datetime.utcnow(), record_count=count))

    await session.commit()
    logger.info(f"CVE feed '{feed_name}': {count} records saved")


# ── Public API ────────────────────────────────────────────────────────────────

async def refresh_feed(feed_name: str):
    """Download and store a single NVD feed."""
    entries = await _download_feed(feed_name)
    if entries:
        async with AsyncSessionLocal() as session:
            await _upsert_feed(session, entries, feed_name)


async def initial_download():
    """Download all year feeds + recent. Runs on first startup."""
    async with AsyncSessionLocal() as session:
        count = (await session.execute(
            select(CVEFeedMeta)
        )).scalars().all()
        if len(count) >= len(FEED_YEARS):
            logger.info("CVE database already populated, skipping initial download")
            return

    logger.info(f"Starting initial CVE database download ({len(FEED_YEARS)} year feeds + recent)...")
    for year in FEED_YEARS:
        await refresh_feed(str(year))
    await refresh_feed(FEED_RECENT)
    logger.info("Initial CVE database download complete")


async def auto_refresh_loop():
    """Background task: refresh 'recent' feed every 24 hours."""
    while True:
        await asyncio.sleep(REFRESH_HOURS * 3600)
        try:
            logger.info("Auto-refreshing CVE feed (recent)...")
            await refresh_feed(FEED_RECENT)
            # Refresh current year feed weekly
            if datetime.utcnow().weekday() == 0:
                await refresh_feed(str(datetime.utcnow().year))
        except Exception as e:
            logger.error(f"CVE auto-refresh error: {e}")


async def lookup_cves(
    package_name: str,
    version:      Optional[str] = None,
    vendor:       Optional[str] = None,
    limit:        int = 20,
) -> List[Dict[str, Any]]:
    """
    Look up CVEs affecting a package.

    Uses CPE string matching: cpe:2.3:a:{vendor}:{product}:{version}
    Falls back to keyword search in cpe_list.
    """
    async with AsyncSessionLocal() as session:
        # Build search pattern
        pkg_lower = package_name.lower().replace("-", "_")
        patterns  = [f"%{pkg_lower}%"]
        if vendor:
            patterns.append(f"%{vendor.lower()}:{pkg_lower}%")
        if version:
            patterns.append(f"%:{version}:%")

        # Try exact CPE match first
        stmt = select(CVERecord).where(
            CVERecord.cpe_list.ilike(f"%:{pkg_lower}:%")
        ).order_by(CVERecord.cvss_v3.desc().nullslast()).limit(limit)

        results = (await session.execute(stmt)).scalars().all()

        # Filter by version if provided
        if version and results:
            filtered = []
            ver_num = _version_to_tuple(version)
            for r in results:
                cpes = (r.cpe_list or "").split(",")
                for cpe in cpes:
                    parts = cpe.split(":")
                    if len(parts) > 5:
                        cpe_ver = parts[5]
                        if cpe_ver in ("*", "-", "") or cpe_ver == version:
                            filtered.append(r)
                            break
            results = filtered or results

        return [
            {
                "cve_id":      r.cve_id,
                "description": r.description,
                "cvss_v3":     r.cvss_v3,
                "cvss_v2":     r.cvss_v2,
                "severity":    r.severity,
                "cwe":         r.cwe,
                "published":   r.published.isoformat() if r.published else None,
                "vendor_fix":  r.vendor_fix,
            }
            for r in results
        ]


async def get_database_stats() -> Dict[str, Any]:
    async with AsyncSessionLocal() as session:
        total = (await session.execute(
            select(CVERecord)
        )).scalars().all()
        feeds = (await session.execute(
            select(CVEFeedMeta)
        )).scalars().all()
        critical = sum(1 for r in total if r.severity == "CRITICAL")
        return {
            "total_cves":    len(total),
            "critical_cves": critical,
            "feeds":         [{"name": f.feed_name, "updated": f.last_updated.isoformat(),
                               "count": f.record_count} for f in feeds],
        }


def _version_to_tuple(version: str) -> tuple:
    """Convert version string to comparable tuple."""
    parts = re.findall(r"\d+", version)
    return tuple(int(p) for p in parts[:4])
