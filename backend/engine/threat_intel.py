"""
Threat Intelligence + GeoIP module.
- AbuseIPDB reputation (1000 checks/day free)
- Known malicious IP sets (TOR exits, scanners, botnets)
- IP reputation scoring
- GeoIP lookup via ip-api.com (free, no key, 45 req/min)
- Private/reserved IP detection
- Async enrichment with in-memory caching (6h TTL)
"""
import re
import logging
import asyncio
import ipaddress
from typing import Dict, Any, Optional, Set
from datetime import datetime, timedelta

import aiohttp

logger = logging.getLogger(__name__)

# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
_abuseipdb_cache: Dict[str, tuple] = {}


async def _check_abuseipdb(ip: str) -> Optional[Dict[str, Any]]:
    from config import settings
    if not settings.ABUSEIPDB_ENABLED or not settings.ABUSEIPDB_API_KEY:
        return None
    if is_private_ip(ip):
        return None

    # Cache check
    if ip in _abuseipdb_cache:
        data, expiry = _abuseipdb_cache[ip]
        if datetime.utcnow() < expiry:
            return data

    try:
        headers = {"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params  = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(_ABUSEIPDB_URL, headers=headers, params=params) as resp:
                if resp.status != 200:
                    return None
                raw = await resp.json()
                d   = raw.get("data", {})
                result = {
                    "abuse_score":       d.get("abuseConfidenceScore", 0),
                    "total_reports":     d.get("totalReports", 0),
                    "country_code":      d.get("countryCode"),
                    "isp":               d.get("isp"),
                    "domain":            d.get("domain"),
                    "is_tor":            d.get("isTor", False),
                    "is_whitelisted":    d.get("isWhitelisted", False),
                    "last_reported":     d.get("lastReportedAt"),
                    "source":            "abuseipdb",
                }
                # Cache for 1 hour
                _abuseipdb_cache[ip] = (result, datetime.utcnow() + timedelta(hours=1))
                if result["abuse_score"] >= settings.ABUSEIPDB_MIN_SCORE:
                    logger.info(f"TI: AbuseIPDB {ip} score={result['abuse_score']} reports={result['total_reports']}")
                return result
    except asyncio.TimeoutError:
        logger.debug(f"AbuseIPDB timeout for {ip}")
    except Exception as e:
        logger.debug(f"AbuseIPDB error for {ip}: {e}")
    return None

# ── Known bad IPs (seed — extend via add_to_blocklist) ───────────────────────

_KNOWN_SCANNERS: Set[str] = {
    "45.33.32.156",  "198.20.69.74",  "198.20.69.98",   "208.180.20.97",
    "209.126.136.4", "71.6.135.131",  "71.6.146.185",   "71.6.158.166",
    "89.248.167.131","93.174.95.106", "94.102.49.190",  "185.220.101.1",
}

_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

# ip → (result_dict, expiry_datetime)
_cache: Dict[str, tuple] = {}
_CACHE_TTL   = timedelta(hours=6)
_GEO_TIMEOUT = aiohttp.ClientTimeout(total=4)

SCORE_MALICIOUS  = 80
SCORE_SUSPICIOUS = 40

# ── Helpers ───────────────────────────────────────────────────────────────────

def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_RANGES)
    except ValueError:
        return False


def _local_score(ip: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "ip":         ip,
        "score":      0,
        "malicious":  False,
        "private":    False,
        "scanner":    False,
        "tor_exit":   False,
        "tags":       [],
        "checked_at": datetime.utcnow().isoformat(),
        # GeoIP fields (filled later)
        "country":    None,
        "country_code": None,
        "city":       None,
        "isp":        None,
        "org":        None,
        "lat":        None,
        "lon":        None,
    }

    if is_private_ip(ip):
        result["private"] = True
        return result

    if ip in _KNOWN_SCANNERS:
        result["score"]     = 90
        result["scanner"]   = True
        result["malicious"] = True
        result["tags"].append("known_scanner")

    try:
        octets = ip.split(".")
        if len(octets) == 4:
            first = int(octets[0])
            if first in (185, 194, 195, 176, 45, 89, 93, 94):
                result["score"] = max(result["score"], 30)
                result["tags"].append("datacenter_range")
    except Exception:
        pass

    result["malicious"] = result["score"] >= SCORE_MALICIOUS
    return result


# ── GeoIP via ip-api.com ──────────────────────────────────────────────────────

_GEO_API = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,isp,org,lat,lon,proxy,hosting"


async def _fetch_geoip(ip: str) -> Optional[Dict[str, Any]]:
    from config import settings
    if not settings.GEOIP_ENABLED:
        return None

    try:
        async with aiohttp.ClientSession(timeout=_GEO_TIMEOUT) as session:
            async with session.get(_GEO_API.format(ip=ip)) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json(content_type=None)
                if data.get("status") != "success":
                    return None
                return {
                    "country":      data.get("country"),
                    "country_code": data.get("countryCode"),
                    "city":         data.get("city"),
                    "isp":          data.get("isp"),
                    "org":          data.get("org"),
                    "lat":          data.get("lat"),
                    "lon":          data.get("lon"),
                    "proxy":        data.get("proxy", False),
                    "hosting":      data.get("hosting", False),
                }
    except asyncio.TimeoutError:
        logger.debug(f"GeoIP timeout for {ip}")
    except Exception as e:
        logger.debug(f"GeoIP error for {ip}: {e}")
    return None


# ── Main enrichment ───────────────────────────────────────────────────────────

async def enrich_ip(ip: str) -> Optional[Dict[str, Any]]:
    if not ip or ip in ("unknown", "-", ""):
        return None

    if ip in _cache:
        data, expiry = _cache[ip]
        if datetime.utcnow() < expiry:
            return data

    result = await asyncio.get_event_loop().run_in_executor(None, _local_score, ip)

    if not result["private"]:
        # AbuseIPDB check (runs concurrently with GeoIP)
        abuse_task = asyncio.create_task(_check_abuseipdb(ip))
        geo_task   = asyncio.create_task(_fetch_geoip(ip))

        abuse, geo = await asyncio.gather(abuse_task, geo_task, return_exceptions=True)

        if isinstance(geo, dict):
            result.update(geo)
            if geo.get("proxy") or geo.get("hosting"):
                result["score"] = max(result["score"], 35)
                result["tags"].append("proxy_or_hosting")

        if isinstance(abuse, dict) and not isinstance(abuse, Exception):
            result["abuseipdb"] = abuse
            score = abuse.get("abuse_score", 0)
            if score >= 50:
                result["score"]     = max(result["score"], score)
                result["malicious"] = True
                result["tags"].append(f"abuseipdb_score_{score}")
                if abuse.get("is_tor"):
                    result["tor_exit"] = True
                    result["tags"].append("tor_exit")

        result["malicious"] = result["score"] >= SCORE_MALICIOUS

    _cache[ip] = (result, datetime.utcnow() + _CACHE_TTL)
    return result


def extract_ips_from_log(log: Dict[str, Any]) -> list:
    ips = []
    pf  = log.get("parsed_fields", {}) or {}

    for key in ("src_ip", "ssh_src_ip", "client_ip", "remote_addr"):
        val = pf.get(key)
        if val and val not in ("unknown", "-", ""):
            ips.append(val)

    if not ips:
        text  = log.get("raw", "") or log.get("message", "")
        found = re.findall(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', text)
        ips.extend([ip for ip in found if not is_private_ip(ip)])

    return list(dict.fromkeys(ips))


def add_to_blocklist(ip: str, reason: str = "manual"):
    _KNOWN_SCANNERS.add(ip)
    _cache.pop(ip, None)
    logger.info(f"TI: {ip} added to blocklist ({reason})")


async def enrich_log(log: Dict[str, Any]) -> Dict[str, Any]:
    ips = extract_ips_from_log(log)
    if not ips:
        return log

    enrichments = []
    for ip in ips[:3]:
        result = await enrich_ip(ip)
        if result:
            enrichments.append(result)

    if enrichments:
        pf = dict(log.get("parsed_fields", {}) or {})
        pf["threat_intel"]    = enrichments
        pf["has_malicious_ip"] = any(e.get("malicious") for e in enrichments)
        # Expose top-level geo for quick UI display
        top = enrichments[0]
        if top.get("country"):
            pf["geo_country"]      = top["country"]
            pf["geo_country_code"] = top.get("country_code")
            pf["geo_city"]         = top.get("city")
            pf["geo_isp"]          = top.get("isp")
        log = {**log, "parsed_fields": pf}

    return log
