"""
GeoIP enrichment — country / city / ASN annotation for public IPs.
Uses ip-api.com (free, 45 req/min, no key) with a 24-hour in-process cache.
Private / loopback IPs are skipped without network calls.
"""
import ipaddress
import logging
import threading
import time
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_lock       = threading.Lock()
_cache:     Dict[str, Any]   = {}   # ip  → {country, city, asn, …, _ts}
_neg_cache: Dict[str, float] = {}   # ip  → failed_at timestamp
_TTL      = 86_400   # 24 h positive cache
_NEG_TTL  =  3_600   # 1 h  negative cache

# Fields in a log event that may carry an IP address
_IP_FIELDS = ('src_ip', 'ssh_src_ip', 'client_ip', 'dst_ip', 'remote_ip', 'ip_address')


def _is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local
                    or a.is_multicast or a.is_reserved or a.is_unspecified)
    except ValueError:
        return False


def lookup(ip: str, timeout: int = 3) -> Optional[Dict[str, str]]:
    """Return GeoIP dict for a public IP, or None."""
    if not ip or not _is_public(ip):
        return None

    now = time.time()

    with _lock:
        if ip in _cache:
            entry = _cache[ip]
            if now - entry['_ts'] < _TTL:
                return {k: v for k, v in entry.items() if k != '_ts'}
            del _cache[ip]
        if ip in _neg_cache and now - _neg_cache[ip] < _NEG_TTL:
            return None

    try:
        import requests  # already in requirements
        r = requests.get(
            f"https://ip-api.com/json/{ip}"   # HTTPS — prevents MITM on lookup
            "?fields=status,country,countryCode,city,isp,org,as",
            timeout=timeout,
        )
        if r.status_code == 429:
            with _lock:
                _neg_cache[ip] = now
            return None
        if r.status_code == 200:
            data = r.json()
            if data.get('status') == 'success':
                geo = {
                    'country':      data.get('country', ''),
                    'country_code': data.get('countryCode', ''),
                    'city':         data.get('city', ''),
                    'isp':          data.get('isp', ''),
                    'asn':          data.get('as', ''),
                }
                with _lock:
                    _cache[ip] = {**geo, '_ts': now}
                return geo
    except Exception as exc:
        logger.debug("GeoIP %s: %s", ip, exc)

    with _lock:
        _neg_cache[ip] = now
    return None


def enrich(log: Dict[str, Any]) -> Dict[str, Any]:
    """Add a `geoip` key to the log dict when a public IP is found."""
    if log.get('geoip'):
        return log

    pf = log.get('parsed_fields') or {}

    for field in _IP_FIELDS:
        ip = str(log.get(field) or pf.get(field) or '').strip()
        if ip and _is_public(ip):
            geo = lookup(ip)
            if geo:
                log['geoip'] = geo
            break  # only enrich the first IP field found

    return log
