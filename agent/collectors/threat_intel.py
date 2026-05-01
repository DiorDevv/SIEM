"""
Threat Intelligence — IP/domain reputation checking.

Sources (auto-downloaded daily, cached locally):
  1. Firehol Level 1 — ~6,000 IPs (highest-confidence attackers)
  2. Emerging Threats Compromised IPs — known C2/botnet IPs
  3. Local custom blocklist (config: threat_intel.blocklist_path)
  4. AbuseIPDB API (optional, requires threat_intel.abuseipdb_key)

How it works:
  - On agent start: downloads feeds to .threat_intel/ directory
  - Loads IPs and CIDRs into memory for O(1) lookups
  - Enriches every log event that contains a public IP field
  - Matching events get a 'threat_intel' field added + severity elevated

Usage:
  from collectors.threat_intel import initialize, enrich as ti_enrich
"""
import ipaddress
import logging
import os
import re
import shutil
import threading
import time
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

_lock            = threading.Lock()
_blocklist_ips:  Set[str]                        = set()
_blocklist_nets: List[ipaddress.IPv4Network]     = []
_loaded_at:      float                           = 0
_RELOAD_TTL      = 86_400   # re-download every 24 h

_TI_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', '.threat_intel'
)

# Feed definitions: (url, local_filename, description)
_FEEDS = [
    (
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        "firehol_level1.netset",
        "Firehol Level 1 (highest-confidence attackers)",
    ),
    (
        "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        "emerging_block.txt",
        "Emerging Threats compromised IPs",
    ),
]

_IP_FIELDS = (
    'src_ip', 'ssh_src_ip', 'attacker_ip', 'client_ip',
    'dst_ip', 'remote_ip', 'ip_address',
)


# ── Internal ──────────────────────────────────────────────────────────────────

def _parse_file(path: str, ips: Set[str], nets: List):
    try:
        with open(path, errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    if '/' in line:
                        nets.append(ipaddress.ip_network(line, strict=False))
                    else:
                        ips.add(line)
                except ValueError:
                    pass
    except Exception as e:
        logger.debug(f"ThreatIntel parse {path}: {e}")


def _load():
    global _blocklist_ips, _blocklist_nets, _loaded_at
    ips: Set[str] = set()
    nets: List    = []

    if os.path.isdir(_TI_DIR):
        for fname in os.listdir(_TI_DIR):
            _parse_file(os.path.join(_TI_DIR, fname), ips, nets)

    with _lock:
        _blocklist_ips  = ips
        _blocklist_nets = nets
        _loaded_at      = time.monotonic()

    total = len(ips) + len(nets)
    if total:
        logger.info(f"ThreatIntel: {len(ips)} IPs + {len(nets)} CIDRs loaded")


def _download_feeds():
    os.makedirs(_TI_DIR, exist_ok=True)
    try:
        import requests
    except ImportError:
        return

    for url, fname, desc in _FEEDS:
        dest = os.path.join(_TI_DIR, fname)
        # Skip if fresh
        if os.path.exists(dest) and (time.time() - os.path.getmtime(dest)) < _RELOAD_TTL:
            continue
        try:
            r = requests.get(url, timeout=20)
            if r.status_code == 200:
                with open(dest, 'w') as f:
                    f.write(r.text)
                logger.info(f"ThreatIntel: updated {desc}")
            else:
                logger.debug(f"ThreatIntel: {fname} HTTP {r.status_code}")
        except Exception as e:
            logger.debug(f"ThreatIntel: download {fname}: {e}")


def _maybe_reload():
    if time.monotonic() - _loaded_at > _RELOAD_TTL:
        _download_feeds()
        _load()


def _background_init(config: dict):
    _download_feeds()
    local = config.get('threat_intel', {}).get('blocklist_path', '')
    if local and os.path.isfile(local):
        dest = os.path.join(_TI_DIR, 'custom_blocklist.txt')
        try:
            shutil.copy(local, dest)
        except Exception:
            pass
    _load()


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

_abuseipdb_key:   str   = ''
_abuse_cache:     Dict  = {}
_abuse_cache_lock = threading.Lock()
_ABUSE_TTL = 3600  # 1-hour cache


def _check_abuseipdb(ip: str) -> Optional[Dict]:
    if not _abuseipdb_key:
        return None
    now = time.time()
    with _abuse_cache_lock:
        if ip in _abuse_cache:
            entry, ts = _abuse_cache[ip]
            if now - ts < _ABUSE_TTL:
                return entry
    try:
        import requests
        r = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={'Key': _abuseipdb_key, 'Accept': 'application/json'},
            params={'ipAddress': ip, 'maxAgeInDays': 30},
            timeout=5,
        )
        if r.status_code == 200:
            d = r.json().get('data', {})
            score = d.get('abuseConfidenceScore', 0)
            if score >= 25:
                result = {
                    'source':     'abuseipdb',
                    'confidence': 'high' if score >= 75 else 'medium',
                    'score':      score,
                    'indicator':  ip,
                }
                with _abuse_cache_lock:
                    _abuse_cache[ip] = (result, now)
                return result
            else:
                with _abuse_cache_lock:
                    _abuse_cache[ip] = (None, now)
    except Exception as e:
        logger.debug(f"AbuseIPDB {ip}: {e}")
    return None


# ── Public API ────────────────────────────────────────────────────────────────

def initialize(config: dict = None):
    """
    Initialize threat intelligence. Call once at agent start.
    Downloads feeds and loads into memory (background thread).
    """
    global _abuseipdb_key
    cfg = (config or {}).get('threat_intel', {})
    if not cfg.get('enabled', False):
        logger.info("ThreatIntel: disabled in config")
        return

    _abuseipdb_key = cfg.get('abuseipdb_key', '')

    t = threading.Thread(target=_background_init, args=(config or {},),
                         name='threat-intel-init', daemon=True)
    t.start()


def check_ip(ip: str) -> Optional[Dict[str, str]]:
    """
    Check if an IP is known-malicious.
    Returns dict with source/confidence/indicator, or None if clean.
    """
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return None
    except ValueError:
        return None

    _maybe_reload()

    with _lock:
        if ip in _blocklist_ips:
            return {'source': 'blocklist', 'confidence': 'high', 'indicator': ip}
        for net in _blocklist_nets:
            try:
                if addr in net:
                    return {'source': 'blocklist_cidr', 'confidence': 'medium',
                            'indicator': str(net)}
            except Exception:
                pass

    # AbuseIPDB fallback (if key configured)
    return _check_abuseipdb(ip)


def enrich(log: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add a 'threat_intel' field to the log dict if a contained IP is known-bad.
    Also elevates severity for matched events.
    """
    if log.get('threat_intel'):
        return log

    pf = log.get('parsed_fields') or {}

    for field in _IP_FIELDS:
        ip = str(pf.get(field) or log.get(field) or '').strip()
        if not ip or ip in ('', 'None', '0.0.0.0', '::'):
            continue
        result = check_ip(ip)
        if result:
            log['threat_intel'] = {**result, 'matched_field': field, 'matched_ip': ip}
            # Elevate severity: INFO/WARNING/MEDIUM → HIGH; HIGH stays HIGH
            if log.get('level') in ('INFO', 'WARNING', 'MEDIUM', 'LOW'):
                log['level'] = 'HIGH'
            original_msg = log.get('message', '')
            if '[TI]' not in original_msg:
                log['message'] = f"[TI:{result['confidence'].upper()}] {original_msg}"
            logger.debug(f"ThreatIntel hit: {ip} ({result['source']})")
            break

    return log


def get_stats() -> Dict[str, int]:
    with _lock:
        return {'ips': len(_blocklist_ips), 'cidrs': len(_blocklist_nets)}
