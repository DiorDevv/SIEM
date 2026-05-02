#!/usr/bin/env python3
"""
SecureWatch SIEM Agent v4.0 — Enterprise-grade security monitoring agent.

New in v2.3:
  - Offline buffer: SQLite queue preserves logs when server is unreachable
  - Server health tracker with exponential backoff
  - Noise filter: configurable exclusion patterns reduce unwanted traffic
  - Agent self-health: CPU/MEM/disk reported in every heartbeat
  - Buffer drain loop: automatic retry when server recovers
  - Graceful shutdown: flushes in-memory events before exit

Collectors:
  - Log files (syslog, auth.log, nginx, JSON logs)
  - Windows Event Log
  - System metrics (CPU, MEM, DISK, NET, processes, connections)
  - File Integrity Monitor — periodic SHA256 + real-time inotify
  - Rootcheck (rootkit, SUID, suspicious cron, hidden processes)
  - Process Monitor (new processes, privilege escalation, persistence)
  - Network Monitor (suspicious connections, C2 indicators)
  - Auditd (Linux audit subsystem)
  - Inventory — packages, ports, processes, interfaces (hourly, delta)
"""
import os
import sys
import time
import logging
import signal
import socket
import platform
import threading
import psutil
from queue import Queue
from typing import Optional, List

import requests
import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Data directory bootstrap (before any collector imports) ───────────────────
# Allow DATA_DIR env override so Docker volume mounts work cleanly.
_data_dir_env = os.environ.get('DATA_DIR', '')
if _data_dir_env:
    os.makedirs(_data_dir_env, exist_ok=True)
    # Propagate to all collectors via environment so they can use it
    os.environ['SIEM_DATA_DIR'] = _data_dir_env

from buffer import LogBuffer, ServerHealth
from collectors.log_collector       import collect_logs
from collectors.journald_collector  import collect_journald_events
from collectors.system_collector    import collect_system_metrics
from collectors.file_integrity      import check_file_integrity, initialize_baselines
from collectors.fim_realtime        import RealtimeFIM
from collectors.rootcheck           import run_rootcheck
from collectors.process_monitor     import collect_processes
from collectors.network_monitor     import collect_connections
from collectors.auditd_collector    import collect_auditd_logs
from collectors.vuln_scanner        import collect_packages
from collectors.sca_collector       import run_sca
from collectors.windows_events      import collect_windows_events
from collectors.inventory_collector import collect_inventory
from collectors.docker_collector    import collect_docker, collect_kubernetes
from collectors.macos_collector     import collect_macos_events
from collectors.dedup               import dedup as _dedup, set_window as _dedup_set_window
from collectors.geoip               import enrich as _geoip_enrich
from collectors.threat_intel        import initialize as _ti_init, enrich as _ti_enrich
from collectors.correlation         import correlate as _correlate
from collectors.dns_monitor         import collect_dns_events
from collectors.windows_registry_fim import (
    initialize_registry_baseline, check_registry_integrity,
)
from collectors.windows_service_monitor import (
    initialize_service_baseline, check_services,
)
from active_response_handler        import execute_action

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)-8s] %(name)-24s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
logger = logging.getLogger('siem-agent')

# ── Constants ─────────────────────────────────────────────────────────────────

AGENT_VERSION = '4.0.0'
AGENT_DIR     = os.path.dirname(os.path.abspath(__file__))
# DATA_DIR holds all mutable state: buffer.db, .agent_id, state files.
# Defaults to AGENT_DIR (bare-metal), overridden by DATA_DIR env var (Docker/container).
DATA_DIR      = os.environ.get('DATA_DIR', AGENT_DIR)
os.makedirs(DATA_DIR, exist_ok=True)
AGENT_ID_FILE = os.path.join(DATA_DIR, '.agent_id')
BUFFER_DB     = os.path.join(DATA_DIR, 'buffer.db')
MAX_RETRIES   = 5
RETRY_DELAYS  = [2, 5, 10, 20, 30]

_shutdown     = threading.Event()
_agent_id     = [None]          # mutable ref shared across threads
_session      = requests.Session()
_session.headers.update({
    'User-Agent':   f'SecureWatch-Agent/{AGENT_VERSION}',
    'Content-Type': 'application/json',
})

_AGENT_SECRET = os.environ.get('AGENT_SECRET', '')
if _AGENT_SECRET:
    _session.headers['X-Agent-Token'] = _AGENT_SECRET

# Global singletons (initialised in main)
_buffer: LogBuffer     = None
_health: ServerHealth  = None

# ── Config ────────────────────────────────────────────────────────────────────

def load_config() -> dict:
    path = os.path.join(AGENT_DIR, 'config.yaml')
    defaults = {
        'manager_url':          'http://localhost:8000',
        'agent_name':           socket.gethostname(),
        'check_interval':       60,
        'heartbeat_interval':   30,
        'fim_interval':         300,
        'rootcheck_interval':   3600,
        'process_interval':     30,
        'network_interval':     30,
        'auditd_interval':      30,
        'batch_size':           100,
        'log_paths':            ['/var/log/syslog', '/var/log/auth.log'],
        'fim_paths':            ['/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/crontab'],
        'windows_event_logs':   ['Security', 'System', 'Application'],
        # Offline buffer
        'buffer_max_batches':   2000,
        'buffer_ttl_hours':     48,
        'buffer_drain_interval': 30,
        # Noise filter — messages/sources matching these are dropped before sending
        'exclusions': {
            'message_contains': [],
            'source_ends_with': [],
            'event_types':      [],
            'log_levels':       [],
        },
        # Deduplication: rolling window in seconds (0 = disabled)
        'dedup_window':  60,
        # GeoIP enrichment via ip-api.com (free, 45 req/min)
        'geoip_enabled': False,
        # Docker/Kubernetes collection interval (seconds)
        'docker_interval': 60,
        # Docker and K8s config blobs
        'docker':     {'events': True, 'logs': True},
        'kubernetes': {'enabled': False},
        # macOS — auto-detected; only active on Darwin
        'macos':      {'unified_log': True, 'audit_trail': True,
                       'persistence': True, 'network': True, 'sessions': True},
    }
    try:
        with open(path) as f:
            user = yaml.safe_load(f) or {}
        # Deep-merge exclusions
        if 'exclusions' in user:
            defaults['exclusions'].update(user.pop('exclusions'))
        defaults.update(user)
        logger.info(f"Config loaded: {path}")
    except FileNotFoundError:
        logger.warning("No config.yaml — using defaults")
    # ── Environment variable overrides (Docker-friendly) ─────────────────────
    env_map = {
        'MANAGER_URL':        'manager_url',
        'AGENT_NAME':         'agent_name',
        'AGENT_SECRET':       '_agent_secret',   # handled separately
        'LOG_LEVEL':          'log_level',
        'DEDUP_WINDOW':       'dedup_window',
        'GEOIP_ENABLED':      'geoip_enabled',
        'THREAT_INTEL_ENABLED': '_ti_enabled',
    }
    for env_key, cfg_key in env_map.items():
        val = os.environ.get(env_key, '')
        if val:
            if val.lower() in ('true', 'false'):
                defaults[cfg_key] = val.lower() == 'true'
            elif val.isdigit():
                defaults[cfg_key] = int(val)
            else:
                defaults[cfg_key] = val

    # Apply THREAT_INTEL_ENABLED to nested config
    _ti_val = defaults.pop('_ti_enabled', None)
    if _ti_val is not None:
        defaults.setdefault('threat_intel', {})['enabled'] = _ti_val

    # AGENT_SECRET → HTTP header (set at session level)
    secret = defaults.pop('_agent_secret', '') or os.environ.get('AGENT_SECRET', '')
    if secret:
        _session.headers['X-Agent-Token'] = secret

    return defaults


# ── Agent ID ──────────────────────────────────────────────────────────────────

def save_id(agent_id: str):
    with open(AGENT_ID_FILE, 'w') as f:
        f.write(agent_id)

def load_id() -> Optional[str]:
    try:
        with open(AGENT_ID_FILE) as f:
            v = f.read().strip()
            return v or None
    except FileNotFoundError:
        return None

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


# ── Agent self-health ─────────────────────────────────────────────────────────

def get_agent_health() -> dict:
    """Collect agent process metrics for heartbeat payload."""
    try:
        proc = psutil.Process(os.getpid())
        mem  = proc.memory_info()
        cpu  = proc.cpu_percent(interval=None)
        return {
            'agent_version':   AGENT_VERSION,
            'agent_cpu_pct':   round(cpu, 1),
            'agent_mem_mb':    round(mem.rss / 1024 / 1024, 1),
            'buffer_batches':  _buffer.size if _buffer else 0,
            'buffer_logs':     _buffer.total_logs if _buffer else 0,
            'server_up':       _health.is_up if _health else True,
        }
    except Exception:
        return {'agent_version': AGENT_VERSION}


# ── Noise filter ──────────────────────────────────────────────────────────────

def apply_noise_filter(logs: List[dict], exclusions: dict) -> List[dict]:
    """
    Drop log entries matching any exclusion rule before sending.
    Runs in O(n * k) where k = number of exclusion patterns.
    """
    if not exclusions or not logs:
        return logs

    msg_filters   = [f.lower() for f in exclusions.get('message_contains', [])]
    src_suffixes  = exclusions.get('source_ends_with', [])
    event_types   = set(exclusions.get('event_types', []))
    skip_levels   = set(exclusions.get('log_levels', []))

    if not (msg_filters or src_suffixes or event_types or skip_levels):
        return logs

    result = []
    dropped = 0
    for log in logs:
        msg        = (log.get('message') or '').lower()
        src        = log.get('source') or ''
        event_type = log.get('event_type') or ''
        level      = log.get('level') or ''

        if any(f in msg for f in msg_filters):
            dropped += 1
            continue
        if any(src.endswith(s) for s in src_suffixes):
            dropped += 1
            continue
        if event_type in event_types:
            dropped += 1
            continue
        if level in skip_levels:
            dropped += 1
            continue
        result.append(log)

    if dropped:
        logger.debug(f"Noise filter: dropped {dropped}/{len(logs)} log(s)")
    return result


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _post(url: str, payload: dict, timeout: int = 20) -> Optional[dict]:
    """POST JSON with retry. Updates server health state."""
    for attempt in range(MAX_RETRIES):
        if _shutdown.is_set():
            return None
        # Respect backoff when server is known-down
        if _health and not _health.should_retry():
            _shutdown.wait(2)
            continue
        try:
            resp = _session.post(url, json=payload, timeout=timeout)
            if resp.status_code < 500:
                if _health:
                    _health.mark_success()
                return resp.json() if resp.content else {}
            logger.warning(f"HTTP {resp.status_code} — retry {attempt+1}/{MAX_RETRIES}")
            if _health:
                _health.mark_failure()
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.ChunkedEncodingError):
            logger.warning(f"Cannot reach {url} — retry {attempt+1}/{MAX_RETRIES}")
            if _health:
                _health.mark_failure()
        except Exception as e:
            logger.error(f"Request error: {e}")
            return None
        _shutdown.wait(RETRY_DELAYS[min(attempt, len(RETRY_DELAYS) - 1)])
    return None


# ── Registration ──────────────────────────────────────────────────────────────

def register(config: dict) -> str:
    payload = {
        'hostname':      config.get('agent_name', socket.gethostname()),
        'ip_address':    get_local_ip(),
        'os':            platform.system(),
        'os_version':    f"{platform.release()} {platform.machine()}",
        'agent_version': AGENT_VERSION,
    }
    logger.info(f"Registering as '{payload['hostname']}' ({payload['ip_address']}) → {config['manager_url']}")
    while not _shutdown.is_set():
        r = _post(f"{config['manager_url']}/api/agents/register", payload, timeout=10)
        if r and 'agent_id' in r:
            save_id(r['agent_id'])
            logger.info(f"Registered: agent_id={r['agent_id']}")
            return r['agent_id']
        logger.warning("Registration failed — retrying in 15s")
        _shutdown.wait(15)
    return ''


# ── Send logs (with offline buffering) ───────────────────────────────────────

def send_logs(config: dict, agent_id: str, logs: List[dict]):
    """
    Send log batch to the server.
    Pipeline: noise_filter → dedup → geoip_enrich → batch → send / buffer
    On failure → push to offline buffer.
    On success → attempt to drain offline buffer.
    """
    if not logs:
        return

    url   = f"{config['manager_url']}/api/logs/ingest"
    bsize = config.get('batch_size', 100)

    # 1. Noise filter
    excl = config.get('exclusions', {})
    logs = apply_noise_filter(logs, excl)
    if not logs:
        return

    # 2. Deduplication (default 60 s window; 0 = disabled)
    dedup_window = config.get('dedup_window', 60)
    if dedup_window > 0:
        before = len(logs)
        logs   = _dedup(logs)
        dropped = before - len(logs)
        if dropped:
            logger.debug(f"Dedup: dropped {dropped} duplicate(s)")
    if not logs:
        return

    # 3. GeoIP enrichment (opt-in)
    if config.get('geoip_enabled', False):
        logs = [_geoip_enrich(log) for log in logs]

    # 4. Threat Intelligence enrichment (opt-in; off by default)
    if config.get('threat_intel', {}).get('enabled', False):
        logs = [_ti_enrich(log) for log in logs]

    # 5. Correlation engine — feed events in, append any composite alerts
    corr_alerts = _correlate(logs)
    if corr_alerts:
        logger.warning(f"Correlation: {len(corr_alerts)} composite alert(s) generated")
        logs = logs + corr_alerts

    all_sent = True
    for i in range(0, len(logs), bsize):
        batch     = logs[i:i + bsize]
        current_id = _agent_id[0] or agent_id
        r = _post(url, {'agent_id': current_id, 'logs': batch}, timeout=30)
        if r is None:
            # Server unreachable — buffer this batch
            if _buffer:
                _buffer.push(current_id, batch)
                logger.info(
                    f"Buffered {len(batch)} logs (buffer={_buffer.size} batches / "
                    f"{_buffer.total_logs} logs total)"
                )
            all_sent = False
        else:
            logger.debug(f"Sent {len(batch)} logs")

    # If everything sent OK and buffer has data — signal drain loop
    if all_sent and _buffer and _buffer.size > 0:
        logger.info(f"Server is up — {_buffer.size} buffered batch(es) pending drain")


# ── Buffer drain loop ─────────────────────────────────────────────────────────

def buffer_drain_loop(config: dict):
    """
    Periodically tries to send buffered (offline) logs to the server.
    Only runs when the buffer is non-empty and the server is reachable.
    """
    url      = f"{config['manager_url']}/api/logs/ingest"
    interval = config.get('buffer_drain_interval', 30)
    logger.info("Buffer drain loop started")

    while not _shutdown.is_set():
        _shutdown.wait(interval)
        if _shutdown.is_set():
            break

        if not _buffer or _buffer.size == 0:
            continue
        if _health and not _health.is_up:
            continue  # don't try while server is known-down

        batches = _buffer.drain(batch_limit=10)
        if not batches:
            continue

        logger.info(f"Draining buffer: {len(batches)} batch(es) ({_buffer.total_logs} total logs)")
        drained = 0
        for batch_id, aid, logs in batches:
            r = _post(url, {'agent_id': aid, 'logs': logs}, timeout=30)
            if r is not None:
                _buffer.ack(batch_id)
                drained += len(logs)
            else:
                _buffer.increment_retry(batch_id)
                logger.warning("Buffer drain: server still unreachable")
                break   # stop trying — wait for next cycle

        if drained:
            logger.info(
                f"Buffer drain: sent {drained} log(s). "
                f"Remaining: {_buffer.size} batches"
            )


# ── Active Response ───────────────────────────────────────────────────────────

def _process_ar_actions(config: dict, agent_id: str, actions: list):
    base_url = config['manager_url']
    for ar in actions:
        exec_id = ar.get("id")
        action  = ar.get("action", "")
        params  = ar.get("action_params") or ar.get("params") or {}
        ok, result = execute_action(action, params)
        status = "success" if ok else "failed"
        try:
            _session.post(
                f"{base_url}/api/ar/complete/{exec_id}",
                json={"status": status, "result": result[:2000]},
                timeout=10,
            )
        except Exception as e:
            logger.error(f"AR report-back failed exec_id={exec_id}: {e}")


# ── Heartbeat ─────────────────────────────────────────────────────────────────

def heartbeat_loop(config: dict, agent_id: str):
    """
    Send heartbeat every N seconds.
    Payload includes agent self-health metrics.
    Receives AR actions from server.
    Handles re-registration if agent was deleted.
    """
    interval = config.get('heartbeat_interval', 30)
    url      = f"{config['manager_url']}/api/agents/{{}}/heartbeat"

    while not _shutdown.is_set():
        current_id = _agent_id[0]
        try:
            health_data = get_agent_health()
            resp = _session.post(
                url.format(current_id),
                json=health_data,
                timeout=8,
            )
            if resp.status_code == 200:
                if _health:
                    _health.mark_success()
                logger.debug(f"Heartbeat OK (buf={health_data.get('buffer_batches', 0)})")
                data       = resp.json() if resp.content else {}
                ar_actions = data.get("ar_actions", [])
                if ar_actions:
                    logger.info(f"Received {len(ar_actions)} AR action(s)")
                    _process_ar_actions(config, current_id, ar_actions)
            elif resp.status_code == 404:
                logger.warning("Agent deleted — re-registering")
                new_id = register(config)
                if new_id:
                    _agent_id[0] = new_id
                    save_id(new_id)
                    logger.info(f"Re-registered: {new_id}")
            else:
                if _health:
                    _health.mark_failure()
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout):
            logger.warning("Heartbeat: server unreachable")
            if _health:
                _health.mark_failure()
        except Exception as e:
            logger.warning(f"Heartbeat: {e}")
        _shutdown.wait(interval)


# ── Collection loops ──────────────────────────────────────────────────────────

def log_collection_loop(config: dict, agent_id: str):
    interval = config.get('check_interval', 60)
    while not _shutdown.is_set():
        try:
            logs     = collect_logs(config)
            metrics  = collect_system_metrics()
            auditd   = collect_auditd_logs()
            journald = collect_journald_events()
            all_logs = logs + [metrics] + auditd + journald
            send_logs(config, agent_id, all_logs)
        except Exception as e:
            logger.error(f"Log collection: {e}", exc_info=True)
        _shutdown.wait(interval)


def process_monitor_loop(config: dict, agent_id: str):
    interval = config.get('process_interval', 30)
    while not _shutdown.is_set():
        try:
            events = collect_processes() + collect_connections()
            if events:
                send_logs(config, agent_id, events)
        except Exception as e:
            logger.error(f"Process/network monitor: {e}", exc_info=True)
        _shutdown.wait(interval)


def fim_loop(config: dict, agent_id: str):
    paths    = config.get('fim_paths', [])
    interval = config.get('fim_interval', 300)
    if not paths:
        return
    initialize_baselines(paths)
    _shutdown.wait(interval)
    while not _shutdown.is_set():
        try:
            alerts = check_file_integrity(paths)
            if alerts:
                logger.warning(f"FIM: {len(alerts)} change(s) detected")
                send_logs(config, agent_id, alerts)
        except Exception as e:
            logger.error(f"FIM: {e}", exc_info=True)
        _shutdown.wait(interval)


def fim_realtime_loop(config: dict, agent_id: str, event_queue: Queue):
    """Drain inotify events from queue and send in micro-batches."""
    batch: list = []
    flush_every = 2.0
    max_batch   = 50
    last_flush  = time.monotonic()

    while not _shutdown.is_set():
        try:
            deadline = time.monotonic() + flush_every
            while len(batch) < max_batch and time.monotonic() < deadline:
                try:
                    entry = event_queue.get(timeout=0.2)
                    batch.append(entry)
                except Exception:
                    break
            if batch:
                send_logs(config, agent_id, batch)
                logger.debug(f"FIM-RT: flushed {len(batch)} event(s)")
                batch = []
                last_flush = time.monotonic()
        except Exception as e:
            logger.error(f"FIM-RT drain: {e}", exc_info=True)


def rootcheck_loop(config: dict, agent_id: str):
    interval = config.get('rootcheck_interval', 3600)
    _shutdown.wait(30)
    while not _shutdown.is_set():
        try:
            logger.info("Rootcheck scan...")
            findings = run_rootcheck(config)
            if findings:
                logger.warning(f"Rootcheck: {len(findings)} finding(s)")
                send_logs(config, agent_id, findings)
            else:
                logger.info("Rootcheck: clean")
        except Exception as e:
            logger.error(f"Rootcheck: {e}", exc_info=True)
        _shutdown.wait(interval)


def vuln_scan_loop(config: dict, agent_id: str):
    interval = config.get('vuln_interval', 3600)
    hostname = config.get('agent_name', socket.gethostname())
    _shutdown.wait(60)
    while not _shutdown.is_set():
        try:
            logger.info("Vulnerability scan...")
            packages = collect_packages()
            if packages:
                url = f"{config['manager_url']}/api/vulns/scan"
                _post(url, {
                    'agent_id': _agent_id[0] or agent_id,
                    'hostname': hostname,
                    'packages': packages,
                }, timeout=60)
                logger.info(f"VulnScan: {len(packages)} packages submitted")
        except Exception as e:
            logger.error(f"VulnScan: {e}", exc_info=True)
        _shutdown.wait(interval)


def sca_loop(config: dict, agent_id: str):
    interval = config.get('sca_interval', 3600)
    hostname = config.get('agent_name', socket.gethostname())
    _shutdown.wait(90)
    while not _shutdown.is_set():
        try:
            logger.info("SCA checks...")
            checks = run_sca()
            if checks:
                url = f"{config['manager_url']}/api/sca/submit"
                _post(url, {
                    'agent_id': _agent_id[0] or agent_id,
                    'hostname': hostname,
                    'checks':   checks,
                }, timeout=30)
        except Exception as e:
            logger.error(f"SCA: {e}", exc_info=True)
        _shutdown.wait(interval)


def inventory_loop(config: dict, agent_id: str):
    """Delta-sync inventory: only changed sections are sent."""
    interval = config.get('inventory_interval', 3600)
    hostname = config.get('agent_name', socket.gethostname())
    base_url = config['manager_url']
    _shutdown.wait(120)

    while not _shutdown.is_set():
        try:
            aid = _agent_id[0] or agent_id
            logger.info("Inventory scan (delta mode)...")

            server_hashes = {"pkg_hash": None, "port_hash": None,
                             "proc_hash": None, "iface_hash": None}
            try:
                r = _session.get(f"{base_url}/api/inventory/hashes/{aid}", timeout=10)
                if r.status_code == 200:
                    server_hashes = r.json()
            except Exception as e:
                logger.warning(f"Inventory: hashes fetch failed: {e}")

            data = collect_inventory()
            changed = {
                'packages':   data['pkg_hash']   != server_hashes.get('pkg_hash'),
                'ports':      data['port_hash']  != server_hashes.get('port_hash'),
                'processes':  data['proc_hash']  != server_hashes.get('proc_hash'),
                'interfaces': data['iface_hash'] != server_hashes.get('iface_hash'),
            }
            n_changed = sum(changed.values())

            payload = {
                'agent_id':         aid,
                'hostname':         hostname,
                'scanned_at':       data['scanned_at'],
                'scan_duration_ms': data['scan_duration_ms'],
                'pkg_hash':         data['pkg_hash'],
                'port_hash':        data['port_hash'],
                'proc_hash':        data['proc_hash'],
                'iface_hash':       data['iface_hash'],
            }

            if n_changed == 4 or server_hashes['pkg_hash'] is None:
                payload.update({
                    'packages':   data['packages'],
                    'ports':      data['ports'],
                    'processes':  data['processes'],
                    'interfaces': data['interfaces'],
                })
                _post(f"{base_url}/api/inventory/submit", payload, timeout=120)
                logger.info(
                    f"Inventory FULL: pkg={len(data['packages'])} "
                    f"ports={len(data['ports'])} procs={len(data['processes'])} "
                    f"ifaces={len(data['interfaces'])}"
                )
            elif n_changed == 0:
                logger.info("Inventory DELTA: no changes")
            else:
                for key in ('packages', 'ports', 'processes', 'interfaces'):
                    if changed[key]:
                        payload[key] = data[key]
                _post(f"{base_url}/api/inventory/delta", payload, timeout=120)
                logger.info(f"Inventory DELTA: changed={[k for k,v in changed.items() if v]}")

        except Exception as e:
            logger.error(f"Inventory: {e}", exc_info=True)
        _shutdown.wait(interval)


def docker_loop(config: dict, agent_id: str):
    """Docker daemon events + container logs + optional Kubernetes."""
    import asyncio
    interval = config.get('docker_interval', 60)
    _shutdown.wait(30)  # give other collectors time to start first

    while not _shutdown.is_set():
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            docker_cfg = config.get('docker', {})
            events = loop.run_until_complete(collect_docker(docker_cfg))

            k8s_cfg = config.get('kubernetes', {})
            if k8s_cfg.get('enabled'):
                k8s_events = loop.run_until_complete(collect_kubernetes(k8s_cfg))
                events.extend(k8s_events)

            loop.close()
            if events:
                send_logs(config, agent_id, events)
        except Exception as e:
            logger.error(f"Docker/K8s loop: {e}", exc_info=True)
        _shutdown.wait(interval)


def macos_loop(config: dict, agent_id: str):
    """macOS Unified Log, BSM audit, persistence scan, and session events."""
    import asyncio
    interval = config.get('check_interval', 60)

    while not _shutdown.is_set():
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            macos_cfg = config.get('macos', {})
            events = loop.run_until_complete(collect_macos_events(macos_cfg))
            loop.close()
            if events:
                send_logs(config, agent_id, events)
        except Exception as e:
            logger.error(f"macOS loop: {e}", exc_info=True)
        _shutdown.wait(interval)


def windows_events_loop(config: dict, agent_id: str):
    interval = config.get('check_interval', 60)
    while not _shutdown.is_set():
        try:
            events = collect_windows_events(config)
            if events:
                send_logs(config, agent_id, events)
        except Exception as e:
            logger.error(f"Windows events: {e}", exc_info=True)
        _shutdown.wait(interval)


def dns_monitor_loop(config: dict, agent_id: str):
    """DNS query monitoring — DGA, tunneling, suspicious TLD, query floods."""
    interval = config.get('dns_monitor_interval', 60)
    while not _shutdown.is_set():
        try:
            events = collect_dns_events()
            if events:
                send_logs(config, agent_id, events)
        except Exception as e:
            logger.error(f"DNS monitor: {e}", exc_info=True)
        _shutdown.wait(interval)


def windows_registry_fim_loop(config: dict, agent_id: str):
    """Windows Registry FIM — detects Run-key, LSA, WDigest, UAC changes."""
    interval = config.get('registry_fim_interval', 120)
    _shutdown.wait(15)
    while not _shutdown.is_set():
        try:
            alerts = check_registry_integrity()
            if alerts:
                logger.warning(f"Registry FIM: {len(alerts)} change(s)")
                send_logs(config, agent_id, alerts)
        except Exception as e:
            logger.error(f"Registry FIM: {e}", exc_info=True)
        _shutdown.wait(interval)


def windows_service_monitor_loop(config: dict, agent_id: str):
    """Windows Service Monitor — new services, path changes, critical disabled."""
    interval = config.get('service_monitor_interval', 120)
    _shutdown.wait(20)
    while not _shutdown.is_set():
        try:
            alerts = check_services()
            if alerts:
                logger.warning(f"Service monitor: {len(alerts)} change(s)")
                send_logs(config, agent_id, alerts)
        except Exception as e:
            logger.error(f"Service monitor: {e}", exc_info=True)
        _shutdown.wait(interval)


# ── Shutdown ──────────────────────────────────────────────────────────────────

def _on_signal(sig, frame):
    logger.info(f"Signal {sig} — shutting down gracefully...")
    _shutdown.set()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    global _buffer, _health

    # Signal handlers only work in the main thread (not when running as a Windows service)
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT,  _on_signal)
        signal.signal(signal.SIGTERM, _on_signal)

    config = load_config()

    # Set log level from config
    level = getattr(logging, config.get('log_level', 'INFO').upper(), logging.INFO)
    logging.getLogger().setLevel(level)

    logger.info("=" * 62)
    logger.info(f"  SecureWatch SIEM Agent v{AGENT_VERSION}")
    logger.info(f"  Manager : {config['manager_url']}")
    logger.info(f"  Host    : {config.get('agent_name', socket.gethostname())}")
    logger.info(f"  OS      : {platform.system()} {platform.release()}")
    logger.info("=" * 62)

    # ── Initialise offline buffer ─────────────────────────────────────────────
    _buffer = LogBuffer(
        db_path     = BUFFER_DB,
        max_batches = config.get('buffer_max_batches', 2000),
        ttl_hours   = config.get('buffer_ttl_hours', 48),
    )
    _health = ServerHealth()
    queued = _buffer.size
    if queued:
        logger.info(
            f"  Buffer  : {queued} batch(es) / {_buffer.total_logs} log(s) pending (will drain when server reachable)"
        )
    else:
        logger.info(f"  Buffer  : {BUFFER_DB} (empty)")

    # ── Noise filter summary ──────────────────────────────────────────────────
    excl = config.get('exclusions', {})
    n_excl = sum(len(v) for v in excl.values() if isinstance(v, list))
    if n_excl:
        logger.info(f"  Filter  : {n_excl} exclusion rule(s) active")

    # ── Deduplication window ──────────────────────────────────────────────────
    dedup_win = config.get('dedup_window', 60)
    if dedup_win > 0:
        _dedup_set_window(dedup_win)
        logger.info(f"  Dedup   : {dedup_win}s rolling window (CRITICAL/ERROR always pass)")
    else:
        logger.info("  Dedup   : disabled")

    # ── GeoIP ─────────────────────────────────────────────────────────────────
    if config.get('geoip_enabled'):
        logger.info("  GeoIP   : enabled (ip-api.com, 24h cache)")

    # ── Agent ID ──────────────────────────────────────────────────────────────
    agent_id = load_id()
    if agent_id:
        logger.info(f"  Agent ID: {agent_id} (resuming)")
    else:
        agent_id = register(config)
        if not agent_id:
            logger.error("Registration failed — exiting")
            sys.exit(1)
    _agent_id[0] = agent_id

    # ── Threat Intelligence ───────────────────────────────────────────────────
    _ti_init(config)
    ti_cfg = config.get('threat_intel', {})
    if ti_cfg.get('enabled', False):
        logger.info("  ThreatIntel: enabled — downloading feeds in background")
    else:
        logger.info("  ThreatIntel: disabled (set threat_intel.enabled: true to activate)")

    # ── Windows baselines ─────────────────────────────────────────────────────
    if os.name == 'nt':
        initialize_registry_baseline()
        initialize_service_baseline()
        logger.info("  Win-FIM : Registry + Service baselines initialised")

    # ── Real-time FIM ─────────────────────────────────────────────────────────
    fim_queue = Queue(maxsize=5000)
    rt_paths  = config.get(
        'windows_fim_realtime_paths' if os.name == 'nt' else 'fim_realtime_paths',
        config.get('fim_realtime_paths', config.get('fim_paths', ['/etc', '/usr/bin'])),
    )
    fim_rt    = RealtimeFIM(rt_paths, fim_queue)
    rt_active = fim_rt.start()
    logger.info(f"  FIM-RT  : {'inotify watching ' + str(len(rt_paths)) + ' path(s)' if rt_active else 'periodic only'}")

    # ── Threads ───────────────────────────────────────────────────────────────
    threads = [
        threading.Thread(target=heartbeat_loop,       args=(config, agent_id), name='heartbeat',        daemon=True),
        threading.Thread(target=log_collection_loop,  args=(config, agent_id), name='log-collector',    daemon=True),
        threading.Thread(target=process_monitor_loop, args=(config, agent_id), name='proc-net-monitor', daemon=True),
        threading.Thread(target=fim_loop,             args=(config, agent_id), name='fim-periodic',     daemon=True),
        threading.Thread(target=rootcheck_loop,       args=(config, agent_id), name='rootcheck',        daemon=True),
        threading.Thread(target=vuln_scan_loop,       args=(config, agent_id), name='vuln-scanner',     daemon=True),
        threading.Thread(target=sca_loop,             args=(config, agent_id), name='sca',              daemon=True),
        threading.Thread(target=inventory_loop,       args=(config, agent_id), name='inventory',        daemon=True),
        threading.Thread(target=windows_events_loop,  args=(config, agent_id), name='win-events',       daemon=True),
        threading.Thread(target=buffer_drain_loop,    args=(config,),          name='buf-drain',        daemon=True),
    ]

    # DNS monitor — all platforms
    threads.append(threading.Thread(
        target=dns_monitor_loop, args=(config, agent_id), name='dns-monitor', daemon=True,
    ))

    # Docker/K8s — start when Docker socket is present or explicitly enabled
    if (os.path.exists('/var/run/docker.sock')
            or config.get('docker', {}).get('enabled')
            or config.get('kubernetes', {}).get('enabled')):
        threads.append(threading.Thread(
            target=docker_loop, args=(config, agent_id), name='docker-k8s', daemon=True,
        ))

    # macOS — only on Darwin
    if platform.system() == 'Darwin':
        threads.append(threading.Thread(
            target=macos_loop, args=(config, agent_id), name='macos-events', daemon=True,
        ))

    # Windows-only collectors
    if os.name == 'nt':
        threads.append(threading.Thread(
            target=windows_registry_fim_loop,
            args=(config, agent_id), name='win-registry-fim', daemon=True,
        ))
        threads.append(threading.Thread(
            target=windows_service_monitor_loop,
            args=(config, agent_id), name='win-svc-monitor', daemon=True,
        ))

    if rt_active:
        threads.append(threading.Thread(
            target=fim_realtime_loop,
            args=(config, agent_id, fim_queue),
            name='fim-realtime', daemon=True,
        ))

    for t in threads:
        t.start()
        logger.info(f"  Started : {t.name}")

    logger.info("Agent active — Ctrl+C to stop")
    _shutdown.wait()

    # ── Graceful shutdown ─────────────────────────────────────────────────────
    if rt_active:
        fim_rt.stop()
    if _buffer:
        remaining = _buffer.size
        if remaining:
            logger.info(
                f"Shutdown: {remaining} batch(es) remain in buffer — "
                "will be sent when agent restarts"
            )
        _buffer.close()
    logger.info("Agent stopped.")


if __name__ == '__main__':
    main()
