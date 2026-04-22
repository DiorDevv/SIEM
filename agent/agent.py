#!/usr/bin/env python3
"""
SecureWatch SIEM Agent v2.1 — Wazuh-class security monitoring agent.

Collectors:
  - Log files (syslog, auth.log, nginx, JSON logs)
  - Windows Event Log
  - System metrics (CPU, MEM, DISK, NET, processes, connections)
  - File Integrity Monitor — periodic SHA256 + real-time inotify
  - Rootcheck (rootkit, SUID, suspicious cron, hidden processes)
  - Process Monitor (new processes, privilege escalation, persistence)
  - Network Monitor (suspicious connections, C2 indicators)
  - Auditd (Linux audit subsystem)
"""
import os
import sys
import logging
import signal
import socket
import platform
import threading
from queue import Queue, Empty
from typing import Optional, List

import requests
import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from collectors.log_collector      import collect_logs
from collectors.journald_collector import collect_journald_events
from collectors.system_collector   import collect_system_metrics
from collectors.file_integrity     import check_file_integrity, initialize_baselines
from collectors.fim_realtime       import RealtimeFIM
from collectors.rootcheck          import run_rootcheck
from collectors.process_monitor    import collect_processes
from collectors.network_monitor    import collect_connections
from collectors.auditd_collector   import collect_auditd_logs
from collectors.vuln_scanner       import collect_packages
from collectors.sca_collector      import run_sca
from collectors.windows_events     import collect_windows_events
from active_response_handler       import execute_action

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)-8s] %(name)-24s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
logger = logging.getLogger('siem-agent')

# ── Constants ─────────────────────────────────────────────────────────────────

AGENT_VERSION  = '2.1.0'
AGENT_ID_FILE  = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.agent_id')
MAX_RETRIES    = 5
RETRY_DELAYS   = [2, 5, 10, 20, 30]

_shutdown   = threading.Event()
_agent_id   = [None]   # mutable ref shared across all threads
_session   = requests.Session()
_session.headers.update({
    'User-Agent':   f'SecureWatch-Agent/{AGENT_VERSION}',
    'Content-Type': 'application/json',
})


# ── Config ────────────────────────────────────────────────────────────────────

def load_config() -> dict:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.yaml')
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
    }
    try:
        with open(path) as f:
            user = yaml.safe_load(f) or {}
        defaults.update(user)
        logger.info(f"Config: {path}")
    except FileNotFoundError:
        logger.warning("No config.yaml — using defaults")
    # Environment variables override config.yaml
    if os.environ.get('MANAGER_URL'):
        defaults['manager_url'] = os.environ['MANAGER_URL']
    return defaults


# ── Agent ID ──────────────────────────────────────────────────────────────────

def save_id(agent_id: str):
    with open(AGENT_ID_FILE, 'w') as f:
        f.write(agent_id)

def load_id() -> Optional[str]:
    try:
        with open(AGENT_ID_FILE) as f:
            val = f.read().strip()
            return val or None
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


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _post(url: str, payload: dict, timeout: int = 20) -> Optional[dict]:
    for attempt in range(MAX_RETRIES):
        if _shutdown.is_set():
            return None
        try:
            resp = _session.post(url, json=payload, timeout=timeout)
            if resp.status_code < 500:
                return resp.json() if resp.content else {}
            logger.warning(f"HTTP {resp.status_code} — retry {attempt+1}")
        except requests.exceptions.ConnectionError:
            logger.warning(f"Cannot connect to {url} — retry {attempt+1}/{MAX_RETRIES}")
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout — retry {attempt+1}/{MAX_RETRIES}")
        except Exception as e:
            logger.error(f"Request error: {e}")
            return None
        _shutdown.wait(RETRY_DELAYS[min(attempt, len(RETRY_DELAYS)-1)])
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


# ── Send logs ─────────────────────────────────────────────────────────────────

def send_logs(config: dict, agent_id: str, logs: List[dict]):
    if not logs:
        return
    url   = f"{config['manager_url']}/api/logs/ingest"
    bsize = config.get('batch_size', 100)
    sent  = 0
    for i in range(0, len(logs), bsize):
        batch = logs[i:i+bsize]
        current_id = _agent_id[0] or agent_id
        r = _post(url, {'agent_id': current_id, 'logs': batch}, timeout=30)
        if r is not None:
            sent += len(batch)
        else:
            logger.error(f"Batch {i//bsize+1} failed")
    if sent:
        logger.info(f"Sent {sent}/{len(logs)} logs")


# ── Threads ───────────────────────────────────────────────────────────────────

def _process_ar_actions(config: dict, agent_id: str, actions: list):
    """Execute active response actions received from the server."""
    ar_complete_url = f"{config['manager_url']}/api/ar/complete"
    for ar in actions:
        exec_id = ar.get("id")
        action  = ar.get("action", "")
        params  = ar.get("params", {})
        ok, result = execute_action(action, params)
        status = "success" if ok else "failed"
        try:
            _session.post(
                f"{ar_complete_url}/{exec_id}",
                json={"status": status, "result": result[:1000]},
                timeout=10,
            )
        except Exception as e:
            logger.error(f"AR report-back failed for exec_id={exec_id}: {e}")


def heartbeat_loop(config: dict, agent_id: str):
    interval = config.get('heartbeat_interval', 30)
    while not _shutdown.is_set():
        current_id = _agent_id[0]
        url = f"{config['manager_url']}/api/agents/{current_id}/heartbeat"
        try:
            resp = _session.post(url, timeout=8)
            if resp.status_code == 200:
                logger.debug("Heartbeat OK")
                data = resp.json() if resp.content else {}
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
                    logger.info(f"Re-registered: all threads switched to {new_id}")
        except Exception as e:
            logger.warning(f"Heartbeat: {e}")
        _shutdown.wait(interval)


def log_collection_loop(config: dict, agent_id: str):
    interval = config.get('check_interval', 60)
    while not _shutdown.is_set():
        try:
            logs     = collect_logs(config)
            metrics  = collect_system_metrics()
            auditd   = collect_auditd_logs()
            journald = collect_journald_events()
            all_logs = logs + [metrics] + auditd + journald
            logger.debug(f"Logs={len(logs)} auditd={len(auditd)} journald={len(journald)}")
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
                logger.warning(f"FIM: {len(alerts)} change(s)")
                send_logs(config, agent_id, alerts)
        except Exception as e:
            logger.error(f"FIM: {e}", exc_info=True)
        _shutdown.wait(interval)


def fim_realtime_loop(config: dict, agent_id: str, event_queue: Queue):
    """Drain inotify events from queue and send to backend in micro-batches."""
    batch: List[dict] = []
    flush_every = 2.0   # seconds between flushes even if batch is small
    max_batch   = 50

    import time
    last_flush = time.monotonic()

    while not _shutdown.is_set():
        try:
            # Drain up to max_batch events without blocking longer than 1s
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
            logger.info("Running rootcheck scan...")
            findings = run_rootcheck(config)
            if findings:
                logger.warning(f"Rootcheck: {len(findings)} finding(s)")
                send_logs(config, agent_id, findings)
            else:
                logger.info("Rootcheck: no findings")
        except Exception as e:
            logger.error(f"Rootcheck: {e}", exc_info=True)
        _shutdown.wait(interval)


def vuln_scan_loop(config: dict, agent_id: str):
    interval = config.get('vuln_interval', 3600)
    hostname = config.get('agent_name', socket.gethostname())
    _shutdown.wait(60)   # wait 1m after startup
    while not _shutdown.is_set():
        try:
            logger.info("Running vulnerability scan...")
            packages = collect_packages()
            if packages:
                url = f"{config['manager_url']}/api/vulns/scan"
                _post(url, {
                    'agent_id': _agent_id[0] or agent_id,
                    'hostname': hostname,
                    'packages': packages,
                }, timeout=60)
                logger.info(f"VulnScan: submitted {len(packages)} packages")
        except Exception as e:
            logger.error(f"VulnScan: {e}", exc_info=True)
        _shutdown.wait(interval)


def sca_loop(config: dict, agent_id: str):
    interval = config.get('sca_interval', 3600)
    hostname = config.get('agent_name', socket.gethostname())
    _shutdown.wait(90)   # wait 1.5m after startup
    while not _shutdown.is_set():
        try:
            logger.info("Running SCA checks...")
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


# ── Shutdown ──────────────────────────────────────────────────────────────────

def _on_signal(sig, frame):
    logger.info(f"Signal {sig} — shutting down...")
    _shutdown.set()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    signal.signal(signal.SIGINT,  _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    config = load_config()

    logger.info("=" * 60)
    logger.info(f"  SecureWatch SIEM Agent v{AGENT_VERSION}")
    logger.info(f"  Manager : {config['manager_url']}")
    logger.info(f"  Host    : {config.get('agent_name', socket.gethostname())}")
    logger.info(f"  OS      : {platform.system()} {platform.release()}")
    logger.info("=" * 60)

    agent_id = load_id()
    if agent_id:
        logger.info(f"Resuming: agent_id={agent_id}")
    else:
        agent_id = register(config)
        if not agent_id:
            logger.error("Registration failed — exiting")
            sys.exit(1)
    _agent_id[0] = agent_id

    # ── Real-time FIM (inotify) ───────────────────────────────────────────────
    fim_queue: Queue = Queue(maxsize=5000)
    rt_paths  = config.get('fim_realtime_paths',
                           config.get('fim_paths', ['/etc', '/usr/bin', '/usr/sbin']))
    fim_rt    = RealtimeFIM(rt_paths, fim_queue)
    rt_active = fim_rt.start()
    if rt_active:
        logger.info(f"  FIM-RT  : inotify watching {len(rt_paths)} path(s)")
    else:
        logger.info("  FIM-RT  : inotify unavailable — periodic FIM only")

    threads = [
        threading.Thread(target=heartbeat_loop,       args=(config, agent_id), name='heartbeat',        daemon=True),
        threading.Thread(target=log_collection_loop,  args=(config, agent_id), name='log-collector',    daemon=True),
        threading.Thread(target=process_monitor_loop, args=(config, agent_id), name='proc-net-monitor', daemon=True),
        threading.Thread(target=fim_loop,             args=(config, agent_id), name='fim-periodic',     daemon=True),
        threading.Thread(target=rootcheck_loop,       args=(config, agent_id), name='rootcheck',        daemon=True),
        threading.Thread(target=vuln_scan_loop,       args=(config, agent_id), name='vuln-scanner',     daemon=True),
        threading.Thread(target=sca_loop,             args=(config, agent_id), name='sca',              daemon=True),
        threading.Thread(target=windows_events_loop,  args=(config, agent_id), name='win-events',       daemon=True),
    ]
    if rt_active:
        threads.append(threading.Thread(
            target=fim_realtime_loop, args=(config, agent_id, fim_queue),
            name='fim-realtime', daemon=True,
        ))

    for t in threads:
        t.start()
        logger.info(f"  Started : {t.name}")

    logger.info("Agent active — Ctrl+C to stop")
    _shutdown.wait()
    if rt_active:
        fim_rt.stop()
    logger.info("Agent stopped.")


if __name__ == '__main__':
    main()
