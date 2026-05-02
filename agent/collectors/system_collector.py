"""
Professional system metrics collector.
Collects CPU, memory, disk, network, processes, and open connections.
"""
import os
import sys
import logging
import socket
from datetime import datetime, timezone
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


def _human_bytes(n: int) -> str:
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n //= 1024
    return f"{n}PB"


def collect_system_metrics() -> Dict[str, Any]:
    try:
        import psutil
    except ImportError:
        logger.warning("psutil not installed")
        return _fallback_metrics()

    try:
        # ── CPU ──────────────────────────────────────────────────────────────
        cpu_pct     = psutil.cpu_percent(interval=1)
        cpu_count   = psutil.cpu_count(logical=True)
        cpu_freq    = psutil.cpu_freq()
        load_avg    = os.getloadavg() if hasattr(os, 'getloadavg') else (0, 0, 0)

        # ── Memory ───────────────────────────────────────────────────────────
        mem   = psutil.virtual_memory()
        swap  = psutil.swap_memory()

        # ── Disk (root partition) ─────────────────────────────────────────────
        disk = psutil.disk_usage('/')
        try:
            disk_io = psutil.disk_io_counters()
            disk_read_mb  = disk_io.read_bytes  // (1024 * 1024)
            disk_write_mb = disk_io.write_bytes // (1024 * 1024)
        except Exception:
            disk_read_mb = disk_write_mb = 0

        # ── Network ───────────────────────────────────────────────────────────
        net = psutil.net_io_counters()
        net_sent_mb = net.bytes_sent // (1024 * 1024)
        net_recv_mb = net.bytes_recv // (1024 * 1024)
        net_errs    = net.errin + net.errout
        net_drops   = getattr(net, 'dropin', 0) + getattr(net, 'dropout', 0)

        # ── Processes ─────────────────────────────────────────────────────────
        proc_count = len(psutil.pids())
        zombie_count = 0
        high_cpu_procs: List[str] = []
        try:
            for p in psutil.process_iter(['pid', 'name', 'status', 'cpu_percent']):
                info = p.info
                if info.get('status') == psutil.STATUS_ZOMBIE:
                    zombie_count += 1
                if (info.get('cpu_percent') or 0) > 80:
                    high_cpu_procs.append(f"{info['name']}({info['pid']})")
        except Exception:
            pass

        # ── Open connections ──────────────────────────────────────────────────
        try:
            conns = psutil.net_connections(kind='inet')
            established = sum(1 for c in conns if c.status == 'ESTABLISHED')
            listening    = sum(1 for c in conns if c.status == 'LISTEN')
        except Exception:
            established = listening = 0

        # ── Determine alert level ─────────────────────────────────────────────
        level = 'INFO'
        warnings: List[str] = []

        if cpu_pct >= 95:
            level = 'CRITICAL'
            warnings.append(f"CPU critical: {cpu_pct}%")
        elif cpu_pct >= 80:
            level = 'WARNING' if level == 'INFO' else level
            warnings.append(f"CPU high: {cpu_pct}%")

        if mem.percent >= 95:
            level = 'CRITICAL'
            warnings.append(f"Memory critical: {mem.percent}%")
        elif mem.percent >= 85:
            level = 'WARNING' if level == 'INFO' else level
            warnings.append(f"Memory high: {mem.percent}%")

        if disk.percent >= 95:
            level = 'CRITICAL'
            warnings.append(f"Disk critical: {disk.percent}%")
        elif disk.percent >= 85:
            level = 'WARNING' if level == 'INFO' else level
            warnings.append(f"Disk high: {disk.percent}%")

        if zombie_count > 5:
            level = 'WARNING' if level == 'INFO' else level
            warnings.append(f"Zombie processes: {zombie_count}")

        if net_errs > 100:
            level = 'WARNING' if level == 'INFO' else level
            warnings.append(f"Network errors: {net_errs}")

        # ── Build summary message ─────────────────────────────────────────────
        parts = [
            f"CPU={cpu_pct}%({cpu_count}cores)",
            f"MEM={mem.percent}%({_human_bytes(mem.used)}/{_human_bytes(mem.total)})",
            f"SWAP={swap.percent}%",
            f"DISK={disk.percent}%({_human_bytes(disk.used)}/{_human_bytes(disk.total)})",
            f"NET=↑{net_sent_mb}MB↓{net_recv_mb}MB",
            f"PROCS={proc_count}",
            f"CONNS={established}est/{listening}listen",
        ]
        if warnings:
            parts.append("ALERTS=" + "|".join(warnings))
        if high_cpu_procs:
            parts.append("HIGH_CPU=" + ",".join(high_cpu_procs[:3]))

        message = " | ".join(parts)

        parsed_fields: Dict[str, Any] = {
            'event_type':          'system_metrics',
            # CPU
            'cpu_percent':          cpu_pct,
            'cpu_cores':            cpu_count,
            'cpu_freq_mhz':         round(cpu_freq.current, 1) if cpu_freq else 0,
            'load_avg_1m':          round(load_avg[0], 2),
            'load_avg_5m':          round(load_avg[1], 2),
            'load_avg_15m':         round(load_avg[2], 2),
            # Memory
            'memory_percent':       mem.percent,
            'memory_used_mb':       mem.used      // (1024 * 1024),
            'memory_total_mb':      mem.total     // (1024 * 1024),
            'memory_available_mb':  mem.available // (1024 * 1024),
            'swap_percent':         swap.percent,
            'swap_used_mb':         swap.used     // (1024 * 1024),
            # Disk
            'disk_percent':         disk.percent,
            'disk_used_gb':         disk.used  // (1024 ** 3),
            'disk_total_gb':        disk.total // (1024 ** 3),
            'disk_read_mb':         disk_read_mb,
            'disk_write_mb':        disk_write_mb,
            # Network
            'net_sent_mb':          net_sent_mb,
            'net_recv_mb':          net_recv_mb,
            'net_packets_sent':     net.packets_sent,
            'net_packets_recv':     net.packets_recv,
            'net_errors':           net_errs,
            'net_drops':            net_drops,
            # Processes
            'process_count':        proc_count,
            'zombie_count':         zombie_count,
            'connections_established': established,
            'connections_listening':   listening,
            # Meta
            'hostname':             socket.gethostname(),
            'warnings':             warnings,
        }

        return {
            'timestamp':     datetime.now(timezone.utc).isoformat(),
            'level':         level,
            'source':        'system_metrics',
            'message':       message,
            'raw':           message,
            'parsed_fields': parsed_fields,
        }

    except Exception as e:
        logger.error(f"System metrics collection error: {e}", exc_info=True)
        return _fallback_metrics(str(e))


def _fallback_metrics(error: str = '') -> Dict[str, Any]:
    msg = f"System metrics unavailable: {error}" if error else "System metrics unavailable"
    return {
        'timestamp':     datetime.now(timezone.utc).isoformat(),
        'level':         'WARNING',
        'source':        'system_metrics',
        'message':       msg,
        'raw':           msg,
        'parsed_fields': {'event_type': 'system_metrics', 'error': error},
    }
