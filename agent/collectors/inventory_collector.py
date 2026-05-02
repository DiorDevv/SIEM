"""
Inventory collector — Wazuh-class system inventory.

Collects:
  - Installed packages (dpkg / rpm / pip / npm / Windows registry)
  - Open ports (LISTEN) with owning process + user
  - All running processes (PID, PPID, user, CPU%, RAM, cmdline)
  - Network interfaces (MAC, IPs, netmask, speed, MTU, state)
"""
import hashlib
import json
import os
import sys
import logging
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# ── Delta helpers ─────────────────────────────────────────────────────────────

def _section_hash(items: List[Dict[str, Any]], keys: List[str]) -> str:
    """
    Stable SHA256 of a section.
    Only the fields that matter for change detection are hashed
    (e.g. processes exclude cpu_pct/mem_mb since those change constantly).
    """
    normalized = sorted(
        [{k: v for k, v in item.items() if k in keys} for item in items],
        key=lambda x: json.dumps(x, sort_keys=True),
    )
    digest = hashlib.sha256(
        json.dumps(normalized, sort_keys=True).encode()
    ).hexdigest()[:16]   # 16 hex chars = 64-bit — enough for change detection
    return digest


def pkg_hash(packages: List[Dict]) -> str:
    return _section_hash(packages, ["name", "version", "ecosystem"])

def port_hash(ports: List[Dict]) -> str:
    return _section_hash(ports, ["port", "protocol", "bind_addr", "process_name"])

def proc_hash(processes: List[Dict]) -> str:
    # Exclude cpu_pct/mem_mb — those change every second
    return _section_hash(processes, ["pid", "name", "user", "exe", "cmdline"])

def iface_hash(interfaces: List[Dict]) -> str:
    return _section_hash(interfaces, ["name", "mac", "ipv4", "ipv6", "is_up"])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Packages ──────────────────────────────────────────────────────────────────

def collect_packages() -> List[Dict[str, Any]]:
    """Reuse vuln_scanner — already production-quality."""
    try:
        from collectors.vuln_scanner import collect_packages as _cp
        return _cp()
    except Exception as e:
        logger.error(f"Inventory packages: {e}")
        return []


# ── Open ports ────────────────────────────────────────────────────────────────

def collect_ports() -> List[Dict[str, Any]]:
    """Return all LISTEN sockets with owning process info."""
    try:
        import psutil
    except ImportError:
        return _ports_fallback()

    ports: List[Dict[str, Any]] = []
    pid_cache: Dict[int, Dict[str, str]] = {}

    def _proc_info(pid: Optional[int]) -> Dict[str, str]:
        if pid is None:
            return {"name": "", "user": "", "cmdline": ""}
        if pid in pid_cache:
            return pid_cache[pid]
        try:
            p = psutil.Process(pid)
            info = {
                "name":    p.name(),
                "user":    p.username(),
                "cmdline": " ".join(p.cmdline())[:256],
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            info = {"name": "", "user": "", "cmdline": ""}
        pid_cache[pid] = info
        return info

    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        # Fallback: root required on some platforms
        return _ports_fallback()

    seen: set = set()
    for c in conns:
        if c.status != psutil.CONN_LISTEN:
            continue
        laddr = c.laddr
        key   = (laddr.port, c.type, c.family)
        if key in seen:
            continue
        seen.add(key)

        proc = _proc_info(c.pid)
        ports.append({
            "port":         laddr.port,
            "bind_addr":    laddr.ip,
            "protocol":     "tcp" if c.type == 1 else "udp",   # socket.SOCK_STREAM=1
            "pid":          c.pid,
            "process_name": proc["name"],
            "process_user": proc["user"],
            "cmdline":      proc["cmdline"],
        })

    return sorted(ports, key=lambda x: x["port"])


def _ports_fallback() -> List[Dict[str, Any]]:
    """ss / netstat fallback when psutil is unavailable."""
    import subprocess
    ports = []
    try:
        out = subprocess.run(
            ["ss", "-tlnup"],
            capture_output=True, text=True, timeout=10
        ).stdout
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            local = parts[3]
            addr_port = local.rsplit(":", 1)
            if len(addr_port) == 2 and addr_port[1].isdigit():
                ports.append({
                    "port":         int(addr_port[1]),
                    "bind_addr":    addr_port[0],
                    "protocol":     "tcp",
                    "pid":          None,
                    "process_name": "",
                    "process_user": "",
                    "cmdline":      "",
                })
    except Exception:
        pass
    return ports


# ── Processes ─────────────────────────────────────────────────────────────────

def collect_processes() -> List[Dict[str, Any]]:
    """Return snapshot of all running processes."""
    try:
        import psutil
    except ImportError:
        return []

    procs: List[Dict[str, Any]] = []

    attrs = ["pid", "ppid", "name", "username", "status",
             "cpu_percent", "memory_info", "cmdline", "create_time", "exe"]

    # First pass triggers CPU measurement
    for p in psutil.process_iter(["pid"]):
        try:
            p.cpu_percent(interval=None)
        except Exception:
            pass

    import time; time.sleep(0.3)   # short interval for cpu_percent accuracy

    for p in psutil.process_iter(attrs):
        try:
            info = p.info
            mem_mb = round(info["memory_info"].rss / (1024 * 1024), 1) if info.get("memory_info") else 0
            cmdline = " ".join(info.get("cmdline") or [])[:512] or info.get("name", "")
            # create_time may be float epoch
            started: Optional[str] = None
            if info.get("create_time"):
                try:
                    started = datetime.fromtimestamp(info["create_time"], tz=timezone.utc).isoformat()
                except Exception:
                    pass

            procs.append({
                "pid":        info.get("pid"),
                "ppid":       info.get("ppid"),
                "name":       info.get("name", ""),
                "user":       info.get("username", ""),
                "status":     str(info.get("status", "")),
                "cpu_pct":    round(info.get("cpu_percent") or 0, 1),
                "mem_mb":     mem_mb,
                "cmdline":    cmdline,
                "exe":        info.get("exe") or "",
                "started_at": started,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return procs


# ── Network interfaces ────────────────────────────────────────────────────────

def collect_interfaces() -> List[Dict[str, Any]]:
    """Return all non-loopback network interfaces with addresses and stats."""
    try:
        import psutil
    except ImportError:
        return _interfaces_fallback()

    addrs_map  = psutil.net_if_addrs()
    stats_map  = psutil.net_if_stats()

    import socket as _socket
    AF_INET   = _socket.AF_INET
    AF_INET6  = _socket.AF_INET6
    AF_PACKET = getattr(_socket, "AF_PACKET", 17)   # Linux only

    interfaces: List[Dict[str, Any]] = []
    for name, addr_list in addrs_map.items():
        if name == "lo":
            continue

        mac  = ""
        ipv4: List[Dict[str, str]] = []
        ipv6: List[str] = []

        for a in addr_list:
            if a.family == AF_PACKET:
                mac = a.address
            elif a.family == AF_INET:
                ipv4.append({"ip": a.address, "netmask": a.netmask or ""})
            elif a.family == AF_INET6:
                ipv6.append(a.address.split("%")[0])   # strip scope id

        stats = stats_map.get(name)
        interfaces.append({
            "name":       name,
            "mac":        mac,
            "ipv4":       ipv4,
            "ipv6":       ipv6,
            "is_up":      bool(stats and stats.isup),
            "speed_mbps": stats.speed if stats else 0,
            "mtu":        stats.mtu   if stats else 0,
            "duplex":     str(stats.duplex).split(".")[-1] if stats else "",
        })

    return sorted(interfaces, key=lambda x: x["name"])


def _interfaces_fallback() -> List[Dict[str, Any]]:
    """ip addr fallback when psutil unavailable."""
    import subprocess, re
    interfaces = []
    try:
        out = subprocess.run(["ip", "addr", "show"], capture_output=True, text=True, timeout=5).stdout
        current: Optional[Dict] = None
        for line in out.splitlines():
            m = re.match(r"^\d+:\s+(\S+):", line)
            if m:
                if current:
                    interfaces.append(current)
                current = {"name": m.group(1).rstrip("@"), "mac": "", "ipv4": [], "ipv6": [],
                           "is_up": "UP" in line, "speed_mbps": 0, "mtu": 0, "duplex": ""}
                mtu = re.search(r"mtu (\d+)", line)
                if mtu and current:
                    current["mtu"] = int(mtu.group(1))
            elif current:
                if "link/ether" in line:
                    parts = line.split()
                    current["mac"] = parts[1] if len(parts) > 1 else ""
                elif "inet " in line:
                    m2 = re.search(r"inet (\S+)", line)
                    if m2:
                        ip, *mask = m2.group(1).split("/")
                        current["ipv4"].append({"ip": ip, "netmask": mask[0] if mask else ""})
                elif "inet6 " in line:
                    m2 = re.search(r"inet6 (\S+)", line)
                    if m2:
                        current["ipv6"].append(m2.group(1).split("/")[0])
        if current:
            interfaces.append(current)
    except Exception:
        pass
    return [i for i in interfaces if i["name"] != "lo"]


# ── Full snapshot ─────────────────────────────────────────────────────────────

def collect_inventory() -> Dict[str, Any]:
    """
    Collect full inventory snapshot with section hashes.
    Returns dict ready for delta comparison + POST.
    """
    started  = datetime.now(timezone.utc)
    hostname = socket.gethostname()

    logger.info("Inventory: collecting packages...")
    packages   = collect_packages()
    logger.info(f"Inventory: {len(packages)} packages")

    logger.info("Inventory: collecting ports...")
    ports      = collect_ports()
    logger.info(f"Inventory: {len(ports)} listening ports")

    logger.info("Inventory: collecting processes...")
    processes  = collect_processes()
    logger.info(f"Inventory: {len(processes)} processes")

    logger.info("Inventory: collecting interfaces...")
    interfaces = collect_interfaces()
    logger.info(f"Inventory: {len(interfaces)} interfaces")

    elapsed_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
    logger.info(f"Inventory: full scan done in {elapsed_ms}ms")

    return {
        "hostname":         hostname,
        "scanned_at":       started.isoformat(),
        "scan_duration_ms": elapsed_ms,
        # Section hashes for delta detection
        "pkg_hash":   pkg_hash(packages),
        "port_hash":  port_hash(ports),
        "proc_hash":  proc_hash(processes),
        "iface_hash": iface_hash(interfaces),
        "packages":        packages,
        "ports":           ports,
        "processes":       processes,
        "interfaces":      interfaces,
    }
