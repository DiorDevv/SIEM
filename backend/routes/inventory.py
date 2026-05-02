"""
Inventory API — per-agent system snapshot with delta sync.

Endpoints:
  GET  /api/inventory/hashes/{agent_id}    — agent fetches last known hashes (delta check)
  POST /api/inventory/submit               — full snapshot (first scan or forced)
  POST /api/inventory/delta                — partial update (only changed sections)
  GET  /api/inventory/agents               — all agents with last scan metadata
  GET  /api/inventory/{agent_id}           — latest snapshot summary
  GET  /api/inventory/{agent_id}/packages  — packages (search, ecosystem, page)
  GET  /api/inventory/{agent_id}/ports     — listening ports
  GET  /api/inventory/{agent_id}/processes — running processes (search, page)
  GET  /api/inventory/{agent_id}/interfaces— network interfaces
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models.inventory import (
    InventorySnapshot, InventoryPackage, InventoryPort,
    InventoryProcess, InventoryInterface,
)
from routes.auth import get_current_user
from models.user import User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/inventory", tags=["inventory"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class PackageIn(BaseModel):
    name:      str
    version:   Optional[str] = None
    ecosystem: Optional[str] = None

class PortIn(BaseModel):
    port:         int
    bind_addr:    Optional[str] = None
    protocol:     Optional[str] = "tcp"
    pid:          Optional[int] = None
    process_name: Optional[str] = None
    process_user: Optional[str] = None
    cmdline:      Optional[str] = None

class ProcessIn(BaseModel):
    pid:        int
    ppid:       Optional[int]   = None
    name:       Optional[str]   = None
    user:       Optional[str]   = None
    status:     Optional[str]   = None
    cpu_pct:    Optional[float] = None
    mem_mb:     Optional[float] = None
    cmdline:    Optional[str]   = None
    exe:        Optional[str]   = None
    started_at: Optional[str]   = None

class InterfaceIn(BaseModel):
    name:       str
    mac:        Optional[str]  = None
    ipv4:       Optional[list] = None
    ipv6:       Optional[list] = None
    is_up:      Optional[bool] = True
    speed_mbps: Optional[int]  = None
    mtu:        Optional[int]  = None
    duplex:     Optional[str]  = None

class InventorySubmit(BaseModel):
    agent_id:         str
    hostname:         Optional[str]   = None
    scanned_at:       Optional[str]   = None
    scan_duration_ms: Optional[int]   = None
    # Section hashes — SHA256 of sorted JSON of each section
    pkg_hash:   Optional[str] = None
    port_hash:  Optional[str] = None
    proc_hash:  Optional[str] = None
    iface_hash: Optional[str] = None
    packages:   List[PackageIn]   = []
    ports:      List[PortIn]      = []
    processes:  List[ProcessIn]   = []
    interfaces: List[InterfaceIn] = []

class InventoryDelta(BaseModel):
    """Agent sends only sections whose hash changed."""
    agent_id:         str
    hostname:         Optional[str] = None
    scanned_at:       Optional[str] = None
    scan_duration_ms: Optional[int] = None
    # New hashes for ALL sections (even unchanged — server updates snapshot)
    pkg_hash:   Optional[str] = None
    port_hash:  Optional[str] = None
    proc_hash:  Optional[str] = None
    iface_hash: Optional[str] = None
    # Only include sections that CHANGED (others are omitted / None)
    packages:   Optional[List[PackageIn]]   = None
    ports:      Optional[List[PortIn]]      = None
    processes:  Optional[List[ProcessIn]]   = None
    interfaces: Optional[List[InterfaceIn]] = None


# ── GET /hashes/{agent_id} ────────────────────────────────────────────────────

@router.get("/hashes/{agent_id}")
async def get_hashes(agent_id: str, db: AsyncSession = Depends(get_db)):
    """
    Agent calls this before scanning to get the last known hashes.
    If a section hash matches what the agent computed locally,
    that section is skipped in the next submit.
    No auth required — agent calls this on startup.
    """
    snap = (await db.execute(
        select(
            InventorySnapshot.pkg_hash,
            InventorySnapshot.port_hash,
            InventorySnapshot.proc_hash,
            InventorySnapshot.iface_hash,
            InventorySnapshot.scanned_at,
        )
        .where(InventorySnapshot.agent_id == agent_id)
        .order_by(InventorySnapshot.scanned_at.desc())
        .limit(1)
    )).one_or_none()

    if snap is None:
        return {"pkg_hash": None, "port_hash": None,
                "proc_hash": None, "iface_hash": None, "scanned_at": None}

    return {
        "pkg_hash":   snap.pkg_hash,
        "port_hash":  snap.port_hash,
        "proc_hash":  snap.proc_hash,
        "iface_hash": snap.iface_hash,
        "scanned_at": snap.scanned_at.isoformat() if snap.scanned_at else None,
    }


# ── POST /submit ──────────────────────────────────────────────────────────────

@router.post("/submit", status_code=204)
async def submit_inventory(payload: InventorySubmit, db: AsyncSession = Depends(get_db)):
    """Full snapshot — replaces all previous data for this agent."""
    scanned_at = _parse_dt(payload.scanned_at)
    await _replace_snapshot(
        db, payload.agent_id, payload.hostname, scanned_at,
        payload.scan_duration_ms,
        payload.pkg_hash, payload.port_hash, payload.proc_hash, payload.iface_hash,
        packages   = payload.packages,
        ports      = payload.ports,
        processes  = payload.processes,
        interfaces = payload.interfaces,
    )
    logger.info(
        f"Inventory FULL: agent={payload.agent_id} "
        f"pkg={len(payload.packages)} ports={len(payload.ports)} "
        f"procs={len(payload.processes)} ifaces={len(payload.interfaces)}"
    )


# ── POST /delta ───────────────────────────────────────────────────────────────

@router.post("/delta", status_code=204)
async def delta_inventory(payload: InventoryDelta, db: AsyncSession = Depends(get_db)):
    """
    Partial update — agent sends only sections whose hash changed.
    Sections not included are kept as-is from the previous snapshot.
    """
    scanned_at = _parse_dt(payload.scanned_at)

    # Load existing snapshot
    existing = (await db.execute(
        select(InventorySnapshot)
        .where(InventorySnapshot.agent_id == payload.agent_id)
        .order_by(InventorySnapshot.scanned_at.desc())
        .limit(1)
    )).scalar_one_or_none()

    if existing is None:
        # No prior snapshot — treat as full submit (can't do delta without base)
        logger.info(f"Inventory DELTA→FULL (no prior snapshot): agent={payload.agent_id}")
        await _replace_snapshot(
            db, payload.agent_id, payload.hostname, scanned_at,
            payload.scan_duration_ms,
            payload.pkg_hash, payload.port_hash, payload.proc_hash, payload.iface_hash,
            packages   = payload.packages   or [],
            ports      = payload.ports      or [],
            processes  = payload.processes  or [],
            interfaces = payload.interfaces or [],
        )
        return

    changed: List[str] = []

    # Update only the sections that were sent
    if payload.packages is not None:
        await db.execute(delete(InventoryPackage).where(InventoryPackage.snapshot_id == existing.id))
        db.add_all(_make_packages(existing.id, payload.agent_id, payload.packages))
        existing.pkg_count = len(payload.packages)
        existing.pkg_hash  = payload.pkg_hash
        changed.append(f"pkg={len(payload.packages)}")

    if payload.ports is not None:
        await db.execute(delete(InventoryPort).where(InventoryPort.snapshot_id == existing.id))
        db.add_all(_make_ports(existing.id, payload.agent_id, payload.ports))
        existing.port_count = len(payload.ports)
        existing.port_hash  = payload.port_hash
        changed.append(f"ports={len(payload.ports)}")

    if payload.processes is not None:
        await db.execute(delete(InventoryProcess).where(InventoryProcess.snapshot_id == existing.id))
        procs = _make_processes(existing.id, payload.agent_id, payload.processes)
        for i in range(0, len(procs), 500):
            db.add_all(procs[i:i + 500])
        existing.process_count = len(payload.processes)
        existing.proc_hash     = payload.proc_hash
        changed.append(f"procs={len(payload.processes)}")

    if payload.interfaces is not None:
        await db.execute(delete(InventoryInterface).where(InventoryInterface.snapshot_id == existing.id))
        db.add_all(_make_interfaces(existing.id, payload.agent_id, payload.interfaces))
        existing.iface_count = len(payload.interfaces)
        existing.iface_hash  = payload.iface_hash
        changed.append(f"ifaces={len(payload.interfaces)}")

    # Always update scan metadata
    if payload.hostname:
        existing.hostname = payload.hostname
    if scanned_at:
        existing.scanned_at = scanned_at
    if payload.scan_duration_ms:
        existing.scan_duration_ms = payload.scan_duration_ms

    await db.commit()
    logger.info(f"Inventory DELTA: agent={payload.agent_id} changed=[{', '.join(changed) or 'none'}]")


# ── GET /agents ───────────────────────────────────────────────────────────────

@router.get("/agents")
async def list_inventory_agents(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    rows = (await db.execute(
        select(
            InventorySnapshot.agent_id,
            InventorySnapshot.hostname,
            InventorySnapshot.scanned_at,
            InventorySnapshot.scan_duration_ms,
            InventorySnapshot.pkg_count,
            InventorySnapshot.port_count,
            InventorySnapshot.process_count,
            InventorySnapshot.iface_count,
        )
    )).all()

    return [
        {
            "agent_id":         r.agent_id,
            "hostname":         r.hostname,
            "scanned_at":       r.scanned_at.isoformat() if r.scanned_at else None,
            "scan_duration_ms": r.scan_duration_ms,
            "pkg_count":        r.pkg_count,
            "port_count":       r.port_count,
            "process_count":    r.process_count,
            "iface_count":      r.iface_count,
        }
        for r in rows
    ]


# ── GET /{agent_id} ───────────────────────────────────────────────────────────

@router.get("/{agent_id}")
async def get_inventory_summary(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    snap = await _latest_snapshot(db, agent_id)
    return {
        "agent_id":         snap.agent_id,
        "hostname":         snap.hostname,
        "scanned_at":       snap.scanned_at.isoformat() if snap.scanned_at else None,
        "scan_duration_ms": snap.scan_duration_ms,
        "pkg_count":        snap.pkg_count,
        "port_count":       snap.port_count,
        "process_count":    snap.process_count,
        "iface_count":      snap.iface_count,
    }


# ── GET /{agent_id}/packages ──────────────────────────────────────────────────

@router.get("/{agent_id}/packages")
async def get_packages(
    agent_id:  str,
    search:    Optional[str] = Query(None),
    ecosystem: Optional[str] = Query(None),
    page:      int = Query(1, ge=1),
    per_page:  int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    snap_id = (await _latest_snapshot(db, agent_id)).id
    q = select(InventoryPackage).where(InventoryPackage.snapshot_id == snap_id)
    if search:
        q = q.where(InventoryPackage.name.ilike(f"%{search}%"))
    if ecosystem:
        q = q.where(InventoryPackage.ecosystem == ecosystem)

    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    rows  = (await db.execute(
        q.order_by(InventoryPackage.name).offset((page - 1) * per_page).limit(per_page)
    )).scalars().all()

    return {
        "total": total,
        "page":  page,
        "items": [{"id": r.id, "name": r.name, "version": r.version,
                   "ecosystem": r.ecosystem} for r in rows],
    }


# ── GET /{agent_id}/ports ─────────────────────────────────────────────────────

@router.get("/{agent_id}/ports")
async def get_ports(
    agent_id: str,
    protocol: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    snap_id = (await _latest_snapshot(db, agent_id)).id
    q = select(InventoryPort).where(InventoryPort.snapshot_id == snap_id)
    if protocol:
        q = q.where(InventoryPort.protocol == protocol)
    rows = (await db.execute(q.order_by(InventoryPort.port))).scalars().all()
    return [
        {"port": r.port, "bind_addr": r.bind_addr, "protocol": r.protocol,
         "pid": r.pid, "process_name": r.process_name,
         "process_user": r.process_user, "cmdline": r.cmdline}
        for r in rows
    ]


# ── GET /{agent_id}/processes ─────────────────────────────────────────────────

@router.get("/{agent_id}/processes")
async def get_processes(
    agent_id: str,
    search:   Optional[str] = Query(None),
    user:     Optional[str] = Query(None),
    page:     int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=500),
    sort:     str = Query("cpu_pct"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    snap_id = (await _latest_snapshot(db, agent_id)).id
    q = select(InventoryProcess).where(InventoryProcess.snapshot_id == snap_id)
    if search:
        q = q.where(
            InventoryProcess.name.ilike(f"%{search}%") |
            InventoryProcess.cmdline.ilike(f"%{search}%")
        )
    if user:
        q = q.where(InventoryProcess.user == user)

    sort_col = {
        "cpu_pct": InventoryProcess.cpu_pct.desc(),
        "mem_mb":  InventoryProcess.mem_mb.desc(),
        "name":    InventoryProcess.name,
        "pid":     InventoryProcess.pid,
    }.get(sort, InventoryProcess.cpu_pct.desc())

    total = (await db.execute(select(func.count()).select_from(q.subquery()))).scalar_one()
    rows  = (await db.execute(
        q.order_by(sort_col).offset((page - 1) * per_page).limit(per_page)
    )).scalars().all()

    return {
        "total": total,
        "page":  page,
        "items": [
            {"pid": r.pid, "ppid": r.ppid, "name": r.name, "user": r.user,
             "status": r.status, "cpu_pct": r.cpu_pct, "mem_mb": r.mem_mb,
             "cmdline": r.cmdline, "exe": r.exe,
             "started_at": r.started_at.isoformat() if r.started_at else None}
            for r in rows
        ],
    }


# ── GET /{agent_id}/interfaces ────────────────────────────────────────────────

@router.get("/{agent_id}/interfaces")
async def get_interfaces(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    snap_id = (await _latest_snapshot(db, agent_id)).id
    rows = (await db.execute(
        select(InventoryInterface)
        .where(InventoryInterface.snapshot_id == snap_id)
        .order_by(InventoryInterface.name)
    )).scalars().all()
    return [
        {"name": r.name, "mac": r.mac, "ipv4": r.ipv4 or [],
         "ipv6": r.ipv6 or [], "is_up": r.is_up,
         "speed_mbps": r.speed_mbps, "mtu": r.mtu, "duplex": r.duplex}
        for r in rows
    ]


# ── Internal helpers ──────────────────────────────────────────────────────────

def _parse_dt(s: Optional[str]) -> datetime:
    if s:
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(timezone.utc)


async def _latest_snapshot(db: AsyncSession, agent_id: str) -> InventorySnapshot:
    snap = (await db.execute(
        select(InventorySnapshot)
        .where(InventorySnapshot.agent_id == agent_id)
        .order_by(InventorySnapshot.scanned_at.desc())
        .limit(1)
    )).scalar_one_or_none()
    if snap is None:
        raise HTTPException(404, f"No inventory for agent {agent_id}")
    return snap


async def _replace_snapshot(
    db: AsyncSession,
    agent_id: str, hostname: Optional[str],
    scanned_at: datetime, scan_duration_ms: Optional[int],
    pkg_hash: Optional[str], port_hash: Optional[str],
    proc_hash: Optional[str], iface_hash: Optional[str],
    packages: List, ports: List, processes: List, interfaces: List,
):
    """Delete previous snapshot and write fresh one."""
    old_ids = (await db.execute(
        select(InventorySnapshot.id).where(InventorySnapshot.agent_id == agent_id)
    )).scalars().all()
    for sid in old_ids:
        await db.execute(delete(InventoryPackage).where(InventoryPackage.snapshot_id == sid))
        await db.execute(delete(InventoryPort).where(InventoryPort.snapshot_id == sid))
        await db.execute(delete(InventoryProcess).where(InventoryProcess.snapshot_id == sid))
        await db.execute(delete(InventoryInterface).where(InventoryInterface.snapshot_id == sid))
    if old_ids:
        await db.execute(delete(InventorySnapshot).where(InventorySnapshot.agent_id == agent_id))

    snap = InventorySnapshot(
        agent_id=agent_id, hostname=hostname, scanned_at=scanned_at,
        scan_duration_ms=scan_duration_ms,
        pkg_count=len(packages), port_count=len(ports),
        process_count=len(processes), iface_count=len(interfaces),
        pkg_hash=pkg_hash, port_hash=port_hash,
        proc_hash=proc_hash, iface_hash=iface_hash,
    )
    db.add(snap)
    await db.flush()

    db.add_all(_make_packages(snap.id, agent_id, packages))
    db.add_all(_make_ports(snap.id, agent_id, ports))
    procs = _make_processes(snap.id, agent_id, processes)
    for i in range(0, len(procs), 500):
        db.add_all(procs[i:i + 500])
    db.add_all(_make_interfaces(snap.id, agent_id, interfaces))
    await db.commit()


def _make_packages(snap_id: int, agent_id: str, items: List) -> List[InventoryPackage]:
    return [
        InventoryPackage(
            snapshot_id=snap_id, agent_id=agent_id,
            name=(p.name or "")[:255],
            version=(p.version or "")[:127],
            ecosystem=(p.ecosystem or "")[:31],
        )
        for p in items
    ]


def _make_ports(snap_id: int, agent_id: str, items: List) -> List[InventoryPort]:
    return [
        InventoryPort(
            snapshot_id=snap_id, agent_id=agent_id,
            port=p.port, bind_addr=p.bind_addr,
            protocol=p.protocol or "tcp", pid=p.pid,
            process_name=(p.process_name or "")[:255],
            process_user=(p.process_user or "")[:127],
            cmdline=p.cmdline,
        )
        for p in items
    ]


def _make_processes(snap_id: int, agent_id: str, items: List) -> List[InventoryProcess]:
    result = []
    for p in items:
        started: Optional[datetime] = None
        if p.started_at:
            try:
                started = datetime.fromisoformat(p.started_at.replace("Z", "+00:00"))
            except ValueError:
                pass
        result.append(InventoryProcess(
            snapshot_id=snap_id, agent_id=agent_id,
            pid=p.pid, ppid=p.ppid,
            name=(p.name or "")[:255], user=(p.user or "")[:127],
            status=(p.status or "")[:31],
            cpu_pct=p.cpu_pct, mem_mb=p.mem_mb,
            cmdline=p.cmdline, exe=p.exe, started_at=started,
        ))
    return result


def _make_interfaces(snap_id: int, agent_id: str, items: List) -> List[InventoryInterface]:
    return [
        InventoryInterface(
            snapshot_id=snap_id, agent_id=agent_id,
            name=iface.name[:63], mac=iface.mac,
            ipv4=iface.ipv4 or [], ipv6=iface.ipv6 or [],
            is_up=iface.is_up, speed_mbps=iface.speed_mbps,
            mtu=iface.mtu, duplex=iface.duplex,
        )
        for iface in items
    ]
