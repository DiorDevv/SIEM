"""
Inventory models — per-agent system snapshot.

Tables:
  inventory_snapshots  — one row per scan (metadata + timing)
  inventory_packages   — installed packages
  inventory_ports      — LISTEN ports with owning process
  inventory_processes  — running processes
  inventory_interfaces — network interfaces
"""
from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, BigInteger, String, DateTime, Boolean,
    Float, Text, JSON, Index, ForeignKey,
)
from database import Base


def _utcnow():
    return datetime.now(timezone.utc)


class InventorySnapshot(Base):
    __tablename__ = "inventory_snapshots"

    id               = Column(Integer, primary_key=True, index=True)
    agent_id         = Column(String(64),  nullable=False, index=True)
    hostname         = Column(String(256), nullable=True)
    scanned_at       = Column(DateTime(timezone=True), default=_utcnow, nullable=False, index=True)
    scan_duration_ms = Column(Integer, nullable=True)
    pkg_count        = Column(Integer, default=0)
    port_count       = Column(Integer, default=0)
    process_count    = Column(Integer, default=0)
    iface_count      = Column(Integer, default=0)
    # Delta sync: SHA256 of each section — agent compares before sending
    pkg_hash         = Column(String(64), nullable=True)
    port_hash        = Column(String(64), nullable=True)
    proc_hash        = Column(String(64), nullable=True)
    iface_hash       = Column(String(64), nullable=True)

    __table_args__ = (
        Index("ix_inv_snap_agent_scanned", "agent_id", "scanned_at"),
    )


class InventoryPackage(Base):
    __tablename__ = "inventory_packages"

    id          = Column(Integer, primary_key=True, index=True)
    snapshot_id = Column(Integer, ForeignKey("inventory_snapshots.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    agent_id    = Column(String(64),  nullable=False, index=True)
    name        = Column(String(256), nullable=False)
    version     = Column(String(128), nullable=True)
    ecosystem   = Column(String(32),  nullable=True)   # apt, rpm, pip, npm, windows

    __table_args__ = (
        Index("ix_inv_pkg_agent_name", "agent_id", "name"),
    )


class InventoryPort(Base):
    __tablename__ = "inventory_ports"

    id           = Column(Integer, primary_key=True, index=True)
    snapshot_id  = Column(Integer, ForeignKey("inventory_snapshots.id", ondelete="CASCADE"),
                          nullable=False, index=True)
    agent_id     = Column(String(64), nullable=False, index=True)
    port         = Column(Integer,    nullable=False)
    bind_addr    = Column(String(64), nullable=True)
    protocol     = Column(String(8),  nullable=True, default="tcp")  # tcp / udp
    pid          = Column(Integer,    nullable=True)
    process_name = Column(String(256), nullable=True)
    process_user = Column(String(128), nullable=True)
    cmdline      = Column(Text, nullable=True)

    __table_args__ = (
        Index("ix_inv_port_agent_port", "agent_id", "port"),
    )


class InventoryProcess(Base):
    __tablename__ = "inventory_processes"

    id          = Column(Integer, primary_key=True, index=True)
    snapshot_id = Column(Integer, ForeignKey("inventory_snapshots.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    agent_id    = Column(String(64),  nullable=False, index=True)
    pid         = Column(Integer,     nullable=False)
    ppid        = Column(Integer,     nullable=True)
    name        = Column(String(256), nullable=True)
    user        = Column(String(128), nullable=True)
    status      = Column(String(32),  nullable=True)   # running, sleeping, zombie...
    cpu_pct     = Column(Float,       nullable=True)
    mem_mb      = Column(Float,       nullable=True)
    cmdline     = Column(Text,        nullable=True)
    exe         = Column(Text,        nullable=True)
    started_at  = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_inv_proc_agent_pid", "agent_id", "pid"),
    )


class InventoryInterface(Base):
    __tablename__ = "inventory_interfaces"

    id          = Column(Integer, primary_key=True, index=True)
    snapshot_id = Column(Integer, ForeignKey("inventory_snapshots.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    agent_id    = Column(String(64),  nullable=False, index=True)
    name        = Column(String(64),  nullable=False)
    mac         = Column(String(32),  nullable=True)
    ipv4        = Column(JSON,        nullable=True)   # [{ip, netmask}]
    ipv6        = Column(JSON,        nullable=True)   # [addr, ...]
    is_up       = Column(Boolean,     default=True)
    speed_mbps  = Column(Integer,     nullable=True)
    mtu         = Column(Integer,     nullable=True)
    duplex      = Column(String(16),  nullable=True)
